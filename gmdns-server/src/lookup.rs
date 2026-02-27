use futures::future::BoxFuture;
use h3x::server::{Request, Response, Service};
use redis::AsyncCommands;

use crate::{
    error::{AppError, normalize_host, parse_query_params},
    policy::DomainPolicy,
    storage::{AppState, Storage, decode_redis_multi_member, encode_multi_response, unix_now_secs},
};

// ---------------------------------------------------------------------------
// Lookup result type
// ---------------------------------------------------------------------------

pub enum LookupResult {
    NotFound,
    /// Single record — legacy Standard-domain response.
    Single(Vec<u8>, Vec<u8>),
    /// Multiple records (OpenMulti) — newest first.
    Multi(Vec<(Vec<u8>, Vec<u8>)>),
}

// ---------------------------------------------------------------------------
// Core lookup logic
// ---------------------------------------------------------------------------

pub async fn perform_lookup(
    state: &AppState,
    host: &str,
    limit: Option<usize>,
) -> Result<LookupResult, AppError> {
    let host = normalize_host(host)?;
    let policy = state.policies.policy_for(&host).clone();

    match policy {
        DomainPolicy::Standard => perform_lookup_standard(state, &host).await,
        DomainPolicy::OpenMulti => perform_lookup_multi(state, &host, limit).await,
    }
}

async fn perform_lookup_standard(state: &AppState, host: &str) -> Result<LookupResult, AppError> {
    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            let dns_bytes: Option<Vec<u8>> = conn
                .get(host)
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            let cert_key = format!("{host}_cert");
            let cert_bytes: Option<Vec<u8>> = conn
                .get(&cert_key)
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            match (dns_bytes, cert_bytes) {
                (Some(dns), Some(cert)) => Ok(LookupResult::Single(dns, cert)),
                (Some(dns), None) => Ok(LookupResult::Single(dns, Vec::new())),
                _ => Ok(LookupResult::NotFound),
            }
        }
        Storage::Memory(mem) => {
            let now = tokio::time::Instant::now();
            if let Some(entry) = mem.standard.get(host) {
                let (dns_bytes, cert_bytes, expire) = entry.value();
                if *expire > now {
                    return Ok(LookupResult::Single(dns_bytes.clone(), cert_bytes.clone()));
                }
            }
            mem.standard.remove(host);
            Ok(LookupResult::NotFound)
        }
    }
}

async fn perform_lookup_multi(
    state: &AppState,
    host: &str,
    limit: Option<usize>,
) -> Result<LookupResult, AppError> {
    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            let set_key = format!("{host}:multi");
            let now_secs = unix_now_secs();

            // Remove expired members: those published more than ttl_secs ago.
            let cutoff_score = now_secs.saturating_sub(state.ttl_secs) as f64;
            let _: () = redis::cmd("ZREMRANGEBYSCORE")
                .arg(&set_key)
                .arg("-inf")
                .arg(cutoff_score)
                .query_async::<_, ()>(&mut *conn)
                .await
                .unwrap_or(());

            // Fetch all remaining, newest first (highest score = most recently published)
            let count: isize = limit.map(|l| l as isize).unwrap_or(-1);
            let members: Vec<Vec<u8>> = conn
                .zrevrange(&set_key, 0isize, if count < 0 { -1 } else { count - 1 })
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            let now_secs = unix_now_secs();
            let records: Vec<(Vec<u8>, Vec<u8>)> = members
                .into_iter()
                .filter_map(|m| {
                    let (dns, cert, expire_secs) = decode_redis_multi_member(&m)?;
                    if expire_secs > now_secs {
                        Some((dns, cert))
                    } else {
                        None
                    }
                })
                .collect();

            if records.is_empty() {
                Ok(LookupResult::NotFound)
            } else {
                Ok(LookupResult::Multi(records))
            }
        }
        Storage::Memory(mem) => {
            let now = tokio::time::Instant::now();
            let result = if let Some(mut entry) = mem.multi.get_mut(host) {
                // Evict expired entries in-place
                entry.retain(|r| r.expire > now);
                let take = limit.unwrap_or(entry.len()).min(entry.len());
                entry[..take]
                    .iter()
                    .map(|r| (r.dns_bytes.clone(), r.cert_bytes.clone()))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            };

            if result.is_empty() {
                Ok(LookupResult::NotFound)
            } else {
                Ok(LookupResult::Multi(result))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP response helpers
// ---------------------------------------------------------------------------

pub async fn write_error(resp: &mut Response, err: AppError) {
    resp.set_status(err.status())
        .set_body(bytes::Bytes::from(format!("{}", err)));
    let _ = resp.flush().await;
}

// ---------------------------------------------------------------------------
// LookupSvc
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct LookupSvc {
    pub state: AppState,
}

/// Handle a lookup request.
///
/// - Standard domain, no `limit`: returns raw DNS bytes + `e-cert` header (legacy format).
/// - OpenMulti domain, OR `limit` param present: returns multi-record binary body
///   `[u32 count BE]([u32 dns_len][dns][u32 cert_len][cert])*` with header
///   `x-record-format: multi`.
///
/// Sort order: newest published first.
pub async fn lookup_with_cert(state: AppState, request: &mut Request, response: &mut Response) {
    let params = parse_query_params(&request.uri());
    let Some(host) = params.get("host") else {
        write_error(response, AppError::MissingHostParam).await;
        return;
    };

    let limit: Option<usize> = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0);

    match perform_lookup(&state, host, limit).await {
        Ok(LookupResult::NotFound) => {
            response
                .set_status(http::StatusCode::NOT_FOUND)
                .set_body(bytes::Bytes::from_static(b"Not Found"));
            let _ = response.flush().await;
        }

        Ok(LookupResult::Single(dns_bytes, cert_bytes)) => {
            if limit.is_some() {
                // Caller explicitly requested the multi format.
                let body = encode_multi_response(&[(dns_bytes, cert_bytes)]);
                response
                    .set_status(http::StatusCode::OK)
                    .set_body(bytes::Bytes::from(body));
                response.headers_mut().insert(
                    http::HeaderName::from_static("x-record-format"),
                    http::HeaderValue::from_static("multi"),
                );
            } else {
                // Legacy single-record format.
                response
                    .set_status(http::StatusCode::OK)
                    .set_body(bytes::Bytes::from(dns_bytes));
                if !cert_bytes.is_empty() {
                    use base64::Engine;
                    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(&cert_bytes);
                    if let Ok(hv) = http::HeaderValue::from_str(&cert_b64) {
                        response
                            .headers_mut()
                            .insert(http::HeaderName::from_static("e-cert"), hv);
                    }
                }
            }
            let _ = response.flush().await;
        }

        Ok(LookupResult::Multi(records)) => {
            let body = encode_multi_response(&records);
            response
                .set_status(http::StatusCode::OK)
                .set_body(bytes::Bytes::from(body));
            response.headers_mut().insert(
                http::HeaderName::from_static("x-record-format"),
                http::HeaderValue::from_static("multi"),
            );
            let _ = response.flush().await;
        }

        Err(e) => {
            write_error(response, e).await;
        }
    }
}

impl Service for LookupSvc {
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        let state = self.state.clone();
        Box::pin(async move {
            lookup_with_cert(state, request, response).await;
        })
    }
}
