use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::SocketAddr,
};

use ddns::{
    MdnsPacket,
    parser::{packet::be_packet, record::RData},
    wire::MultiResponse,
};
use deadpool_redis::redis::{self, AsyncCommands};
use h3x::message::stream::MessageStreamError;
use http_body_util::{Full, combinators::UnsyncBoxBody};
use tracing::debug;

use crate::{
    error::{AppError, normalize_host, parse_query_params},
    storage::{AppState, LookupRecord, Storage, StoredRecord, unix_now_secs},
};

pub type Request = http::Request<UnsyncBoxBody<bytes::Bytes, MessageStreamError>>;
pub type Response = http::Response<Full<bytes::Bytes>>;

// ---------------------------------------------------------------------------
// Lookup result type
// ---------------------------------------------------------------------------

pub enum LookupResult {
    NotFound,
    /// Multiple records, newest-first.
    Multi(MultiResponse),
}

type EndpointKey = (SocketAddr, Option<SocketAddr>);

fn normalize_lookup_records(records: Vec<LookupRecord>) -> Vec<LookupRecord> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for (dns_bytes, cert_bytes) in records {
        let Ok((_, packet)) = be_packet(&dns_bytes) else {
            normalized.push((dns_bytes, cert_bytes));
            continue;
        };

        let mut emitted_endpoint = false;

        for answer in &packet.answers {
            let RData::E(endpoint) = answer.data() else {
                continue;
            };

            emitted_endpoint = true;
            let key: EndpointKey = (endpoint.addr(), endpoint.agent_addr());

            if !seen.insert(key) {
                continue;
            }

            let mut hosts = HashMap::new();
            hosts.insert(answer.name().to_string(), vec![endpoint.clone()]);
            normalized.push((MdnsPacket::answer(0, &hosts).to_bytes(), cert_bytes.clone()));
        }

        if !emitted_endpoint {
            normalized.push((dns_bytes, cert_bytes));
        }
    }

    normalized
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
    perform_lookup_multi(state, &host, limit).await
}

async fn perform_lookup_multi(
    state: &AppState,
    host: &str,
    limit: Option<usize>,
) -> Result<LookupResult, AppError> {
    let mut records = match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = pool.get().await.map_err(|e| AppError::Redis {
                message: e.to_string(),
            })?;

            let set_key = format!("{host}:multi");
            let now_secs = unix_now_secs();

            // Remove expired members: those published more than ttl_secs ago.
            let cutoff_score = now_secs.saturating_sub(state.ttl_secs) as f64;
            let _: () = redis::cmd("ZREMRANGEBYSCORE")
                .arg(&set_key)
                .arg("-inf")
                .arg(cutoff_score)
                .query_async::<()>(&mut *conn)
                .await
                .unwrap_or(());

            // Fetch all remaining, newest first (highest score = most recently published)
            let count: isize = limit.map(|l| l as isize).unwrap_or(-1);
            let members: Vec<Vec<u8>> = conn
                .zrevrange(&set_key, 0isize, if count < 0 { -1 } else { count - 1 })
                .await
                .map_err(|e| AppError::Redis {
                    message: e.to_string(),
                })?;

            let now_secs = unix_now_secs();
            let records: Vec<(Vec<u8>, Vec<u8>)> = members
                .into_iter()
                .filter_map(|m| {
                    let r = StoredRecord::decode(&m)?;
                    if r.expire_unix_secs > now_secs {
                        Some((r.dns, r.cert))
                    } else {
                        None
                    }
                })
                .collect();

            records
        }
        Storage::Memory(mem) => {
            let now = tokio::time::Instant::now();
            if let Some(mut entry) = mem.records.get_mut(host) {
                // Evict expired entries in-place.
                entry.retain(|_, r| r.expire > now);
                // Sort newest-first by published_at.
                let take = limit.unwrap_or(entry.len()).min(entry.len());
                let mut records: Vec<_> = entry.values().collect();
                records.sort_by_key(|b| std::cmp::Reverse(b.published_at));
                records[..take]
                    .iter()
                    .map(|r| (r.dns_bytes.clone(), r.cert_bytes.clone()))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        }
    };

    if let Some(seed_records) = state.seed_records.get(host) {
        records.extend(seed_records.iter().cloned());
    }

    let records = normalize_lookup_records(records);

    if records.is_empty() {
        Ok(LookupResult::NotFound)
    } else {
        Ok(LookupResult::Multi(MultiResponse::new(records)))
    }
}

// ---------------------------------------------------------------------------
// HTTP response helpers
// ---------------------------------------------------------------------------

pub fn body_response(status: http::StatusCode, body: impl Into<bytes::Bytes>) -> Response {
    http::Response::builder()
        .status(status)
        .body(Full::new(body.into()))
        .expect("response parts must be valid")
}

pub fn write_error(err: AppError) -> Response {
    debug!(
        status = %err.status(),
        error = %err,
        "writing error response"
    );
    body_response(err.status(), bytes::Bytes::from(err.to_string()))
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
/// Always returns multi-record binary body:
/// `[u32 count BE]([u32 dns_len BE][dns][u32 cert_len BE][cert])*`
/// with header `x-record-format: multi`.
///
/// Optional query param `limit=N` caps the number of records returned.
/// Dynamic records are newest-first; configured seed records are appended after them.
pub async fn lookup_with_cert(state: AppState, request: Request) -> Response {
    let params = parse_query_params(request.uri());
    let Some(host) = params.get("host") else {
        return write_error(AppError::MissingHostParam);
    };

    let limit: Option<usize> = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0);

    debug!(host = %host, limit, "lookup.request");

    match perform_lookup(&state, host, limit).await {
        Ok(LookupResult::NotFound) => {
            debug!(host = %host, "lookup.not_found");
            body_response(
                http::StatusCode::NOT_FOUND,
                bytes::Bytes::from_static(b"Not Found"),
            )
        }

        Ok(LookupResult::Multi(resp)) => {
            let body = resp.encode();
            debug!(host = %host, records = resp.records.len(), "lookup.found");
            let mut response = body_response(http::StatusCode::OK, bytes::Bytes::from(body));
            response.headers_mut().insert(
                http::HeaderName::from_static("x-record-format"),
                http::HeaderValue::from_static("multi"),
            );
            response
        }

        Err(e) => write_error(e),
    }
}

impl LookupSvc {
    pub fn call(
        &self,
        request: Request,
    ) -> impl Future<Output = Result<Response, Infallible>> + Send + 'static {
        let state = self.state.clone();
        async move { Ok(lookup_with_cert(state, request).await) }
    }
}
