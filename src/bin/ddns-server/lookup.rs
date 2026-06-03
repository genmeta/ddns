use std::{
    any::Any,
    cmp::Ordering,
    collections::{HashMap, HashSet},
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use ddns::core::{
    MdnsPacket,
    parser::{packet::be_packet, record::RData},
    wire::MultiResponse,
};
use deadpool_redis::redis::{self, AsyncCommands};
use h3x::{connection::ConnectionState, quic};
use h3x::dhttp::message::MessageStreamError;
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

fn lookup_endpoint(dns_bytes: &[u8]) -> Option<(SocketAddr, Option<f32>)> {
    let (_, packet) = be_packet(dns_bytes).ok()?;
    packet.answers.iter().find_map(|answer| match answer.data() {
        RData::E(endpoint) => Some((endpoint.addr(), endpoint.load())),
        _ => None,
    })
}

fn common_prefix_len(source: IpAddr, target: IpAddr) -> u32 {
    fn bytes_prefix_len(left: &[u8], right: &[u8]) -> u32 {
        let mut matched = 0;
        for (l, r) in left.iter().zip(right.iter()) {
            let diff = l ^ r;
            if diff == 0 {
                matched += 8;
                continue;
            }
            matched += (diff as u32).leading_zeros().saturating_sub(24);
            break;
        }
        matched
    }

    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            bytes_prefix_len(&source.octets(), &target.octets())
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            bytes_prefix_len(&source.octets(), &target.octets())
        }
        _ => 0,
    }
}

fn sort_lookup_records(records: Vec<LookupRecord>, source_ip: Option<IpAddr>) -> Vec<LookupRecord> {
    let mut decorated = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let sort_key = lookup_endpoint(&record.0).map(|(endpoint, load)| {
                let (family_match, prefix_len) = match source_ip {
                    Some(source_ip) if source_ip.is_ipv4() == endpoint.ip().is_ipv4() => {
                        (true, common_prefix_len(source_ip, endpoint.ip()))
                    }
                    Some(_) => (false, 0),
                    None => (false, 0),
                };

                (family_match, prefix_len, load)
            });
            (sort_key, index, record)
        })
        .collect::<Vec<_>>();

    decorated.sort_by(|(left_key, left_index, _), (right_key, right_index, _)| {
        match (left_key, right_key) {
            (Some((left_family, left_prefix, left_load)), Some((right_family, right_prefix, right_load))) => right_family
                .cmp(left_family)
                .then_with(|| right_prefix.cmp(left_prefix))
                .then_with(|| match (left_load, right_load) {
                    (Some(left), Some(right)) => left.partial_cmp(right).unwrap_or(Ordering::Equal),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
        .then_with(|| left_index.cmp(right_index))
    });

    decorated
        .into_iter()
        .map(|(_, _, record)| record)
        .collect()
}

fn request_source_ip(request: &Request) -> Option<IpAddr> {
    let connection = request
        .extensions()
        .get::<Arc<ConnectionState<dyn quic::DynConnection>>>()?
        .clone();
    let quic = connection.quic();
    let dquic = (quic.as_ref() as &dyn Any).downcast_ref::<dquic::prelude::Connection>()?;
    let ctx = dquic.path_context().ok()?;

    ctx.paths::<Vec<_>>()
        .into_iter()
        .next()
        .map(|(pathway, _)| pathway.remote().addr().ip())
}

// ---------------------------------------------------------------------------
// Core lookup logic
// ---------------------------------------------------------------------------

pub async fn perform_lookup(
    state: &AppState,
    host: &str,
    limit: Option<usize>,
    source_ip: Option<IpAddr>,
) -> Result<LookupResult, AppError> {
    let host = normalize_host(host)?;
    perform_lookup_multi(state, &host, limit, source_ip).await
}

async fn perform_lookup_multi(
    state: &AppState,
    host: &str,
    limit: Option<usize>,
    source_ip: Option<IpAddr>,
) -> Result<LookupResult, AppError> {
    let dynamic_records = match &state.storage {
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

            // Fetch all remaining active dynamic records; scheduling is applied after decode.
            let members: Vec<Vec<u8>> = conn
                .zrevrange(&set_key, 0isize, -1isize)
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
                let mut records: Vec<_> = entry.values().collect();
                records.sort_by_key(|b| std::cmp::Reverse(b.published_at));
                records
                    .iter()
                    .map(|r| (r.dns_bytes.clone(), r.cert_bytes.clone()))
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        }
    };

    let mut records = sort_lookup_records(normalize_lookup_records(dynamic_records), source_ip);

    let should_append_seeds = records.is_empty() || limit.is_some_and(|max| records.len() < max);
    if should_append_seeds
        && let Some(seed_records) = state.seed_records.get(host)
    {
        let seeds = sort_lookup_records(seed_records.iter().cloned().collect(), source_ip);
        records.extend(seeds);
    }

    let records = normalize_lookup_records(records);
    let records = if let Some(limit) = limit {
        records.into_iter().take(limit).collect::<Vec<_>>()
    } else {
        records
    };

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
    let source_ip = request_source_ip(&request);

    let limit: Option<usize> = params
        .get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 0);

    debug!(host = %host, limit, ?source_ip, "lookup.request");

    match perform_lookup(&state, host, limit, source_ip).await {
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
