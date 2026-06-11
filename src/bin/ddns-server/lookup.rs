use std::{
    any::Any,
    cmp::Ordering,
    collections::{HashMap, HashSet},
    convert::Infallible,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use ddns::core::{
    MdnsPacket,
    parser::{packet::be_packet, record::RData},
    wire::{MultiResponse, ResponseRecord},
};
use deadpool_redis::redis::{self, AsyncCommands};
use h3x::{connection::ConnectionState, dhttp::message::MessageStreamError, quic};
use http_body_util::{Full, combinators::UnsyncBoxBody};
use tracing::debug;

use crate::{
    error::{AppError, normalize_host, parse_query_params},
    geo::{GeoResolver, GeoTraits},
    storage::{
        AppState, LookupRecord, MemoryStorage, SeedRecords, Storage, StoredRecord,
        redis_all_index_key, redis_asn_index_key, redis_blacklist_key, redis_country_index_key,
        redis_primary_key, unix_now_secs,
    },
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

const LOOKUP_CANDIDATE_CAP_TOTAL: usize = 64;
const LOOKUP_CANDIDATE_CAP_ASN: usize = 16;
const LOOKUP_CANDIDATE_CAP_COUNTRY: usize = 16;
const LOOKUP_CANDIDATE_CAP_ALL: usize = 32;

// GEO-aware ranking dimensions. Final ordering still falls back to the original
// record index so we keep lookups stable when all computed dimensions tie.
#[derive(Clone, Copy, Debug, PartialEq)]
struct GeoSortKey {
    same_country: bool,
    same_asn: bool,
    family_match: bool,
    same_city: bool,
    load: Option<f32>,
    geo_distance: Option<f64>,
}

fn normalize_lookup_records(records: Vec<LookupRecord>) -> Vec<LookupRecord> {
    let mut normalized = Vec::new();
    let mut seen = HashSet::new();

    for record in records {
        if !record.signature_fields.is_empty() {
            normalized.push(record);
            continue;
        }

        let Ok((_, packet)) = be_packet(&record.dns) else {
            normalized.push(record);
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
            normalized.push(ResponseRecord::unsigned(
                MdnsPacket::answer(0, &hosts).to_bytes(),
                record.cert.clone(),
            ));
        }

        if !emitted_endpoint {
            normalized.push(record);
        }
    }

    normalized
}

fn lookup_endpoint(dns_bytes: &[u8]) -> Option<(SocketAddr, Option<f32>)> {
    let (_, packet) = be_packet(dns_bytes).ok()?;
    packet
        .answers
        .iter()
        .find_map(|answer| match answer.data() {
            RData::E(endpoint) => Some((endpoint.addr(), endpoint.load())),
            _ => None,
        })
}

// Fallback ordering when GEO routing is disabled: prefer matching address family,
// then lower load, and finally preserve input order. We intentionally avoid
// IP prefix heuristics here because they are not reliable on the public Internet.
fn sort_lookup_records(records: Vec<LookupRecord>, source_ip: Option<IpAddr>) -> Vec<LookupRecord> {
    let mut decorated = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let sort_key = lookup_endpoint(&record.dns).map(|(endpoint, load)| {
                let family_match = source_ip
                    .map(|source| source.is_ipv4() == endpoint.ip().is_ipv4())
                    .unwrap_or(false);

                (family_match, load)
            });
            (sort_key, index, record)
        })
        .collect::<Vec<_>>();

    decorated.sort_by(|(left_key, left_index, _), (right_key, right_index, _)| {
        match (left_key, right_key) {
            (Some((left_family, left_load)), Some((right_family, right_load))) => right_family
                .cmp(left_family)
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

    decorated.into_iter().map(|(_, _, record)| record).collect()
}

fn request_source_geo_traits(
    source_ip: Option<IpAddr>,
    geo: Option<&GeoResolver>,
) -> Option<GeoTraits> {
    Some(geo?.lookup_traits(source_ip?))
}

fn lookup_endpoint_geo_traits(
    dns_bytes: &[u8],
    geo: &GeoResolver,
) -> Option<(SocketAddr, Option<f32>, GeoTraits)> {
    let (endpoint, load) = lookup_endpoint(dns_bytes)?;
    Some((endpoint, load, geo.lookup_traits(endpoint.ip())))
}

fn compare_optional_partial<T: PartialOrd>(left: Option<T>, right: Option<T>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
        _ => Ordering::Equal,
    }
}

// GEO ordering is layered rather than score-based:
// country > ASN > address family > city name > lower load > shorter GEO distance.
// Missing optional values do not penalize a candidate; they simply skip that layer.
fn compare_geo_sort_keys(left: GeoSortKey, right: GeoSortKey) -> Ordering {
    right
        .same_country
        .cmp(&left.same_country)
        .then_with(|| right.same_asn.cmp(&left.same_asn))
        .then_with(|| right.family_match.cmp(&left.family_match))
        .then_with(|| right.same_city.cmp(&left.same_city))
        .then_with(|| compare_optional_partial(left.load, right.load))
        .then_with(|| compare_optional_partial(left.geo_distance, right.geo_distance))
}

// Build the per-endpoint GEO ranking tuple. City name only participates when both
// sides have a name and already match on country; coordinate distance only
// participates when GeoResolver accepts both accuracy radii.
fn build_geo_sort_key(
    source_ip: Option<IpAddr>,
    source_traits: Option<&GeoTraits>,
    endpoint: SocketAddr,
    load: Option<f32>,
    endpoint_traits: &GeoTraits,
    geo: &GeoResolver,
) -> GeoSortKey {
    let family_match = source_ip
        .map(|source| source.is_ipv4() == endpoint.ip().is_ipv4())
        .unwrap_or(false);

    let same_country = source_traits
        .and_then(|source| source.country.as_deref())
        .zip(endpoint_traits.country.as_deref())
        .is_some_and(|(source, target)| source == target);

    let same_asn = source_traits
        .and_then(|source| source.asn)
        .zip(endpoint_traits.asn)
        .is_some_and(|(source, target)| source == target);

    let same_city = same_country
        && source_traits
            .and_then(|source| source.city.as_deref())
            .zip(endpoint_traits.city.as_deref())
            .is_some_and(|(source, target)| source == target);

    let geo_distance = source_traits
        .and_then(|source| source.point.as_ref())
        .zip(endpoint_traits.point.as_ref())
        .and_then(|(source, target)| geo.geo_distance_km(source, target));

    GeoSortKey {
        same_country,
        same_asn,
        family_match,
        same_city,
        load,
        geo_distance,
    }
}

fn candidate_total_cap(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(LOOKUP_CANDIDATE_CAP_TOTAL)
        .max(LOOKUP_CANDIDATE_CAP_TOTAL)
}

fn all_candidate_cap(total_cap: usize, source_traits: Option<&GeoTraits>) -> usize {
    let has_geo_buckets = source_traits
        .is_some_and(|traits| traits.asn.is_some() || traits.country.as_deref().is_some());

    if has_geo_buckets {
        LOOKUP_CANDIDATE_CAP_ALL.min(total_cap)
    } else {
        total_cap
    }
}

fn push_unique_candidates<T>(
    candidates: &mut Vec<T>,
    seen: &mut HashSet<T>,
    source: impl IntoIterator<Item = T>,
    total_cap: usize,
) where
    T: Clone + Eq + Hash,
{
    for item in source {
        if candidates.len() >= total_cap {
            break;
        }

        if seen.insert(item.clone()) {
            candidates.push(item);
        }
    }
}

fn sort_lookup_records_with_geo(
    records: Vec<LookupRecord>,
    source_ip: Option<IpAddr>,
    geo: &GeoResolver,
) -> Vec<LookupRecord> {
    let source_traits = request_source_geo_traits(source_ip, Some(geo));

    let mut decorated = records
        .into_iter()
        .enumerate()
        .map(|(index, record)| {
            let sort_key = lookup_endpoint_geo_traits(&record.dns, geo).map(
                |(endpoint, load, endpoint_traits)| {
                    build_geo_sort_key(
                        source_ip,
                        source_traits.as_ref(),
                        endpoint,
                        load,
                        &endpoint_traits,
                        geo,
                    )
                },
            );
            (sort_key, index, record)
        })
        .collect::<Vec<_>>();

    decorated.sort_by(|(left_key, left_index, _), (right_key, right_index, _)| {
        match (left_key, right_key) {
            (Some(left_key), Some(right_key)) => compare_geo_sort_keys(*left_key, *right_key),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        }
        .then_with(|| left_index.cmp(right_index))
    });

    decorated.into_iter().map(|(_, _, record)| record).collect()
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
    let host = normalize_host(host, state.host_allowlist.as_ref())?;
    perform_lookup_multi(state, &host, limit, source_ip).await
}

async fn perform_lookup_multi(
    state: &AppState,
    host: &str,
    limit: Option<usize>,
    source_ip: Option<IpAddr>,
) -> Result<LookupResult, AppError> {
    let source_traits = request_source_geo_traits(source_ip, state.geo.as_deref());
    let candidate_total = candidate_total_cap(limit);
    let candidate_all = all_candidate_cap(candidate_total, source_traits.as_ref());

    let dynamic_records = match &state.storage {
        Storage::Redis(redis) => {
            let mut conn = redis.read.get().await.map_err(|e| AppError::Redis {
                message: e.to_string(),
            })?;

            if redis_host_blacklisted(&mut *conn, host).await? {
                debug!(host = %host, "lookup.blacklisted");
                return Ok(LookupResult::NotFound);
            }

            let now_secs = unix_now_secs();
            let mut candidate_fingerprints = Vec::new();
            let mut seen_fingerprints = HashSet::new();

            if let Some(asn) = source_traits.as_ref().and_then(|traits| traits.asn) {
                let index_key = redis_asn_index_key(host, asn);
                let members: Vec<String> = conn
                    .zrevrange(
                        &index_key,
                        0isize,
                        LOOKUP_CANDIDATE_CAP_ASN.saturating_sub(1) as isize,
                    )
                    .await
                    .map_err(|e| AppError::Redis {
                        message: e.to_string(),
                    })?;

                push_unique_candidates(
                    &mut candidate_fingerprints,
                    &mut seen_fingerprints,
                    members,
                    candidate_total,
                );
            }

            if let Some(country) = source_traits
                .as_ref()
                .and_then(|traits| traits.country.as_deref())
            {
                let index_key = redis_country_index_key(host, country);
                let members: Vec<String> = conn
                    .zrevrange(
                        &index_key,
                        0isize,
                        LOOKUP_CANDIDATE_CAP_COUNTRY.saturating_sub(1) as isize,
                    )
                    .await
                    .map_err(|e| AppError::Redis {
                        message: e.to_string(),
                    })?;

                push_unique_candidates(
                    &mut candidate_fingerprints,
                    &mut seen_fingerprints,
                    members,
                    candidate_total,
                );
            }

            let all_index_key = redis_all_index_key(host);
            let all_members: Vec<String> = conn
                .zrevrange(
                    &all_index_key,
                    0isize,
                    candidate_all.saturating_sub(1) as isize,
                )
                .await
                .map_err(|e| AppError::Redis {
                    message: e.to_string(),
                })?;

            push_unique_candidates(
                &mut candidate_fingerprints,
                &mut seen_fingerprints,
                all_members,
                candidate_total,
            );

            let mut records = Vec::new();
            for fingerprint in candidate_fingerprints {
                let primary_key = redis_primary_key(host, &fingerprint);
                let member: Option<Vec<u8>> =
                    conn.get(&primary_key).await.map_err(|e| AppError::Redis {
                        message: e.to_string(),
                    })?;

                let Some(member) = member else {
                    continue;
                };
                let Some(record) = StoredRecord::decode(&member) else {
                    continue;
                };
                if record.expire_unix_secs > now_secs {
                    records.push(ResponseRecord::new(
                        record.signature_fields,
                        record.dns,
                        record.cert,
                    ));
                }
            }

            records
        }
        Storage::Memory(mem) => {
            if mem.is_blacklisted(host) {
                debug!(host = %host, "lookup.blacklisted");
                return Ok(LookupResult::NotFound);
            }

            let now = tokio::time::Instant::now();
            if let Some(mut entry) = mem.records.get_mut(host) {
                entry.retain_active(now);
                let candidate_fingerprints = entry.collect_candidates(
                    source_traits
                        .as_ref()
                        .and_then(|traits| traits.country.as_deref()),
                    source_traits.as_ref().and_then(|traits| traits.asn),
                    candidate_total,
                    LOOKUP_CANDIDATE_CAP_ASN,
                    LOOKUP_CANDIDATE_CAP_COUNTRY,
                    candidate_all,
                );

                candidate_fingerprints
                    .into_iter()
                    .filter_map(|fingerprint| {
                        entry.records.get(&fingerprint).map(|record| {
                            ResponseRecord::new(
                                record.signature_fields.clone(),
                                record.dns_bytes.clone(),
                                record.cert_bytes.clone(),
                            )
                        })
                    })
                    .collect::<Vec<_>>()
            } else {
                vec![]
            }
        }
    };

    let normalized_dynamic_records = normalize_lookup_records(dynamic_records);
    let mut records = if let Some(geo) = state.geo.as_deref() {
        sort_lookup_records_with_geo(normalized_dynamic_records, source_ip, geo)
    } else {
        sort_lookup_records(normalized_dynamic_records, source_ip)
    };

    let should_append_seeds = records.is_empty() || limit.is_some_and(|max| records.len() < max);
    if should_append_seeds && let Some(seed_records) = state.seed_records.get(host) {
        let seeds = if let Some(geo) = state.geo.as_deref() {
            sort_lookup_records_with_geo(seed_records.iter().cloned().collect(), source_ip, geo)
        } else {
            sort_lookup_records(seed_records.iter().cloned().collect(), source_ip)
        };
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

async fn redis_host_blacklisted<C>(conn: &mut C, host: &str) -> Result<bool, AppError>
where
    C: redis::aio::ConnectionLike + Send + Sync,
{
    conn.sismember(redis_blacklist_key(), host)
        .await
        .map_err(|e| AppError::Redis {
            message: e.to_string(),
        })
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

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddrV4},
        path::PathBuf,
    };

    use ddns::core::{MdnsEndpoint, signature::SignatureFields};

    use super::*;
    use crate::geo::{GeoPoint, GeoResolver};

    fn fixture_geo_resolver() -> GeoResolver {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let city_db = manifest_dir.join("geoip/GeoLite2-City.mmdb");
        let asn_db = manifest_dir.join("geoip/GeoLite2-ASN.mmdb");

        GeoResolver::open(&city_db, &asn_db, true, 100).expect("fixture geo db should open")
    }

    fn lookup_record(host: &str, addr: SocketAddr, load: Option<f32>) -> LookupRecord {
        let mut endpoint = match addr {
            SocketAddr::V4(addr) => MdnsEndpoint::direct_v4(addr),
            SocketAddr::V6(addr) => MdnsEndpoint::direct_v6(addr),
        };
        endpoint.set_load(load);

        let mut hosts = HashMap::new();
        hosts.insert(host.to_string(), vec![endpoint]);

        ResponseRecord::unsigned(MdnsPacket::answer(0, &hosts).to_bytes(), Vec::new())
    }

    struct FakeRedis {
        response: redis::Value,
        packed_commands: Vec<Vec<u8>>,
    }

    impl redis::aio::ConnectionLike for FakeRedis {
        fn req_packed_command<'a>(
            &'a mut self,
            cmd: &'a redis::Cmd,
        ) -> redis::RedisFuture<'a, redis::Value> {
            self.packed_commands.push(cmd.get_packed_command());
            let response = self.response.clone();
            Box::pin(async move { Ok(response) })
        }

        fn req_packed_commands<'a>(
            &'a mut self,
            _cmd: &'a redis::Pipeline,
            _offset: usize,
            _count: usize,
        ) -> redis::RedisFuture<'a, Vec<redis::Value>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn get_db(&self) -> i64 {
            0
        }
    }

    #[tokio::test]
    async fn redis_host_blacklisted_queries_external_blacklist_set() {
        let mut redis = FakeRedis {
            response: redis::Value::Int(1),
            packed_commands: Vec::new(),
        };

        let blacklisted = redis_host_blacklisted(&mut redis, "blocked.example.genmeta.net")
            .await
            .unwrap();

        assert!(blacklisted);
        assert_eq!(redis.packed_commands.len(), 1);
        let command = String::from_utf8(redis.packed_commands.remove(0)).unwrap();
        assert!(command.contains("SISMEMBER"));
        assert!(command.contains(redis_blacklist_key()));
        assert!(command.contains("blocked.example.genmeta.net"));
    }

    #[tokio::test]
    async fn memory_blacklist_returns_not_found_before_seed_records() {
        let host = "blocked.example.genmeta.net";
        let mut seed_records = HashMap::new();
        seed_records.insert(
            host.to_string(),
            vec![lookup_record(
                host,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
                None,
            )],
        );
        let state = AppState {
            storage: Storage::Memory(MemoryStorage::with_blacklist([host.to_string()])),
            host_allowlist: Arc::new(vec!["genmeta.net".to_string()]),
            require_signature: false,
            ttl_secs: 30,
            policies: Arc::new(crate::policy::DomainPolicies::default()),
            seed_records: SeedRecords::new(seed_records),
            geo: None,
        };

        let result = perform_lookup(&state, host, None, None).await.unwrap();

        assert!(matches!(result, LookupResult::NotFound));
    }

    #[test]
    fn normalize_lookup_records_keeps_signed_packets_whole() {
        let mut record = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
            None,
        );
        record.signature_fields = SignatureFields {
            content_digest: b"sha-256=:abc:".to_vec(),
            signature_input:
                b"dns=(\"content-digest\");created=1;keyid=\"sha256:abc\";alg=\"ed25519\"".to_vec(),
            signature: b"dns=:sig:".to_vec(),
        };

        let normalized = normalize_lookup_records(vec![record.clone()]);

        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0], record);
    }

    #[test]
    fn compare_geo_sort_keys_follows_documented_priority() {
        let best = GeoSortKey {
            same_country: true,
            same_asn: true,
            family_match: true,
            same_city: true,
            load: Some(0.2),
            geo_distance: Some(20.0),
        };
        let worse_load = GeoSortKey {
            load: Some(0.8),
            ..best
        };
        let worse_family = GeoSortKey {
            same_asn: true,
            family_match: false,
            same_city: true,
            load: Some(0.1),
            geo_distance: Some(1.0),
            ..best
        };
        let worse_city = GeoSortKey {
            same_city: false,
            load: Some(0.1),
            geo_distance: Some(1.0),
            ..best
        };
        let worse_asn = GeoSortKey {
            same_asn: false,
            family_match: true,
            same_city: true,
            load: Some(0.1),
            geo_distance: Some(1.0),
            ..best
        };
        let worse_country = GeoSortKey {
            same_country: false,
            same_asn: true,
            family_match: true,
            same_city: false,
            load: Some(0.1),
            geo_distance: Some(1.0),
        };

        assert_eq!(compare_geo_sort_keys(best, worse_load), Ordering::Less);
        assert_eq!(compare_geo_sort_keys(best, worse_family), Ordering::Less);
        assert_eq!(compare_geo_sort_keys(best, worse_city), Ordering::Less);
        assert_eq!(compare_geo_sort_keys(best, worse_asn), Ordering::Less);
        assert_eq!(compare_geo_sort_keys(best, worse_country), Ordering::Less);
    }

    #[test]
    fn compare_geo_sort_keys_skips_unknown_dimensions() {
        let known_distance = GeoSortKey {
            same_country: true,
            same_asn: true,
            family_match: true,
            same_city: true,
            load: Some(0.2),
            geo_distance: Some(10.0),
        };
        let missing_distance = GeoSortKey {
            geo_distance: None,
            ..known_distance
        };
        let missing_load = GeoSortKey {
            load: None,
            ..known_distance
        };

        assert_eq!(
            compare_geo_sort_keys(known_distance, missing_distance),
            Ordering::Equal
        );
        assert_eq!(
            compare_geo_sort_keys(known_distance, missing_load),
            Ordering::Equal
        );
    }

    #[test]
    fn sort_lookup_records_with_geo_prefers_same_source_endpoint_even_with_higher_load() {
        let geo = fixture_geo_resolver();
        let source_ip = Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let matching = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
            Some(0.9),
        );
        let non_matching = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478)),
            Some(0.1),
        );

        let sorted =
            sort_lookup_records_with_geo(vec![non_matching, matching.clone()], source_ip, &geo);

        let (endpoint, _) = lookup_endpoint(&sorted[0].dns).expect("sorted record should decode");
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn sort_lookup_records_without_geo_ignores_ip_prefix_and_prefers_lower_load() {
        let source_ip = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let closer_prefix_higher_load = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 3478)),
            Some(0.9),
        );
        let farther_prefix_lower_load = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
            Some(0.1),
        );

        let sorted = sort_lookup_records(
            vec![closer_prefix_higher_load, farther_prefix_lower_load],
            source_ip,
        );

        let (endpoint, _) = lookup_endpoint(&sorted[0].dns).expect("sorted record should decode");
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn sort_lookup_records_with_geo_prefers_same_asn_then_same_country_on_real_ips() {
        let geo = fixture_geo_resolver();
        let source_ip = Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));

        let different_country = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 3478)),
            Some(0.01),
        );
        let same_country_different_asn = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(114, 114, 114, 114), 3478)),
            Some(0.02),
        );
        let same_country_same_asn = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 3478)),
            Some(0.9),
        );

        let sorted = sort_lookup_records_with_geo(
            vec![
                different_country,
                same_country_different_asn,
                same_country_same_asn,
            ],
            source_ip,
            &geo,
        );

        let ordered_ips = sorted
            .iter()
            .map(|record| {
                lookup_endpoint(&record.dns)
                    .expect("record should decode")
                    .0
                    .ip()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ordered_ips,
            vec![
                IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
                IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            ]
        );
    }

    #[test]
    fn sort_lookup_records_with_geo_prefers_same_country_over_lower_load_on_real_ips() {
        let geo = fixture_geo_resolver();
        let source_ip = Some(IpAddr::V4(Ipv4Addr::new(114, 114, 114, 114)));

        let different_country_low_load = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(80, 80, 80, 80), 3478)),
            Some(0.01),
        );
        let same_country_higher_load = lookup_record(
            "stun.example.com",
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 5, 5, 5), 3478)),
            Some(0.9),
        );

        let sorted = sort_lookup_records_with_geo(
            vec![different_country_low_load, same_country_higher_load.clone()],
            source_ip,
            &geo,
        );

        let (endpoint, _) = lookup_endpoint(&sorted[0].dns).expect("sorted record should decode");
        assert_eq!(endpoint.ip(), IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)));
    }

    #[test]
    fn build_geo_sort_key_ignores_city_distance_when_accuracy_is_too_large() {
        let geo = fixture_geo_resolver();
        let source_traits = GeoTraits {
            country: Some("CN".to_string()),
            city: Some("Beijing".to_string()),
            asn: Some(64512),
            point: Some(GeoPoint {
                latitude: 39.9,
                longitude: 116.4,
                accuracy_radius_km: 500,
            }),
        };
        let endpoint_traits = GeoTraits {
            country: Some("CN".to_string()),
            city: Some("Shanghai".to_string()),
            asn: Some(64512),
            point: Some(GeoPoint {
                latitude: 31.2,
                longitude: 121.5,
                accuracy_radius_km: 10,
            }),
        };

        let key = build_geo_sort_key(
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(&source_traits),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 3478)),
            Some(0.2),
            &endpoint_traits,
            &geo,
        );

        assert!(key.same_country);
        assert!(key.same_asn);
        assert!(!key.same_city);
        assert_eq!(key.geo_distance, None);
    }

    #[test]
    fn build_geo_sort_key_prefers_same_city_when_available() {
        let geo = fixture_geo_resolver();
        let source_traits = GeoTraits {
            country: Some("CN".to_string()),
            city: Some("Hangzhou".to_string()),
            asn: Some(64512),
            point: None,
        };
        let same_city_traits = GeoTraits {
            country: Some("CN".to_string()),
            city: Some("Hangzhou".to_string()),
            asn: Some(64513),
            point: None,
        };
        let different_city_traits = GeoTraits {
            country: Some("CN".to_string()),
            city: Some("Shanghai".to_string()),
            asn: Some(64513),
            point: None,
        };

        let same_city_key = build_geo_sort_key(
            Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))),
            Some(&source_traits),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(223, 6, 6, 6), 3478)),
            Some(0.9),
            &same_city_traits,
            &geo,
        );
        let different_city_key = build_geo_sort_key(
            Some(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5))),
            Some(&source_traits),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(114, 114, 114, 114), 3478)),
            Some(0.1),
            &different_city_traits,
            &geo,
        );

        assert!(same_city_key.same_city);
        assert!(!different_city_key.same_city);
        assert_eq!(
            compare_geo_sort_keys(same_city_key, different_city_key),
            Ordering::Less
        );
    }
}
