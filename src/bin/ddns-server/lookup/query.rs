use std::{collections::HashSet, hash::Hash, net::IpAddr};

use ddns::core::wire::{MultiResponse, ResponseRecord};
use deadpool_redis::redis::{self, AsyncCommands};
use tracing::debug;

use super::ranking::{
    LOOKUP_CANDIDATE_CAP_ALL, LOOKUP_CANDIDATE_CAP_ASN, LOOKUP_CANDIDATE_CAP_COUNTRY,
    LOOKUP_CANDIDATE_CAP_TOTAL, normalize_lookup_records, request_source_geo_traits,
    sort_lookup_records, sort_lookup_records_with_geo,
};
use crate::{
    error::{AppError, normalize_host},
    geo::GeoTraits,
    storage::{
        AppState, Storage, StoredRecord, redis_all_index_key, redis_asn_index_key,
        redis_blacklist_key, redis_country_index_key, redis_primary_key, unix_now_secs,
    },
};

pub enum LookupResult {
    NotFound,
    /// Multiple records, newest-first.
    Multi(MultiResponse),
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

pub(super) async fn redis_host_blacklisted<C>(conn: &mut C, host: &str) -> Result<bool, AppError>
where
    C: redis::aio::ConnectionLike + Send + Sync,
{
    conn.sismember(redis_blacklist_key(), host)
        .await
        .map_err(|e| AppError::Redis {
            message: e.to_string(),
        })
}
