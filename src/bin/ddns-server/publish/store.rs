use std::collections::HashSet;

use ddns::core::signature::SignatureFields;
use deadpool_redis::redis::{self, AsyncCommands};
use dhttp_identity::identity::RemoteAuthority;
use tokio::time::{Duration, Instant};
use tracing::info;

use crate::{
    error::AppError,
    lookup::{Response, body_response, write_error},
    storage::{
        AppState, Record, Storage, StoredRecord, cert_fingerprint, cert_fingerprint_hex,
        record_index_tags, redis_all_index_key, redis_asn_index_key, redis_country_index_key,
        redis_primary_key, unix_now_secs,
    },
};

async fn trim_expired_index_keys<C>(
    conn: &mut C,
    keys: impl IntoIterator<Item = String>,
    cutoff: f64,
    expire_ttl_secs: i64,
) where
    C: redis::aio::ConnectionLike + Send + Sync,
{
    for key in keys {
        let _: bool = conn.expire(&key, expire_ttl_secs).await.unwrap_or(false);
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(&key)
            .arg("-inf")
            .arg(cutoff)
            .query_async::<()>(&mut *conn)
            .await
            .unwrap_or(());
    }
}

/// Unified publish handler: stores the record keyed by (host, cert-fingerprint).
/// Both Standard and OpenMulti policies follow the same storage path;
/// the only policy difference (SAN check) is already enforced in the caller.
///
/// Certificate fingerprint is the publish-source identity. In PKI ecosystems,
/// a single domain name can have multiple valid certificates (from different CAs,
/// or issued at different times for rotation/failover/multi-region scenarios).
/// Using fingerprint as part of the storage key enables:
/// - Multi-publisher coexistence: different cert holders can publish the same domain
/// - Idempotent updates: re-publishing from same cert source (same fingerprint) overwrites old data
/// - Client choice: lookups return all active records, client picks which certificate to trust
pub async fn publish_record(
    state: &AppState,
    host: &str,
    body: &bytes::Bytes,
    authority: &(impl RemoteAuthority + ?Sized),
    signature_fields: SignatureFields,
) -> Response {
    let cert_bytes = authority
        .cert_chain()
        .first()
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();

    let fp = cert_fingerprint(&cert_bytes);
    let fp_hex = cert_fingerprint_hex(&cert_bytes);

    match &state.storage {
        Storage::Redis(redis) => {
            let mut conn = match redis.write.get().await {
                Ok(c) => c,
                Err(e) => {
                    return write_error(AppError::Redis {
                        message: e.to_string(),
                    });
                }
            };
            let ttl_secs = state.ttl_secs;
            let expire_ttl_secs = i64::try_from(state.ttl_secs).unwrap_or(i64::MAX);
            let now_secs = unix_now_secs();
            let expire_secs = now_secs + state.ttl_secs;
            let index_tags = record_index_tags(body.as_ref(), state.geo.as_deref());

            let fp_key = redis_primary_key(host, &fp_hex);
            let all_index_key = redis_all_index_key(host);
            let mut touched_index_keys = HashSet::from([all_index_key.clone()]);

            let old_member: Option<Vec<u8>> = conn.get(&fp_key).await.unwrap_or(None);
            if let Some(old_record) = old_member.as_deref().and_then(StoredRecord::decode) {
                let old_tags = record_index_tags(&old_record.dns, state.geo.as_deref());
                let _: () = conn.zrem(&all_index_key, &fp_hex).await.unwrap_or(());

                for country in &old_tags.countries {
                    let key = redis_country_index_key(host, country);
                    touched_index_keys.insert(key.clone());
                    let _: () = conn.zrem(&key, &fp_hex).await.unwrap_or(());
                }

                for asn in &old_tags.asns {
                    let key = redis_asn_index_key(host, *asn);
                    touched_index_keys.insert(key.clone());
                    let _: () = conn.zrem(&key, &fp_hex).await.unwrap_or(());
                }
            }

            let new_member = StoredRecord {
                expire_unix_secs: expire_secs,
                fingerprint: fp,
                dns: body.to_vec(),
                cert: cert_bytes.clone(),
                signature_fields: signature_fields.clone(),
            }
            .encode();

            if let Err(e) = conn
                .set_ex::<_, _, ()>(&fp_key, &new_member, ttl_secs)
                .await
            {
                return write_error(AppError::Redis {
                    message: e.to_string(),
                });
            }

            if let Err(e) = conn
                .zadd::<_, _, _, ()>(&all_index_key, &fp_hex, now_secs as f64)
                .await
            {
                return write_error(AppError::Redis {
                    message: e.to_string(),
                });
            }

            for country in &index_tags.countries {
                let key = redis_country_index_key(host, country);
                touched_index_keys.insert(key.clone());
                if let Err(e) = conn
                    .zadd::<_, _, _, ()>(&key, &fp_hex, now_secs as f64)
                    .await
                {
                    return write_error(AppError::Redis {
                        message: e.to_string(),
                    });
                }
            }

            for asn in &index_tags.asns {
                let key = redis_asn_index_key(host, *asn);
                touched_index_keys.insert(key.clone());
                if let Err(e) = conn
                    .zadd::<_, _, _, ()>(&key, &fp_hex, now_secs as f64)
                    .await
                {
                    return write_error(AppError::Redis {
                        message: e.to_string(),
                    });
                }
            }

            let cutoff = now_secs.saturating_sub(state.ttl_secs) as f64;
            trim_expired_index_keys(&mut *conn, touched_index_keys, cutoff, expire_ttl_secs).await;
        }
        Storage::Memory(mem) => {
            let now = Instant::now();
            let expire = now + Duration::from_secs(state.ttl_secs);
            let record = Record {
                dns_bytes: body.to_vec(),
                cert_bytes,
                signature_fields,
                expire,
                index_tags: record_index_tags(body.as_ref(), state.geo.as_deref()),
            };
            let mut host_map = mem.records.entry(host.to_string()).or_default();
            host_map.retain_active(now);
            host_map.insert(fp, record);
        }
    }

    info!(host = %host, ttl = state.ttl_secs, bytes = body.len(), fp = %fp_hex, "publish.ok");
    body_response(http::StatusCode::OK, bytes::Bytes::from_static(b"OK"))
}

pub async fn clear_record(
    state: &AppState,
    host: &str,
    authority: &(impl RemoteAuthority + ?Sized),
) -> Response {
    let cert_bytes = authority
        .cert_chain()
        .first()
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();

    let fp = cert_fingerprint(&cert_bytes);
    let fp_hex = cert_fingerprint_hex(&cert_bytes);

    match &state.storage {
        Storage::Redis(redis) => {
            let mut conn = match redis.write.get().await {
                Ok(c) => c,
                Err(e) => {
                    return write_error(AppError::Redis {
                        message: e.to_string(),
                    });
                }
            };

            let fp_key = redis_primary_key(host, &fp_hex);
            let all_index_key = redis_all_index_key(host);
            let mut touched_index_keys = HashSet::from([all_index_key.clone()]);

            let old_member: Option<Vec<u8>> = conn.get(&fp_key).await.unwrap_or(None);
            if let Some(old_record) = old_member.as_deref().and_then(StoredRecord::decode) {
                let old_tags = record_index_tags(&old_record.dns, state.geo.as_deref());
                let _: () = conn.zrem(&all_index_key, &fp_hex).await.unwrap_or(());
                for country in &old_tags.countries {
                    let key = redis_country_index_key(host, country);
                    touched_index_keys.insert(key.clone());
                    let _: () = conn.zrem(&key, &fp_hex).await.unwrap_or(());
                }
                for asn in &old_tags.asns {
                    let key = redis_asn_index_key(host, *asn);
                    touched_index_keys.insert(key.clone());
                    let _: () = conn.zrem(&key, &fp_hex).await.unwrap_or(());
                }
            }

            if let Err(e) = conn.del::<_, ()>(&fp_key).await {
                return write_error(AppError::Redis {
                    message: e.to_string(),
                });
            }

            let cutoff = unix_now_secs().saturating_sub(state.ttl_secs) as f64;
            let expire_ttl_secs = i64::try_from(state.ttl_secs).unwrap_or(i64::MAX);
            trim_expired_index_keys(&mut *conn, touched_index_keys, cutoff, expire_ttl_secs).await;
        }
        Storage::Memory(mem) => {
            let remove_host = if let Some(mut host_map) = mem.records.get_mut(host) {
                let _ = host_map.remove(&fp);
                host_map.is_empty()
            } else {
                false
            };
            if remove_host {
                mem.records.remove(host);
            }
        }
    }

    info!(host = %host, fp = %fp_hex, "publish.clear");
    body_response(http::StatusCode::OK, bytes::Bytes::from_static(b"OK"))
}
