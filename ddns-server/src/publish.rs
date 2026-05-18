use deadpool_redis::redis::{self, AsyncCommands};
use futures::future::BoxFuture;
use h3x::{
    endpoint::server::{Request, Response, Service},
    quic::agent::RemoteAgent,
};
use tokio::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::{
    error::{AppError, normalize_host, parse_query_params},
    lookup::write_error,
    policy::{DomainPolicy, client_allowed_host, validate_dns_packet},
    storage::{
        AppState, Record, Storage, StoredRecord, cert_fingerprint, cert_fingerprint_hex,
        unix_now_secs,
    },
};

// ---------------------------------------------------------------------------
// PublishSvc
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PublishSvc {
    pub state: AppState,
}

impl Service for PublishSvc {
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&self, request: &'s mut Request, response: &'s mut Response) -> Self::Future<'s> {
        let state = self.state.clone();
        Box::pin(async move {
            debug!("received publish request");

            let params = parse_query_params(&request.uri());
            debug!("query params: {:?}", params);

            let Some(host) = params.get("host") else {
                warn!("missing host parameter");
                write_error(response, AppError::MissingHostParam).await;
                return;
            };

            let host = match normalize_host(host) {
                Ok(h) => h,
                Err(e) => {
                    write_error(response, e).await;
                    return;
                }
            };
            debug!(host = %host, "publish.host");

            // Require a valid client certificate for all publish requests.
            let Some(agent) = request.agent().cloned() else {
                warn!("missing client certificate");
                write_error(response, AppError::MissingClientCertificate).await;
                return;
            };

            let policy = state.policies.policy_for(&host).clone();

            // Standard policy: cert SAN must match the target host.
            // OpenMulti policy: any authenticated node may publish — skip SAN check.
            if policy == DomainPolicy::Standard {
                let allowed = match client_allowed_host(agent.as_ref()) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(error = %snafu::Report::from_error(&e), "client certificate domain not allowed");
                        write_error(response, e).await;
                        return;
                    }
                };
                if allowed != host {
                    warn!(allowed = %allowed, requested = %host, "publish.host_mismatch");
                    write_error(response, AppError::HostMismatch).await;
                    return;
                }
            }

            let body = match request.read_to_bytes().await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %snafu::Report::from_error(&e), "failed to read request body");
                    write_error(
                        response,
                        AppError::InvalidDnsPacket {
                            message: e.to_string(),
                        },
                    )
                    .await;
                    return;
                }
            };

            // Validate DNS packet; signature check only for Standard hosts.
            let require_sig = policy == DomainPolicy::Standard && state.require_signature;
            let packet_name = match validate_dns_packet(body.as_ref(), require_sig, agent.as_ref())
            {
                Ok(n) => n,
                Err(e) => {
                    write_error(response, e).await;
                    return;
                }
            };

            let packet_host = match normalize_host(&packet_name) {
                Ok(h) => h,
                Err(e) => {
                    write_error(response, e).await;
                    return;
                }
            };

            if packet_host != host {
                write_error(response, AppError::HostMismatch).await;
                return;
            }

            publish_record(&state, &host, &body, agent.as_ref(), response).await
        })
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
    agent: &(impl RemoteAgent + ?Sized),
    response: &mut Response,
) {
    let cert_bytes = agent
        .cert_chain()
        .first()
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();

    let fp = cert_fingerprint(&cert_bytes);
    let fp_hex = cert_fingerprint_hex(&cert_bytes);

    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = match pool.get().await {
                Ok(c) => c,
                Err(e) => {
                    write_error(
                        response,
                        AppError::Redis {
                            message: e.to_string(),
                        },
                    )
                    .await;
                    return;
                }
            };
            let ttl_secs = state.ttl_secs;
            let expire_ttl_secs = i64::try_from(state.ttl_secs).unwrap_or(i64::MAX);
            let now_secs = unix_now_secs();
            let expire_secs = now_secs + state.ttl_secs;

            let fp_key = format!("{host}:fp:{fp_hex}");
            let set_key = format!("{host}:multi");

            // Remove the previous entry from this source (if any) from the ZSET.
            let old_member: Option<Vec<u8>> = conn.get(&fp_key).await.unwrap_or(None);
            if let Some(old) = old_member {
                let _: () = conn.zrem(&set_key, &old).await.unwrap_or(());
            }

            // Encode and store the new member.
            let new_member = StoredRecord {
                expire_unix_secs: expire_secs,
                fingerprint: fp,
                dns: body.to_vec(),
                cert: cert_bytes.clone(),
            }
            .encode();

            if let Err(e) = conn
                .set_ex::<_, _, ()>(&fp_key, &new_member, ttl_secs)
                .await
            {
                write_error(
                    response,
                    AppError::Redis {
                        message: e.to_string(),
                    },
                )
                .await;
                return;
            }

            if let Err(e) = conn
                .zadd::<_, _, _, ()>(&set_key, &new_member, now_secs as f64)
                .await
            {
                write_error(
                    response,
                    AppError::Redis {
                        message: e.to_string(),
                    },
                )
                .await;
                return;
            }

            // Expire the ZSET key at max(ttl_secs) from now as a safety net.
            let _: bool = conn
                .expire(&set_key, expire_ttl_secs)
                .await
                .unwrap_or(false);

            // Evict stale (score < now - ttl) entries.
            let cutoff = now_secs.saturating_sub(state.ttl_secs) as f64;
            let _: () = redis::cmd("ZREMRANGEBYSCORE")
                .arg(&set_key)
                .arg("-inf")
                .arg(cutoff)
                .query_async::<()>(&mut *conn)
                .await
                .unwrap_or(());
        }
        Storage::Memory(mem) => {
            let now = Instant::now();
            let expire = now + Duration::from_secs(state.ttl_secs);
            let record = Record {
                dns_bytes: body.to_vec(),
                cert_bytes,
                expire,
                published_at: now,
            };
            // Upsert by fingerprint: same source overwrites its own entry;
            // different sources (different certs) coexist independently.
            let mut host_map = mem.records.entry(host.to_string()).or_default();
            host_map.insert(fp, record);
            // Evict expired entries while we hold the write lock.
            host_map.retain(|_, r| r.expire > now);
        }
    }

    info!(host = %host, ttl = state.ttl_secs, bytes = body.len(), fp = %fp_hex, "publish.ok");
    response
        .set_status(http::StatusCode::OK)
        .set_body(bytes::Bytes::from_static(b"OK"));
    let _ = response.flush().await;
}
