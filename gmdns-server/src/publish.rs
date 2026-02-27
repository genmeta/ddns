use futures::future::BoxFuture;
use h3x::server::{Request, Response, Service};
use redis::AsyncCommands;
use tokio::time::{Duration, Instant};
use tracing::{info, warn};

use crate::{
    error::{AppError, normalize_host, parse_query_params},
    lookup::write_error,
    policy::{DomainPolicy, client_allowed_host, validate_dns_packet},
    storage::{AppState, MultiRecord, Storage, encode_redis_multi_member, unix_now_secs},
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
            info!("Received publish request");

            let params = parse_query_params(&request.uri());
            info!("Query params: {:?}", params);

            let Some(host) = params.get("host") else {
                warn!("Missing host parameter");
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
            info!(host = %host, "publish.host");

            // Require a valid client certificate for all publish requests.
            let Some(agent) = request.agent().cloned() else {
                warn!("Missing client certificate");
                write_error(response, AppError::MissingClientCertificate).await;
                return;
            };

            let policy = state.policies.policy_for(&host).clone();

            // Standard policy: cert SAN must match the target host.
            // OpenMulti policy: any authenticated node may publish — skip SAN check.
            if policy == DomainPolicy::Standard {
                let allowed = match client_allowed_host(&agent) {
                    Ok(h) => h,
                    Err(e) => {
                        warn!("Client certificate domain not allowed: {:?}", e);
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
                    warn!("Failed to read request body: {:?}", e);
                    write_error(response, AppError::InvalidDnsPacket(e.to_string())).await;
                    return;
                }
            };

            // Validate DNS packet; signature check only for Standard hosts.
            let require_sig = policy == DomainPolicy::Standard && state.require_signature;
            let packet_name = match validate_dns_packet(body.as_ref(), require_sig, &agent) {
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

            match policy {
                DomainPolicy::Standard => {
                    publish_standard(&state, &host, &body, &agent, response).await
                }
                DomainPolicy::OpenMulti => {
                    publish_multi(&state, &host, &body, &agent, response).await
                }
            }
        })
    }
}

pub async fn publish_standard(
    state: &AppState,
    host: &str,
    body: &bytes::Bytes,
    agent: &h3x::agent::RemoteAgent,
    response: &mut Response,
) {
    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = match pool.get().await {
                Ok(c) => c,
                Err(e) => {
                    write_error(response, AppError::Redis(e.to_string())).await;
                    return;
                }
            };
            let ttl_secs: usize = state.ttl_secs.try_into().unwrap_or(usize::MAX);

            if let Err(e) = conn.set_ex::<_, _, ()>(host, body.as_ref(), ttl_secs).await {
                write_error(response, AppError::Redis(e.to_string())).await;
                return;
            }
            if let Some(cert_chain) = agent.cert_chain().first() {
                let cert_key = format!("{host}_cert");
                if let Err(e) = conn
                    .set_ex::<_, _, ()>(&cert_key, cert_chain.as_ref(), ttl_secs)
                    .await
                {
                    write_error(response, AppError::Redis(e.to_string())).await;
                    return;
                }
            }
        }
        Storage::Memory(mem) => {
            let expire = Instant::now() + Duration::from_secs(state.ttl_secs);
            let cert_bytes = agent
                .cert_chain()
                .first()
                .map(|c| c.as_ref().to_vec())
                .unwrap_or_default();
            mem.standard
                .insert(host.to_string(), (body.to_vec(), cert_bytes, expire));
        }
    }
    info!(host = %host, ttl = state.ttl_secs, bytes = body.len(), "publish.standard.ok");
    response
        .set_status(http::StatusCode::OK)
        .set_body(bytes::Bytes::from_static(b"OK"));
    let _ = response.flush().await;
}

pub async fn publish_multi(
    state: &AppState,
    host: &str,
    body: &bytes::Bytes,
    agent: &h3x::agent::RemoteAgent,
    response: &mut Response,
) {
    let cert_bytes = agent
        .cert_chain()
        .first()
        .map(|c| c.as_ref().to_vec())
        .unwrap_or_default();

    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = match pool.get().await {
                Ok(c) => c,
                Err(e) => {
                    write_error(response, AppError::Redis(e.to_string())).await;
                    return;
                }
            };
            let set_key = format!("{host}:multi");
            let now_secs = unix_now_secs();
            let expire_secs = now_secs + state.ttl_secs;
            let member = encode_redis_multi_member(body.as_ref(), &cert_bytes, expire_secs);

            // ZADD with score = publish timestamp (newest = highest score).
            if let Err(e) = conn
                .zadd::<_, _, _, ()>(&set_key, member, now_secs as f64)
                .await
            {
                write_error(response, AppError::Redis(e.to_string())).await;
                return;
            }

            // Evict older entries beyond ttl window immediately.
            let cutoff = now_secs.saturating_sub(state.ttl_secs) as f64;
            let _: () = redis::cmd("ZREMRANGEBYSCORE")
                .arg(&set_key)
                .arg("-inf")
                .arg(cutoff)
                .query_async::<_, ()>(&mut *conn)
                .await
                .unwrap_or(());
        }
        Storage::Memory(mem) => {
            let expire = Instant::now() + Duration::from_secs(state.ttl_secs);
            let record = MultiRecord {
                dns_bytes: body.to_vec(),
                cert_bytes,
                expire,
            };
            // Insert at the front so index 0 is always the newest.
            let mut entry = mem.multi.entry(host.to_string()).or_default();
            entry.insert(0, record);
            // Evict expired entries while we hold the lock.
            let now = Instant::now();
            entry.retain(|r| r.expire > now);
        }
    }

    info!(host = %host, ttl = state.ttl_secs, bytes = body.len(), "publish.multi.ok");
    response
        .set_status(http::StatusCode::OK)
        .set_body(bytes::Bytes::from_static(b"OK"));
    let _ = response.flush().await;
}
