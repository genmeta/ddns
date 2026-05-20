mod config;
mod error;
mod lookup;
mod policy;
mod publish;
mod storage;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use clap::Parser;
use ddns::{MdnsEndpoint, MdnsPacket};
use futures::future::BoxFuture;
use h3x::{
    dquic::{
        Identity, Network, QuicEndpoint,
        binds::BindPattern,
        cert::handy::{ToCertificate, ToPrivateKey},
        server::ServerQuicConfig,
    },
    endpoint::H3Endpoint,
    hyper::server::TowerService,
};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::{Config, Options, PolicyKind, SeedRecordConfig},
    lookup::LookupSvc,
    policy::{DomainPolicies, DomainPolicy, PolicyRule},
    publish::PublishSvc,
    storage::{AppState, MemoryStorage, SeedRecords, Storage},
};

#[derive(Clone)]
struct DnsService {
    publish: PublishSvc,
    lookup: LookupSvc,
}

impl tower_service::Service<lookup::Request> for DnsService {
    type Response = lookup::Response;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: lookup::Request) -> Self::Future {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let publish = self.publish.clone();
        let lookup = self.lookup.clone();
        Box::pin(async move {
            match (method, path.as_str()) {
                (http::Method::POST, "/publish") => match publish.call(request).await {
                    Ok(response) => Ok(response),
                    Err(never) => match never {},
                },
                (http::Method::GET, "/lookup") => match lookup.call(request).await {
                    Ok(response) => Ok(response),
                    Err(never) => match never {},
                },
                (_, "/publish" | "/lookup") => Ok(lookup::body_response(
                    http::StatusCode::METHOD_NOT_ALLOWED,
                    bytes::Bytes::from_static(b"Method Not Allowed"),
                )),
                _ => Ok(lookup::body_response(
                    http::StatusCode::NOT_FOUND,
                    bytes::Bytes::from_static(b"Not Found"),
                )),
            }
        })
    }
}

fn bind_patterns_for_listen(listen: SocketAddr) -> Vec<BindPattern> {
    let bind_addr = match listen {
        SocketAddr::V4(addr) if addr.ip().is_unspecified() => {
            SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), addr.port())
        }
        addr => addr,
    };

    vec![BindPattern::from_str(&format!("inet://{bind_addr}")).expect("valid bind pattern")]
}

// ---------------------------------------------------------------------------
// TLS helpers
// ---------------------------------------------------------------------------

fn load_root_store_from_pem(pem: &[u8]) -> io::Result<RootCertStore> {
    let mut reader = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut store = RootCertStore::empty();
    store.add_parsable_certificates(certs);
    Ok(store)
}

fn build_seed_records(seed_records: &[SeedRecordConfig]) -> io::Result<SeedRecords> {
    let mut records = HashMap::new();

    for seed_record in seed_records {
        if seed_record.endpoints.is_empty() {
            continue;
        }

        let host = error::normalize_host(&seed_record.host)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let endpoints = seed_record
            .endpoints
            .iter()
            .map(|addr| match addr {
                SocketAddr::V4(addr) => MdnsEndpoint::direct_v4(*addr),
                SocketAddr::V6(addr) => MdnsEndpoint::direct_v6(*addr),
            })
            .collect::<Vec<_>>();

        let mut hosts = HashMap::new();
        hosts.insert(host.clone(), endpoints);

        records
            .entry(host.clone())
            .or_insert_with(Vec::new)
            .push((MdnsPacket::answer(0, &hosts).to_bytes(), Vec::new()));

        info!(host = %host, endpoint_count = seed_record.endpoints.len(), "seed_records.loaded");
    }

    Ok(Arc::new(records))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install ring crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::filter_fn(|metadata| {
            !metadata.target().contains("netlink_packet_route")
        }))
        .with(LevelFilter::DEBUG)
        .init();

    let options = Options::parse();

    let config_str = std::fs::read_to_string(&options.config).unwrap_or_else(|e| {
        eprintln!("failed to read config {:?}: {e}", options.config);
        std::process::exit(1);
    });
    let config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
        eprintln!("failed to parse config {:?}: {e}", options.config);
        std::process::exit(1);
    });
    let config = config.expand_paths();
    let seed_records = build_seed_records(&config.seed_records)?;

    // Build storage backend.
    let storage = match config.redis.clone() {
        Some(url) => {
            let redis_cfg = deadpool_redis::Config::from_url(url);
            let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
            Storage::Redis(redis_pool)
        }
        None => Storage::Memory(MemoryStorage::new()),
    };

    // Build domain-policy rules from config file.
    let mut policy_rules: Vec<(PolicyRule, DomainPolicy)> = config
        .domain_policies
        .iter()
        .filter_map(|pc| {
            error::normalize_host(&pc.host).ok().map(|h| {
                let policy = match pc.policy {
                    PolicyKind::Standard => DomainPolicy::Standard,
                    PolicyKind::OpenMulti => DomainPolicy::OpenMulti,
                };
                (PolicyRule::Exact(h), policy)
            })
        })
        .collect();
    // Deduplicate (preserve first occurrence).
    policy_rules.dedup_by(|(ra, _), (rb, _)| {
        matches!((ra, rb), (PolicyRule::Exact(a), PolicyRule::Exact(b)) if a == b)
    });
    let policies = Arc::new(DomainPolicies(policy_rules));
    info!(?policies, "domain_policies.loaded");

    // Load the root CA used to validate client certificates when they are provided.
    let root_ca_pem = std::fs::read(&config.root_cert)?;
    let roots = load_root_store_from_pem(&root_ca_pem)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .unwrap();

    let state = AppState {
        storage,
        require_signature: config.require_signature,
        ttl_secs: config.ttl_secs,
        policies,
        seed_records,
    };

    let cert_pem = std::fs::read(&config.cert)?;
    let key_pem = std::fs::read(&config.key)?;

    let router = TowerService(DnsService {
        publish: PublishSvc {
            state: state.clone(),
        },
        lookup: LookupSvc {
            state: state.clone(),
        },
    });

    let identity = Arc::new(Identity {
        name: config.server_name.parse().unwrap(),
        certs: Arc::new(cert_pem.to_certificate()),
        key: Arc::new(key_pem.to_private_key()),
        ocsp: Arc::new(None),
    });
    let server_config = ServerQuicConfig {
        alpns: vec![b"h3".to_vec()],
        client_cert_verifier: verifier,
        ..Default::default()
    };
    let quic = QuicEndpoint::builder()
        .network(Network::builder().build())
        .identity(identity)
        .server(server_config)
        .bind(Arc::new(bind_patterns_for_listen(config.listen)))
        .build()
        .await;
    let server = Arc::new(H3Endpoint::new(quic));
    info!(listen = %config.listen, server_name = %config.server_name, "h3_server.start");
    server.serve_owned(router).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    #[test]
    fn unspecified_ipv4_listen_uses_dual_stack_wildcard() {
        let listen: SocketAddr = "0.0.0.0:4433".parse().unwrap();
        let patterns = bind_patterns_for_listen(listen);

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].to_string(), "inet://[::]:4433");
    }
}
