mod config;
mod error;
mod lookup;
mod policy;
mod publish;
mod storage;

use std::{collections::HashMap, io, net::SocketAddr, str::FromStr, sync::Arc};

use clap::Parser;
use gmdns::{MdnsEndpoint, MdnsPacket};
use h3x::{
    dquic::{
        Identity, Network, QuicEndpoint, ServerName,
        binds::BindPattern,
        cert::handy::{ToCertificate, ToPrivateKey},
        server::ServerQuicConfig,
    },
    endpoint::{H3Endpoint, server::Router},
};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, info, level_filters::LevelFilter};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::{Config, Options, PolicyKind, SeedRecordConfig},
    lookup::LookupSvc,
    policy::{DomainPolicies, DomainPolicy, PolicyRule},
    publish::PublishSvc,
    storage::{AppState, MemoryStorage, SeedRecords, Storage},
};

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

    let router = Router::new()
        .post(
            "/publish",
            PublishSvc {
                state: state.clone(),
            },
        )
        .get(
            "/lookup",
            LookupSvc {
                state: state.clone(),
            },
        );

    let identity = Arc::new(Identity {
        name: ServerName::new(&config.server_name),
        certs: Arc::new(cert_pem.to_certificate()),
        key: Arc::new(key_pem.to_private_key()),
        ocsp: Arc::new(None),
    });
    let server_config = ServerQuicConfig {
        client_cert_verifier: verifier,
        ..Default::default()
    };
    let quic = QuicEndpoint::builder()
        .network(Network::builder().build())
        .identity(identity)
        .server(server_config)
        .bind(Arc::new(vec![
            BindPattern::from_str(&format!("inet://{}", config.listen))
                .expect("valid bind pattern"),
        ]))
        .build()
        .await;
    let server = Arc::new(H3Endpoint::new(quic));
    info!(listen = %config.listen, server_name = %config.server_name, "h3_server.start");
    let _serve = AbortOnDropHandle::new(tokio::spawn(server.serve_owned(router).in_current_span()));

    Ok(())
}
