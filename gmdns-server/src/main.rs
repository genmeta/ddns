mod config;
mod error;
mod lookup;
mod policy;
mod publish;
mod storage;

use std::{io, sync::Arc};

use clap::Parser;
use h3x::{
    gm_quic::prelude::{
        BindUri,
        handy::{ToCertificate, ToPrivateKey},
    },
    server::{Router, Servers},
};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::{Config, Options, PolicyKind},
    lookup::LookupSvc,
    policy::{DomainPolicies, DomainPolicy, PolicyRule},
    publish::PublishSvc,
    storage::{AppState, MemoryStorage, Storage},
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
        eprintln!("Failed to read config {:?}: {e}", options.config);
        std::process::exit(1);
    });
    let config: Config = toml::from_str(&config_str).unwrap_or_else(|e| {
        eprintln!("Failed to parse config {:?}: {e}", options.config);
        std::process::exit(1);
    });

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

    // Load the root CA that signed the client certificates.
    let root_ca_pem = std::fs::read(&config.root_cert)?;
    let roots = load_root_store_from_pem(&root_ca_pem)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let state = AppState {
        storage,
        require_signature: config.require_signature,
        ttl_secs: config.ttl_secs,
        policies,
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

    let bind = {
        let base = BindUri::from(format!("inet://{}", config.listen));
        if config.listen.port() == 0 {
            base.alloc_port()
        } else {
            base
        }
    };

    let mut servers = Servers::builder()
        .with_client_cert_verifier(verifier)?
        .listen()?;

    servers
        .add_server(
            config.server_name.clone(),
            cert_pem.to_certificate(),
            key_pem.to_private_key(),
            None,
            [bind],
            router,
        )
        .await?;

    info!(listen = %config.listen, server_name = %config.server_name, "h3_server.start");
    _ = servers.run().await;

    Ok(())
}
