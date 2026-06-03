mod config;
mod error;
mod geo;
mod lookup;
mod policy;
mod publish;
mod storage;

use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use clap::Parser;
use ddns::core::{MdnsEndpoint, MdnsPacket};
use futures::future::BoxFuture;
use h3x::{
    dquic::{
        Identity, Network, QuicEndpoint,
        cert::handy::{ToCertificate, ToPrivateKey},
        server::ServerQuicConfig,
    },
    endpoint::H3Endpoint,
    hyper::TowerService,
};
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tracing::{info, level_filters::LevelFilter, warn};
use tracing_subscriber::{prelude::__tracing_subscriber_SubscriberExt, util::SubscriberInitExt};

use crate::{
    config::{Config, Options, PolicyKind, SeedRecordConfig},
    geo::GeoResolver,
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

fn log_geo_db_freshness(kind: &str, build_epoch: u64) {
    const STALE_GEO_DB_AGE_SECS: u64 = 45 * 24 * 60 * 60;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(build_epoch);
    let age_secs = now_secs.saturating_sub(build_epoch);

    if age_secs > STALE_GEO_DB_AGE_SECS {
        warn!(kind, build_epoch, age_secs, "geo_routing.db_outdated");
    }
}

const GEO_CITY_DISTANCE_ROUTING: bool = true;
const GEO_MAX_ACCURACY_RADIUS_KM: u32 = 100;

fn build_geo_resolver(config: &Config) -> io::Result<Option<Arc<GeoResolver>>> {
    let Some(city_db) = config.geoip_city_db.as_deref() else {
        return if config.geoip_asn_db.is_none() {
            Ok(None)
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "geoip_city_db and geoip_asn_db must be configured together",
            ))
        };
    };

    let Some(asn_db) = config.geoip_asn_db.as_deref() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "geoip_city_db and geoip_asn_db must be configured together",
        ));
    };

    let resolver = Arc::new(GeoResolver::open(
        city_db,
        asn_db,
        GEO_CITY_DISTANCE_ROUTING,
        GEO_MAX_ACCURACY_RADIUS_KM,
    )?);
    info!(
        city_db = %city_db.display(),
        asn_db = %asn_db.display(),
        city_distance_routing = GEO_CITY_DISTANCE_ROUTING,
        max_accuracy_radius_km = GEO_MAX_ACCURACY_RADIUS_KM,
        "geo_routing.enabled"
    );
    log_geo_db_freshness("city", resolver.city_build_epoch());
    log_geo_db_freshness("asn", resolver.asn_build_epoch());

    Ok(Some(resolver))
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let geo = build_geo_resolver(&config)?;

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
        geo,
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
        .bind(Arc::new(config.binds.clone()))
        .build()
        .await;
    let server = Arc::new(H3Endpoint::new(quic));
    info!(binds = ?config.binds, server_name = %config.server_name, "h3_server.start");
    server.listen_owned(router).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::PathBuf};

    use super::*;
    use crate::config::Config;

    fn test_config() -> Config {
        Config {
            redis: None,
            listen: Config::default_listen(),
            server_name: Config::default_server_name(),
            cert: Config::default_cert(),
            key: Config::default_key(),
            root_cert: Config::default_root_cert(),
            require_signature: Config::default_require_signature(),
            ttl_secs: Config::default_ttl_secs(),
            domain_policies: Vec::new(),
            seed_records: Vec::new(),
            geoip_city_db: None,
            geoip_asn_db: None,
        }
    }

    #[test]
    fn unspecified_ipv4_listen_uses_dual_stack_wildcard() {
        let listen: SocketAddr = "0.0.0.0:4433".parse().unwrap();
        let patterns = bind_patterns_for_listen(listen);

        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].to_string(), "inet://[::]:4433");
    }

    #[test]
    fn geo_routing_requires_city_db_path() {
        let mut config = test_config();
        config.geoip_asn_db = Some(PathBuf::from("/tmp/asn.mmdb"));

        let err = build_geo_resolver(&config).expect_err("missing city db should fail");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "geoip_city_db and geoip_asn_db must be configured together");
    }

    #[test]
    fn geo_routing_requires_asn_db_path() {
        let mut config = test_config();
        config.geoip_city_db = Some(PathBuf::from("/tmp/city.mmdb"));

        let err = build_geo_resolver(&config).expect_err("missing asn db should fail");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(err.to_string(), "geoip_city_db and geoip_asn_db must be configured together");
    }
}
