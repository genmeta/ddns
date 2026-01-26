use std::{collections::HashMap, fs::File, io, net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use dashmap::DashMap;
use deadpool_redis::Pool;
use futures::future::BoxFuture;
use gm_quic::prelude::handy::{ToCertificate, ToPrivateKey};
use gmdns::parser::{packet::be_packet, record::RData};
use h3x::{
    agent::RemoteAgent,
    server::{Request, Response, Router, Servers, Service},
};
use redis::AsyncCommands;
use rustls::{RootCertStore, server::WebPkiClientVerifier};
use tokio::time::{Duration, Instant};
use tracing::{Level, info, warn};

#[derive(Parser, Clone, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    #[arg(long)]
    redis: Option<String>,

    #[arg(long, default_value = "0.0.0.0:4433")]
    listen: SocketAddr,

    #[arg(long, default_value = "xforward.cloudns.ph")]
    server_name: String,

    #[arg(
        long,
        default_value = "examples/keychain/xforward.cloudns.ph/xforward.cloudns.ph-ECC.crt"
    )]
    cert: PathBuf,

    #[arg(
        long,
        default_value = "examples/keychain/xforward.cloudns.ph/xforward.cloudns.ph-ECC.key"
    )]
    key: PathBuf,

    #[arg(long, default_value = "examples/keychain/root/rootCA-ECC.crt")]
    root_cert: PathBuf,

    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    require_signature: bool,

    #[arg(long, default_value_t = 30)]
    ttl_secs: u64,
}

#[derive(Clone)]
enum Storage {
    Redis(Pool),
    Memory(Arc<DashMap<String, (Vec<u8>, Instant)>>),
}

#[derive(Clone)]
struct AppState {
    storage: Storage,
    require_signature: bool,
    ttl_secs: u64,
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("Missing host parameter")]
    MissingHostParam,
    #[error("Invalid host")]
    InvalidHost,
    #[error("Forbidden host")]
    ForbiddenHost,
    #[error("Domain not allowed")]
    DomainNotAllowed,
    #[error("Host mismatch")]
    HostMismatch,
    #[error("Missing client certificate")]
    MissingClientCertificate,
    #[error("Client certificate domain not allowed")]
    ClientCertDomainNotAllowed,
    #[error("Invalid DNS packet: {0}")]
    InvalidDnsPacket(String),
    #[error("No answers in packet")]
    NoAnswersInPacket,
    #[error("Signature required")]
    SignatureRequired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Redis error: {0}")]
    Redis(String),
}

impl AppError {
    fn status(&self) -> http::StatusCode {
        match self {
            AppError::MissingHostParam => http::StatusCode::BAD_REQUEST,
            AppError::InvalidHost => http::StatusCode::BAD_REQUEST,
            AppError::ForbiddenHost => http::StatusCode::BAD_REQUEST,
            AppError::DomainNotAllowed => http::StatusCode::FORBIDDEN,
            AppError::HostMismatch => http::StatusCode::BAD_REQUEST,
            AppError::MissingClientCertificate => http::StatusCode::UNAUTHORIZED,
            AppError::ClientCertDomainNotAllowed => http::StatusCode::FORBIDDEN,
            AppError::InvalidDnsPacket(_) => http::StatusCode::BAD_REQUEST,
            AppError::NoAnswersInPacket => http::StatusCode::UNPROCESSABLE_ENTITY,
            AppError::SignatureRequired => http::StatusCode::BAD_REQUEST,
            AppError::InvalidSignature => http::StatusCode::BAD_REQUEST,
            AppError::Redis(_) => http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

fn normalize_host(host: &str) -> Result<String, AppError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(AppError::InvalidHost);
    }
    if host.contains('*') {
        return Err(AppError::ForbiddenHost);
    }

    // 允许末尾 '.'（FQDN 写法）
    let host = host.strip_suffix('.').unwrap_or(host);

    let host = idna::domain_to_ascii(host).map_err(|_| AppError::InvalidHost)?;
    let host = host.to_ascii_lowercase();

    // 校验是否为 genmeta.net 域名
    if !host.ends_with("genmeta.net") {
        return Err(AppError::DomainNotAllowed);
    }

    Ok(host)
}

fn parse_query_params(uri: &http::Uri) -> HashMap<String, String> {
    let query = uri.query().unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn extract_client_dns_sans(agent: &RemoteAgent) -> Vec<String> {
    use x509_parser::prelude::*;

    let Some(leaf) = agent.cert_chain().first() else {
        return vec![];
    };

    let Ok((_remain, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return vec![];
    };

    let mut out = vec![];
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in san.value.general_names.iter() {
            if let GeneralName::DNSName(dns) = name {
                out.push(dns.to_string());
            }
        }
    }
    out
}

fn client_allowed_host(agent: &RemoteAgent) -> Result<String, AppError> {
    let mut sans = extract_client_dns_sans(agent)
        .into_iter()
        .filter_map(|h| normalize_host(&h).ok())
        .collect::<Vec<_>>();

    sans.sort();
    sans.dedup();

    match sans.len() {
        1 => Ok(sans.remove(0)),
        _ => Err(AppError::ClientCertDomainNotAllowed),
    }
}

fn validate_dns_packet(
    packet: &[u8],
    require_signature: bool,
    agent: &RemoteAgent,
) -> Result<String, AppError> {
    let (remaining, dns_packet) =
        be_packet(packet).map_err(|e| AppError::InvalidDnsPacket(e.to_string()))?;
    if !remaining.is_empty() {
        warn!(remain = remaining.len(), "dns.parse.extra_bytes");
    }

    if require_signature {
        let has_signature = dns_packet
            .answers
            .iter()
            .any(|record| matches!(record.data(), RData::E(endpoint) if endpoint.is_signed()));

        if !has_signature {
            return Err(AppError::SignatureRequired);
        }

        for record in &dns_packet.answers {
            if let RData::E(endpoint) = record.data()
                && endpoint.is_signed()
            {
                let ok = endpoint
                    .verify_signature(agent.public_key())
                    .map_err(|_| AppError::InvalidSignature)?;
                if !ok {
                    return Err(AppError::InvalidSignature);
                }
            }
        }
    }

    dns_packet
        .answers
        .first()
        .map(|record| record.name().to_string())
        .ok_or(AppError::NoAnswersInPacket)
}

// 核心查询逻辑，独立于 transport
async fn perform_lookup(state: &AppState, host: &str) -> Result<Option<Vec<u8>>, AppError> {
    let host = normalize_host(host)?;

    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = pool
                .get()
                .await
                .map_err(|e| AppError::Redis(e.to_string()))?;

            match conn.get::<_, Option<Vec<u8>>>(&host).await {
                Ok(bytes) => Ok(bytes),
                Err(e) => Err(AppError::Redis(e.to_string())),
            }
        }
        Storage::Memory(map) => {
            let now = Instant::now();
            if let Some(entry) = map.get(&host) {
                let (bytes, expire) = entry.value();
                if *expire > now {
                    return Ok(Some(bytes.clone()));
                }
            }
            map.remove(&host);
            Ok(None)
        }
    }
}

async fn write_error(resp: &mut Response, err: AppError) {
    resp.set_status(err.status())
        .set_body(bytes::Bytes::from(format!("{}", err)));
    let _ = resp.flush().await;
}

async fn publish(state: AppState, mut req: Request, resp: &mut Response) {
    let params = parse_query_params(&req.uri());
    let Some(host) = params.get("host") else {
        write_error(resp, AppError::MissingHostParam).await;
        return;
    };

    let host = match normalize_host(host) {
        Ok(h) => h,
        Err(e) => {
            write_error(resp, e).await;
            return;
        }
    };

    let Some(agent) = req.agent().cloned() else {
        write_error(resp, AppError::MissingClientCertificate).await;
        return;
    };

    let allowed = match client_allowed_host(&agent) {
        Ok(h) => h,
        Err(e) => {
            write_error(resp, e).await;
            return;
        }
    };

    if allowed != host {
        write_error(resp, AppError::HostMismatch).await;
        return;
    }

    let body = match req.read_to_bytes().await {
        Ok(b) => b,
        Err(e) => {
            write_error(resp, AppError::InvalidDnsPacket(e.to_string())).await;
            return;
        }
    };

    let packet_name = match validate_dns_packet(body.as_ref(), state.require_signature, &agent) {
        Ok(n) => n,
        Err(e) => {
            write_error(resp, e).await;
            return;
        }
    };

    let packet_host = match normalize_host(&packet_name) {
        Ok(h) => h,
        Err(e) => {
            write_error(resp, e).await;
            return;
        }
    };

    if packet_host != host {
        write_error(resp, AppError::HostMismatch).await;
        return;
    }

    match &state.storage {
        Storage::Redis(pool) => {
            let mut conn = match pool.get().await {
                Ok(c) => c,
                Err(e) => {
                    write_error(resp, AppError::Redis(e.to_string())).await;
                    return;
                }
            };

            let ttl_secs: usize = state.ttl_secs.try_into().unwrap_or(usize::MAX);
            if let Err(e) = conn
                .set_ex::<_, _, ()>(&host, body.as_ref(), ttl_secs)
                .await
            {
                write_error(resp, AppError::Redis(e.to_string())).await;
                return;
            }
        }
        Storage::Memory(map) => {
            let expire = Instant::now() + Duration::from_secs(state.ttl_secs);
            map.insert(host.clone(), (body.to_vec(), expire));
        }
    }

    info!(host = %host, ttl = state.ttl_secs, bytes = body.len(), "publish.ok");
    resp.set_status(http::StatusCode::OK)
        .set_body(bytes::Bytes::from_static(b"OK"));
    let _ = resp.flush().await;
}

// H3 lookup handler
async fn lookup(state: AppState, req: Request, resp: &mut Response) {
    let params = parse_query_params(&req.uri());
    let Some(host) = params.get("host") else {
        write_error(resp, AppError::MissingHostParam).await;
        return;
    };

    match perform_lookup(&state, host).await {
        Ok(Some(bytes)) => {
            resp.set_status(http::StatusCode::OK)
                .set_body(bytes::Bytes::from(bytes));
            let _ = resp.flush().await;
        }
        Ok(None) => {
            resp.set_status(http::StatusCode::NOT_FOUND)
                .set_body(bytes::Bytes::from_static(b"Not Found"));
            let _ = resp.flush().await;
        }
        Err(e) => {
            write_error(resp, e).await;
        }
    }
}

#[derive(Clone)]
struct PublishSvc {
    state: AppState,
}

impl Service for PublishSvc {
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&'s mut self, req: Request, resp: &'s mut Response) -> Self::Future<'s> {
        let state = self.state.clone();
        Box::pin(async move { publish(state, req, resp).await })
    }
}

#[derive(Clone)]
struct LookupSvc {
    state: AppState,
}

impl Service for LookupSvc {
    type Future<'s> = BoxFuture<'s, ()>;

    fn serve<'s>(&'s mut self, req: Request, resp: &'s mut Response) -> Self::Future<'s> {
        let state = self.state.clone();
        Box::pin(async move { lookup(state, req, resp).await })
    }
}

fn load_root_store_from_pem(pem: &[u8]) -> io::Result<RootCertStore> {
    let mut reader = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let mut store = RootCertStore::empty();
    store.add_parsable_certificates(certs);
    Ok(store)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install ring crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

    let file = File::create("error.log").expect("Failed to create error.log");
    tracing_subscriber::fmt()
        .with_writer(file)
        .with_max_level(Level::ERROR)
        .init();

    let options = Options::parse();

    let storage = match options.redis.clone() {
        Some(url) => {
            let redis_cfg = deadpool_redis::Config::from_url(url);
            let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;
            Storage::Redis(redis_pool)
        }
        None => Storage::Memory(Arc::new(DashMap::new())),
    };

    // Load the root CA that signed the client certificates
    let root_ca_pem = std::fs::read(&options.root_cert)?;
    let roots = load_root_store_from_pem(&root_ca_pem)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();

    let state = AppState {
        storage,
        require_signature: options.require_signature,
        ttl_secs: options.ttl_secs,
    };

    let cert_pem = std::fs::read(&options.cert)?;
    let key_pem = std::fs::read(&options.key)?;

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
        let base = gm_quic::prelude::BindUri::from(format!("inet://{}", options.listen));
        if options.listen.port() == 0 {
            base.alloc_port()
        } else {
            base
        }
    };

    let mut servers = Servers::builder()
        .with_client_cert_verifier(verifier)?
        .build()?;

    servers
        .add_server(
            options.server_name.clone(),
            cert_pem.to_certificate(),
            key_pem.to_private_key(),
            None,
            [bind],
            router,
        )
        .await?;

    info!(listen = %options.listen, server_name = %options.server_name, "h3_server.start");
    _ = servers.run().await;

    Ok(())
}
