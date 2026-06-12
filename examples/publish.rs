use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use ddns::{
    core::parser::record::endpoint::EndpointAddr,
    resolvers::{DHTTP_H3_DNS_SERVER, h3::H3Publisher},
};
use h3x::dquic::{
    Identity, Network, QuicEndpoint,
    cert::handy::{ToCertificate, ToPrivateKey},
    client::{ClientQuicConfig, ServerCertVerifierChoice},
    resolver::{Publish, handy::SystemResolver},
};
use rustls::{RootCertStore, client::WebPkiServerVerifier};
use tracing::{Level, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Base URL of the线上 H3 DNS server.
    #[arg(long, default_value_t = default_h3_base_url())]
    base_url: String,

    /// 用于校验线上服务端证书的 CA PEM 文件。
    #[arg(long)]
    server_ca: PathBuf,

    /// 发布所使用的客户端身份名称。
    #[arg(long)]
    client_name: String,

    /// 客户端证书链 PEM。
    #[arg(long)]
    client_cert: PathBuf,

    /// 客户端私钥 PEM。
    #[arg(long)]
    client_key: PathBuf,

    /// Sign Endpoint records using the client private key.
    ///
    /// This must correspond to the client certificate presented in mTLS, because the server
    /// verifies the signature with the peer certificate's SPKI.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    sign: bool,

    /// 要发布的线上域名，必须与客户端证书 SAN 匹配。
    #[arg(long)]
    host: String,

    /// 要发布的地址列表。
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    addr: Vec<SocketAddr>,
}

fn default_h3_base_url() -> String {
    format!("{}/", DHTTP_H3_DNS_SERVER.trim_end_matches('/'))
}

fn load_root_store_from_pem(path: &Path) -> io::Result<RootCertStore> {
    let pem = std::fs::read(path)?;

    let mut store = RootCertStore::empty();
    let mut reader: &[u8] = pem.as_slice();

    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        store
            .add(cert)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    }

    Ok(store)
}

fn expand_tilde(path: &Path) -> io::Result<PathBuf> {
    let path = path.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Path is not valid UTF-8: {}", path.display()),
        )
    })?;

    Ok(PathBuf::from(shellexpand::tilde(path).into_owned()))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let opt = Options::parse();

    let server_ca = expand_tilde(&opt.server_ca)?;
    let client_cert = expand_tilde(&opt.client_cert)?;
    let client_key = expand_tilde(&opt.client_key)?;
    let root_store = load_root_store_from_pem(&server_ca)?;
    let cert_chain_pem = std::fs::read(&client_cert)?;
    let private_key_pem = std::fs::read(&client_key)?;

    // Build WebPki server cert verifier from CA root store
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Build TLS identity from cert chain and private key PEM
    let identity = Arc::new(Identity {
        name: opt.client_name.parse().unwrap(),
        certs: Arc::new(cert_chain_pem.to_certificate()),
        key: Arc::new(private_key_pem.to_private_key()),
        ocsp: Arc::new(None),
    });

    // Build network and QuicEndpoint with client mTLS config
    let network = Network::builder().build();
    let quic = QuicEndpoint::builder()
        .network(network)
        .identity(identity.clone())
        .resolver(Arc::new(SystemResolver))
        .client(ClientQuicConfig {
            verifier: ServerCertVerifierChoice::WebPki(verifier),
            ..Default::default()
        })
        .build()
        .await;
    let h3_endpoint = h3x::dquic::H3Endpoint::new(quic);

    // Uses H3Resolver which uses dquic internally aka HTTP/3
    let resolver = H3Publisher::new(opt.base_url.clone(), h3_endpoint)?;

    info!(host = %opt.host, addrs = ?opt.addr, base_url = %opt.base_url, "publish.start");
    if opt.sign {
        info!("publish.endpoint_signing.enabled");
    } else {
        info!("publish.endpoint_signing.disabled");
    }
    let selector = identity
        .dhttp_subject_key_identifier()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let chain = selector.chain();

    for &addr in &opt.addr {
        info!("creating endpoint for address: {}", addr);
        let mut endpoint = match addr {
            SocketAddr::V4(v4) => EndpointAddr::direct_v4(v4),
            SocketAddr::V6(v6) => EndpointAddr::direct_v6(v6),
        };
        endpoint.set_certificate_chain_key(chain);
        if opt.sign {
            info!("signing endpoint");
            endpoint
                .sign_with_authority(identity.as_ref())
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        info!("publishing endpoint: {:?}", endpoint);
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(opt.host.clone(), vec![endpoint]);
        let packet = ddns::core::MdnsPacket::answer(0, &hosts).to_bytes();
        resolver
            .publish(&opt.host, &packet)
            .await
            .map_err(io::Error::other)?;
        info!("successfully published endpoint for {}", addr);
    }
    info!("publish.ok");

    Ok(())
}
