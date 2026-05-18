use std::{
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use ddns::{parser::record::endpoint::EndpointAddr, resolvers::H3Publisher};
use h3x::dquic::{
    Identity, Network, QuicEndpoint,
    cert::handy::{ToCertificate, ToPrivateKey},
    client::{ClientQuicConfig, ServerCertVerifierChoice},
    resolver::{Publish, handy::SystemResolver},
};
use rustls::{
    RootCertStore, SignatureScheme, client::WebPkiServerVerifier, pki_types::PrivateKeyDer,
    sign::SigningKey,
};
use tracing::{Level, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Base URL of the线上 H3 DNS server.
    #[arg(long, default_value = "https://dns.genmeta.net:4433/")]
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

    #[arg(long, default_value_t = true)]
    is_main: bool,

    #[arg(long, default_value_t = 1)]
    sequence: u64,
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

fn load_private_key_from_pem(pem: &[u8]) -> io::Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::Cursor::new(pem);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "No private key found in PEM"))?;
    Ok(key)
}

fn build_signing_key_from_pem(pem: &[u8]) -> io::Result<Arc<dyn SigningKey>> {
    let key = load_private_key_from_pem(pem)?;
    rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn pick_signature_scheme(key: &dyn SigningKey) -> io::Result<SignatureScheme> {
    // Order is preference; choose_scheme picks the first it supports.
    let offered = [
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
    ];

    let signer = key
        .choose_scheme(&offered)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Unsupported key type/scheme"))?;
    Ok(signer.scheme())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    // Install ring crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");

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

    let signer = opt
        .sign
        .then(|| build_signing_key_from_pem(&private_key_pem))
        .transpose()?;
    let signer_scheme = signer.as_deref().map(pick_signature_scheme).transpose()?;

    // Build WebPki server cert verifier from CA root store
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Build TLS identity from cert chain and private key PEM
    let identity = Identity {
        name: opt.client_name.parse().unwrap(),
        certs: Arc::new(cert_chain_pem.to_certificate()),
        key: Arc::new(private_key_pem.to_private_key()),
        ocsp: Arc::new(None),
    };

    // Build network and QuicEndpoint with client mTLS config
    let network = Network::builder().build();
    let quic = QuicEndpoint::builder()
        .network(network)
        .identity(Arc::new(identity))
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
    if let Some(scheme) = signer_scheme {
        info!(?scheme, "publish.endpoint_signing.enabled");
    } else {
        info!("publish.endpoint_signing.disabled");
    }

    for &addr in &opt.addr {
        info!("Creating endpoint for address: {}", addr);
        let mut endpoint = match addr {
            SocketAddr::V4(v4) => EndpointAddr::direct_v4(v4),
            SocketAddr::V6(v6) => EndpointAddr::direct_v6(v6),
        };
        endpoint.set_main(opt.is_main);
        endpoint.set_sequence(opt.sequence);
        if let Some((key, scheme)) = signer.as_deref().zip(signer_scheme) {
            info!("Signing endpoint with scheme: {:?}", scheme);
            endpoint
                .sign_with(key, scheme)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        info!("Publishing endpoint: {:?}", endpoint);
        let mut hosts = std::collections::HashMap::new();
        hosts.insert(opt.host.clone(), vec![endpoint]);
        let packet = ddns::MdnsPacket::answer(0, &hosts).to_bytes();
        resolver
            .publish(&opt.host, &packet)
            .await
            .map_err(io::Error::other)?;
        info!("Successfully published endpoint for {}", addr);
    }
    info!("publish.ok");

    Ok(())
}
