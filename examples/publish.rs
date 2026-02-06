use std::{io, net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gmdns::{parser::record::endpoint::EndpointAddr, resolvers::H3Publisher};
use h3x::gm_quic::H3Client;
use qdns::{Publish, SocketEndpointAddr};
use rustls::{RootCertStore, SignatureScheme, pki_types::PrivateKeyDer, sign::SigningKey};
use tracing::{Level, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Base URL of the H3 DNS server, e.g. https://localhost:4433/
    #[arg(long, default_value = "https://localhost:4433/")]
    base_url: String,

    /// PEM file containing CA certificates that can verify the server certificate.
    #[arg(long, default_value = "examples/keychain/root/rootCA-ECC.crt")]
    server_ca: PathBuf,

    /// Client identity name (passed into h3x/gm-quic identity builder).
    #[arg(long, default_value = "publish.test.genmeta.net")]
    client_name: String,

    /// Client certificate chain in PEM.
    #[arg(
        long,
        default_value = "examples/keychain/publish.test.genmeta.net/publish.test.genmeta.net-ECC.crt"
    )]
    client_cert: PathBuf,

    /// Client private key in PEM (PKCS#8 or RSA).
    #[arg(
        long,
        default_value = "examples/keychain/publish.test.genmeta.net/publish.test.genmeta.net-ECC.key"
    )]
    client_key: PathBuf,

    /// Sign Endpoint records using the client private key.
    ///
    /// This must correspond to the client certificate presented in mTLS, because the server
    /// verifies the signature with the peer certificate's SPKI.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    sign: bool,

    /// DNS name to publish. Must match the single DNS SAN in the client cert.
    #[arg(long, default_value = "publish.test.genmeta.net")]
    host: String,

    /// Socket addresses to publish.
    #[arg(long, value_delimiter = ',', num_args = 1.., default_value = "127.0.0.1:5555")]
    addr: Vec<SocketAddr>,

    #[arg(long, default_value_t = true)]
    is_main: bool,

    #[arg(long, default_value_t = 1)]
    sequence: u64,
}

fn load_root_store_from_pem(path: &PathBuf) -> io::Result<RootCertStore> {
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

    let root_store = load_root_store_from_pem(&opt.server_ca)?;
    let cert_chain_pem = std::fs::read(&opt.client_cert)?;
    let private_key_pem = std::fs::read(&opt.client_key)?;

    // 显示将要使用的证书信息
    let mut cert_reader = std::io::Cursor::new(&cert_chain_pem);
    if let Ok(certs) = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()
        && let Some(first_cert) = certs.first()
    {
        info!(
            cert_len = first_cert.len(),
            "Client certificate loaded, will be sent to server for storage"
        );
    }

    let signer = opt
        .sign
        .then(|| build_signing_key_from_pem(&private_key_pem))
        .transpose()?;
    let signer_scheme = signer.as_deref().map(pick_signature_scheme).transpose()?;

    let client = H3Client::builder()
        .with_root_certificates(Arc::new(root_store))
        .with_identity(
            opt.client_name,
            cert_chain_pem.as_slice(),
            private_key_pem.as_slice(),
        )
        .map_err(io::Error::other)?
        .build();

    // Uses H3Resolver which uses gm-quic internally aka HTTP/3
    let resolver = H3Publisher::new(opt.base_url.clone(), client)?;

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
            endpoint.sign_with(key, scheme).map_err(io::Error::other)?;
        }
        info!("Publishing endpoint: {:?}", endpoint);
        let endpoint = SocketEndpointAddr::try_from(endpoint).unwrap().into();
        resolver.publish(&opt.host, &[endpoint]).await?;
        info!("Successfully published endpoint for {}", addr);
    }
    info!("publish.ok");

    Ok(())
}
