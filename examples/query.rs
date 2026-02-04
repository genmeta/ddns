use std::{io, path::PathBuf, sync::Arc};

use clap::Parser;
use gmdns::{MdnsPacket, parser::record::RData};
use h3x::gm_quic::{
    BuildClientError, H3Client,
    prelude::handy::{ToCertificate, ToPrivateKey},
};
use rustls::RootCertStore;
use tracing::{Level, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Base URL of the HTTP DNS server (TCP/HTTPS), e.g. https://localhost:4433/
    #[arg(long, default_value = "https://localhost:4433/")]
    base_url: String,

    /// PEM file containing CA certificates that can verify the server certificate.
    #[arg(long, default_value = "examples/keychain/root/rootCA-ECC.crt")]
    server_ca: PathBuf,

    /// Client identity name (passed into h3x/gm-quic identity builder).
    #[arg(long, default_value = "query.test.genmeta.net")]
    client_name: String,

    /// Client certificate chain in PEM.
    #[arg(
        long,
        default_value = "examples/keychain/query.test.genmeta.net/query.test.genmeta.net-ECC.crt"
    )]
    client_cert: PathBuf,

    /// Client private key in PEM (PKCS#8 or RSA).
    #[arg(
        long,
        default_value = "examples/keychain/query.test.genmeta.net/query.test.genmeta.net-ECC.key"
    )]
    client_key: PathBuf,

    /// DNS name to lookup.
    #[arg(long, default_value = "publish.test.genmeta.net")]
    host: String,
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

fn format_packet(packet: &MdnsPacket) -> String {
    let mut output = String::new();

    if !packet.answers.is_empty() {
        output.push_str("Answer:\n");
        for rr in &packet.answers {
            match rr.data() {
                RData::A(ip) => {
                    output.push_str(&format!("Name:   {}\nAddress: {}\n", rr.name(), ip));
                }
                RData::AAAA(ip) => {
                    output.push_str(&format!("Name:   {}\nAddress: {}\n", rr.name(), ip));
                }
                RData::CName(cname) => {
                    output.push_str(&format!("Name:   {}\nCNAME:  {}\n", rr.name(), cname));
                }
                RData::E(ep) => {
                    output.push_str(&format!("Name:   {}\nAddress: {}\n", rr.name(), ep.primary));
                    if ep.is_signed() {
                        output.push_str("Signature: present\n");
                    }
                }
                _ => {
                    output.push_str(&format!("Name:   {}\nData:   {:?}\n", rr.name(), rr.data()));
                }
            }
        }
    }

    output
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG) // 显示INFO级别的日志
        .init();

    let opt = Options::parse();
    let root_store = load_root_store_from_pem(&opt.server_ca)?;
    let cert_pem = std::fs::read(&opt.client_cert)?;
    let key_pem = std::fs::read(&opt.client_key)?;

    let client = H3Client::builder()
        .with_root_certificates(Arc::new(root_store))
        .with_identity(
            opt.client_name,
            cert_pem.to_certificate(),
            key_pem.to_private_key(),
        )
        .map_err(|e: BuildClientError| io::Error::other(e.to_string()))?
        .build();

    let url = format!("{}lookup?host={}", opt.base_url, opt.host);
    info!(url = %url, "lookup.start");

    let uri: http::Uri = url.parse()?;
    let (_req, mut resp) = client.new_request().get(uri).await?;

    if resp.status().is_success() {
        let bytes = resp.read_to_bytes().await?;

        let cert = if let Some(cert_header) = resp.headers().get("e-cert")
            && let Ok(cert_b64) = cert_header.to_str()
        {
            use base64::Engine;
            match base64::engine::general_purpose::STANDARD.decode(cert_b64) {
                Ok(cert_der) => {
                    info!(
                        cert_len = cert_der.len(),
                        "Certificate received in E-Cert header"
                    );
                    println!(
                        "Certificate (DER, {} bytes): {:02x?}...",
                        cert_der.len(),
                        &cert_der[..std::cmp::min(32, cert_der.len())]
                    );
                    Some(cert_der)
                }
                Err(e) => {
                    info!(?e, "Failed to decode E-Cert header");
                    None
                }
            }
        } else {
            None
        };

        // Try to parse as gmdns packet for display if possible, or just raw
        match gmdns::parser::packet::be_packet(&bytes) {
            Ok((_, packet)) => {
                info!("DNS lookup successful, parsed packet:\n{}", packet);
                println!("{}", format_packet(&packet));
                // 验证证书
                if let Some(cert) = cert {
                    if let Some(rrs) = packet
                        .answers
                        .iter()
                        .filter_map(|rr| {
                            if let RData::E(ep) = rr.data() {
                                Some((rr.name().to_string(), ep))
                            } else {
                                None
                            }
                        })
                        .collect::<Vec<_>>()
                        .first()
                    {
                        let (name, ep) = rrs;
                        match ep.verify_signature_from_der(&cert) {
                            Ok(_) => {
                                info!(name = %name, "Certificate verification succeeded");
                                println!("Certificate verification succeeded for record: {}", name);
                            }
                            Err(e) => {
                                info!(name = %name, ?e, "Certificate verification failed");
                                println!(
                                    "Certificate verification failed for record: {}: {:?}",
                                    name, e
                                );
                            }
                        }
                    } else {
                        info!("No E records found in DNS answer for certificate verification");
                    }
                }
            }
            Err(_) => {
                info!(bytes = bytes.len(), "lookup.ok.raw");
                println!("Lookup Result (Raw): {:?}", bytes);
            }
        }
    } else {
        let status = resp.status();
        info!(%status, "lookup.failed");
        eprintln!("Lookup failed: {}", status);
    }

    Ok(())
}
