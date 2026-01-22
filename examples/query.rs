use std::{io, path::PathBuf};

use clap::Parser;
use gmdns::{MdnsPacket, parser::record::RData};
use rustls::RootCertStore;
use tracing::info;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Base URL of the HTTP DNS server (TCP/HTTPS), e.g. https://localhost:4433/
    #[arg(long, default_value = "https://localhost:4433/")]
    base_url: String,

    /// PEM file containing CA certificates that can verify the server certificate.
    #[arg(long, default_value = "examples/keychain/localhost/ca.cert")]
    server_ca: PathBuf,

    /// DNS name to lookup.
    #[arg(long, default_value = "client")]
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
                        // TODO: Provide SPKI to verify signature
                        // For now, indicate signed but unable to verify without key
                        output.push_str("Signature: present (unable to verify without SPKI)\n");
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
    tracing_subscriber::fmt::init();

    let opt = Options::parse();

    // Use regular reqwest client (HTTP/1.1 or HTTP/2 over TCP)
    // This demonstrates decouple: The query does not use gm-quic/H3.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .add_root_certificate(reqwest::tls::Certificate::from_pem(&std::fs::read(
            &opt.server_ca,
        )?)?)
        .build()?;

    let url = format!("{}lookup?host={}", opt.base_url, opt.host);
    info!(url = %url, "lookup.start");

    let resp = client.get(&url).send().await?;

    if resp.status().is_success() {
        let bytes = resp.bytes().await?;
        // In this example, the server returns raw bytes (e.g., DNS packet or custom format).
        // Since the resolver example was returning serialized data, we just print it.
        // If it returns MDNS packet bytes, we could parse it, but for now we just show we got it.

        // Try to parse as gmdns packet for display if possible, or just raw
        match gmdns::parser::packet::be_packet(&bytes) {
            Ok((_, packet)) => {
                info!("DNS lookup successful, parsed packet:\n{}", packet);
                println!("{}", format_packet(&packet));
            }
            Err(_) => {
                info!(bytes = bytes.len(), "lookup.ok.raw");
                println!("Lookup Result (Raw): {:?}", bytes);
            }
        }
    } else {
        let status = resp.status();
        let text = resp.text().await?;
        info!(%status, error = %text, "lookup.failed");
        eprintln!("Lookup failed: {} - {}", status, text);
    }

    Ok(())
}
