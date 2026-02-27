use std::{io, net::IpAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use gmdns::{
    MdnsPacket,
    mdns::Mdns,
    parser::record::RData,
    wire::be_multi_response,
};
use h3x::gm_quic::{
    BuildClientError, H3Client,
    prelude::handy::{ToCertificate, ToPrivateKey},
};
use nix::{
    ifaddrs::getifaddrs,
    sys::socket::{AddressFamily, SockaddrLike},
};
use rustls::RootCertStore;
use tracing::{Level, info};

const MDNS_SERVICE: &str = "_genmeta.local";

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

    /// Local device name for mDNS query (e.g. en1). When set, perform mDNS lookup before HTTP DNS.
    #[arg(long)]
    mdns: Option<String>,
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
                    output.push_str(&format!("Name:   {}\nAddress: {}\n", rr.name(), ep));
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

fn resolve_mdns_ip(device: &str) -> io::Result<IpAddr> {
    let ifaddrs = getifaddrs().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut v4 = None;
    let mut v6 = None;

    for ifaddr in ifaddrs {
        if ifaddr.interface_name != device {
            continue;
        }
        let Some(addr) = ifaddr.address else {
            continue;
        };
        match addr.family() {
            Some(AddressFamily::Inet) => {
                if let Some(sockaddr) = addr.as_sockaddr_in() {
                    v4 = Some(IpAddr::V4(sockaddr.ip()));
                }
            }
            Some(AddressFamily::Inet6) => {
                if let Some(sockaddr) = addr.as_sockaddr_in6() {
                    v6 = Some(IpAddr::V6(sockaddr.ip()));
                }
            }
            _ => {}
        }
    }

    v4.or(v6).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("No IP found for device {device}"),
        )
    })
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
    if let Some(mdns_device) = opt.mdns.as_deref() {
        let mdns_ip = resolve_mdns_ip(mdns_device)?;
        let mdns = Mdns::new(MDNS_SERVICE, mdns_ip, mdns_device)?;
        match mdns.query(opt.host.clone()).await {
            Ok(endpoints) => {
                println!("mDNS Result:");
                for ep in endpoints {
                    println!("  {}", ep);
                }
            }
            Err(e) => {
                eprintln!("mDNS lookup failed: {}", e);
            }
        }
    }
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

        let (_remain, multi) = be_multi_response(bytes.as_ref()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid multi-record payload: {e}"),
            )
        })?;

        info!(count = multi.records.len(), "lookup.ok");
        println!("Lookup Result: {} record(s)", multi.records.len());

        for (index, record) in multi.records.iter().enumerate() {
            println!("\n-- Record #{} --", index + 1);

            // Source: abbreviated fingerprint of the publisher's certificate.
            match record.cert_fingerprint_hex() {
                Some(fp) => println!("Source fingerprint: {}…{}", &fp[..16], &fp[fp.len() - 8..]),
                None => println!("Source fingerprint: (no certificate)"),
            }

            match gmdns::parser::packet::be_packet(&record.dns) {
                Ok((_, packet)) => {
                    print!("{}", format_packet(&packet));

                    // Signature verification per endpoint record.
                    for rr in &packet.answers {
                        if let RData::E(ep) = rr.data() {
                            if !ep.is_signed() {
                                println!("Signature: none");
                                continue;
                            }
                            if record.cert.is_empty() {
                                println!("Signature: present but no certificate to verify against");
                                continue;
                            }
                            match ep.verify_signature_from_der(&record.cert) {
                                Ok(true) => println!("Signature: ✓ verified"),
                                Ok(false) => println!("Signature: ✗ invalid"),
                                Err(e) => println!("Signature: ✗ error ({e:?})"),
                            }
                        }
                    }
                }
                Err(_) => {
                    println!("DNS payload: invalid ({} bytes)", record.dns.len());
                }
            }
        }
    } else {
        let status = resp.status();
        info!(%status, "lookup.failed");
        eprintln!("Lookup failed: {}", status);
    }

    Ok(())
}
