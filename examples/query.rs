use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use clap::Parser;
use gmdns::{MdnsPacket, parser::record::RData, wire::be_multi_response};
use h3x::{
    dquic::{
        Network, QuicEndpoint,
        client::{ClientQuicConfig, ServerCertVerifierChoice},
        resolver::handy::SystemResolver,
    },
    endpoint::H3Endpoint,
};
use http::Method;
use rustls::{RootCertStore, client::WebPkiServerVerifier};
use tracing::{Level, info};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Options {
    /// Base URL of the线上 HTTP/3 DNS server.
    #[arg(long, default_value = "https://dns.genmeta.net:4433/")]
    base_url: String,

    /// 用于校验线上服务端证书的 CA PEM 文件。
    #[arg(long)]
    server_ca: PathBuf,

    /// 要查询的线上域名。
    #[arg(long, default_value = "stun.genmeta.net")]
    host: String,
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring crypto provider");
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();

    let opt = Options::parse();
    let server_ca = expand_tilde(&opt.server_ca)?;
    let root_store = load_root_store_from_pem(&server_ca)?;
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let client_config = ClientQuicConfig {
        verifier: ServerCertVerifierChoice::WebPki(verifier),
        ..Default::default()
    };
    let network = Network::builder().build();
    let quic = QuicEndpoint::builder()
        .network(network)
        .resolver(Arc::new(SystemResolver))
        .client(client_config)
        .build()
        .await;
    let client = H3Endpoint::new(quic);

    let url = format!("{}lookup?host={}", opt.base_url, opt.host);
    info!(url = %url, "lookup.start");

    let uri: http::Uri = url.parse()?;
    let client = Arc::new(client);
    let req = client.new_request_owned();
    req.method(Method::GET);
    req.uri(uri);
    let mut resp = req.into_response().await?;

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

            match record.cert_fingerprint_hex() {
                Some(fp) => println!("Source fingerprint: {}…{}", &fp[..16], &fp[fp.len() - 8..]),
                None => println!("Source fingerprint: (no certificate)"),
            }

            match gmdns::parser::packet::be_packet(&record.dns) {
                Ok((_, packet)) => {
                    print!("{}", format_packet(&packet));

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
