use std::{
    io::Error,
    net::{IpAddr, SocketAddr},
};

use clap::Parser;
use ddns::{core::MdnsEndpoint, mdns::service::Mdns, resolvers::DHTTP_MDNS_SERVICE};
use futures::StreamExt;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    ip: IpAddr,
    #[arg(long, default_value = "lo0")]
    device: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let mdns = Mdns::new(DHTTP_MDNS_SERVICE, args.ip, &args.device)?;
    mdns.insert_host(
        "test.dhttp.net".to_string(),
        vec![
            {
                let addr: SocketAddr = "192.168.1.7:7000".parse().unwrap();
                if let SocketAddr::V4(v4) = addr {
                    MdnsEndpoint::direct_v4(v4)
                } else {
                    panic!("Expected IPv4 address");
                }
            },
            {
                let addr: SocketAddr = "192.168.1.13:7000".parse().unwrap();
                if let SocketAddr::V4(v4) = addr {
                    MdnsEndpoint::direct_v4(v4)
                } else {
                    panic!("Expected IPv4 address");
                }
            },
        ],
    );

    mdns.insert_host(
        "mdns.test.dhttp.net".to_string(),
        vec![
            {
                let addr: SocketAddr = "192.168.1.7:7001".parse().unwrap();
                if let SocketAddr::V4(v4) = addr {
                    MdnsEndpoint::direct_v4(v4)
                } else {
                    panic!("Expected IPv4 address");
                }
            },
            {
                let addr: SocketAddr = "192.168.1.7:7001".parse().unwrap();
                if let SocketAddr::V4(v4) = addr {
                    MdnsEndpoint::direct_v4(v4)
                } else {
                    panic!("Expected IPv4 address");
                }
            },
            {
                let addr: SocketAddr = "192.168.1.7:7001".parse().unwrap();
                if let SocketAddr::V4(v4) = addr {
                    MdnsEndpoint::direct_v4(v4)
                } else {
                    panic!("Expected IPv4 address");
                }
            },
        ],
    );

    let mut stream = mdns.discover();
    while let Some((addr, packet)) = stream.next().await {
        println!("Received packet from {addr}: {packet}");
    }
    Ok(())
}
