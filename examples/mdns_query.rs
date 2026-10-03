use std::net::IpAddr;

use clap::Parser;
use ddns::{mdns::MdnsResolver, resolvers::DHTTP_MDNS_SERVICE_DOMAIN};
use futures::StreamExt;
use qresolve::Resolve;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    ip: IpAddr,
    #[arg(long)]
    device: String,
    #[arg(long)]
    host: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mdns = MdnsResolver::bind(DHTTP_MDNS_SERVICE_DOMAIN, args.device, args.ip).await?;
    let records = mdns.lookup(&args.host, "443", None).await?;
    for record in records.collect::<Vec<_>>().await {
        println!("{record:?}");
    }
    mdns.shutdown().await?;
    Ok(())
}
