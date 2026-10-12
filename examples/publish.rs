use std::{net::SocketAddr, sync::Arc};

use clap::Parser;
use ddns::{H3Resolver, resolvers::DHTTP_NAME_SERVICE};
use qresolve::EndpointAddr;

#[derive(Debug, Parser)]
struct Options {
    #[arg(long)]
    identity: String,
    #[arg(long, default_value_t = DHTTP_NAME_SERVICE.to_owned())]
    server_origin: String,
    #[arg(long)]
    host: String,
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    addr: Vec<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let options = Options::parse();
    qresolve::Resolver::add(Arc::new(qresolve::SystemResolver));
    dhttp::DhttpNetwork::init().await?;
    let endpoint = Arc::new(dhttp::Endpoint::load(options.identity).await?);
    let resolver = H3Resolver::new(options.server_origin.parse()?, &endpoint)?;
    let lease = resolver
        .publish_endpoints(
            &options.host,
            options.addr.into_iter().map(EndpointAddr::direct),
        )
        .await?;
    println!("published {}: lease {lease:?}", options.host);
    Ok(())
}
