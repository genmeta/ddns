use std::sync::Arc;

use clap::Parser;
use ddns::{H3Resolver, resolvers::DHTTP_NAME_SERVICE};
use futures::StreamExt;

#[derive(Debug, Parser)]
struct Options {
    #[arg(long)]
    identity: Option<String>,
    #[arg(long, default_value_t = DHTTP_NAME_SERVICE.to_owned())]
    server_origin: String,
    #[arg(long)]
    host: String,
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
    let endpoint = match options.identity {
        Some(identity) => Some(Arc::new(dhttp::Endpoint::load(identity).await?)),
        None => None,
    };
    let origin = options.server_origin.parse()?;
    let resolver = match endpoint.as_ref() {
        Some(endpoint) => H3Resolver::new(origin, endpoint)?,
        None => H3Resolver::anonymous(origin)?,
    };
    let records = resolver.lookup(&options.host, "443", None).await?;
    for (source, endpoint) in records.collect::<Vec<_>>().await {
        println!("{source}: {endpoint}");
    }
    Ok(())
}
