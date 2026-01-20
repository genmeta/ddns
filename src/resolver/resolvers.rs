use std::{error::Error, fmt::Debug, future, net::SocketAddr, sync::Arc};

use futures::{Stream, StreamExt, stream};
use snafu::Report;
use tokio::io;

use super::Resolve;

mod http;
mod mdns;

pub use http::HttpResolver;
pub use mdns::MdnsResolver;

type ArcResolver = Arc<dyn Resolve + Send + Sync + 'static>;

#[derive(Default, Clone)]
pub struct Resolvers {
    resolvers: Vec<ArcResolver>,
}

#[derive(Debug)]
pub struct DnsErrors {
    errors: Vec<(ArcResolver, io::Error)>,
}

impl std::fmt::Display for DnsErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.errors.is_empty() {
            return writeln!(f, "No DNS resolvers available");
        }
        writeln!(f, "All DNS resolvers failed")?;
        for (resolver, error) in &self.errors {
            writeln!(
                f,
                "Resolver `{resolver}` failed: {}",
                Report::from_error(error)
            )?;
        }
        Ok(())
    }
}

impl Error for DnsErrors {}

impl Resolvers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, resolver: Arc<dyn Resolve + Send + Sync + 'static>) -> Self {
        self.resolvers.push(resolver);
        self
    }

    pub async fn lookup(
        &self,
        name: &str,
    ) -> Result<impl Stream<Item = (ArcResolver, Vec<SocketAddr>)> + use<>, DnsErrors> {
        let mut errors = vec![];

        let mut lookups = stream::FuturesUnordered::from_iter(
            (self.resolvers.clone().into_iter()).map(|resolver| {
                let name = name.to_string();
                async move { (resolver.clone(), resolver.lookup(&name).await) }
            }),
        );

        let (resolver, endpoints) = loop {
            match lookups.next().await {
                Some((resolver, Ok(endpoints))) => break (resolver, endpoints),
                Some((resolver, Err(error))) => errors.push((resolver, error)),
                None => return Err(DnsErrors { errors }),
            }
        };

        Ok(
            stream::once(future::ready((resolver, endpoints))).chain(lookups.filter_map(
                |(source, endpoints)| {
                    future::ready(endpoints.ok().map(|endpoints| (source, endpoints)))
                },
            )),
        )
    }
}
