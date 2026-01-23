use std::{error::Error, fmt::Debug, sync::Arc};

use futures::{Stream, StreamExt, stream};
use snafu::Report;
use tokio::io;

use super::{Publisher, Resolver};
use crate::parser::record::endpoint::EndpointAddr;

#[cfg(feature = "h3x-resolver")]
mod h3;
mod http;
mod mdns;

#[cfg(feature = "h3x-resolver")]
pub use h3::H3Resolver;
pub use http::HttpResolver;
pub use mdns::MdnsResolver;

type ArcResolver = Arc<dyn Resolver + Send + Sync + 'static>;

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

    pub fn with(mut self, resolver: Arc<dyn Resolver + Send + Sync + 'static>) -> Self {
        self.resolvers.push(resolver);
        self
    }

    pub fn lookup(&self, name: &str) -> impl Stream<Item = (Option<String>, EndpointAddr)> {
        let futures = self.resolvers.iter().map(|resolver| {
            let name = name.to_string();
            async move { resolver.lookup(&name).await.unwrap_or_default() }
        });
        stream::FuturesUnordered::from_iter(futures).flat_map(stream::iter)
    }
}
