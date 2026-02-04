use std::{error::Error, fmt::Debug, sync::Arc};

use futures::{Stream, StreamExt, stream};
use snafu::Report;
use tokio::io;

use super::{Publisher, Resolver};
use crate::parser::record::endpoint::EndpointAddr;

#[cfg(feature = "h3x-resolver")]
use gm_quic::qbase::net::addr::SocketEndpointAddr;
mod h3;
mod http;
mod mdns;

#[cfg(feature = "h3x-resolver")]
pub use h3::{H3Publisher, H3Resolver};
pub use http::HttpResolver;
pub use mdns::MdnsResolver;

type ArcResolver = Arc<dyn Resolver + Send + Sync + 'static>;

#[derive(Default, Clone, Debug)]
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

#[cfg(feature = "h3x-resolver")]
impl gm_quic::qtraversal::resolver::Resolve for Resolvers {
    fn lookup<'a>(&'a self, name: &'a str) -> gm_quic::qtraversal::resolver::ResolveStream<'a> {
        self.lookup(name)
            .map(|(uri, ep)| {
                let socket_ep = match ep.agent {
                    Some(agent) => SocketEndpointAddr::with_agent(
                        agent, ep.primary,
                    ),
                    None => SocketEndpointAddr::direct(ep.primary),
                };
                let bind_uri = uri.and_then(|u| std::str::FromStr::from_str(&u).ok());
                Ok((bind_uri, socket_ep))
            })
            .boxed()
    }
}
