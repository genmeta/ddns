use std::{
    error::Error,
    fmt::{self, Debug, Display},
    sync::Arc,
};

use futures::{FutureExt, Stream, StreamExt, TryFutureExt, stream};
use qdns::{EndpointAddr, Family, Publish, Resolve, ResolveFuture, Source};
use qinterface::device::Devices;
use snafu::Report;
use tokio::io;

#[cfg(feature = "h3x-resolver")]
mod h3;
mod http;
mod mdns;

#[cfg(feature = "h3x-resolver")]
pub use h3::{H3Publisher, H3Resolver};
pub use http::HttpResolver;
pub use mdns::MdnsResolver;

type ArcResolver = Arc<dyn Resolve + Send + Sync + 'static>;

#[derive(Default, Clone, Debug)]
pub struct Resolvers {
    resolvers: Vec<ArcResolver>,
}

impl Display for Resolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resolvers(")?;
        if self.resolvers.is_empty() {
            f.write_str("empty")?;
        } else {
            for (i, resolver) in self.resolvers.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                fmt::Display::fmt(resolver.as_ref(), f)?;
            }
        }
        f.write_str(")")
    }
}

#[derive(Debug)]
pub struct DnsErrors {
    errors: Vec<(ArcResolver, io::Error)>,
}

impl fmt::Display for DnsErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return writeln!(f, "No DNS resolvers available");
        }
        writeln!(f, "All DNS resolvers failed")?;
        for (resolver, error) in &self.errors {
            writeln!(f, "`{resolver}` failed: {}", Report::from_error(error))?;
        }
        Ok(())
    }
}

impl Error for DnsErrors {}

impl Resolvers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, resolver: ArcResolver) -> Self {
        self.resolvers.push(resolver);
        self
    }

    pub fn with_mdns_resolvers(
        mut self,
        service_name: &str,
        mut filter: impl FnMut(&str, Family) -> bool,
    ) -> Self {
        let devices = Devices::global();
        self.resolvers.extend(
            devices
                .interfaces()
                .iter()
                .flat_map(|(device, iface)| {
                    Option::into_iter(
                        (!iface.ipv4.is_empty()).then_some((device.as_str(), Family::V4)),
                    )
                    .chain((!iface.ipv4.is_empty()).then_some((device.as_str(), Family::V6)))
                })
                .filter(|(device, family)| filter(device, *family))
                .filter_map(|(device, family)| Some((device, devices.resolve(device, family)?)))
                .filter_map(|(device, ip)| MdnsResolver::new(service_name, ip, device).ok())
                .map(|resolver| Arc::new(resolver) as ArcResolver),
        );
        self
    }

    pub async fn lookup<'n>(
        &self,
        name: &'n str,
    ) -> Result<impl Stream<Item = (Source, EndpointAddr)> + use<'n>, DnsErrors> {
        let mut errors = vec![];

        let mut lookups = stream::FuturesUnordered::from_iter(
            (self.resolvers.clone().into_iter()).map(|resolver| {
                let resolver = resolver.clone();
                async move { (resolver.lookup(name).await, resolver.clone()) }
            }),
        );

        let endpoints = loop {
            match lookups.next().await {
                Some((Ok(endpoints), _)) => break endpoints,
                Some((Err(error), resolver)) => errors.push((resolver, error)),
                None => return Err(DnsErrors { errors }),
            }
        };

        Ok(endpoints.chain(lookups.flat_map(|(endpoints, _)| stream::iter(endpoints).flatten())))
    }
}

impl Resolve for Resolvers {
    fn lookup<'r, 'n: 'r>(&'r self, name: &'n str) -> ResolveFuture<'r, 'n> {
        self.lookup(name)
            .map_ok(StreamExt::boxed)
            .map_err(io::Error::other)
            .boxed()
    }
}
