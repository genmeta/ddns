use std::{
    error::Error,
    fmt::{self, Debug, Display},
    sync::Arc,
};

use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{Resolve, ResolveFuture, Source},
};
use futures::{FutureExt, Stream, StreamExt, TryFutureExt, stream};
use snafu::Report;
use tokio::io;

#[cfg(feature = "h3x-resolver")]
mod h3;
#[cfg(feature = "http-resolver")]
mod http;

/// Extract and validate the DNS host from `name`, which may include a `:port`
/// suffix. Returns `Some(host)` if the host part is a valid RFC-compliant DNS
/// name, or `None` for raw IP addresses, bracketed IPv6, or malformed input.
#[cfg_attr(
    not(any(feature = "h3x-resolver", feature = "http-resolver")),
    allow(dead_code)
)]
pub(crate) fn resolvable_name(name: &str) -> Option<&str> {
    let host = match name.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => name,
    };
    rustls::pki_types::DnsName::try_from(host).ok()?;
    Some(host)
}

pub use gmdns::resolvers::{MdnsResolver, MdnsResolvers};
#[cfg(feature = "h3x-resolver")]
pub use h3::{H3Publisher, H3Resolver};
#[cfg(feature = "http-resolver")]
pub use http::HttpResolver;

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
    errors: Vec<(String, io::Error)>,
}

impl fmt::Display for DnsErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "no DNS resolvers available");
        }
        writeln!(f, "all DNS resolvers failed")?;
        for (resolver, error) in self.errors.iter() {
            write!(f, "`{resolver}` failed: {}", Report::from_error(error))?;
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

    pub async fn lookup(
        &self,
        name: &str,
    ) -> Result<impl Stream<Item = (Source, EndpointAddr)> + use<>, DnsErrors> {
        let mut errors = vec![];

        let mut lookups = stream::FuturesUnordered::from_iter(
            (self.resolvers.clone().into_iter()).map(|resolver| {
                let resolver = resolver.clone();
                let name = name.to_string();
                async move { (resolver.lookup(&name).await, resolver.clone()) }
            }),
        );

        let endpoints = loop {
            match lookups.next().await {
                Some((Ok(endpoints), _)) => break endpoints,
                Some((Err(error), resolver)) => errors.push((resolver.to_string(), error)),
                None => return Err(DnsErrors { errors }),
            }
        };

        Ok(endpoints.chain(lookups.flat_map(|(endpoints, _)| stream::iter(endpoints).flatten())))
    }
}

impl Resolve for Resolvers {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        self.lookup(name)
            .map_ok(StreamExt::boxed)
            .map_err(io::Error::other)
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::resolvable_name;

    #[test]
    fn resolvable_name_accepts_dns_name_with_numeric_port() {
        assert_eq!(
            resolvable_name("example.genmeta.net:443"),
            Some("example.genmeta.net")
        );
    }

    #[test]
    fn resolvable_name_rejects_ip_literals() {
        assert_eq!(resolvable_name("127.0.0.1:443"), None);
        assert_eq!(resolvable_name("[::1]:443"), None);
    }
}
