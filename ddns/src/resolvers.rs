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

/// Default DNS-over-H3 server for DHTTP endpoints.
pub const DHTTP_H3_DNS_SERVER: &str = "https://dns.genmeta.net:4433";

/// Default DNS-over-HTTP server for DHTTP endpoints.
pub const DHTTP_HTTP_DNS_SERVER: &str = "https://dns.genmeta.net";

/// mDNS service type used by DHTTP endpoints.
pub const DHTTP_MDNS_SERVICE: &str = "_genmeta.local";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsScheme {
    Mdns,
    Http,
    H3,
    System,
}

impl Display for DnsScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Mdns => "mdns",
            Self::Http => "http",
            Self::H3 => "h3",
            Self::System => "system",
        })
    }
}

#[derive(Debug, snafu::Snafu)]
#[snafu(display("unsupported dns scheme {scheme}"))]
pub struct ParseDnsSchemeError {
    scheme: String,
}

impl std::str::FromStr for DnsScheme {
    type Err = ParseDnsSchemeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mdns" => Ok(Self::Mdns),
            "http" => Ok(Self::Http),
            "h3" => Ok(Self::H3),
            "system" => Ok(Self::System),
            scheme => Err(ParseDnsSchemeError {
                scheme: scheme.to_owned(),
            }),
        }
    }
}

pub use gmdns::resolvers::MdnsResolver;
#[cfg(feature = "mdns-resolver")]
pub use gmdns::resolvers::MdnsResolvers;
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

#[derive(Default)]
pub struct ResolversBuilder {
    resolvers: Resolvers,
}

impl ResolversBuilder {
    #[cfg(feature = "mdns-resolver")]
    pub async fn mdns(
        mut self,
        network: Arc<h3x::dquic::Network>,
        patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    ) -> Self {
        let mdns = Arc::new(MdnsResolvers::bind(network, patterns, DHTTP_MDNS_SERVICE).await);
        self.resolvers = self.resolvers.with(mdns);
        self
    }

    #[cfg(feature = "h3x-resolver")]
    pub fn h3<C>(
        self,
        endpoint: Arc<h3x::endpoint::H3Endpoint<C, C::Connection>>,
    ) -> io::Result<Self>
    where
        C: h3x::quic::Connect + Send + Sync + 'static,
        C::Error: Send + Sync + 'static,
        C::Connection: Send + 'static,
    {
        self.h3_with_base_url(DHTTP_H3_DNS_SERVER, endpoint)
    }

    #[cfg(feature = "h3x-resolver")]
    pub fn h3_with_base_url<C>(
        mut self,
        base_url: impl AsRef<str>,
        endpoint: Arc<h3x::endpoint::H3Endpoint<C, C::Connection>>,
    ) -> io::Result<Self>
    where
        C: h3x::quic::Connect + Send + Sync + 'static,
        C::Error: Send + Sync + 'static,
        C::Connection: Send + 'static,
    {
        let resolver = H3Resolver::from_endpoint(base_url, endpoint)?;
        self.resolvers = self.resolvers.with(Arc::new(resolver));
        Ok(self)
    }

    #[cfg(feature = "http-resolver")]
    pub fn http(self) -> io::Result<Self> {
        self.http_with_base_url(DHTTP_HTTP_DNS_SERVER)
    }

    #[cfg(feature = "http-resolver")]
    pub fn http_with_base_url(mut self, base_url: impl AsRef<str>) -> io::Result<Self> {
        let resolver = HttpResolver::new(base_url.as_ref())?;
        self.resolvers = self.resolvers.with(Arc::new(resolver));
        Ok(self)
    }

    pub fn system(mut self) -> Self {
        self.resolvers = self
            .resolvers
            .with(Arc::new(dquic::qresolve::SystemResolver));
        self
    }

    pub fn build(self) -> Resolvers {
        self.resolvers
    }
}

impl Resolvers {
    pub fn builder() -> ResolversBuilder {
        ResolversBuilder::default()
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, resolver: ArcResolver) -> Self {
        self.resolvers.push(resolver);
        self
    }

    pub fn iter(&self) -> impl Iterator<Item = &ArcResolver> {
        self.resolvers.iter()
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
    use std::str::FromStr;

    #[cfg(feature = "mdns-resolver")]
    use super::{DHTTP_MDNS_SERVICE, MdnsResolvers, Resolvers};
    use super::{DnsScheme, resolvable_name};

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

    #[test]
    fn dns_scheme_round_trips_supported_schemes_and_rejects_dht() {
        let cases = [
            ("mdns", DnsScheme::Mdns),
            ("http", DnsScheme::Http),
            ("h3", DnsScheme::H3),
            ("system", DnsScheme::System),
        ];

        for (text, scheme) in cases {
            assert_eq!(DnsScheme::from_str(text).expect("supported scheme"), scheme);
            assert_eq!(scheme.to_string(), text);
        }

        assert!(DnsScheme::from_str("dht").is_err());
    }

    #[cfg(feature = "mdns-resolver")]
    #[tokio::test]
    async fn resolvers_builder_can_enable_mdns() {
        use std::sync::Arc;

        use h3x::dquic::{Network, binds::BindPattern};

        let network = Network::builder().build();
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");

        let resolvers = Resolvers::builder()
            .mdns(network, Arc::new(vec![pattern]))
            .await
            .build();

        assert!(resolvers.to_string().contains("mDNS resolvers"));
    }

    #[cfg(feature = "h3x-resolver")]
    #[tokio::test]
    async fn resolvers_builder_accepts_custom_h3_base_url() {
        use std::sync::Arc;

        let endpoint = Arc::new(h3x::endpoint::H3Endpoint::new(
            h3x::dquic::QuicEndpoint::builder().build().await,
        ));

        let resolvers = Resolvers::builder()
            .h3_with_base_url("https://custom-dns.example:4433", endpoint)
            .expect("valid h3 dns url")
            .build();

        assert!(resolvers.to_string().contains("custom-dns.example"));
    }

    #[cfg(feature = "http-resolver")]
    #[test]
    fn resolvers_builder_accepts_custom_http_base_url() {
        let resolvers = Resolvers::builder()
            .http_with_base_url("https://custom-dns.example")
            .expect("valid http dns url")
            .build();

        assert!(resolvers.to_string().contains("custom-dns.example"));
    }

    #[cfg(feature = "mdns-resolver")]
    #[tokio::test]
    async fn mdns_resolvers_bind_installs_mdns_on_null_io_binding() {
        use std::sync::Arc;

        use dquic::qinterface::io::IO;
        use h3x::dquic::{Network, binds::BindPattern};

        let network = Network::builder().build();
        let pattern = BindPattern::from_str("iface://v4.lo:0").expect("valid pattern");
        let resolvers = MdnsResolvers::bind(
            network.clone(),
            Arc::new(vec![pattern.clone()]),
            DHTTP_MDNS_SERVICE,
        )
        .await;

        let ifaces = resolvers
            .bound_interfaces(&pattern)
            .expect("bound interfaces");
        assert!(!ifaces.is_empty());
        assert!(ifaces[0].borrow().bound_addr().is_err());
        assert!(ifaces[0].with_components(|components, _| components.exist::<gmdns::Mdns>()));
    }
}
