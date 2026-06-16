#[cfg(feature = "resolvers")]
use std::{
    error::Error,
    fmt::{self, Display},
    sync::Arc,
};

#[cfg(feature = "resolvers")]
use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{Resolve, ResolveFuture, Source},
};
#[cfg(feature = "resolvers")]
use futures::{FutureExt, Stream, StreamExt, TryFutureExt, stream};
#[cfg(feature = "resolvers")]
use tokio::io;

#[cfg(feature = "h3")]
pub use crate::h3::H3Resolver;
#[cfg(feature = "http")]
pub use crate::http::HttpResolver;
#[cfg(feature = "mdns")]
pub use crate::mdns::MdnsResolver;
#[cfg(all(feature = "mdns", feature = "dquic-network", feature = "resolvers"))]
use crate::mdns::MdnsResolvers;

/// Extract and validate the DNS host from `name`, which may include a `:port`
/// suffix. Returns `Some(host)` if the host part is a valid RFC-compliant DNS
/// name, or `None` for raw IP addresses, bracketed IPv6, or malformed input.
#[cfg_attr(not(any(feature = "h3", feature = "http")), allow(dead_code))]
pub(crate) fn resolvable_name(name: &str) -> Option<&str> {
    let host = match name.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => name,
    };
    rustls::pki_types::DnsName::try_from(host).ok()?;
    Some(host)
}

/// Default DNS-over-H3 server for DHTTP endpoints.
pub const DHTTP_H3_DNS_SERVER: &str = crate::bootstrap::DHTTP_H3_DNS_SERVER;

/// Default DNS-over-HTTP server for DHTTP endpoints.
pub const DHTTP_HTTP_DNS_SERVER: &str = crate::bootstrap::DHTTP_HTTP_DNS_SERVER;

/// mDNS service type used by DHTTP endpoints.
pub const DHTTP_MDNS_SERVICE: &str = crate::bootstrap::DHTTP_MDNS_SERVICE;

#[cfg(feature = "resolvers")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DnsScheme {
    Mdns,
    Http,
    H3,
    System,
}

#[cfg(feature = "resolvers")]
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

#[cfg(feature = "resolvers")]
#[derive(Debug, snafu::Snafu)]
#[snafu(display("unsupported dns scheme {scheme}"))]
pub struct ParseDnsSchemeError {
    scheme: String,
}

#[cfg(feature = "resolvers")]
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

pub mod deferred;
#[cfg(feature = "mdns")]
pub(crate) mod selector;
pub mod weak;

#[cfg(feature = "resolvers")]
type ArcResolver = Arc<dyn Resolve + Send + Sync + 'static>;

#[cfg(feature = "resolvers")]
#[derive(Default, Clone, Debug)]
pub struct Resolvers {
    resolvers: Vec<ArcResolver>,
}

#[cfg(feature = "resolvers")]
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

#[cfg(feature = "resolvers")]
#[derive(Debug)]
pub struct DnsErrors {
    errors: Vec<(String, io::Error)>,
}

#[cfg(feature = "resolvers")]
fn format_dns_error_sources(
    f: &mut fmt::Formatter<'_>,
    error: &(dyn Error + 'static),
) -> fmt::Result {
    let mut index = 1;
    let mut current = error.source();

    while let Some(source) = current {
        write!(f, "\n    {index}. {source}")?;
        index += 1;
        current = source.source();
    }

    Ok(())
}

#[cfg(feature = "resolvers")]
fn format_dns_error_entry(
    f: &mut fmt::Formatter<'_>,
    resolver: &str,
    error: &io::Error,
) -> fmt::Result {
    write!(f, "\n  - {resolver}: {error}")?;
    format_dns_error_sources(f, error)
}

#[cfg(feature = "resolvers")]
impl fmt::Display for DnsErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "no DNS resolvers available");
        }

        write!(f, "all DNS resolvers failed")?;
        for (resolver, error) in &self.errors {
            format_dns_error_entry(f, resolver, error)?;
        }
        Ok(())
    }
}

#[cfg(feature = "resolvers")]
impl Error for DnsErrors {}

#[cfg(feature = "resolvers")]
#[derive(Default)]
pub struct ResolversBuilder {
    resolvers: Resolvers,
}

#[cfg(feature = "resolvers")]
impl ResolversBuilder {
    pub fn resolver(mut self, resolver: ArcResolver) -> Self {
        self.resolvers.push(resolver);
        self
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    pub async fn mdns(
        mut self,
        network: Arc<h3x::dquic::Network>,
        patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    ) -> Self {
        let mdns: ArcResolver =
            Arc::new(MdnsResolvers::bind(network, patterns, DHTTP_MDNS_SERVICE).await);
        self.resolvers.push(mdns);
        self
    }

    #[cfg(feature = "h3")]
    pub fn h3<C>(
        self,
        endpoint: Arc<h3x::endpoint::H3Endpoint<C, C::Connection>>,
    ) -> io::Result<Self>
    where
        C: h3x::quic::Connect + h3x::quic::WithLocalAuthority + Send + Sync + 'static,
        C::Error: Send + Sync + 'static,
        C::Connection: Send + 'static,
    {
        self.h3_with_base_url(DHTTP_H3_DNS_SERVER, endpoint)
    }

    #[cfg(feature = "h3")]
    pub fn h3_with_base_url<C>(
        mut self,
        base_url: impl AsRef<str>,
        endpoint: Arc<h3x::endpoint::H3Endpoint<C, C::Connection>>,
    ) -> io::Result<Self>
    where
        C: h3x::quic::Connect + h3x::quic::WithLocalAuthority + Send + Sync + 'static,
        C::Error: Send + Sync + 'static,
        C::Connection: Send + 'static,
    {
        let resolver = H3Resolver::from_endpoint(base_url, endpoint)?;
        self.resolvers.push(Arc::new(resolver));
        Ok(self)
    }

    #[cfg(feature = "http")]
    pub fn http(self) -> io::Result<Self> {
        self.http_with_base_url(DHTTP_HTTP_DNS_SERVER)
    }

    #[cfg(feature = "http")]
    pub fn http_with_base_url(mut self, base_url: impl AsRef<str>) -> io::Result<Self> {
        let resolver = HttpResolver::new(base_url.as_ref())?;
        self.resolvers.push(Arc::new(resolver));
        Ok(self)
    }

    pub fn system(mut self) -> Self {
        self.resolvers
            .push(Arc::new(dquic::qresolve::SystemResolver));
        self
    }

    pub fn build(self) -> Resolvers {
        self.resolvers
    }
}

#[cfg(feature = "resolvers")]
impl Resolvers {
    pub fn builder() -> ResolversBuilder {
        ResolversBuilder::default()
    }

    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, resolver: ArcResolver) -> Self {
        self.push(resolver);
        self
    }

    pub fn push(&mut self, resolver: ArcResolver) {
        self.resolvers.push(resolver);
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

#[cfg(feature = "resolvers")]
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
    use std::{error::Error as StdError, fmt, io, str::FromStr};

    #[cfg(all(feature = "mdns", feature = "dquic-network", feature = "resolvers"))]
    use super::MdnsResolvers;
    #[cfg(feature = "resolvers")]
    use super::Resolvers;
    use super::{DHTTP_H3_DNS_SERVER, DHTTP_HTTP_DNS_SERVER, DHTTP_MDNS_SERVICE, resolvable_name};
    #[cfg(feature = "resolvers")]
    use super::{DnsErrors, DnsScheme};

    #[derive(Debug)]
    struct TestSourceError {
        message: &'static str,
        source: Option<Box<TestSourceError>>,
    }

    impl TestSourceError {
        fn leaf(message: &'static str) -> Self {
            Self {
                message,
                source: None,
            }
        }

        fn with_source(message: &'static str, source: TestSourceError) -> Self {
            Self {
                message,
                source: Some(Box::new(source)),
            }
        }
    }

    impl fmt::Display for TestSourceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message)
        }
    }

    impl StdError for TestSourceError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.source
                .as_deref()
                .map(|source| source as &(dyn StdError + 'static))
        }
    }

    fn other_error(message: &'static str) -> io::Error {
        io::Error::other(message)
    }

    fn chained_other_error(root: TestSourceError) -> io::Error {
        io::Error::other(root)
    }

    #[test]
    fn resolver_defaults_come_from_compile_time_environment() {
        if let Some(expected) = option_env!("DHTTP_H3_DNS_SERVER") {
            assert_eq!(DHTTP_H3_DNS_SERVER, expected);
        }
        if let Some(expected) = option_env!("DHTTP_HTTP_DNS_SERVER") {
            assert_eq!(DHTTP_HTTP_DNS_SERVER, expected);
        }
        if let Some(expected) = option_env!("DHTTP_MDNS_SERVICE") {
            assert_eq!(DHTTP_MDNS_SERVICE, expected);
        }
    }

    #[test]
    fn resolvable_name_accepts_dns_name_with_numeric_port() {
        assert_eq!(
            resolvable_name("example.dhttp.net:443"),
            Some("example.dhttp.net")
        );
    }

    #[test]
    fn resolvable_name_accepts_stun_authority_with_numeric_port() {
        assert_eq!(
            resolvable_name("nat.genmeta.net:20004"),
            Some("nat.genmeta.net")
        );
    }

    #[test]
    fn resolvable_name_rejects_ip_literals() {
        assert_eq!(resolvable_name("127.0.0.1:443"), None);
        assert_eq!(resolvable_name("[::1]:443"), None);
    }

    #[cfg(feature = "resolvers")]
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

    #[cfg(feature = "resolvers")]
    #[test]
    fn dns_errors_render_no_resolvers_available_when_empty() {
        let error = DnsErrors { errors: vec![] };

        assert_eq!(error.to_string(), "no DNS resolvers available");
    }

    #[cfg(feature = "resolvers")]
    #[test]
    fn dns_errors_render_resolver_bullets_in_stored_order() {
        let error = DnsErrors {
            errors: vec![
                (
                    "System DNS Resolver".to_string(),
                    other_error("invalid socket address"),
                ),
                ("mDNS resolvers".to_string(), other_error("timed out")),
            ],
        };

        assert_eq!(
            error.to_string(),
            concat!(
                "all DNS resolvers failed\n",
                "  - System DNS Resolver: invalid socket address\n",
                "  - mDNS resolvers: timed out"
            )
        );
    }

    #[cfg(feature = "resolvers")]
    #[test]
    fn dns_errors_render_numbered_source_chain_for_one_resolver() {
        let error = DnsErrors {
            errors: vec![(
                "DeferredResolver(H3 DNS Resolver(https://dns.genmeta.net:4433/))".to_string(),
                chained_other_error(TestSourceError::with_source(
                    "deferred resolver lookup failed",
                    TestSourceError::leaf("no DNS record found"),
                )),
            )],
        };

        assert_eq!(
            error.to_string(),
            concat!(
                "all DNS resolvers failed\n",
                "  - DeferredResolver(H3 DNS Resolver(https://dns.genmeta.net:4433/)): deferred resolver lookup failed\n",
                "    1. no DNS record found"
            )
        );
    }

    #[cfg(feature = "resolvers")]
    #[test]
    fn dns_errors_render_repeated_source_messages_without_deduplication() {
        let error = DnsErrors {
            errors: vec![(
                "DeferredResolver(H3 DNS Resolver(https://dns.genmeta.net:4433/))".to_string(),
                chained_other_error(TestSourceError::with_source(
                    "deferred resolver lookup failed",
                    TestSourceError::with_source(
                        "deferred resolver lookup failed",
                        TestSourceError::leaf("no DNS record found"),
                    ),
                )),
            )],
        };

        assert_eq!(
            error.to_string(),
            concat!(
                "all DNS resolvers failed\n",
                "  - DeferredResolver(H3 DNS Resolver(https://dns.genmeta.net:4433/)): deferred resolver lookup failed\n",
                "    1. deferred resolver lookup failed\n",
                "    2. no DNS record found"
            )
        );
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network", feature = "resolvers"))]
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

    #[cfg(all(feature = "h3", feature = "resolvers", feature = "dquic-network"))]
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

    #[cfg(all(feature = "http", feature = "resolvers"))]
    #[test]
    fn resolvers_builder_accepts_custom_http_base_url() {
        let resolvers = Resolvers::builder()
            .http_with_base_url("https://custom-dns.example")
            .expect("valid http dns url")
            .build();

        assert!(resolvers.to_string().contains("custom-dns.example"));
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network", feature = "resolvers"))]
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
        if ifaces.is_empty() {
            return;
        }
        assert!(ifaces[0].borrow().bound_addr().is_err());
        assert!(
            ifaces[0]
                .with_components(|components, _| components.exist::<crate::mdns::service::Mdns>())
        );
    }
}
