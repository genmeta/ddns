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
pub(crate) fn resolvable_name(name: &str) -> Option<&str> {
    let host = match name.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => name,
    };
    rustls::pki_types::DnsName::try_from(host).ok()?;
    Some(host)
}

#[cfg_attr(
    not(any(feature = "h3", feature = "http", feature = "mdns")),
    allow(dead_code)
)]
pub(crate) fn endpoint_lookup_name_and_sequence(
    name: &str,
) -> Option<(
    &str,
    Option<dhttp_identity::certificate::CertificateSequence>,
)> {
    use dhttp_identity::certificate::CertificateSequence;

    let (host, sequence) = match name.rsplit_once(':') {
        Some((host, digits))
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) =>
        {
            let sequence = digits.parse::<u64>().ok()?;
            let sequence = CertificateSequence::try_from(sequence).ok()?;
            (host, Some(sequence))
        }
        _ => (name, None),
    };

    Some((resolvable_name(host)?, sequence))
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
pub mod endpoint_candidates;
#[cfg(any(feature = "h3", feature = "mdns", test))]
pub(crate) mod endpoint_group;
pub mod weak;

#[cfg(feature = "resolvers")]
type ArcResolver = Arc<dyn Resolve + Send + Sync + 'static>;

#[cfg(feature = "resolvers")]
#[derive(Clone)]
struct ResolverEntry {
    resolver: ArcResolver,
    endpoint_candidates:
        Option<crate::resolvers::endpoint_candidates::ArcEndpointCandidateResolver>,
}

#[cfg(feature = "resolvers")]
impl fmt::Debug for ResolverEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverEntry")
            .field("resolver", &self.resolver.to_string())
            .field(
                "supports_endpoint_candidates",
                &self.endpoint_candidates.is_some(),
            )
            .finish()
    }
}

#[cfg(feature = "resolvers")]
#[derive(Default, Clone, Debug)]
pub struct Resolvers {
    resolvers: Vec<ResolverEntry>,
}

#[cfg(feature = "resolvers")]
impl Display for Resolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resolvers(")?;
        if self.resolvers.is_empty() {
            f.write_str("empty")?;
        } else {
            for (i, entry) in self.resolvers.iter().enumerate() {
                if i > 0 {
                    f.write_str(", ")?;
                }
                fmt::Display::fmt(entry.resolver.as_ref(), f)?;
            }
        }
        f.write_str(")")
    }
}

#[cfg(feature = "resolvers")]
#[derive(Debug)]
pub struct ResolversError {
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
impl fmt::Display for ResolversError {
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
impl Error for ResolversError {}

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

    pub fn candidate_resolver<R>(mut self, resolver: Arc<R>) -> Self
    where
        R: crate::resolvers::endpoint_candidates::ResolveEndpointCandidates + Send + Sync + 'static,
    {
        self.resolvers.push_candidate_resolver(resolver);
        self
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    pub async fn mdns(
        mut self,
        network: Arc<h3x::dquic::Network>,
        patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    ) -> Self {
        let mdns = Arc::new(MdnsResolvers::bind(network, patterns, DHTTP_MDNS_SERVICE).await);
        self.resolvers.push_candidate_resolver(mdns);
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
        let resolver = Arc::new(H3Resolver::from_endpoint(base_url, endpoint)?);
        self.resolvers.push_candidate_resolver(resolver);
        Ok(self)
    }

    #[cfg(feature = "http")]
    pub fn http(self) -> io::Result<Self> {
        self.http_with_base_url(DHTTP_HTTP_DNS_SERVER)
    }

    #[cfg(feature = "http")]
    pub fn http_with_base_url(mut self, base_url: impl AsRef<str>) -> io::Result<Self> {
        let resolver = Arc::new(HttpResolver::new(base_url.as_ref())?);
        self.resolvers.push_candidate_resolver(resolver);
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

    pub fn with_candidate_resolver<R>(mut self, resolver: Arc<R>) -> Self
    where
        R: crate::resolvers::endpoint_candidates::ResolveEndpointCandidates + Send + Sync + 'static,
    {
        self.push_candidate_resolver(resolver);
        self
    }

    pub fn push(&mut self, resolver: ArcResolver) {
        self.resolvers.push(ResolverEntry {
            resolver,
            endpoint_candidates: None,
        });
    }

    pub fn push_candidate_resolver<R>(&mut self, resolver: Arc<R>)
    where
        R: crate::resolvers::endpoint_candidates::ResolveEndpointCandidates + Send + Sync + 'static,
    {
        let endpoint_candidates =
            Some(resolver.clone()
                as crate::resolvers::endpoint_candidates::ArcEndpointCandidateResolver);
        let resolver = resolver as ArcResolver;
        self.resolvers.push(ResolverEntry {
            resolver,
            endpoint_candidates,
        });
    }

    pub fn iter(&self) -> impl Iterator<Item = &ArcResolver> {
        self.resolvers.iter().map(|entry| &entry.resolver)
    }

    pub async fn lookup_endpoint_candidates(
        &self,
        name: &str,
        lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    ) -> Result<crate::resolvers::endpoint_candidates::EndpointCandidates, ResolversError> {
        let mut errors = vec![];
        let mut groups = Vec::new();

        for entry in self.resolvers.clone() {
            let Some(candidate_resolver) = entry.endpoint_candidates else {
                errors.push((
                    entry.resolver.to_string(),
                    io::Error::other("resolver does not support endpoint candidate lookup"),
                ));
                continue;
            };

            match candidate_resolver
                .lookup_endpoint_candidates(name, lookup)
                .await
            {
                Ok(candidates) => groups.extend(candidates.groups),
                Err(error) => errors.push((entry.resolver.to_string(), error)),
            }
        }

        if groups.is_empty() && !errors.is_empty() {
            return Err(ResolversError { errors });
        }

        Ok(crate::resolvers::endpoint_candidates::EndpointCandidates { groups })
    }

    pub async fn lookup(
        &self,
        name: &str,
    ) -> Result<impl Stream<Item = (Source, EndpointAddr)> + use<>, ResolversError> {
        let mut errors = vec![];

        let mut lookups = stream::FuturesUnordered::from_iter(
            (self.resolvers.clone().into_iter()).map(|entry| {
                let resolver = entry.resolver.clone();
                let name = name.to_string();
                async move { (resolver.lookup(&name).await, resolver.clone()) }
            }),
        );

        let endpoints = loop {
            match lookups.next().await {
                Some((Ok(endpoints), _)) => break endpoints,
                Some((Err(error), resolver)) => errors.push((resolver.to_string(), error)),
                None => return Err(ResolversError { errors }),
            }
        };

        Ok(endpoints.chain(lookups.flat_map(|(endpoints, _)| stream::iter(endpoints).flatten())))
    }
}

#[cfg(feature = "resolvers")]
impl crate::resolvers::endpoint_candidates::ResolveEndpointCandidates for Resolvers {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        async move {
            Resolvers::lookup_endpoint_candidates(self, name, lookup)
                .await
                .map_err(io::Error::other)
        }
        .boxed()
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
    #[cfg(all(feature = "mdns", feature = "dquic-network", feature = "resolvers"))]
    use std::str::FromStr;
    #[cfg(feature = "resolvers")]
    use std::{error::Error as StdError, fmt, io, sync::Arc};

    #[cfg(all(feature = "mdns", feature = "dquic-network", feature = "resolvers"))]
    use super::MdnsResolvers;
    #[cfg(feature = "resolvers")]
    use super::Resolvers;
    use super::{DHTTP_H3_DNS_SERVER, DHTTP_HTTP_DNS_SERVER, DHTTP_MDNS_SERVICE, resolvable_name};
    #[cfg(feature = "resolvers")]
    use super::{DnsScheme, ResolversError};

    #[cfg(feature = "resolvers")]
    #[derive(Debug)]
    struct TestSourceError {
        message: &'static str,
        source: Option<Box<TestSourceError>>,
    }

    #[cfg(feature = "resolvers")]
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

    #[cfg(feature = "resolvers")]
    impl fmt::Display for TestSourceError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.message)
        }
    }

    #[cfg(feature = "resolvers")]
    impl StdError for TestSourceError {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            self.source
                .as_deref()
                .map(|source| source as &(dyn StdError + 'static))
        }
    }

    #[cfg(feature = "resolvers")]
    fn other_error(message: &'static str) -> io::Error {
        io::Error::other(message)
    }

    #[cfg(feature = "resolvers")]
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

    #[test]
    fn endpoint_lookup_name_and_sequence_accepts_plain_name() {
        let (name, sequence) =
            super::endpoint_lookup_name_and_sequence("example.dhttp.net").expect("dns name");

        assert_eq!(name, "example.dhttp.net");
        assert_eq!(sequence, None);
    }

    #[test]
    fn endpoint_lookup_name_and_sequence_parses_numeric_selector() {
        let (name, sequence) =
            super::endpoint_lookup_name_and_sequence("reimu.hakurei.dhttp.net:1")
                .expect("dns name");

        assert_eq!(name, "reimu.hakurei.dhttp.net");
        assert_eq!(
            sequence.map(dhttp_identity::certificate::CertificateSequence::get),
            Some(1)
        );
    }

    #[test]
    fn endpoint_lookup_name_and_sequence_rejects_out_of_range_selector() {
        let invalid = format!("example.dhttp.net:{}", (1u64 << 62) + 1);

        assert_eq!(super::endpoint_lookup_name_and_sequence(&invalid), None);
    }

    #[cfg(feature = "resolvers")]
    #[derive(Debug)]
    struct CandidateResolver {
        label: &'static str,
        sequence: u8,
    }

    #[cfg(feature = "resolvers")]
    impl fmt::Display for CandidateResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.label)
        }
    }

    #[cfg(feature = "resolvers")]
    impl dquic::qresolve::Resolve for CandidateResolver {
        fn lookup<'l>(&'l self, _name: &'l str) -> dquic::qresolve::ResolveFuture<'l> {
            use futures::{FutureExt, StreamExt, stream};
            async { Ok(stream::empty().boxed()) }.boxed()
        }
    }

    #[cfg(feature = "resolvers")]
    impl crate::resolvers::endpoint_candidates::ResolveEndpointCandidates for CandidateResolver {
        fn lookup_endpoint_candidates<'a>(
            &'a self,
            _name: &'a str,
            _lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
        ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
            use dhttp_identity::certificate::{
                CertificateChainKey, CertificateChainKind, CertificateSequence,
            };
            use dquic::qresolve::Source;
            use futures::FutureExt;

            let sequence = self.sequence;
            async move {
                Ok(crate::resolvers::endpoint_candidates::EndpointCandidates {
                    groups: vec![
                        crate::resolvers::endpoint_candidates::EndpointCandidateGroup {
                            chain: CertificateChainKey::new(
                                CertificateSequence::from(sequence),
                                CertificateChainKind::Primary,
                            ),
                            endpoints: Vec::new(),
                            sources: vec![Source::Dht],
                        },
                    ],
                })
            }
            .boxed()
        }
    }

    #[cfg(feature = "resolvers")]
    #[tokio::test]
    async fn aggregate_endpoint_candidates_preserve_resolver_order() {
        let resolvers = Resolvers::new()
            .with_candidate_resolver(Arc::new(CandidateResolver {
                label: "a",
                sequence: 1,
            }))
            .with_candidate_resolver(Arc::new(CandidateResolver {
                label: "b",
                sequence: 0,
            }));

        let candidates = resolvers
            .lookup_endpoint_candidates(
                "demo.dhttp.net",
                crate::resolvers::endpoint_candidates::EndpointLookup::default(),
            )
            .await
            .expect("candidate lookup succeeds");

        assert_eq!(candidates.groups.len(), 2);
        assert_eq!(candidates.groups[0].chain.to_string(), "primary:1");
        assert_eq!(candidates.groups[1].chain.to_string(), "primary:0");
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
    fn resolvers_error_renders_no_resolvers_available_when_empty() {
        let error = ResolversError { errors: vec![] };

        assert_eq!(error.to_string(), "no DNS resolvers available");
    }

    #[cfg(feature = "resolvers")]
    #[test]
    fn resolvers_error_renders_resolver_bullets_in_stored_order() {
        let error = ResolversError {
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
    fn resolvers_error_renders_numbered_source_chain_for_one_resolver() {
        let error = ResolversError {
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
    fn resolvers_error_renders_repeated_source_messages_without_deduplication() {
        let error = ResolversError {
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
