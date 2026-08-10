mod if_nametoindex;
mod protocol;
pub mod service;

use std::{fmt, io, net::IpAddr};
#[cfg(feature = "dquic-network")]
use std::{net::SocketAddr, sync::Arc};

#[cfg(feature = "dquic-network")]
use dquic::qresolve::RecordStream;
use dquic::{
    qbase::net::Family,
    qresolve::{Publish, PublishFuture, Resolve, ResolveFuture, Source},
};
use futures::{FutureExt, StreamExt, TryFutureExt, future, stream};
#[cfg(feature = "dquic-network")]
use futures::{Stream, stream::FuturesUnordered};

#[cfg(feature = "dquic-network")]
use crate::core::parser::packet::Packet;

pub type MdnsResolver = service::Mdns;
pub type MdnsPublisher = service::Mdns;

const DHTTP_DNS_SUFFIX: &str = "dhttp.net";
const LOCAL_MDNS_SUFFIX: &str = "local";

/// Return the host portion while treating only a numeric suffix as a port.
fn authority_host(name: &str) -> &str {
    match name.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => name,
    }
}

/// Validate and normalize the host used for mDNS scope checks.
fn normalized_authority_host(name: &str) -> Option<&str> {
    let authority_host = authority_host(name);
    let host = authority_host.strip_suffix('.').unwrap_or(authority_host);
    crate::resolvers::resolvable_name(host)
}

/// Return whether a validated host is within the DHTTP DNS suffix.
fn is_dhttp_authority_host(host: &str) -> bool {
    host.eq_ignore_ascii_case(DHTTP_DNS_SUFFIX)
        || host.len() > DHTTP_DNS_SUFFIX.len()
            && host.as_bytes()[host.len() - DHTTP_DNS_SUFFIX.len() - 1] == b'.'
            && host[host.len() - DHTTP_DNS_SUFFIX.len()..].eq_ignore_ascii_case(DHTTP_DNS_SUFFIX)
}

/// Return whether a validated host ends in the standard local mDNS label.
fn is_local_mdns_host(host: &str) -> bool {
    host.len() > LOCAL_MDNS_SUFFIX.len()
        && host.as_bytes()[host.len() - LOCAL_MDNS_SUFFIX.len() - 1] == b'.'
        && host[host.len() - LOCAL_MDNS_SUFFIX.len()..].eq_ignore_ascii_case(LOCAL_MDNS_SUFFIX)
}

/// Parse DHTTP sequence semantics or a plain local mDNS authority.
fn mdns_lookup_parts(
    name: &str,
) -> Option<(
    &str,
    Option<dhttp_identity::certificate::CertificateSequence>,
)> {
    let host = normalized_authority_host(name)?;
    if is_dhttp_authority_host(host) {
        return crate::resolvers::endpoint_lookup_name_and_sequence(name);
    }
    is_local_mdns_host(host).then_some((host, None))
}

impl MdnsResolver {
    pub fn source(&self) -> Source {
        Source::Mdns {
            nic: self.bound_nic().into(),
            family: match self.bound_ip() {
                IpAddr::V4(..) => Family::V4,
                IpAddr::V6(..) => Family::V6,
            },
        }
    }
}

impl fmt::Display for MdnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source(), f)
    }
}

impl Publish for MdnsPublisher {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = dquic::qbase::net::addr::EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints = match mdns_endpoints_from_dquic(endpoints) {
            Ok(endpoints) => endpoints,
            Err(error) => return future::ready(Err(error)).boxed(),
        };
        self.insert_host(name.to_string(), endpoints);
        future::ready(Ok(())).boxed()
    }
}

impl Resolve for MdnsResolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let source = self.source();
        let Some((domain, sequence)) = mdns_lookup_parts(name) else {
            return future::ready(Err(io::Error::other("no DNS record found"))).boxed();
        };
        self.query(domain.to_owned())
            .map_ok(move |list| {
                let endpoints =
                    crate::resolvers::endpoint_group::selected_endpoint_addrs_for_sequence(
                        list, sequence,
                    );
                stream::iter(endpoints.into_iter().map(move |ep| (source.clone(), ep))).boxed()
            })
            .boxed()
    }
}

fn mdns_endpoints_from_dquic(
    endpoints: &mut dyn Iterator<Item = dquic::qbase::net::addr::EndpointAddr>,
) -> io::Result<Vec<crate::core::MdnsEndpoint>> {
    let mut records = Vec::new();
    for endpoint in endpoints {
        let endpoint = crate::core::parser::record::endpoint::EndpointAddr::try_from(endpoint)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to encode endpoint address",
                )
            })?;
        records.push(endpoint);
    }
    Ok(records)
}

#[cfg(feature = "dquic-network")]
/// Installs mDNS resources on concrete h3x interface bindings.
pub struct MdnsBindDriver {
    /// Creates and manages each concrete binding interface.
    iface_manager: Arc<h3x::dquic::net::InterfaceManager>,

    /// Reuses h3x binding lifecycle without using its packet I/O.
    null_io_factory: Arc<h3x::dquic::NullIoFactory>,

    /// Service name published and queried by bindings from this driver.
    service_name: Arc<str>,
}

#[cfg(feature = "dquic-network")]
impl MdnsBindDriver {
    pub fn new(service_name: impl Into<Arc<str>>) -> Self {
        Self {
            iface_manager: Arc::new(h3x::dquic::net::InterfaceManager::new()),
            null_io_factory: Arc::new(h3x::dquic::NullIoFactory),
            service_name: service_name.into(),
        }
    }

    fn install_or_rebind_mdns(
        &self,
        network: &h3x::dquic::Network,
        bind_iface: &h3x::dquic::net::BindInterface,
    ) {
        let bind_uri = bind_iface.bind_uri();
        let Some((family, device, _port)) = bind_uri.as_iface_bind_uri() else {
            tracing::debug!(%bind_uri, "skipping mdns binding for non-interface bind uri");
            return;
        };
        let Some(ip) = network.resolve_device_addr(device, family) else {
            tracing::debug!(%bind_uri, "skipping mdns binding without local interface address");
            return;
        };

        bind_iface.with_components_mut(|components, _iface| {
            match components.try_init_with(|| service::Mdns::new(&self.service_name, ip, device)) {
                Ok(mdns) => mdns.reinit_on(device, ip),
                Err(error) => {
                    let report = snafu::Report::from_error(&error);
                    tracing::debug!(error = %report, %bind_uri, "failed to initialize mdns binding");
                }
            }
        });
    }
}

#[cfg(feature = "dquic-network")]
impl h3x::dquic::BindDriver for MdnsBindDriver {
    fn bind<'a>(
        &'a self,
        network: &'a h3x::dquic::Network,
        uri: h3x::dquic::net::BindUri,
    ) -> futures::future::BoxFuture<'a, h3x::dquic::net::BindInterface> {
        async move {
            let iface = self
                .iface_manager
                .bind(uri, self.null_io_factory.clone())
                .await;
            self.install_or_rebind_mdns(network, &iface);
            iface
        }
        .boxed()
    }

    fn rebind<'a>(
        &'a self,
        network: &'a h3x::dquic::Network,
        iface: &'a h3x::dquic::net::BindInterface,
    ) -> futures::future::BoxFuture<'a, ()> {
        async move {
            self.install_or_rebind_mdns(network, iface);
        }
        .boxed()
    }
}

#[cfg(feature = "dquic-network")]
/// Aggregates concrete mDNS resolvers for a set of bind patterns.
pub struct MdnsResolvers {
    /// Owns the bind registry and current interface snapshot.
    network: Arc<h3x::dquic::Network>,

    /// Provides the identity used to share and locate bindings.
    driver: Arc<MdnsBindDriver>,

    /// Enumerates the concrete bindings exposed by this resolver set.
    patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,

    /// Keeps each `(driver, pattern, LanMulticast)` registration alive.
    _handles: Vec<h3x::dquic::BindHandle>,
}

#[cfg(feature = "dquic-network")]
#[derive(Debug, Clone)]
pub struct BoundMdnsResolver {
    pub device: String,
    pub family: Family,
    pub resolver: MdnsResolver,
}

#[cfg(feature = "dquic-network")]
impl fmt::Debug for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResolvers")
            .field("patterns", &self.patterns)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dquic-network")]
impl fmt::Display for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mDNS resolvers")
    }
}

#[cfg(feature = "dquic-network")]
impl MdnsResolvers {
    pub async fn bind(
        network: Arc<h3x::dquic::Network>,
        patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
        service_name: impl Into<Arc<str>>,
    ) -> Self {
        let driver = Arc::new(MdnsBindDriver::new(service_name));
        Self::bind_with_driver(network, patterns, driver).await
    }

    /// Register mDNS patterns through a caller-owned driver so equal bindings can be shared.
    pub async fn bind_with_driver(
        network: Arc<h3x::dquic::Network>,
        patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
        driver: Arc<MdnsBindDriver>,
    ) -> Self {
        let mut handles = Vec::with_capacity(patterns.len());
        for pattern in patterns.iter() {
            handles.push(
                network
                    .bind_with_policy(
                        driver.clone(),
                        pattern.clone(),
                        h3x::dquic::WildcardInterfacePolicy::LanMulticast,
                    )
                    .await,
            );
        }

        Self {
            network,
            driver,
            patterns,
            _handles: handles,
        }
    }

    pub fn bound_interfaces(
        &self,
        pattern: &h3x::dquic::binds::BindPattern,
    ) -> Option<Vec<h3x::dquic::net::BindInterface>> {
        self.network.get_interfaces_with_policy(
            &self.driver,
            pattern,
            h3x::dquic::WildcardInterfacePolicy::LanMulticast,
        )
    }

    fn for_each_resolver(&self, mut f: impl FnMut(&MdnsResolver)) {
        for pattern in self.patterns.iter() {
            let Some(ifaces) = self.bound_interfaces(pattern) else {
                continue;
            };
            for iface in ifaces {
                iface.with_components(|components, _| {
                    if let Some(mdns) = components.get::<MdnsResolver>() {
                        f(mdns);
                    }
                });
            }
        }
    }

    pub fn bound_resolvers(&self) -> Vec<BoundMdnsResolver> {
        let mut resolvers = Vec::new();
        for pattern in self.patterns.iter() {
            let Some(ifaces) = self.bound_interfaces(pattern) else {
                continue;
            };
            for iface in ifaces {
                let bind_uri = iface.bind_uri();
                let Some((family, device, _port)) = bind_uri.as_iface_bind_uri() else {
                    continue;
                };
                iface.with_components(|components, _| {
                    if let Some(resolver) = components.get::<MdnsResolver>() {
                        resolvers.push(BoundMdnsResolver {
                            device: device.to_owned(),
                            family,
                            resolver: resolver.clone(),
                        });
                    }
                });
            }
        }
        resolvers
    }

    pub async fn query(&self, name: &str) -> io::Result<RecordStream> {
        self.query_with_sequence(name, None).await
    }

    pub async fn query_with_sequence(
        &self,
        name: &str,
        sequence: Option<dhttp_identity::certificate::CertificateSequence>,
    ) -> io::Result<RecordStream> {
        let mut lookup_futures = FuturesUnordered::new();
        let mut has_resolver = false;
        self.for_each_resolver(|resolver| {
            has_resolver = true;
            let source = resolver.source();
            lookup_futures.push(
                resolver
                    .query(name.to_owned())
                    .map_ok(move |eps| (source, eps)),
            );
        });
        if !has_resolver {
            return Err(io::Error::other("no mdns resolvers available"));
        }

        let mut last_error = None;
        let mut has_success = false;
        let mut records = Vec::new();
        while let Some(result) = lookup_futures.next().await {
            match result {
                Ok((source, endpoints)) => {
                    has_success = true;
                    records.extend(
                        endpoints
                            .into_iter()
                            .map(|endpoint| (source.clone(), endpoint)),
                    );
                }
                Err(error) => last_error = Some(error),
            }
        }

        if !has_success {
            return Err(
                last_error.unwrap_or_else(|| io::Error::other("no mdns resolvers available"))
            );
        }

        let records = crate::resolvers::endpoint_group::selected_endpoint_records_for_sequence(
            records, sequence,
        );

        Ok(stream::iter(records).boxed())
    }

    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> + use<> {
        let streams = self
            .bound_resolvers()
            .into_iter()
            .map(|bound| Box::pin(bound.resolver.discover()))
            .collect::<Vec<_>>();
        stream::select_all(streams)
    }
}

#[cfg(feature = "dquic-network")]
fn select_candidate_groups(
    groups: Vec<crate::resolvers::endpoint_candidates::EndpointCandidateGroup>,
    query: crate::resolvers::endpoint_candidates::SequenceQuery,
) -> Vec<crate::resolvers::endpoint_candidates::EndpointCandidateGroup> {
    use crate::resolvers::endpoint_candidates::SequenceQuery;

    match query {
        SequenceQuery::Default => groups.into_iter().take(3).collect(),
        SequenceQuery::Exact(sequence) => groups
            .into_iter()
            .filter(|group| group.chain.sequence() == sequence)
            .collect(),
        SequenceQuery::Limit(limit) => groups.into_iter().take(limit.get()).collect(),
        SequenceQuery::All => groups,
    }
}

#[cfg(feature = "dquic-network")]
impl crate::resolvers::endpoint_candidates::ResolveEndpointCandidates for MdnsResolvers {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        Box::pin(async move {
            let Some((domain, sequence)) = mdns_lookup_parts(name) else {
                return Err(io::Error::other("no DNS record found"));
            };
            let lookup = sequence
                .map(crate::resolvers::endpoint_candidates::EndpointLookup::exact)
                .unwrap_or(lookup);

            let mut lookup_futures = FuturesUnordered::new();
            let mut has_resolver = false;
            self.for_each_resolver(|resolver| {
                has_resolver = true;
                let source = resolver.source();
                lookup_futures.push(
                    resolver
                        .query(domain.to_owned())
                        .map_ok(move |eps| (source, eps)),
                );
            });
            if !has_resolver {
                return Err(io::Error::other("no mdns resolvers available"));
            }

            let mut last_error = None;
            let mut records = Vec::new();
            while let Some(result) = lookup_futures.next().await {
                match result {
                    Ok((source, endpoints)) => {
                        records.extend(endpoints.into_iter().map(|record| {
                            crate::resolvers::endpoint_candidates::TaggedEndpointCandidate {
                                tag: source.clone(),
                                record,
                                fallback_chain_key: None,
                            }
                        }));
                    }
                    Err(error) => last_error = Some(error),
                }
            }

            if records.is_empty() {
                return Err(last_error.unwrap_or_else(|| io::Error::other("no DNS record found")));
            }

            let groups =
                crate::resolvers::endpoint_candidates::grouped_endpoint_candidates(records)
                    .into_iter()
                    .map(|(chain, tagged)| {
                        let mut sources = Vec::new();
                        let mut endpoints = Vec::new();
                        for (source, endpoint) in tagged {
                            if !sources.contains(&source) {
                                sources.push(source);
                            }
                            endpoints.push(endpoint);
                        }
                        crate::resolvers::endpoint_candidates::EndpointCandidateGroup {
                            chain,
                            endpoints,
                            sources,
                        }
                    })
                    .collect();
            let groups = select_candidate_groups(groups, lookup.sequences);

            Ok(crate::resolvers::endpoint_candidates::EndpointCandidates { groups })
        })
    }
}

#[cfg(feature = "dquic-network")]
impl Publish for MdnsResolvers {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = dquic::qbase::net::addr::EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints = match mdns_endpoints_from_dquic(endpoints) {
            Ok(endpoints) => endpoints,
            Err(error) => return future::ready(Err(error)).boxed(),
        };

        self.for_each_resolver(|resolver| {
            resolver.insert_host(name.to_string(), endpoints.clone());
        });

        future::ready(Ok(())).boxed()
    }
}

#[cfg(feature = "dquic-network")]
impl Resolve for MdnsResolvers {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let Some((domain, sequence)) = mdns_lookup_parts(name) else {
            return future::ready(Err(io::Error::other("no DNS record found"))).boxed();
        };
        self.query_with_sequence(domain, sequence).boxed()
    }
}

#[cfg(all(test, feature = "dquic-network"))]
mod tests {
    use std::num::NonZeroUsize;

    use dhttp_identity::certificate::CertificateSequence;

    use super::*;
    use crate::resolvers::endpoint_candidates::{
        EndpointCandidateGroup, EndpointLookup, SequenceQuery,
    };

    fn group(sequence: u8) -> EndpointCandidateGroup {
        EndpointCandidateGroup {
            chain: crate::core::certificate::primary_chain_key(CertificateSequence::from(sequence)),
            endpoints: Vec::new(),
            sources: Vec::new(),
        }
    }

    #[test]
    fn mdns_candidate_selection_applies_sequence_query_locally() {
        let groups = || vec![group(2), group(1), group(3), group(4)];
        let sequences = |groups: Vec<EndpointCandidateGroup>| {
            groups
                .into_iter()
                .map(|group| group.chain.sequence().get())
                .collect::<Vec<_>>()
        };

        assert_eq!(
            sequences(select_candidate_groups(groups(), SequenceQuery::Default)),
            vec![2, 1, 3]
        );
        assert_eq!(
            sequences(select_candidate_groups(
                groups(),
                SequenceQuery::Limit(NonZeroUsize::new(2).unwrap()),
            )),
            vec![2, 1]
        );
        assert_eq!(
            sequences(select_candidate_groups(
                groups(),
                SequenceQuery::Exact(CertificateSequence::from(3u8)),
            )),
            vec![3]
        );
        assert_eq!(
            sequences(select_candidate_groups(groups(), SequenceQuery::All)),
            vec![2, 1, 3, 4]
        );

        let lookup = EndpointLookup::all().with_record_limit(NonZeroUsize::new(1).unwrap());
        assert_eq!(
            sequences(select_candidate_groups(groups(), lookup.sequences)),
            vec![2, 1, 3, 4]
        );
    }

    #[test]
    fn mdns_lookup_scope_accepts_only_dhttp_and_local_names() {
        assert_eq!(
            mdns_lookup_parts("printer.local"),
            Some(("printer.local", None))
        );
        assert_eq!(
            mdns_lookup_parts("Printer.LOCAL.:8080"),
            Some(("Printer.LOCAL", None))
        );

        let (name, sequence) =
            mdns_lookup_parts("node.dhttp.net:2").expect("DHTTP endpoint is in scope");
        assert_eq!(name, "node.dhttp.net");
        assert_eq!(sequence, Some(CertificateSequence::from(2u8)));

        for name in [
            "nat.genmeta.net",
            "notlocal",
            "printer.notlocal",
            "local.example",
            "127.0.0.1",
            "[::1]:443",
        ] {
            assert_eq!(
                mdns_lookup_parts(name),
                None,
                "unexpected mDNS scope: {name}"
            );
        }
    }
}
