mod if_nametoindex;
mod protocol;
mod service;

use std::{
    collections::HashMap,
    fmt, io,
    net::IpAddr,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use futures::{FutureExt, StreamExt, TryFutureExt, future, stream, stream::FuturesUnordered};
use qresolve::{Family, Resolve, ResolveFuture, Source};
use qtls::LocalAuthority;
pub use service::MdnsResolver;

use crate::resolvers::endpoint_candidates::ResolveEndpointCandidates as _;

const DHTTP_DNS_SUFFIX: &str = "dhttp.net";
const LOCAL_MDNS_SUFFIX: &str = "local";

#[derive(Debug, snafu::Snafu)]
#[snafu(module(mdns_bind_error))]
#[non_exhaustive]
pub enum MdnsBindError {
    #[snafu(display("invalid mDNS service name"))]
    InvalidServiceName,
    #[snafu(display("failed to bind mDNS on {device} at {ip}"))]
    Bind {
        device: String,
        ip: IpAddr,
        source: io::Error,
    },
    #[snafu(display("mDNS resolver set is shut down"))]
    Closed,
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(mdns_publish_error))]
#[non_exhaustive]
pub enum MdnsPublishError {
    #[snafu(display("invalid DNS name"))]
    InvalidName,
    #[snafu(display("publisher identity does not match DNS name"))]
    IdentityNameMismatch,
    #[snafu(display("failed to encode mDNS records"))]
    Encode {
        source: crate::publishers::packet::EncodeAuthorityDnsPacketError,
    },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module(mdns_shutdown_error))]
#[non_exhaustive]
pub enum MdnsShutdownError {
    #[snafu(display("mDNS task failed"))]
    TaskFailed { source: tokio::task::JoinError },
}

fn valid_service_name(name: &str) -> bool {
    name.len() <= 253
        && name.to_ascii_lowercase().ends_with(".local")
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
}

impl MdnsResolver {
    pub async fn bind(
        service_name: impl Into<Arc<str>>,
        device: impl Into<Arc<str>>,
        ip: IpAddr,
    ) -> Result<Self, MdnsBindError> {
        let service_name = service_name.into();
        if !valid_service_name(&service_name) {
            return Err(MdnsBindError::InvalidServiceName);
        }
        let device = device.into();
        service::MdnsResolver::new(service_name, device.clone(), ip).map_err(|source| {
            MdnsBindError::Bind {
                device: device.to_string(),
                ip,
                source,
            }
        })
    }

    pub fn source(&self) -> Source {
        Source::Mdns {
            nic: self.bound_device().into(),
            family: self.family(),
        }
    }

    pub fn family(&self) -> Family {
        match self.bound_ip() {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }

    /// Publish records using the primary certificate sequence of a local TLS authority.
    pub fn publish_endpoints(
        &self,
        identity: &LocalAuthority,
        name: &str,
        endpoints: impl IntoIterator<Item = qresolve::EndpointAddr>,
    ) -> Result<(), MdnsPublishError> {
        dhttp_home::validate_name(name).map_err(|_| MdnsPublishError::InvalidName)?;
        if identity.name() != name {
            return Err(MdnsPublishError::IdentityNameMismatch);
        }
        let mut endpoints = endpoints.into_iter();
        let records =
            crate::publishers::packet::dns_endpoints_for_authority(identity, name, &mut endpoints)
                .map_err(|source| MdnsPublishError::Encode { source })?;
        if records.is_empty() {
            self.remove_name(name);
        } else {
            self.insert_host(name, records);
        }
        Ok(())
    }

    pub fn remove_name(&self, name: &str) {
        self.remove_host(name);
    }

    pub async fn shutdown(&self) -> Result<(), MdnsShutdownError> {
        self.shutdown_tasks()
            .await
            .map_err(|source| MdnsShutdownError::TaskFailed { source })
    }
}

impl fmt::Display for MdnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source(), f)
    }
}

impl Resolve for MdnsResolver {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        _servname: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        if family.is_some_and(|family| family != self.family()) {
            return future::ready(Ok(stream::empty().boxed())).boxed();
        }
        let Some((domain, sequence)) = mdns_lookup_parts(hostname) else {
            return future::ready(Err(io::Error::other("no DNS record found"))).boxed();
        };
        let source = self.source();
        self.query(domain)
            .map_ok(move |records| {
                let endpoints =
                    crate::resolvers::endpoint_group::selected_endpoint_addrs_for_sequence(
                        records, sequence,
                    );
                stream::iter(
                    endpoints
                        .into_iter()
                        .filter(move |endpoint| {
                            crate::resolvers::endpoint_candidates::endpoint_matches_family(
                                endpoint, family,
                            )
                        })
                        .map(move |endpoint| (source.clone(), endpoint)),
                )
                .boxed()
            })
            .boxed()
    }
}

impl crate::resolvers::endpoint_candidates::ResolveEndpointCandidates for MdnsResolver {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        Box::pin(async move {
            let Some((domain, sequence)) = mdns_lookup_parts(name) else {
                return Err(io::Error::other("no DNS record found"));
            };
            let lookup = exact_override(lookup, sequence);
            let source = self.source();
            let records = self.query(domain).await?;
            let tagged = records.into_iter().map(|record| {
                crate::resolvers::endpoint_candidates::TaggedEndpointCandidate {
                    tag: source.clone(),
                    record,
                    fallback_chain_key: None,
                }
            });
            Ok(candidate_groups(tagged, lookup))
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct MdnsBinding {
    device: Arc<str>,
    ip: IpAddr,
}

impl MdnsBinding {
    pub fn new(device: impl Into<Arc<str>>, ip: IpAddr) -> Self {
        Self {
            device: device.into(),
            ip,
        }
    }

    pub fn device(&self) -> &str {
        &self.device
    }

    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    pub fn family(&self) -> Family {
        match self.ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

struct MdnsResolverSetInner {
    service_name: Arc<str>,
    resolvers: RwLock<HashMap<MdnsBinding, Arc<MdnsResolver>>>,
    closed: AtomicBool,
}

#[derive(Clone)]
pub struct MdnsResolverSet(Arc<MdnsResolverSetInner>);

impl MdnsResolverSet {
    pub fn new(service_name: impl Into<Arc<str>>) -> Self {
        Self(Arc::new(MdnsResolverSetInner {
            service_name: service_name.into(),
            resolvers: RwLock::new(HashMap::new()),
            closed: AtomicBool::new(false),
        }))
    }

    pub async fn upsert(&self, binding: MdnsBinding) -> Result<Arc<MdnsResolver>, MdnsBindError> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(MdnsBindError::Closed);
        }
        if let Some(resolver) = self
            .0
            .resolvers
            .read()
            .expect("mDNS resolver set lock poisoned")
            .get(&binding)
            .cloned()
        {
            return Ok(resolver);
        }
        let candidate = Arc::new(
            MdnsResolver::bind(
                self.0.service_name.clone(),
                binding.device.clone(),
                binding.ip,
            )
            .await?,
        );
        enum Race {
            Closed,
            Existing(Arc<MdnsResolver>),
        }
        let race = {
            let mut resolvers = self
                .0
                .resolvers
                .write()
                .expect("mDNS resolver set lock poisoned");
            if self.0.closed.load(Ordering::Acquire) {
                Race::Closed
            } else if let Some(existing) = resolvers.get(&binding) {
                Race::Existing(existing.clone())
            } else {
                resolvers.insert(binding, candidate.clone());
                return Ok(candidate);
            }
        };
        candidate
            .shutdown()
            .await
            .map_err(|error| MdnsBindError::Bind {
                device: binding.device().to_owned(),
                ip: binding.ip(),
                source: io::Error::other(error),
            })?;
        match race {
            Race::Closed => Err(MdnsBindError::Closed),
            Race::Existing(existing) => Ok(existing),
        }
    }

    pub async fn remove(&self, binding: &MdnsBinding) -> Result<bool, MdnsShutdownError> {
        let resolver = self
            .0
            .resolvers
            .write()
            .expect("mDNS resolver set lock poisoned")
            .remove(binding);
        let Some(resolver) = resolver else {
            return Ok(false);
        };
        resolver.shutdown().await?;
        Ok(true)
    }

    pub fn snapshot(&self) -> Vec<Arc<MdnsResolver>> {
        self.0
            .resolvers
            .read()
            .expect("mDNS resolver set lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub async fn shutdown(&self) -> Result<(), MdnsShutdownError> {
        self.0.closed.store(true, Ordering::Release);
        let resolvers = self
            .0
            .resolvers
            .write()
            .expect("mDNS resolver set lock poisoned")
            .drain()
            .map(|(_, resolver)| resolver)
            .collect::<Vec<_>>();
        let mut error = None;
        for resolver in resolvers {
            if let Err(failed) = resolver.shutdown().await {
                error.get_or_insert(failed);
            }
        }
        error.map_or(Ok(()), Err)
    }

    async fn candidates(
        &self,
        name: &str,
        lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    ) -> io::Result<crate::resolvers::endpoint_candidates::EndpointCandidates> {
        let resolvers = self
            .snapshot()
            .into_iter()
            .filter(|resolver| {
                lookup
                    .family()
                    .is_none_or(|family| resolver.family() == family)
            })
            .collect::<Vec<_>>();
        if resolvers.is_empty() {
            return Err(io::Error::other("no mDNS resolvers available"));
        }
        let pending = resolvers
            .into_iter()
            .map(|resolver| {
                let name = name.to_owned();
                async move { resolver.lookup_endpoint_candidates(&name, lookup).await }
            })
            .collect::<FuturesUnordered<_>>();
        let mut groups =
            Vec::<crate::resolvers::endpoint_candidates::EndpointCandidateGroup>::new();
        let mut last_error = None;
        futures::pin_mut!(pending);
        while let Some(result) = pending.next().await {
            match result {
                Ok(candidates) => merge_groups(&mut groups, candidates.groups),
                Err(error) => last_error = Some(error),
            }
        }
        if groups.is_empty() {
            Err(last_error.unwrap_or_else(|| io::Error::other("no DNS record found")))
        } else {
            Ok(crate::resolvers::endpoint_candidates::EndpointCandidates { groups })
        }
    }
}

impl fmt::Debug for MdnsResolverSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResolverSet")
            .field("service_name", &self.0.service_name)
            .field("bindings", &self.snapshot().len())
            .finish()
    }
}

impl fmt::Display for MdnsResolverSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mDNS Resolver Set({})", self.0.service_name)
    }
}

impl Resolve for MdnsResolverSet {
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        _servname: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        if mdns_lookup_parts(hostname).is_none() {
            return future::ready(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "unsupported mDNS name",
            )))
            .boxed();
        }
        let pending = self
            .snapshot()
            .into_iter()
            .filter(|resolver| family.is_none_or(|family| resolver.family() == family))
            .map(|resolver| {
                let hostname = hostname.to_owned();
                async move { resolver.lookup(&hostname, "", family).await }.boxed()
            })
            .collect::<FuturesUnordered<_>>();
        async move {
            let mut pending = pending;
            let mut error = io::Error::new(io::ErrorKind::NotFound, "no mDNS resolvers available");
            while let Some(result) = pending.next().await {
                match result {
                    Ok(first) => {
                        let remaining = pending
                            .filter_map(|result| future::ready(result.ok()))
                            .flatten_unordered(None);
                        return Ok(stream::select(first, remaining).boxed());
                    }
                    Err(failed) => error = failed,
                }
            }
            Err(error)
        }
        .boxed()
    }
}

impl crate::resolvers::endpoint_candidates::ResolveEndpointCandidates for MdnsResolverSet {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    ) -> crate::resolvers::endpoint_candidates::EndpointCandidateFuture<'a> {
        Box::pin(async move { self.candidates(name, lookup).await })
    }
}

fn candidate_groups(
    records: impl IntoIterator<
        Item = crate::resolvers::endpoint_candidates::TaggedEndpointCandidate<Source>,
    >,
    lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
) -> crate::resolvers::endpoint_candidates::EndpointCandidates {
    let groups = crate::resolvers::endpoint_candidates::select_group_pairs(
        crate::resolvers::endpoint_candidates::filter_endpoint_candidate_groups(
            crate::resolvers::endpoint_candidates::grouped_endpoint_candidates(records),
            lookup.family(),
        ),
        lookup.sequences(),
    )
    .into_iter()
    .map(|(chain, tagged)| {
        let mut sources = Vec::new();
        let mut endpoints = Vec::new();
        for (source, endpoint) in tagged {
            if !sources.contains(&source) {
                sources.push(source);
            }
            if !endpoints.contains(&endpoint)
                && endpoints.len()
                    < lookup
                        .record_limit()
                        .map_or(usize::MAX, |limit| limit.get())
            {
                endpoints.push(endpoint);
            }
        }
        crate::resolvers::endpoint_candidates::EndpointCandidateGroup {
            chain,
            endpoints,
            sources,
        }
    })
    .filter(|group| !group.endpoints.is_empty())
    .collect();
    crate::resolvers::endpoint_candidates::EndpointCandidates { groups }
}

fn merge_groups(
    target: &mut Vec<crate::resolvers::endpoint_candidates::EndpointCandidateGroup>,
    groups: Vec<crate::resolvers::endpoint_candidates::EndpointCandidateGroup>,
) {
    for mut group in groups {
        if let Some(existing) = target.iter_mut().find(|item| item.chain == group.chain) {
            group
                .endpoints
                .retain(|endpoint| !existing.endpoints.contains(endpoint));
            group
                .sources
                .retain(|source| !existing.sources.contains(source));
            existing.endpoints.extend(group.endpoints);
            existing.sources.extend(group.sources);
        } else {
            target.push(group);
        }
    }
}

fn exact_override(
    lookup: crate::resolvers::endpoint_candidates::EndpointLookup,
    sequence: Option<dhttp_home::certificate::CertificateSequence>,
) -> crate::resolvers::endpoint_candidates::EndpointLookup {
    sequence.map_or(lookup, |sequence| {
        let mut exact = crate::resolvers::endpoint_candidates::EndpointLookup::exact(sequence)
            .with_family(lookup.family());
        if let Some(limit) = lookup.record_limit() {
            exact = exact.with_record_limit(limit);
        }
        exact
    })
}

fn authority_host(name: &str) -> &str {
    match name.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => name,
    }
}

fn mdns_lookup_parts(
    name: &str,
) -> Option<(&str, Option<dhttp_home::certificate::CertificateSequence>)> {
    let authority = authority_host(name);
    let host = authority.strip_suffix('.').unwrap_or(authority);
    let host = crate::resolvers::resolvable_name(host)?;
    let dhttp = host.eq_ignore_ascii_case(DHTTP_DNS_SUFFIX)
        || host.to_ascii_lowercase().ends_with(".dhttp.net");
    if dhttp {
        crate::resolvers::endpoint_lookup_name_and_sequence(name)
    } else if host.to_ascii_lowercase().ends_with(".local") && host.len() > LOCAL_MDNS_SUFFIX.len()
    {
        Some((host, None))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_and_scope_are_platform_independent_values() {
        let binding = MdnsBinding::new("en0", "192.0.2.1".parse().unwrap());
        assert_eq!(binding.device(), "en0");
        assert_eq!(binding.family(), Family::V4);
        assert!(mdns_lookup_parts("node.dhttp.net:2").is_some());
        assert!(mdns_lookup_parts("printer.local").is_some());
        assert!(mdns_lookup_parts("example.com").is_none());
    }
}
