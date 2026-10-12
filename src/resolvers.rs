#[cfg(feature = "resolvers")]
use std::io;
#[cfg(feature = "resolvers")]
use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Display},
    sync::Arc,
};

#[cfg(feature = "resolvers")]
use futures::{
    FutureExt, Stream, StreamExt, TryFutureExt,
    future::BoxFuture,
    stream::{self, FuturesUnordered, SelectAll},
};
#[cfg(feature = "resolvers")]
use qresolve::{EndpointAddr, Family, RecordStream, Resolve, ResolveFuture, Source};

#[cfg(feature = "h3")]
pub use crate::h3::H3Resolver;
#[cfg(feature = "http")]
pub use crate::http::HttpResolver;
#[cfg(feature = "mdns")]
pub use crate::mdns::{MdnsBinding, MdnsResolver, MdnsResolverSet};

pub mod endpoint_candidates;
#[cfg(any(feature = "mdns", test))]
pub(crate) mod endpoint_group;

/// Default DNS-over-H3 server for DHTTP endpoints.
pub const DHTTP_NAME_SERVICE: &str = crate::bootstrap::DHTTP_NAME_SERVICE;
/// Default bootstrap service URL for DHTTP endpoints.
pub const DHTTP_BOOTSTRAP_URL: &str = crate::bootstrap::DHTTP_BOOTSTRAP_URL;
/// mDNS service type used by DHTTP endpoints.
pub const DHTTP_MDNS_SERVICE_DOMAIN: &str = crate::bootstrap::DHTTP_MDNS_SERVICE_DOMAIN;

/// Extract a syntactically valid DNS host, optionally followed by a numeric port.
pub(crate) fn resolvable_name(name: &str) -> Option<&str> {
    let host = match name.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
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
) -> Option<(&str, Option<dhttp_home::certificate::CertificateSequence>)> {
    use dhttp_home::certificate::CertificateSequence;

    let (host, sequence) = match name.rsplit_once(':') {
        Some((host, digits))
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) =>
        {
            (
                host,
                Some(CertificateSequence::try_from(digits.parse::<u64>().ok()?).ok()?),
            )
        }
        _ => (name, None),
    };
    Some((resolvable_name(host)?, sequence))
}

#[cfg(feature = "resolvers")]
type ArcResolver = Arc<dyn Resolve>;
#[cfg(feature = "resolvers")]
type PendingLookup = BoxFuture<'static, (String, io::Result<RecordStream>)>;

#[cfg(feature = "resolvers")]
#[derive(Clone)]
struct ResolverEntry {
    resolver: ArcResolver,
    candidates: Option<endpoint_candidates::ArcEndpointCandidateResolver>,
}

#[cfg(feature = "resolvers")]
impl fmt::Debug for ResolverEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverEntry")
            .field("resolver", &self.resolver.to_string())
            .field("supports_endpoint_candidates", &self.candidates.is_some())
            .finish()
    }
}

#[cfg(feature = "resolvers")]
#[derive(Clone, Default, Debug)]
pub struct Resolvers {
    resolvers: Vec<ResolverEntry>,
}

#[cfg(feature = "resolvers")]
impl Display for Resolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resolvers(")?;
        for (index, entry) in self.resolvers.iter().enumerate() {
            if index != 0 {
                f.write_str(", ")?;
            }
            fmt::Display::fmt(&entry.resolver, f)?;
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
impl ResolversError {
    #[must_use]
    pub fn errors(&self) -> &[(String, io::Error)] {
        &self.errors
    }
}

#[cfg(feature = "resolvers")]
impl fmt::Display for ResolversError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return f.write_str("no DNS resolvers available");
        }
        f.write_str("all DNS resolvers failed")?;
        for (resolver, error) in &self.errors {
            write!(f, "\n  - {resolver}: {error}")?;
            let mut source = error.source();
            let mut index = 1;
            while let Some(error) = source {
                write!(f, "\n    {index}. {error}")?;
                source = error.source();
                index += 1;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "resolvers")]
impl Error for ResolversError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.errors.first().map(|(_, error)| error as _)
    }
}

#[cfg(feature = "resolvers")]
struct LookupState {
    pending: FuturesUnordered<PendingLookup>,
    streams: SelectAll<RecordStream>,
    seen: HashSet<(Source, EndpointAddr)>,
}

#[cfg(feature = "resolvers")]
impl Resolvers {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.push(resolver);
        self
    }

    pub fn push(&mut self, resolver: Arc<dyn Resolve>) {
        self.resolvers.push(ResolverEntry {
            resolver,
            candidates: None,
        });
    }

    #[must_use]
    pub fn with_candidate_resolver<R>(mut self, resolver: Arc<R>) -> Self
    where
        R: endpoint_candidates::ResolveEndpointCandidates + 'static,
    {
        self.push_candidate_resolver(resolver);
        self
    }

    pub fn push_candidate_resolver<R>(&mut self, resolver: Arc<R>)
    where
        R: endpoint_candidates::ResolveEndpointCandidates + 'static,
    {
        self.resolvers.push(ResolverEntry {
            resolver: resolver.clone(),
            candidates: Some(resolver),
        });
    }

    pub async fn lookup_endpoint_candidates(
        &self,
        name: &str,
        lookup: endpoint_candidates::EndpointLookup,
    ) -> Result<endpoint_candidates::EndpointCandidates, ResolversError> {
        let mut errors = Vec::new();
        let pending = self
            .resolvers
            .iter()
            .filter_map(|entry| {
                let Some(resolver) = entry.candidates.clone() else {
                    errors.push((
                        entry.resolver.to_string(),
                        io::Error::other("resolver does not support endpoint candidate lookup"),
                    ));
                    return None;
                };
                let label = entry.resolver.to_string();
                let name = name.to_owned();
                Some(
                    async move {
                        (
                            label,
                            resolver.lookup_endpoint_candidates(&name, lookup).await,
                        )
                    }
                    .boxed(),
                )
            })
            .collect::<FuturesUnordered<_>>();

        let mut groups = Vec::<endpoint_candidates::EndpointCandidateGroup>::new();
        let mut succeeded = false;
        futures::pin_mut!(pending);
        while let Some((label, result)) = pending.next().await {
            match result {
                Ok(candidates) => {
                    succeeded = true;
                    for mut group in candidates.groups {
                        if let Some(existing) = groups.iter_mut().find(|g| g.chain == group.chain) {
                            group
                                .endpoints
                                .retain(|endpoint| !existing.endpoints.contains(endpoint));
                            group
                                .sources
                                .retain(|source| !existing.sources.contains(source));
                            existing.endpoints.extend(group.endpoints);
                            existing.sources.extend(group.sources);
                        } else {
                            groups.push(group);
                        }
                    }
                }
                Err(error) => errors.push((label, error)),
            }
        }

        if !succeeded {
            Err(ResolversError { errors })
        } else {
            Ok(endpoint_candidates::EndpointCandidates { groups })
        }
    }

    pub async fn lookup(
        &self,
        hostname: &str,
        servname: &str,
        family: Option<Family>,
    ) -> Result<impl Stream<Item = (Source, EndpointAddr)> + use<>, ResolversError> {
        let pending = self
            .resolvers
            .iter()
            .map(|entry| {
                let resolver = entry.resolver.clone();
                let hostname = hostname.to_owned();
                let servname = servname.to_owned();
                async move {
                    let label = resolver.to_string();
                    (label, resolver.lookup(&hostname, &servname, family).await)
                }
                .boxed()
            })
            .collect::<FuturesUnordered<_>>();
        let mut state = LookupState {
            pending,
            streams: SelectAll::new(),
            seen: HashSet::new(),
        };
        let mut errors = Vec::new();

        while let Some((label, result)) = state.pending.next().await {
            match result {
                Ok(records) => {
                    state.streams.push(records);
                    return Ok(stream::unfold(state, next_unique_record));
                }
                Err(error) => errors.push((label, error)),
            }
        }
        Err(ResolversError { errors })
    }
}

#[cfg(feature = "resolvers")]
async fn next_unique_record(
    mut state: LookupState,
) -> Option<((Source, EndpointAddr), LookupState)> {
    loop {
        let record = if state.pending.is_empty() {
            state.streams.next().await?
        } else if state.streams.is_empty() {
            match state.pending.next().await {
                Some((_, Ok(records))) => {
                    state.streams.push(records);
                    continue;
                }
                Some((resolver, Err(error))) => {
                    tracing::debug!(%resolver, %error, "DNS resolver failed");
                    continue;
                }
                None => continue,
            }
        } else {
            tokio::select! {
                record = state.streams.next() => match record {
                    Some(record) => record,
                    None => continue,
                },
                result = state.pending.next() => {
                    match result {
                        Some((_, Ok(records))) => state.streams.push(records),
                        Some((resolver, Err(error))) => {
                            tracing::debug!(%resolver, %error, "DNS resolver failed");
                        }
                        None => {}
                    }
                    continue;
                }
            }
        };

        if state.seen.insert(record.clone()) {
            return Some((record, state));
        }
    }
}

#[cfg(feature = "resolvers")]
impl endpoint_candidates::ResolveEndpointCandidates for Resolvers {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: endpoint_candidates::EndpointLookup,
    ) -> endpoint_candidates::EndpointCandidateFuture<'a> {
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
    fn lookup<'a>(
        &'a self,
        hostname: &'a str,
        servname: &'a str,
        family: Option<Family>,
    ) -> ResolveFuture<'a> {
        Resolvers::lookup(self, hostname, servname, family)
            .map_ok(StreamExt::boxed)
            .map_err(io::Error::other)
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_name_and_optional_certificate_sequence() {
        assert!(resolvable_name("127.0.0.1:443").is_none());
        let (name, sequence) = endpoint_lookup_name_and_sequence("demo.dhttp.net:2").unwrap();
        assert_eq!(name, "demo.dhttp.net");
        assert_eq!(sequence.unwrap().get(), 2);
    }

    #[cfg(feature = "resolvers")]
    mod aggregate {
        use super::*;

        #[derive(Debug)]
        struct DuplicateResolver;

        impl fmt::Display for DuplicateResolver {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("duplicate")
            }
        }

        impl Resolve for DuplicateResolver {
            fn lookup<'a>(
                &'a self,
                _hostname: &'a str,
                _servname: &'a str,
                _family: Option<Family>,
            ) -> ResolveFuture<'a> {
                let record = (
                    Source::System,
                    EndpointAddr::direct("192.0.2.1:443".parse().unwrap()),
                );
                async move { Ok(stream::iter([record.clone(), record]).boxed()) }.boxed()
            }
        }

        #[tokio::test]
        async fn standard_lookup_deduplicates_source_and_endpoint_pair() {
            let records = Resolvers::new()
                .with(Arc::new(DuplicateResolver))
                .lookup("demo.dhttp.net", "443", None)
                .await
                .unwrap()
                .collect::<Vec<_>>()
                .await;
            assert_eq!(records.len(), 1);
        }
    }
}
