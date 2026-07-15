use std::{io, num::NonZeroUsize};

use dhttp_identity::certificate::{CertificateChainKey, CertificateSequence};
use dquic::{
    qbase::net::addr::EndpointAddr as DquicEndpointAddr,
    qresolve::{Resolve, Source},
};
use futures::future::BoxFuture;

use crate::core::parser::record::endpoint::EndpointAddr as DnsEndpointAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCandidateGroup {
    pub chain: CertificateChainKey,
    pub endpoints: Vec<DquicEndpointAddr>,
    pub sources: Vec<Source>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EndpointCandidates {
    pub groups: Vec<EndpointCandidateGroup>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SequenceQuery {
    #[default]
    Default,
    Exact(CertificateSequence),
    Limit(NonZeroUsize),
    All,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EndpointLookup {
    pub sequences: SequenceQuery,
    pub record_limit: Option<NonZeroUsize>,
}

impl EndpointLookup {
    #[must_use]
    pub fn exact(sequence: CertificateSequence) -> Self {
        Self {
            sequences: SequenceQuery::Exact(sequence),
            record_limit: None,
        }
    }

    #[must_use]
    pub fn limit(count: NonZeroUsize) -> Self {
        Self {
            sequences: SequenceQuery::Limit(count),
            record_limit: None,
        }
    }

    #[must_use]
    pub fn all() -> Self {
        Self {
            sequences: SequenceQuery::All,
            record_limit: None,
        }
    }

    #[must_use]
    pub fn with_record_limit(mut self, count: NonZeroUsize) -> Self {
        self.record_limit = Some(count);
        self
    }
}

pub type EndpointCandidateFuture<'a> = BoxFuture<'a, io::Result<EndpointCandidates>>;

pub trait ResolveEndpointCandidates: Resolve {
    fn lookup_endpoint_candidates<'a>(
        &'a self,
        name: &'a str,
        lookup: EndpointLookup,
    ) -> EndpointCandidateFuture<'a>;
}

pub type ArcEndpointCandidateResolver =
    std::sync::Arc<dyn ResolveEndpointCandidates + Send + Sync + 'static>;

#[cfg_attr(
    not(any(feature = "h3", feature = "http", feature = "mdns", test)),
    allow(dead_code)
)]
pub(crate) type EndpointCandidateGroups<T> =
    Vec<(CertificateChainKey, Vec<(T, DquicEndpointAddr)>)>;

#[cfg_attr(
    not(any(feature = "h3", feature = "http", feature = "mdns", test)),
    allow(dead_code)
)]
#[derive(Debug, Clone)]
pub(crate) struct TaggedEndpointCandidate<T> {
    pub(crate) tag: T,
    pub(crate) record: DnsEndpointAddr,
    pub(crate) fallback_chain_key: Option<CertificateChainKey>,
}

#[cfg_attr(
    not(any(feature = "h3", feature = "http", feature = "mdns", test)),
    allow(dead_code)
)]
pub(crate) fn grouped_endpoint_candidates<T>(
    records: impl IntoIterator<Item = TaggedEndpointCandidate<T>>,
) -> EndpointCandidateGroups<T> {
    let mut groups: Vec<(CertificateChainKey, Vec<(T, DquicEndpointAddr)>)> = Vec::new();

    for TaggedEndpointCandidate {
        tag,
        record,
        fallback_chain_key,
    } in records
    {
        let chain_key = effective_chain_key(&record, fallback_chain_key);
        let Ok(endpoint) = DquicEndpointAddr::try_from(record) else {
            continue;
        };

        if let Some((_key, endpoints)) = groups.iter_mut().find(|(key, _)| *key == chain_key) {
            endpoints.push((tag, endpoint));
        } else {
            groups.push((chain_key, vec![(tag, endpoint)]));
        }
    }

    groups
}

#[cfg_attr(
    not(any(feature = "h3", feature = "http", feature = "mdns", test)),
    allow(dead_code)
)]
fn effective_chain_key(
    record: &DnsEndpointAddr,
    fallback_chain_key: Option<CertificateChainKey>,
) -> CertificateChainKey {
    if record.is_main() || record.sequence().is_some() {
        return record.certificate_chain_key();
    }

    fallback_chain_key.unwrap_or_else(|| record.certificate_chain_key())
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddrV4, num::NonZeroUsize};

    use dhttp_identity::certificate::{CertificateChainKind, CertificateSequence};

    use super::*;

    #[test]
    fn endpoint_lookup_constructors_encode_valid_states() {
        let one = NonZeroUsize::new(1).unwrap();
        let exact = CertificateSequence::from(2u8);

        assert_eq!(EndpointLookup::default().sequences, SequenceQuery::Default);
        assert_eq!(
            EndpointLookup::exact(exact).sequences,
            SequenceQuery::Exact(exact)
        );
        assert_eq!(
            EndpointLookup::limit(one).sequences,
            SequenceQuery::Limit(one)
        );
        assert_eq!(EndpointLookup::all().sequences, SequenceQuery::All);
        assert_eq!(
            EndpointLookup::all().with_record_limit(one).record_limit,
            Some(one)
        );
    }

    fn direct(addr: &str, main: bool, sequence: u32) -> DnsEndpointAddr {
        let socket: SocketAddrV4 = addr.parse().expect("socket addr");
        let mut endpoint = DnsEndpointAddr::direct_v4(socket);
        endpoint.set_main(main);
        endpoint.set_sequence(CertificateSequence::try_from(sequence).unwrap());
        endpoint
    }

    #[test]
    fn grouping_preserves_input_order_between_primary_sequences() {
        let groups = grouped_endpoint_candidates([
            TaggedEndpointCandidate {
                tag: "wifi",
                record: direct("192.0.2.10:4433", true, 2),
                fallback_chain_key: None,
            },
            TaggedEndpointCandidate {
                tag: "ethernet",
                record: direct("192.0.2.20:4433", true, 1),
                fallback_chain_key: None,
            },
            TaggedEndpointCandidate {
                tag: "wifi-backup",
                record: direct("192.0.2.11:4433", true, 2),
                fallback_chain_key: None,
            },
        ]);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0.to_string(), "primary:2");
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].0.to_string(), "primary:1");
        assert_eq!(groups[1].1.len(), 1);
    }

    #[test]
    fn grouping_uses_fallback_chain_key_for_unmarked_endpoint() {
        let endpoint = DnsEndpointAddr::direct_v4("192.0.2.60:4433".parse().unwrap());
        let groups = grouped_endpoint_candidates([TaggedEndpointCandidate {
            tag: "h3",
            record: endpoint,
            fallback_chain_key: Some(CertificateChainKey::new(
                CertificateSequence::from(3u8),
                CertificateChainKind::Primary,
            )),
        }]);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].0.to_string(), "primary:3");
        assert_eq!(groups[0].1[0].0, "h3");
    }
}
