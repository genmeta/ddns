use std::io;

use dhttp_identity::certificate::{CertificateChainKey, CertificateChainKind};
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

pub type EndpointCandidateFuture<'a> = BoxFuture<'a, io::Result<EndpointCandidates>>;

pub trait ResolveEndpointCandidates: Resolve {
    fn lookup_endpoint_candidates<'a>(&'a self, name: &'a str) -> EndpointCandidateFuture<'a>;
}

pub type ArcEndpointCandidateResolver =
    std::sync::Arc<dyn ResolveEndpointCandidates + Send + Sync + 'static>;

pub(crate) type EndpointCandidateGroups<T> =
    Vec<(CertificateChainKey, Vec<(T, DquicEndpointAddr)>)>;

#[derive(Debug, Clone)]
pub(crate) struct TaggedEndpointCandidate<T> {
    pub(crate) tag: T,
    pub(crate) record: DnsEndpointAddr,
    pub(crate) fallback_chain_key: Option<CertificateChainKey>,
}

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

    groups.sort_by_key(|(chain_key, _)| {
        let primary_rank = match chain_key.kind() {
            CertificateChainKind::Primary => 0,
            CertificateChainKind::Secondary => 1,
        };
        (primary_rank, chain_key.sequence().get())
    });

    groups
}

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
    use std::net::SocketAddrV4;

    use dhttp_identity::certificate::CertificateSequence;

    use super::*;

    fn direct(addr: &str, main: bool, sequence: u32) -> DnsEndpointAddr {
        let socket: SocketAddrV4 = addr.parse().expect("socket addr");
        let mut endpoint = DnsEndpointAddr::direct_v4(socket);
        endpoint.set_main(main);
        endpoint.set_sequence(CertificateSequence::try_from(sequence).unwrap());
        endpoint
    }

    #[test]
    fn grouping_returns_multiple_primary_sequences() {
        let groups = grouped_endpoint_candidates([
            TaggedEndpointCandidate {
                tag: "wifi",
                record: direct("192.0.2.10:4433", true, 0),
                fallback_chain_key: None,
            },
            TaggedEndpointCandidate {
                tag: "ethernet",
                record: direct("192.0.2.20:4433", true, 1),
                fallback_chain_key: None,
            },
            TaggedEndpointCandidate {
                tag: "wifi-backup",
                record: direct("192.0.2.11:4433", true, 0),
                fallback_chain_key: None,
            },
        ]);

        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0.to_string(), "primary:0");
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
