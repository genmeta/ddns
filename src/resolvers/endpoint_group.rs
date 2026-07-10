use dhttp_identity::certificate::{CertificateChainKey, CertificateChainKind, CertificateSequence};
use dquic::qbase::net::addr::EndpointAddr as DquicEndpointAddr;

use crate::core::parser::record::endpoint::EndpointAddr as DnsEndpointAddr;

pub(crate) fn selected_endpoint_addrs(
    records: impl IntoIterator<Item = DnsEndpointAddr>,
) -> Vec<DquicEndpointAddr> {
    selected_endpoint_records(records.into_iter().map(|record| ((), record)))
        .into_iter()
        .map(|((), endpoint)| endpoint)
        .collect()
}

pub(crate) fn selected_endpoint_addrs_for_sequence(
    records: impl IntoIterator<Item = DnsEndpointAddr>,
    sequence: Option<CertificateSequence>,
) -> Vec<DquicEndpointAddr> {
    match sequence {
        Some(sequence) => selected_endpoint_records_for_sequence(
            records.into_iter().map(|record| ((), record)),
            Some(sequence),
        )
        .into_iter()
        .map(|((), endpoint)| endpoint)
        .collect(),
        None => selected_endpoint_addrs(records),
    }
}

pub(crate) fn selected_endpoint_records<T>(
    records: impl IntoIterator<Item = (T, DnsEndpointAddr)>,
) -> Vec<(T, DquicEndpointAddr)> {
    selected_endpoint_records_with_fallback_chain_keys(
        records.into_iter().map(|(tag, record)| (tag, record, None)),
        None,
    )
}

pub(crate) fn selected_endpoint_records_for_sequence<T>(
    records: impl IntoIterator<Item = (T, DnsEndpointAddr)>,
    sequence: Option<CertificateSequence>,
) -> Vec<(T, DquicEndpointAddr)> {
    selected_endpoint_records_with_fallback_chain_keys(
        records.into_iter().map(|(tag, record)| (tag, record, None)),
        sequence,
    )
}

pub(crate) fn selected_endpoint_records_with_fallback_chain_keys<T>(
    records: impl IntoIterator<Item = (T, DnsEndpointAddr, Option<CertificateChainKey>)>,
    sequence: Option<CertificateSequence>,
) -> Vec<(T, DquicEndpointAddr)> {
    let groups = crate::resolvers::endpoint_candidates::grouped_endpoint_candidates(
        records
            .into_iter()
            .map(|(tag, record, fallback_chain_key)| {
                crate::resolvers::endpoint_candidates::TaggedEndpointCandidate {
                    tag,
                    record,
                    fallback_chain_key,
                }
            }),
    );

    if let Some(sequence) = sequence {
        return groups
            .into_iter()
            .find(|(chain_key, _)| {
                chain_key.kind() == CertificateChainKind::Primary
                    && chain_key.sequence() == sequence
            })
            .map(|(_, endpoints)| endpoints)
            .unwrap_or_default();
    }

    groups
        .into_iter()
        .next()
        .map(|(_, endpoints)| endpoints)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use dhttp_identity::certificate::{
        CertificateChainKey, CertificateChainKind, CertificateSequence,
    };

    use crate::core::parser::record::endpoint::EndpointAddr;

    fn direct(addr: &str, main: bool, sequence: u32) -> EndpointAddr {
        let mut endpoint = match addr.parse().unwrap() {
            std::net::SocketAddr::V4(addr) => EndpointAddr::direct_v4(addr),
            std::net::SocketAddr::V6(addr) => EndpointAddr::direct_v6(addr),
        };
        endpoint.set_main(main);
        endpoint.set_sequence(CertificateSequence::try_from(sequence).unwrap());
        endpoint
    }

    #[test]
    fn selected_endpoint_addrs_uses_first_chain_key_group() {
        let secondary = direct("192.0.2.20:4433", false, 0);
        let primary_a = direct("192.0.2.10:4433", true, 2);
        let primary_b = direct("192.0.2.11:4433", true, 2);

        let selected = super::selected_endpoint_addrs([secondary, primary_a, primary_b]);

        assert_eq!(selected.len(), 1);
        assert_eq!(
            selected[0],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.20:4433".parse().unwrap())
        );
    }

    #[test]
    fn selected_endpoint_addrs_uses_one_secondary_chain_key_group_when_no_primary_exists() {
        let secondary_a = direct("192.0.2.20:4433", false, 5);
        let secondary_b = direct("192.0.2.21:4433", false, 5);
        let other_secondary = direct("192.0.2.30:4433", false, 6);

        let selected = super::selected_endpoint_addrs([secondary_a, secondary_b, other_secondary]);

        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.20:4433".parse().unwrap())
        );
        assert_eq!(
            selected[1],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.21:4433".parse().unwrap())
        );
    }

    #[test]
    fn selected_endpoint_addrs_treats_missing_sequence_as_zero() {
        let mut first = direct("192.0.2.40:4433", true, 0);
        first.set_clustered(false);
        let second = direct("192.0.2.41:4433", true, 0);

        let selected = super::selected_endpoint_addrs([first, second]);

        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn selected_endpoint_records_uses_one_chain_key_across_sources() {
        let selected = super::selected_endpoint_records([
            ("wifi", direct("192.0.2.50:4433", true, 3)),
            ("ethernet", direct("192.0.2.51:4433", true, 4)),
            ("wifi", direct("192.0.2.52:4433", true, 3)),
        ]);

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, "wifi");
        assert_eq!(
            selected[0].1,
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.50:4433".parse().unwrap())
        );
        assert_eq!(selected[1].0, "wifi");
        assert_eq!(
            selected[1].1,
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.52:4433".parse().unwrap())
        );
    }

    #[test]
    fn selected_endpoint_addrs_for_sequence_filters_requested_primary_group() {
        let selected = super::selected_endpoint_addrs_for_sequence(
            [
                direct("192.0.2.10:4433", true, 0),
                direct("192.0.2.11:4433", true, 0),
                direct("192.0.2.20:4433", true, 1),
                direct("192.0.2.30:4433", false, 1),
            ],
            Some(CertificateSequence::from(1u8)),
        );

        assert_eq!(
            selected,
            vec![dquic::qbase::net::addr::EndpointAddr::direct(
                "192.0.2.20:4433".parse().unwrap()
            )]
        );
    }

    #[test]
    fn selected_endpoint_addrs_for_sequence_returns_empty_when_primary_sequence_missing() {
        let selected = super::selected_endpoint_addrs_for_sequence(
            [
                direct("192.0.2.10:4433", true, 0),
                direct("192.0.2.20:4433", false, 2),
            ],
            Some(CertificateSequence::from(9u8)),
        );

        assert!(selected.is_empty());
    }

    #[test]
    fn selected_endpoint_records_for_sequence_uses_fallback_chain_key_when_packet_omits_it() {
        let endpoint = EndpointAddr::direct_v4("192.0.2.60:4433".parse().unwrap());
        let selected = super::selected_endpoint_records_with_fallback_chain_keys(
            [(
                "wifi",
                endpoint,
                Some(CertificateChainKey::new(
                    CertificateSequence::from(1u8),
                    CertificateChainKind::Primary,
                )),
            )],
            Some(CertificateSequence::from(1u8)),
        );

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].0, "wifi");
        assert_eq!(
            selected[0].1,
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.60:4433".parse().unwrap())
        );
    }
}
