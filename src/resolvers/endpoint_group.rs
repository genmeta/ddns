use dhttp_identity::certificate::CertificateChainKey;
use dquic::qbase::net::addr::EndpointAddr as DquicEndpointAddr;

use crate::core::parser::record::endpoint::EndpointAddr as DnsEndpointAddr;

type TaggedEndpoint<T> = (T, DquicEndpointAddr);
type EndpointGroup<T> = (CertificateChainKey, Vec<TaggedEndpoint<T>>);

pub(crate) fn selected_endpoint_addrs(
    records: impl IntoIterator<Item = DnsEndpointAddr>,
) -> Vec<DquicEndpointAddr> {
    selected_endpoint_records(records.into_iter().map(|record| ((), record)))
        .into_iter()
        .map(|((), endpoint)| endpoint)
        .collect()
}

pub(crate) fn selected_endpoint_records<T>(
    records: impl IntoIterator<Item = (T, DnsEndpointAddr)>,
) -> Vec<(T, DquicEndpointAddr)> {
    let mut groups: Vec<EndpointGroup<T>> = Vec::new();

    for (tag, record) in records {
        let chain_key = record.certificate_chain_key();
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
            dhttp_identity::certificate::CertificateChainKind::Primary => 0,
            dhttp_identity::certificate::CertificateChainKind::Secondary => 1,
        };
        (primary_rank, chain_key.sequence().get())
    });

    groups
        .into_iter()
        .next()
        .map(|(_, endpoints)| endpoints)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use dhttp_identity::certificate::CertificateSequence;

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
    fn selected_endpoint_addrs_prefers_primary_chain_key_group() {
        let secondary = direct("192.0.2.20:4433", false, 0);
        let primary_a = direct("192.0.2.10:4433", true, 2);
        let primary_b = direct("192.0.2.11:4433", true, 2);

        let selected = super::selected_endpoint_addrs([secondary, primary_a, primary_b]);

        assert_eq!(selected.len(), 2);
        assert_eq!(
            selected[0],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.10:4433".parse().unwrap())
        );
        assert_eq!(
            selected[1],
            dquic::qbase::net::addr::EndpointAddr::direct("192.0.2.11:4433".parse().unwrap())
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
}
