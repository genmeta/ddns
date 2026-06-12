use dhttp_identity::certificate::{CertificateChainKey, CertificateChainKind};
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

pub(crate) fn selected_endpoint_records<T>(
    records: impl IntoIterator<Item = (T, DnsEndpointAddr)>,
) -> Vec<(T, DquicEndpointAddr)> {
    let mut groups: Vec<(CertificateChainKey, Vec<(T, DquicEndpointAddr)>)> = Vec::new();

    for (tag, record) in records {
        let Ok(selector) = record.certificate_chain_key() else {
            continue;
        };
        let Ok(endpoint) = DquicEndpointAddr::try_from(record) else {
            continue;
        };

        if let Some((_key, endpoints)) = groups.iter_mut().find(|(key, _)| *key == selector) {
            endpoints.push((tag, endpoint));
        } else {
            groups.push((selector, vec![(tag, endpoint)]));
        }
    }

    let selected = groups
        .iter()
        .position(|(key, endpoints)| {
            key.kind() == CertificateChainKind::Primary && !endpoints.is_empty()
        })
        .or_else(|| {
            groups
                .iter()
                .position(|(_key, endpoints)| !endpoints.is_empty())
        });

    selected
        .map(|index| groups.swap_remove(index).1)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use crate::core::parser::record::endpoint::EndpointAddr;

    fn direct(addr: &str, main: bool, sequence: u64) -> EndpointAddr {
        let mut endpoint = match addr.parse().unwrap() {
            std::net::SocketAddr::V4(addr) => EndpointAddr::direct_v4(addr),
            std::net::SocketAddr::V6(addr) => EndpointAddr::direct_v6(addr),
        };
        endpoint.set_main(main);
        endpoint.set_sequence(sequence);
        endpoint
    }

    #[test]
    fn selected_endpoint_addrs_prefers_primary_group() {
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
    fn selected_endpoint_addrs_uses_one_secondary_group_when_no_primary_exists() {
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
    fn selected_endpoint_records_uses_one_group_across_sources() {
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
