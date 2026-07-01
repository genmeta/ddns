use std::collections::HashMap;

use dhttp_identity::{
    certificate::{CertificateChainKey, CertificateChainKind},
    name::Name,
};
use dquic::qbase::net::addr::EndpointAddr;
use snafu::Snafu;

use crate::core::{MdnsPacket, parser::record::endpoint::EndpointAddr as DnsEndpointAddr};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeEndpointPacketError {
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
}

pub(crate) fn endpoint_packet(
    name: &Name<'_>,
    endpoints: impl IntoIterator<Item = EndpointAddr>,
) -> Result<Vec<u8>, EncodeEndpointPacketError> {
    endpoint_packet_with_chain_key(name, endpoints, None)
}

pub(crate) fn endpoint_packet_with_chain_key(
    name: &Name<'_>,
    endpoints: impl IntoIterator<Item = EndpointAddr>,
    chain_key: Option<&CertificateChainKey>,
) -> Result<Vec<u8>, EncodeEndpointPacketError> {
    let mut encoded = Vec::new();
    for endpoint in endpoints {
        let Ok(mut endpoint) = DnsEndpointAddr::try_from(endpoint) else {
            return encode_endpoint_packet_error::EncodeEndpointSnafu.fail();
        };
        if let Some(chain_key) = chain_key {
            endpoint.set_main(matches!(chain_key.kind(), CertificateChainKind::Primary));
            endpoint.set_sequence(chain_key.sequence());
        }
        encoded.push(endpoint);
    }

    let mut hosts = HashMap::new();
    hosts.insert(name.as_str().to_owned(), encoded);
    Ok(MdnsPacket::answer(0, &hosts).to_bytes())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use dhttp_identity::{
        certificate::{CertificateChainKey, CertificateChainKind, CertificateSequence},
        name::Name,
    };
    use dquic::qbase::net::addr::EndpointAddr as DquicEndpointAddr;

    use super::{endpoint_packet, endpoint_packet_with_chain_key};
    use crate::core::parser::{
        packet::be_packet,
        record::{RData, Type},
    };

    #[test]
    fn endpoint_packet_encodes_unsigned_e_records() {
        let name = Name::try_from("alice.dhttp.net").expect("valid dns owner name");
        let endpoint = DquicEndpointAddr::direct(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, 10),
            4433,
        )));

        let packet = endpoint_packet(&name, [endpoint]).expect("endpoint packet");
        let (remain, parsed) = be_packet(&packet).expect("dns packet parses");
        assert!(remain.is_empty());
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name(), "alice.dhttp.net");
        assert_eq!(parsed.answers[0].typ(), Type::E);

        let RData::E(encoded) = parsed.answers[0].data() else {
            panic!("answer must be an E record");
        };
        assert!(!encoded.is_signed());
    }

    #[test]
    fn endpoint_packet_allows_empty_endpoint_set() {
        let name = Name::try_from("alice.dhttp.net").expect("valid dns owner name");

        let packet = endpoint_packet(&name, []).expect("endpoint packet");
        let (remain, parsed) = be_packet(&packet).expect("dns packet parses");
        assert!(remain.is_empty());
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn endpoint_packet_uses_publisher_chain_key() {
        let name = Name::try_from("alice.dhttp.net").expect("valid dns owner name");
        let endpoint = DquicEndpointAddr::direct(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, 10),
            4433,
        )));
        let chain_key = CertificateChainKey::new(
            CertificateSequence::try_from(0u32).expect("sequence"),
            CertificateChainKind::Primary,
        );

        let packet = endpoint_packet_with_chain_key(&name, [endpoint], Some(&chain_key))
            .expect("endpoint packet");
        let (remain, parsed) = be_packet(&packet).expect("dns packet parses");
        assert!(remain.is_empty());

        let RData::E(encoded) = parsed.answers[0].data() else {
            panic!("answer must be an E record");
        };
        assert!(encoded.is_main());
        assert_eq!(encoded.certificate_chain_key(), chain_key);
    }
}
