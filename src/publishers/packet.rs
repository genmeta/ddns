#[cfg(any(feature = "h3", test))]
use std::collections::HashMap;

use qresolve::EndpointAddr;
use qtls::LocalAuthority;
use snafu::{ResultExt, Snafu, ensure};

#[cfg(any(feature = "h3", test))]
use crate::core::MdnsPacket;
use crate::core::parser::record::endpoint::EndpointAddr as DnsEndpointAddr;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeAuthorityDnsPacketError {
    #[snafu(display("publisher authority name does not match dns name"))]
    AuthorityNameMismatch,
    #[snafu(display("publisher authority has no valid dhttp subject key identifier"))]
    DhttpSubjectKeyIdentifier {
        source: dhttp_home::certificate::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
    #[snafu(display("secondary authority cannot publish dns endpoints"))]
    SecondaryAuthority,
}

pub(crate) fn dns_endpoints_for_authority(
    authority: &LocalAuthority,
    name: &str,
    endpoints: &mut dyn Iterator<Item = EndpointAddr>,
) -> Result<Vec<DnsEndpointAddr>, EncodeAuthorityDnsPacketError> {
    ensure!(
        authority.name() == name,
        encode_authority_dns_packet_error::AuthorityNameMismatchSnafu
    );

    let ski =
        dhttp_home::certificate::extract_dhttp_subject_key_identifier(authority.certificates())
            .context(encode_authority_dns_packet_error::DhttpSubjectKeyIdentifierSnafu)?;
    let chain = ski.chain();

    let mut encoded = Vec::new();
    for endpoint in endpoints {
        let Ok(mut endpoint) = DnsEndpointAddr::try_from(endpoint) else {
            return encode_authority_dns_packet_error::EncodeEndpointSnafu.fail();
        };
        endpoint.set_main(true);
        endpoint.set_sequence(chain.sequence());
        encoded.push(endpoint);
    }

    ensure!(
        encoded.is_empty() || crate::core::certificate::is_primary_chain_key(chain),
        encode_authority_dns_packet_error::SecondaryAuthoritySnafu
    );

    Ok(encoded)
}

#[cfg(any(feature = "h3", test))]
pub(crate) fn dns_packet_for_authority(
    authority: &LocalAuthority,
    name: &str,
    endpoints: &mut dyn Iterator<Item = EndpointAddr>,
) -> Result<Vec<u8>, EncodeAuthorityDnsPacketError> {
    let encoded = dns_endpoints_for_authority(authority, name, endpoints)?;

    let mut hosts = HashMap::new();
    hosts.insert(name.to_owned(), encoded);
    Ok(MdnsPacket::answer(0, &hosts).to_bytes())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use qresolve::EndpointAddr as DquicEndpointAddr;
    use qtls::LocalAuthority;

    use super::{dns_endpoints_for_authority, dns_packet_for_authority};
    use crate::core::parser::{
        packet::be_packet,
        record::{RData, Type},
    };

    fn authority(name: &str) -> LocalAuthority {
        authority_with_chain(name, 0, 0)
    }

    fn authority_with_chain(name: &str, sequence: u8, kind_flag: u8) -> LocalAuthority {
        crate::test_support::authority(name, sequence, kind_flag)
    }

    fn endpoint() -> DquicEndpointAddr {
        DquicEndpointAddr::direct(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(203, 0, 113, 10),
            4433,
        )))
    }

    #[test]
    fn dns_packet_for_authority_encodes_chain_key_from_authority_ski() {
        let authority = authority("client.example.com.dhttp.net");
        let mut endpoints = std::iter::once(endpoint());

        let packet =
            dns_packet_for_authority(&authority, "client.example.com.dhttp.net", &mut endpoints)
                .expect("authority packet");

        let (remain, parsed) = be_packet(&packet).expect("dns packet parses");
        assert!(remain.is_empty());
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name(), "client.example.com.dhttp.net");
        assert_eq!(parsed.answers[0].typ(), Type::E);

        let RData::E(encoded) = parsed.answers[0].data() else {
            panic!("answer must be an E record");
        };
        assert!(!encoded.is_signed());
        assert!(encoded.is_main());
        assert_eq!(encoded.normalized_sequence().get(), 0);
    }

    #[test]
    fn dns_packet_preserves_relay_outer_agent_and_nat_flag() {
        let name = "client.example.com.dhttp.net";
        let authority = authority(name);
        for (agent, outer) in [
            ("8.8.8.8:20002", "1.1.1.1:51000"),
            (
                "[2001:4860:4860::8888]:20002",
                "[2606:4700:4700::1111]:51000",
            ),
        ] {
            let agent: SocketAddr = agent.parse().unwrap();
            let outer: SocketAddr = outer.parse().unwrap();
            let relay = DquicEndpointAddr::mediate(agent, outer);
            let packet =
                dns_packet_for_authority(&authority, name, &mut std::iter::once(relay)).unwrap();
            let (remain, parsed) = be_packet(&packet).unwrap();
            assert!(remain.is_empty());
            assert_eq!(parsed.answers.len(), 1);
            let RData::E(encoded) = parsed.answers[0].data() else {
                panic!("expected E record")
            };
            assert!(encoded.is_nat());
            assert_eq!(encoded.addr(), outer);
            assert_eq!(encoded.agent_addr(), Some(agent));
            assert_eq!(encoded.to_string(), format!("{outer}-{agent}"));
            assert_eq!(DquicEndpointAddr::try_from(encoded.clone()).unwrap(), relay);
        }
    }

    #[test]
    fn dns_packet_for_authority_rejects_name_mismatch() {
        let authority = authority("client.example.com.dhttp.net");
        let mut endpoints = std::iter::once(endpoint());

        let error =
            dns_packet_for_authority(&authority, "other.example.com.dhttp.net", &mut endpoints)
                .expect_err("name mismatch fails");

        assert_eq!(
            error.to_string(),
            "publisher authority name does not match dns name"
        );
    }

    #[test]
    fn dns_packet_for_authority_allows_empty_endpoint_set() {
        let authority = authority("client.example.com.dhttp.net");
        let mut endpoints = std::iter::empty();

        let packet =
            dns_packet_for_authority(&authority, "client.example.com.dhttp.net", &mut endpoints)
                .expect("authority packet");

        let (remain, parsed) = be_packet(&packet).expect("dns packet parses");
        assert!(remain.is_empty());
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn dns_endpoints_for_primary_authority_stamp_sequence_metadata() {
        let authority = authority_with_chain("client.example.com.dhttp.net", 7, 0);
        let mut endpoints = std::iter::once(endpoint());

        let encoded =
            dns_endpoints_for_authority(&authority, "client.example.com.dhttp.net", &mut endpoints)
                .expect("primary endpoints encode");

        assert_eq!(encoded.len(), 1);
        assert!(encoded[0].is_main());
        assert_eq!(encoded[0].normalized_sequence().get(), 7);
    }

    #[test]
    fn dns_endpoints_for_secondary_authority_reject_non_empty_publication() {
        let authority = authority_with_chain("client.example.com.dhttp.net", 7, 1);
        let mut endpoints = std::iter::once(endpoint());

        let error =
            dns_endpoints_for_authority(&authority, "client.example.com.dhttp.net", &mut endpoints)
                .expect_err("secondary publication is rejected");

        assert_eq!(
            error.to_string(),
            "secondary authority cannot publish dns endpoints"
        );
    }

    #[test]
    fn dns_endpoints_for_secondary_authority_allows_empty_clear() {
        let authority = authority_with_chain("client.example.com.dhttp.net", 7, 1);
        let mut endpoints = std::iter::empty();

        let encoded =
            dns_endpoints_for_authority(&authority, "client.example.com.dhttp.net", &mut endpoints)
                .expect("empty secondary clear is allowed");

        assert!(encoded.is_empty());
    }
}
