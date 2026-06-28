use std::collections::HashMap;

use dhttp_identity::{
    certificate::CertificateChainKind,
    identity::{LocalAuthority, LocalAuthorityCertificateExt},
};
use dquic::qbase::net::addr::EndpointAddr;
use snafu::{ResultExt, Snafu, ensure};

use crate::core::{MdnsPacket, parser::record::endpoint::EndpointAddr as DnsEndpointAddr};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeAuthorityDnsPacketError {
    #[snafu(display("publisher authority name does not match dns name"))]
    AuthorityNameMismatch,
    #[snafu(display("publisher authority has no valid dhttp subject key identifier"))]
    DhttpSubjectKeyIdentifier {
        source: dhttp_identity::identity::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
}


#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeEndpointPacketError {
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
}

pub(crate) fn endpoint_packet(
    name: &dhttp_identity::name::Name<'_>,
    endpoints: impl IntoIterator<Item = EndpointAddr>,
) -> Result<Vec<u8>, EncodeEndpointPacketError> {
    let mut encoded = Vec::new();
    for endpoint in endpoints {
        let Ok(endpoint) = DnsEndpointAddr::try_from(endpoint) else {
            return encode_endpoint_packet_error::EncodeEndpointSnafu.fail();
        };
        encoded.push(endpoint);
    }

    let mut hosts = HashMap::new();
    hosts.insert(name.as_str().to_owned(), encoded);
    Ok(MdnsPacket::answer(0, &hosts).to_bytes())
}

pub(crate) fn dns_packet_for_authority(
    authority: &dyn LocalAuthority,
    name: &str,
    endpoints: &mut dyn Iterator<Item = EndpointAddr>,
) -> Result<Vec<u8>, EncodeAuthorityDnsPacketError> {
    ensure!(
        authority.name() == name,
        encode_authority_dns_packet_error::AuthorityNameMismatchSnafu
    );

    let ski = authority.dhttp_subject_key_identifier().context(
        encode_authority_dns_packet_error::DhttpSubjectKeyIdentifierSnafu,
    )?;
    let chain = ski.chain();

    let mut encoded = Vec::new();
    for endpoint in endpoints {
        let Ok(mut endpoint) = DnsEndpointAddr::try_from(endpoint) else {
            return encode_authority_dns_packet_error::EncodeEndpointSnafu.fail();
        };
        endpoint.set_main(chain.kind() == CertificateChainKind::Primary);
        endpoint.set_sequence(chain.sequence());
        encoded.push(endpoint);
    }

    let mut hosts = HashMap::new();
    hosts.insert(name.to_owned(), encoded);
    Ok(MdnsPacket::answer(0, &hosts).to_bytes())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use dhttp_identity::identity::LocalAuthority;
    use dquic::qbase::net::addr::EndpointAddr as DquicEndpointAddr;
    use futures::future::BoxFuture;
    use rustls::pki_types::CertificateDer;

    use super::dns_packet_for_authority;
    use crate::core::parser::{
        packet::be_packet,
        record::{RData, Type},
    };

    #[derive(Debug)]
    struct TestAuthority {
        name: &'static str,
        cert_chain: Vec<CertificateDer<'static>>,
    }

    impl LocalAuthority for TestAuthority {
        fn name(&self) -> &str {
            self.name
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }

        fn sign(
            &self,
            _data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }
    }

    fn authority(name: &'static str) -> TestAuthority {
        TestAuthority {
            name,
            cert_chain: vec![CertificateDer::from(
                include_bytes!("../../tests/fixtures/valid.der").to_vec(),
            )],
        }
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

        let packet = dns_packet_for_authority(
            &authority,
            "client.example.com.dhttp.net",
            &mut endpoints,
        )
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
    fn dns_packet_for_authority_rejects_name_mismatch() {
        let authority = authority("client.example.com.dhttp.net");
        let mut endpoints = std::iter::once(endpoint());

        let error = dns_packet_for_authority(
            &authority,
            "other.example.com.dhttp.net",
            &mut endpoints,
        )
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

        let packet = dns_packet_for_authority(
            &authority,
            "client.example.com.dhttp.net",
            &mut endpoints,
        )
        .expect("authority packet");

        let (remain, parsed) = be_packet(&packet).expect("dns packet parses");
        assert!(remain.is_empty());
        assert!(parsed.answers.is_empty());
    }
}
