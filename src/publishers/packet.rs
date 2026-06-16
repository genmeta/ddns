use std::collections::HashMap;

use dhttp_identity::name::Name;
use dquic::qbase::net::addr::EndpointAddr;
use snafu::Snafu;

use crate::core::{MdnsPacket, parser::record::endpoint::EndpointAddr as DnsEndpointAddr};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeEndpointPacketError {
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
}

#[allow(dead_code)]
pub type SignEndpointRecordsError = EncodeEndpointPacketError;

#[allow(dead_code)]
#[derive(Clone)]
pub struct EndpointRecordSigner<A: ?Sized> {
    authority: std::sync::Arc<A>,
}

impl<A: ?Sized> std::fmt::Debug for EndpointRecordSigner<A>
where
    A: dhttp_identity::identity::LocalAuthority,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointRecordSigner")
            .field("authority", &self.authority.name())
            .finish()
    }
}

#[allow(dead_code)]
impl<A> EndpointRecordSigner<A>
where
    A: dhttp_identity::identity::LocalAuthority + Send + Sync + ?Sized,
{
    pub fn new(authority: std::sync::Arc<A>) -> Self {
        Self { authority }
    }

    pub fn authority(&self) -> &std::sync::Arc<A> {
        &self.authority
    }

    pub async fn signed_packet(
        &self,
        name: &Name<'_>,
        endpoints: &[EndpointAddr],
    ) -> Result<Vec<u8>, SignEndpointRecordsError> {
        let _ = &self.authority;
        endpoint_packet(name, endpoints.iter().copied())
    }
}

pub(crate) fn endpoint_packet(
    name: &Name<'_>,
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

    use dhttp_identity::name::Name;
    use dquic::qbase::net::addr::EndpointAddr as DquicEndpointAddr;

    use super::endpoint_packet;
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
}
