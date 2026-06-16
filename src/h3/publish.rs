use std::collections::HashMap;

use dquic::qbase::net::addr::EndpointAddr;
use h3x::quic;
use http_body_util::Full;
use tracing::trace;

use super::{H3PublishError, H3Resolver};
use crate::core::{
    MdnsPacket,
    signature::{CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SignatureFields},
};

impl<C> H3Resolver<C>
where
    C: quic::Connect + quic::WithLocalAuthority + Send + Sync + 'static,
    C::Error: Send + Sync + 'static,
    C::Connection: Send + 'static,
{
    pub async fn publish_endpoints(
        &self,
        name: &str,
        endpoints: &[EndpointAddr],
    ) -> Result<(), H3PublishError<C::Error>> {
        trace!("h3x publishing {} with {} endpoints", name, endpoints.len());
        let bytes = {
            let endpoints = endpoints
                .iter()
                .filter_map(|ep| {
                    crate::core::parser::record::endpoint::EndpointAddr::try_from(*ep).ok()
                })
                .collect();
            let mut hosts = HashMap::new();
            hosts.insert(name.to_string(), endpoints);
            MdnsPacket::answer(0, &hosts).to_bytes()
        };

        self.publish_packet(name, &bytes).await
    }

    /// Publish a pre-built DNS packet (with signatures already included).
    pub async fn publish_packet(
        &self,
        name: &str,
        packet: &[u8],
    ) -> Result<(), H3PublishError<C::Error>> {
        self.publish_packet_with_signature(name, packet, &SignatureFields::empty())
            .await
    }

    pub async fn publish_signed(
        &self,
        name: &str,
        packet: &[u8],
        signature_fields: &SignatureFields,
    ) -> std::io::Result<()> {
        self.publish_packet_with_signature(name, packet, signature_fields)
            .await
            .map_err(std::io::Error::other)
    }

    async fn publish_packet_with_signature(
        &self,
        name: &str,
        packet: &[u8],
        signature_fields: &SignatureFields,
    ) -> Result<(), H3PublishError<C::Error>> {
        let mut url = self.base_url.join("publish").expect("Invalid base URL");
        url.set_query(Some(&format!("host={name}")));
        let uri: http::Uri = url.as_str().parse().expect("URL should be valid URI");
        tracing::trace!(
            name,
            packet_len = packet.len(),
            url = %self.base_url,
            "h3x publishing packet"
        );
        let mut request = http::Request::post(uri);
        if !signature_fields.is_empty() {
            request = request
                .header(
                    CONTENT_DIGEST_HEADER,
                    signature_fields.content_digest.as_slice(),
                )
                .header(
                    SIGNATURE_INPUT_HEADER,
                    signature_fields.signature_input.as_slice(),
                )
                .header(SIGNATURE_HEADER, signature_fields.signature.as_slice());
        }
        let request = request
            .body(Full::new(bytes::Bytes::copy_from_slice(packet)))
            .expect("h3 dns publish request must be valid");
        let resp = self.execute_request(request).await?;

        if resp.status() != http::StatusCode::OK {
            return Err(H3PublishError::Status {
                status: resp.status(),
            });
        }

        Ok(())
    }
}
