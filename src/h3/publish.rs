use std::collections::HashMap;

use dhttp_identity::identity::LocalAuthority;
use dquic::qbase::net::addr::EndpointAddr;
use h3x::quic;
use http_body_util::Full;
use snafu::{OptionExt, ResultExt};
use tracing::trace;

use super::{H3PublishError, H3Resolver, h3_publish_error};
use crate::core::{
    MdnsPacket,
    signature::{CONTENT_DIGEST_HEADER, SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SignatureFields},
};

const PUBLISH_API_PATH: &str = "/api/v2/publish";

fn publish_url(base_url: &url::Url, name: &str) -> url::Url {
    let mut url = base_url
        .join(PUBLISH_API_PATH)
        .expect("h3 dns publish api path must be valid");
    url.query_pairs_mut().append_pair("host", name);
    url
}

async fn signed_publish_request<A: LocalAuthority + ?Sized>(
    base_url: &url::Url,
    name: &str,
    packet: &[u8],
    authority: &A,
) -> Result<http::Request<Full<bytes::Bytes>>, crate::core::signature::SignatureFieldsError> {
    let url = publish_url(base_url, name);
    let uri: http::Uri = url
        .as_str()
        .parse()
        .expect("h3 dns publish URL is a valid URI");
    let signature_fields = SignatureFields::sign(packet, authority).await?;

    Ok(http::Request::post(uri)
        .header(
            CONTENT_DIGEST_HEADER,
            signature_fields.content_digest.as_slice(),
        )
        .header(
            SIGNATURE_INPUT_HEADER,
            signature_fields.signature_input.as_slice(),
        )
        .header(SIGNATURE_HEADER, signature_fields.signature.as_slice())
        .body(Full::new(bytes::Bytes::copy_from_slice(packet)))
        .expect("h3 dns publish request must be valid"))
}

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
        tracing::trace!(
            name,
            packet_len = packet.len(),
            url = %self.base_url,
            "h3 dns publishing packet"
        );
        let authority = self
            .endpoint
            .quic()
            .local_authority()
            .await
            .context(h3_publish_error::LocalAuthoritySnafu)?
            .context(h3_publish_error::AnonymousEndpointSnafu)?;
        let request = signed_publish_request(&self.base_url, name, packet, &authority)
            .await
            .context(h3_publish_error::SignRequestSnafu)?;
        let resp = self.execute_request(request).await?;

        if resp.status() != http::StatusCode::OK {
            return Err(H3PublishError::Status {
                status: resp.status(),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[cfg(feature = "dquic-network")]
    use dquic::qresolve::Publish as _;
    use futures::future::BoxFuture;
    #[cfg(feature = "dquic-network")]
    use h3x::endpoint::H3Endpoint;
    use ring::signature::KeyPair as _;
    use rustls::{
        SignatureAlgorithm, SignatureScheme,
        pki_types::CertificateDer,
        sign::{Signer, SigningKey},
    };

    use super::*;

    #[cfg(feature = "dquic-network")]
    #[tokio::test]
    async fn publish_rejects_anonymous_endpoint_before_request() {
        let endpoint = Arc::new(H3Endpoint::new(
            h3x::dquic::QuicEndpoint::builder().build().await,
        ));
        let resolver = H3Resolver::from_endpoint("https://dns.example.test:4433", endpoint)
            .expect("valid h3 resolver");

        let error = resolver
            .publish_packet("demo.dhttp.net", b"dns-packet")
            .await
            .expect_err("anonymous endpoint should not publish");

        assert_eq!(
            error.to_string(),
            "anonymous h3 endpoint cannot sign dns publish request"
        );

        let trait_error = resolver
            .publish("demo.dhttp.net", b"dns-packet")
            .await
            .expect_err("trait publish should surface anonymous endpoint");
        assert!(
            trait_error
                .to_string()
                .contains("anonymous h3 endpoint cannot sign dns publish request")
        );
    }

    #[derive(Debug)]
    struct TestAuthority {
        keypair: Arc<ring::signature::Ed25519KeyPair>,
        cert_chain: Vec<CertificateDer<'static>>,
    }

    impl dhttp_identity::identity::LocalAuthority for TestAuthority {
        fn name(&self) -> &str {
            "authority.example"
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &self.cert_chain
        }

        fn sign(
            &self,
            data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>> {
            let result = dhttp_identity::identity::sign_with_key(
                &TestSigningKey(self.keypair.clone()),
                data,
            );
            Box::pin(std::future::ready(result))
        }
    }

    #[derive(Debug)]
    struct TestSigningKey(Arc<ring::signature::Ed25519KeyPair>);

    impl SigningKey for TestSigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&SignatureScheme::ED25519)
                .then(|| Box::new(TestSigner(self.0.clone())) as Box<dyn Signer>)
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ED25519
        }
    }

    #[derive(Debug)]
    struct TestSigner(Arc<ring::signature::Ed25519KeyPair>);

    impl Signer for TestSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            Ok(self.0.sign(message).as_ref().to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ED25519
        }
    }

    fn test_authority() -> TestAuthority {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("pkcs8");
        let keypair =
            Arc::new(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("keypair"));
        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ]);
        spki.extend_from_slice(keypair.public_key().as_ref());

        TestAuthority {
            keypair,
            cert_chain: vec![CertificateDer::from(spki)],
        }
    }

    #[tokio::test]
    async fn signed_publish_request_uses_authority_headers() {
        let authority = test_authority();
        let base_url = url::Url::parse("https://dns.example.test:4433").expect("url");
        let request =
            signed_publish_request(&base_url, "demo.dhttp.net", b"dns-packet", &authority)
                .await
                .expect("signed request");

        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request.uri().to_string(),
            "https://dns.example.test:4433/api/v2/publish?host=demo.dhttp.net"
        );
        assert!(
            request
                .headers()
                .contains_key(crate::core::signature::CONTENT_DIGEST_HEADER)
        );
        assert!(
            request
                .headers()
                .contains_key(crate::core::signature::SIGNATURE_INPUT_HEADER)
        );
        assert!(
            request
                .headers()
                .contains_key(crate::core::signature::SIGNATURE_HEADER)
        );
    }
}
