use std::{collections::HashMap, sync::Arc};

use dhttp_identity::{
    identity::{LocalAuthority, LocalAuthorityCertificateExt},
    name::Name,
};
use dquic::qbase::net::addr::EndpointAddr;
use snafu::{ResultExt, Snafu};

use crate::core::{
    MdnsPacket,
    parser::record::endpoint::{EndpointAddr as DnsEndpointAddr, SignEndpointError},
};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignEndpointRecordsError {
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
    #[snafu(display("failed to extract dhttp certificate selector"))]
    CertificateSelector {
        source: dhttp_identity::identity::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("failed to sign endpoint address"))]
    SignEndpoint { source: SignEndpointError },
}

#[derive(Clone)]
pub struct EndpointRecordSigner<A: ?Sized> {
    authority: Arc<A>,
}

impl<A: ?Sized> std::fmt::Debug for EndpointRecordSigner<A>
where
    A: LocalAuthority,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointRecordSigner")
            .field("authority", &self.authority.name())
            .finish()
    }
}

impl<A> EndpointRecordSigner<A>
where
    A: LocalAuthority + Send + Sync + ?Sized,
{
    pub fn new(authority: Arc<A>) -> Self {
        Self { authority }
    }

    pub fn authority(&self) -> &Arc<A> {
        &self.authority
    }

    pub async fn signed_packet(
        &self,
        name: &Name<'_>,
        endpoints: &[EndpointAddr],
    ) -> Result<Vec<u8>, SignEndpointRecordsError> {
        let selector = self
            .authority
            .dhttp_subject_key_identifier()
            .context(sign_endpoint_records_error::CertificateSelectorSnafu)?;
        let chain = selector.chain();

        let mut signed = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let Ok(mut endpoint) = DnsEndpointAddr::try_from(*endpoint) else {
                return sign_endpoint_records_error::EncodeEndpointSnafu.fail();
            };
            endpoint.set_main(
                chain.kind() == dhttp_identity::certificate::CertificateChainKind::Primary,
            );
            endpoint.set_sequence(chain.sequence().get().into());
            endpoint
                .sign_with_authority(self.authority.as_ref())
                .await
                .context(sign_endpoint_records_error::SignEndpointSnafu)?;
            signed.push(endpoint);
        }

        let mut hosts = HashMap::new();
        hosts.insert(name.as_str().to_owned(), signed);
        Ok(MdnsPacket::answer(0, &hosts).to_bytes())
    }
}
