use std::{collections::HashMap, sync::Arc};

use dhttp_identity::{identity::LocalAuthority, name::Name};
use dquic::qbase::net::addr::EndpointAddr;
use snafu::{ResultExt, Snafu};

use super::PublishOptions;
use crate::core::{
    MdnsPacket,
    parser::record::endpoint::{EndpointAddr as DnsEndpointAddr, SignEndpointError},
};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignEndpointRecordsError {
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
    #[snafu(display("failed to sign endpoint address"))]
    SignEndpoint { source: SignEndpointError },
}

pub struct EndpointRecordSigner<A: ?Sized> {
    authority: Arc<A>,
    options: PublishOptions,
}

impl<A: ?Sized> std::fmt::Debug for EndpointRecordSigner<A>
where
    A: LocalAuthority,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointRecordSigner")
            .field("authority", &self.authority.name())
            .field("options", &self.options)
            .finish()
    }
}

impl<A> EndpointRecordSigner<A>
where
    A: LocalAuthority + Send + Sync + ?Sized,
{
    pub fn new(authority: Arc<A>) -> Self {
        Self {
            authority,
            options: PublishOptions::default(),
        }
    }

    pub fn with_options(mut self, options: PublishOptions) -> Self {
        self.options = options;
        self
    }

    pub fn options(&self) -> PublishOptions {
        self.options
    }

    pub fn authority(&self) -> &Arc<A> {
        &self.authority
    }

    pub async fn signed_packet(
        &self,
        name: &Name<'_>,
        endpoints: &[EndpointAddr],
    ) -> Result<Vec<u8>, SignEndpointRecordsError> {
        let mut signed = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let Ok(mut endpoint) = DnsEndpointAddr::try_from(*endpoint) else {
                return sign_endpoint_records_error::EncodeEndpointSnafu.fail();
            };
            if let Some(server_id) = self.options.server_id {
                endpoint.set_main(server_id == 0);
                endpoint.set_sequence(server_id.into());
            }
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
