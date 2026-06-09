use std::any::Any;

use dhttp_identity::{identity::LocalAuthority, name::Name};
use dquic::{
    qbase::net::addr::EndpointAddr,
    qresolve::{Publish, Resolve},
};
use snafu::ResultExt;

use super::{
    AddressSelector, AddressView, PublishOnceError, Publisher, PublisherResolver,
    publish_once_error,
};
use crate::resolvers::Resolvers;

impl<A, R> Publisher<A, R>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: PublisherResolver + ?Sized,
{
    pub(crate) async fn publish_to_resolver<V>(
        &self,
        resolver: &(dyn Resolve + Send + Sync),
        name: &Name<'_>,
        addresses: &V,
    ) -> Result<bool, PublishOnceError>
    where
        V: AddressView + Sync,
    {
        let any: &dyn Any = resolver;

        if let Some(resolvers) = any.downcast_ref::<Resolvers>() {
            let mut published = false;
            for resolver in resolvers.iter() {
                published |= self
                    .publish_single_resolver(resolver.as_ref(), name, addresses)
                    .await?;
            }
            return Ok(published);
        }

        self.publish_single_resolver(resolver, name, addresses)
            .await
    }

    async fn publish_single_resolver<V>(
        &self,
        resolver: &(dyn Resolve + Send + Sync),
        name: &Name<'_>,
        addresses: &V,
    ) -> Result<bool, PublishOnceError>
    where
        V: AddressView + Sync,
    {
        #[cfg(not(any(
            feature = "http-resolver",
            feature = "h3x-resolver",
            feature = "mdns-resolver"
        )))]
        {
            let _ = name;
            let _ = addresses;
        }

        let any: &dyn Any = resolver;

        #[cfg(feature = "http-resolver")]
        if let Some(http) = any.downcast_ref::<crate::resolvers::http::HttpResolver>() {
            self.publish_selected(http, name, addresses, AddressSelector::WideArea)
                .await?;
            return Ok(true);
        }

        #[cfg(feature = "h3x-resolver")]
        if let Some(h3) =
            any.downcast_ref::<crate::resolvers::h3::H3Resolver<h3x::dquic::QuicEndpoint>>()
        {
            self.publish_selected(h3, name, addresses, AddressSelector::WideArea)
                .await?;
            return Ok(true);
        }

        #[cfg(feature = "mdns-resolver")]
        if let Some(mdns) = any.downcast_ref::<crate::mdns::resolvers::mdns::MdnsResolvers>() {
            let mut published = false;
            for bound in mdns.bound_resolvers() {
                self.publish_selected(
                    &bound.resolver,
                    name,
                    addresses,
                    AddressSelector::LocalLink {
                        device: &bound.device,
                        family: bound.family,
                    },
                )
                .await?;
                published = true;
            }
            return Ok(published);
        }

        Ok(false)
    }

    async fn publish_selected<V>(
        &self,
        publisher: &(dyn Publish + Send + Sync),
        name: &Name<'_>,
        addresses: &V,
        selector: AddressSelector<'_>,
    ) -> Result<(), PublishOnceError>
    where
        V: AddressView + Sync,
    {
        let endpoints: Vec<EndpointAddr> = addresses.endpoints(selector).collect();
        let packet = self
            .signer
            .signed_packet(name, &endpoints)
            .await
            .context(publish_once_error::SignEndpointRecordsSnafu)?;
        tracing::debug!(
            publisher = %publisher,
            name = %name,
            endpoint_count = endpoints.len(),
            packet_len = packet.len(),
            "publishing dns packet"
        );
        publisher
            .publish(name.as_str(), &packet)
            .await
            .context(publish_once_error::PublishSnafu {
                publisher: publisher.to_string(),
            })
    }
}

pub(crate) fn clear_resolver_publish_state(resolver: &(dyn Resolve + Send + Sync)) {
    let any: &dyn Any = resolver;

    if let Some(resolvers) = any.downcast_ref::<Resolvers>() {
        for resolver in resolvers.iter() {
            clear_resolver_publish_state(resolver.as_ref());
        }
    }

    #[cfg(feature = "h3x-resolver")]
    if let Some(h3) =
        any.downcast_ref::<crate::resolvers::h3::H3Resolver<h3x::dquic::QuicEndpoint>>()
    {
        h3.clear_pool();
    }
}
