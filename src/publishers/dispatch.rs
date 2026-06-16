use std::any::Any;

use dhttp_identity::{identity::LocalAuthority, name::Name};
use dquic::qresolve::{Publish, Resolve};
use snafu::{IntoError, ResultExt};

use super::{
    AddressSelector, AddressView, EndpointRecordSigner, PublishOnceError, publish_once_error,
};
#[cfg(feature = "resolvers")]
use crate::resolvers::Resolvers;

#[cfg(all(feature = "h3", feature = "dquic-network"))]
type DeferredH3Resolver =
    crate::resolvers::deferred::DeferredResolver<crate::h3::H3Resolver<h3x::dquic::QuicEndpoint>>;

#[doc(hidden)]
pub trait ResolveDispatchTarget: Resolve {
    fn as_resolve(&self) -> &(dyn Resolve + Send + Sync);
    fn as_any(&self) -> &dyn Any;
}

impl<T> ResolveDispatchTarget for T
where
    T: Resolve + Send + Sync + 'static,
{
    fn as_resolve(&self) -> &(dyn Resolve + Send + Sync) {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl ResolveDispatchTarget for dyn Resolve + Send + Sync {
    fn as_resolve(&self) -> &(dyn Resolve + Send + Sync) {
        self
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub(crate) async fn publish_to_resolver<A, R, V>(
    signer: &EndpointRecordSigner<A>,
    resolver: &R,
    name: &Name<'_>,
    addresses: &V,
) -> Result<bool, PublishOnceError>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: ResolveDispatchTarget + ?Sized,
    V: AddressView + Sync,
{
    let any = resolver.as_any();

    #[cfg(feature = "resolvers")]
    if let Some(resolvers) = any.downcast_ref::<Resolvers>() {
        let mut published = false;
        for resolver in resolvers.iter() {
            published |=
                publish_single_resolver(signer, resolver.as_ref(), name, addresses).await?;
        }
        return Ok(published);
    }

    publish_single_resolver(signer, resolver.as_resolve(), name, addresses).await
}

async fn publish_single_resolver<A, V>(
    signer: &EndpointRecordSigner<A>,
    resolver: &(dyn Resolve + Send + Sync),
    name: &Name<'_>,
    addresses: &V,
) -> Result<bool, PublishOnceError>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    V: AddressView + Sync,
{
    let any = resolver as &dyn Any;

    #[cfg(not(any(
        feature = "http",
        all(feature = "h3", feature = "dquic-network"),
        all(feature = "mdns", feature = "dquic-network")
    )))]
    {
        let _ = any;
        let _ = name;
        let _ = addresses;
    }

    #[cfg(feature = "http")]
    if let Some(http) = any.downcast_ref::<crate::http::HttpResolver>() {
        publish_selected(signer, http, name, addresses, AddressSelector::WideArea).await?;
        return Ok(true);
    }

    #[cfg(all(feature = "h3", feature = "dquic-network"))]
    if let Some(h3) = any.downcast_ref::<crate::h3::H3Resolver<h3x::dquic::QuicEndpoint>>() {
        publish_selected(signer, h3, name, addresses, AddressSelector::WideArea).await?;
        return Ok(true);
    }

    #[cfg(all(feature = "h3", feature = "dquic-network"))]
    if let Some(h3) = any.downcast_ref::<DeferredH3Resolver>() {
        let Some(h3) = h3.get() else {
            return Err(publish_once_error::PublishSnafu {
                publisher: h3.to_string(),
            }
            .into_error(std::io::Error::other(
                "deferred h3 resolver has not been initialized",
            )));
        };
        publish_selected(signer, h3, name, addresses, AddressSelector::WideArea).await?;
        return Ok(true);
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    if let Some(mdns) = any.downcast_ref::<crate::mdns::MdnsResolvers>() {
        let mut published = false;
        for bound in mdns.bound_resolvers() {
            publish_selected(
                signer,
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

async fn publish_selected<A, V>(
    signer: &EndpointRecordSigner<A>,
    publisher: &(dyn Publish + Send + Sync),
    name: &Name<'_>,
    addresses: &V,
    selector: AddressSelector<'_>,
) -> Result<(), PublishOnceError>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    V: AddressView + Sync,
{
    let endpoints: Vec<_> = addresses.endpoints(selector).collect();
    let packet = signer
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

pub(crate) fn clear_resolver_publish_state<R>(resolver: &R)
where
    R: ResolveDispatchTarget + ?Sized,
{
    clear_single_resolver_publish_state(resolver.as_resolve());
}

fn clear_single_resolver_publish_state(resolver: &(dyn Resolve + Send + Sync)) {
    let any = resolver as &dyn Any;

    #[cfg(feature = "resolvers")]
    if let Some(resolvers) = any.downcast_ref::<Resolvers>() {
        for resolver in resolvers.iter() {
            clear_single_resolver_publish_state(resolver.as_ref());
        }
    }

    #[cfg(all(feature = "h3", feature = "dquic-network"))]
    if let Some(h3) = any.downcast_ref::<crate::h3::H3Resolver<h3x::dquic::QuicEndpoint>>() {
        h3.clear_pool();
    }

    #[cfg(all(feature = "h3", feature = "dquic-network"))]
    if let Some(h3) = any.downcast_ref::<DeferredH3Resolver>()
        && let Some(h3) = h3.get()
    {
        h3.clear_pool();
    }
}
