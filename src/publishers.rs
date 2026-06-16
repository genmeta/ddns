#[cfg(feature = "publishers")]
mod address;
#[cfg(feature = "publishers")]
mod aggregate;
#[cfg(feature = "publishers")]
mod dispatch;
#[cfg(feature = "publishers")]
mod packet;
#[cfg(feature = "publishers")]
mod publisher;

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
use std::{any::TypeId, net::SocketAddr, time::Duration};
#[cfg(feature = "publishers")]
use std::{io, sync::Arc};

#[cfg(feature = "publishers")]
pub use address::{
    AddressSelector, AddressView, FnAddressView, PublishAddressGroup, PublishAddressScope,
    PublishAddresses, PublishScope,
};
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub use address::{AddressViewSource, EndpointBindingAddresses};
#[cfg(feature = "publishers")]
pub use aggregate::{Publishers, PublishersError};
#[cfg(feature = "publishers")]
use dhttp_identity::{identity::LocalAuthority, name::Name};
#[cfg(feature = "publishers")]
use dquic::qresolve::Resolve;
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
use dquic::{
    qinterface::component::location::AddressEvent, qtraversal::nat::client::ClientLocationData,
};
#[cfg(feature = "publishers")]
pub use packet::{EndpointRecordSigner, SignEndpointRecordsError};
#[cfg(feature = "publishers")]
pub use publisher::{Publisher, PublisherError};
#[cfg(feature = "publishers")]
use snafu::Snafu;

#[cfg(feature = "h3")]
pub use crate::h3::H3Resolver as H3Publisher;
#[cfg(feature = "http")]
pub use crate::http::HttpResolver as HttpPublisher;
#[cfg(feature = "mdns")]
pub use crate::mdns::MdnsPublisher;

#[cfg(feature = "publishers")]
#[derive(Debug, Snafu)]
#[snafu(module(create_publisher_error))]
pub enum CreatePublisherError {
    #[snafu(display("anonymous endpoint cannot publish dns records"))]
    AnonymousEndpoint,
}

#[cfg(feature = "publishers")]
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PublishOnceError {
    #[snafu(display("no publisher resolver available"))]
    NoPublisherResolver,
    #[snafu(display("failed to sign endpoint records"))]
    SignEndpointRecords { source: SignEndpointRecordsError },
    #[snafu(display("failed to publish dns packet with {publisher}"))]
    Publish {
        publisher: String,
        source: io::Error,
    },
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::from_secs(20);
/// Upper bound for a single publish attempt in the background loop.
///
/// Network changes can leave an in-flight H3 publish waiting on paths that no
/// longer exist. Timing out the attempt keeps consecutive publishes
/// independent: the next interval observes the current bindings again.
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
const PUBLISH_CHANGE_DEBOUNCE: Duration = Duration::from_millis(50);

#[cfg(feature = "publishers")]
#[derive(Clone)]
pub struct EndpointPublisher<
    A: ?Sized = dyn LocalAuthority + Send + Sync,
    R: ?Sized = dyn Resolve + Send + Sync,
> {
    signer: EndpointRecordSigner<A>,
    resolver: Arc<R>,
}

#[cfg(feature = "publishers")]
impl<A, R> EndpointPublisher<A, R>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: ?Sized,
{
    pub fn new(signer: EndpointRecordSigner<A>, resolver: Arc<R>) -> Self {
        Self { signer, resolver }
    }

    pub fn signer(&self) -> &EndpointRecordSigner<A> {
        &self.signer
    }

    pub fn resolver(&self) -> &Arc<R> {
        &self.resolver
    }
}

#[cfg(feature = "publishers")]
impl<A, R> EndpointPublisher<A, R>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: dispatch::ResolveDispatchTarget + ?Sized,
{
    pub async fn publish_once<V>(
        &self,
        name: &Name<'_>,
        addresses: &V,
    ) -> Result<(), PublishOnceError>
    where
        V: AddressView + Sync,
    {
        let published =
            dispatch::publish_to_resolver(self.signer(), self.resolver.as_ref(), name, addresses)
                .await?;
        if !published {
            return publish_once_error::NoPublisherResolverSnafu.fail();
        }
        Ok(())
    }
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub type EndpointPublisherLoop = EndpointPublicationLoop<
    dyn LocalAuthority + Send + Sync,
    dyn Resolve + Send + Sync,
    EndpointBindingAddresses,
>;

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub struct EndpointPublicationLoop<A: ?Sized, R: ?Sized, S> {
    name: Name<'static>,
    publisher: EndpointPublisher<A, R>,
    source: S,
    interval: Duration,
    publish_timeout: Duration,
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
impl<A, R, S> std::fmt::Debug for EndpointPublicationLoop<A, R, S>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: ?Sized,
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointPublicationLoop")
            .field("name", &self.name)
            .field("signer", self.publisher.signer())
            .field("source", &self.source)
            .field("interval", &self.interval)
            .field("publish_timeout", &self.publish_timeout)
            .finish()
    }
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
impl<A, R, S> EndpointPublicationLoop<A, R, S>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: dispatch::ResolveDispatchTarget + ?Sized,
    S: AddressViewSource + Sync,
{
    pub fn new(name: Name<'static>, publisher: EndpointPublisher<A, R>, source: S) -> Self {
        Self {
            name,
            publisher,
            source,
            interval: DEFAULT_PUBLISH_INTERVAL,
            publish_timeout: DEFAULT_PUBLISH_TIMEOUT,
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn publish_timeout(&self) -> Duration {
        self.publish_timeout
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    pub fn with_publish_timeout(mut self, timeout: Duration) -> Self {
        self.publish_timeout = timeout;
        self
    }

    pub async fn run(&self) -> ! {
        let mut locations = self.source.subscribe();
        let interval = tokio::time::sleep(self.interval);
        tokio::pin!(interval);
        let mut current_publish = self.new_publish_loop_future();

        loop {
            tokio::select! {
                _ = &mut current_publish => {
                    current_publish = Self::pending_publish_loop_future();
                }
                _ = &mut interval => {
                    interval.as_mut().reset(tokio::time::Instant::now() + self.interval);
                    self.clear_publish_state();
                    current_publish = self.new_publish_loop_future();
                }
                event = locations.recv() => {
                    let Some((bind_uri, event)) = event else {
                        continue;
                    };
                    if !self.source.observes(&bind_uri) {
                        continue;
                    }
                    if !Self::location_event_requires_publish(&event) {
                        continue;
                    }

                    self.clear_publish_state();
                    current_publish = self.new_publish_loop_future();
                }
            }
        }
    }

    fn new_publish_loop_future(&self) -> futures::future::BoxFuture<'_, ()> {
        Box::pin(async move {
            tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE).await;
            let _ = self.publish_attempt().await;
        })
    }

    fn pending_publish_loop_future<'a>() -> futures::future::BoxFuture<'a, ()> {
        Box::pin(std::future::pending())
    }

    async fn publish_attempt(&self) -> bool {
        tracing::trace!(
            timeout_ms = self.publish_timeout.as_millis(),
            name = %self.name,
            "starting dns publish attempt"
        );
        let view = self.source.address_view();
        match tokio::time::timeout(
            self.publish_timeout,
            self.publisher.publish_once(&self.name, &view),
        )
        .await
        {
            Ok(Ok(())) => {
                tracing::info!(name = %self.name, "published resolver endpoints");
                true
            }
            Ok(Err(error)) => {
                let report = snafu::Report::from_error(&error);
                tracing::warn!(error = %report, name = %self.name, "dns publish failed");
                false
            }
            Err(_elapsed) => {
                self.clear_publish_state();
                tracing::warn!(
                    timeout_ms = self.publish_timeout.as_millis(),
                    name = %self.name,
                    "dns publish timed out"
                );
                false
            }
        }
    }

    fn location_event_requires_publish(event: &AddressEvent) -> bool {
        match event {
            AddressEvent::Upsert(data) => {
                if let Some(bound_addr) = data.downcast_ref::<io::Result<SocketAddr>>() {
                    return bound_addr.is_ok();
                }
                if let Some(stun_addr) = data.downcast_ref::<ClientLocationData>() {
                    return stun_addr.is_ok();
                }
                false
            }
            AddressEvent::Remove(type_id) => {
                *type_id == TypeId::of::<io::Result<SocketAddr>>()
                    || *type_id == TypeId::of::<ClientLocationData>()
            }
            AddressEvent::Closed => true,
        }
    }

    fn clear_publish_state(&self) {
        dispatch::clear_resolver_publish_state(self.publisher.resolver().as_ref());
    }
}
