#[cfg(feature = "publishers")]
mod address;
#[cfg(feature = "publishers")]
mod aggregate;
#[cfg(feature = "publishers")]
mod packet;
#[cfg(feature = "publishers")]
mod publisher;

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
use std::{any::TypeId, net::SocketAddr, time::Duration};

#[cfg(feature = "publishers")]
pub use address::{
    AddressSelector, AddressView, FnAddressView, PublishAddressGroup, PublishAddresses,
    PublishScope,
};
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub use address::{AddressViewSource, EndpointBindingAddresses};
#[cfg(feature = "publishers")]
pub use aggregate::{Publishers, PublishersError};
#[cfg(feature = "publishers")]
use dhttp_identity::name::Name;
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
use dquic::{
    qinterface::component::location::AddressEvent, qtraversal::nat::client::ClientLocationData,
};
#[cfg(feature = "publishers")]
pub use publisher::{Publisher, PublisherError};

#[cfg(feature = "h3")]
pub use crate::h3::H3Resolver as H3Publisher;
#[cfg(feature = "http")]
pub use crate::http::HttpResolver as HttpPublisher;
#[cfg(feature = "mdns")]
pub use crate::mdns::MdnsPublisher;

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::from_secs(20);
/// Upper bound for a single publish attempt in the background loop.
///
/// Network changes can leave an in-flight publish waiting on paths that no
/// longer exist. Timing out the attempt keeps consecutive publishes
/// independent: the next interval observes the current bindings again.
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
const PUBLISH_CHANGE_DEBOUNCE: Duration = Duration::from_millis(50);

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub struct EndpointPublicationLoop<S> {
    name: Name<'static>,
    publishers: Publishers,
    source: S,
    interval: Duration,
    publish_timeout: Duration,
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
impl<S> std::fmt::Debug for EndpointPublicationLoop<S>
where
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointPublicationLoop")
            .field("name", &self.name)
            .field("publishers", &self.publishers)
            .field("source", &self.source)
            .field("interval", &self.interval)
            .field("publish_timeout", &self.publish_timeout)
            .finish()
    }
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
impl<S> EndpointPublicationLoop<S>
where
    S: AddressViewSource + Sync,
{
    pub fn new(name: Name<'static>, publishers: Publishers, source: S) -> Self {
        Self {
            name,
            publishers,
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
            self.publishers.publish(&self.name, &view),
        )
        .await
        {
            Ok(Ok(())) => {
                tracing::info!(name = %self.name, "published resolver endpoints");
                true
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, name = %self.name, "dns publish failed");
                false
            }
            Err(_elapsed) => {
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
                if let Some(bound_addr) = data.downcast_ref::<std::io::Result<SocketAddr>>() {
                    return bound_addr.is_ok();
                }
                if let Some(stun_addr) = data.downcast_ref::<ClientLocationData>() {
                    return stun_addr.is_ok();
                }
                false
            }
            AddressEvent::Remove(type_id) => {
                *type_id == TypeId::of::<std::io::Result<SocketAddr>>()
                    || *type_id == TypeId::of::<ClientLocationData>()
            }
            AddressEvent::Closed => true,
        }
    }
}
