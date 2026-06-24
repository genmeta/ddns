#[cfg(feature = "publishers")]
mod address;
#[cfg(feature = "publishers")]
mod aggregate;
#[cfg(feature = "publishers")]
mod packet;
#[cfg(feature = "publishers")]
mod publisher;

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

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
use dquic::qinterface::component::local_endpoint::InterfaceEndpointUpdate;
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
///
/// This timeout must stay above the QUIC endpoint's default connect-path
/// timeout (20s) so a publish attempt can survive the transport's own path
/// discovery window instead of being aborted before connect has a chance to
/// complete.
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
pub const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(all(feature = "publishers", feature = "dquic-network"))]
const PUBLISH_CHANGE_DEBOUNCE: Duration = Duration::from_millis(50);

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
struct ScheduledPublish<'a> {
    future: futures::future::BoxFuture<'a, ()>,
    attempt_started: Arc<AtomicBool>,
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
impl ScheduledPublish<'_> {
    fn attempt_started(&self) -> bool {
        self.attempt_started.load(Ordering::SeqCst)
    }
}

#[cfg(all(feature = "publishers", feature = "dquic-network"))]
impl Future for ScheduledPublish<'_> {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

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
        let mut local_endpoints = self.source.subscribe();
        let interval = tokio::time::sleep(self.interval);
        tokio::pin!(interval);
        let mut current_publish = Some(self.new_publish_loop_future());

        loop {
            tokio::select! {
                _ = async {
                    match current_publish.as_mut() {
                        Some(current_publish) => current_publish.await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    current_publish = None;
                }
                _ = &mut interval => {
                    interval.as_mut().reset(tokio::time::Instant::now() + self.interval);
                    if current_publish
                        .as_ref()
                        .is_some_and(ScheduledPublish::attempt_started)
                    {
                        continue;
                    }
                    current_publish = Some(self.new_publish_loop_future());
                }
                update = local_endpoints.recv() => {
                    let Some((bind_uri, update)) = update else {
                        continue;
                    };
                    if !self.source.observes(&bind_uri) {
                        continue;
                    }
                    if !Self::local_endpoint_update_requires_publish(&update) {
                        continue;
                    }

                    current_publish = Some(self.new_publish_loop_future());
                }
            }
        }
    }

    fn new_publish_loop_future(&self) -> ScheduledPublish<'_> {
        let attempt_started = Arc::new(AtomicBool::new(false));
        let mark_attempt_started = attempt_started.clone();
        ScheduledPublish {
            future: Box::pin(async move {
                tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE).await;
                mark_attempt_started.store(true, Ordering::SeqCst);
                let _ = self.publish_attempt().await;
            }),
            attempt_started,
        }
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

    fn local_endpoint_update_requires_publish(update: &InterfaceEndpointUpdate) -> bool {
        match update {
            InterfaceEndpointUpdate::Upsert { .. }
            | InterfaceEndpointUpdate::Remove { .. }
            | InterfaceEndpointUpdate::Close => true,
        }
    }
}

#[cfg(all(test, feature = "publishers", feature = "dquic-network"))]
mod tests {
    use std::{
        fmt,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use dhttp_identity::name::Name;
    use dquic::{
        qbase::net::addr::EndpointAddr,
        qinterface::component::local_endpoint::{
            InterfaceEndpointKey, InterfaceEndpointUpdate, LocalEndpointSubscriber, LocalEndpoints,
        },
        qresolve::{Publish, PublishFuture},
    };
    use futures::FutureExt;
    use h3x::dquic::net::BindUri;
    use tokio::sync::Notify;

    use super::{
        AddressView, AddressViewSource, EndpointPublicationLoop, PublishAddresses, PublishScope,
        Publisher, Publishers,
    };

    #[derive(Debug, Default)]
    struct PublishState {
        started: AtomicUsize,
        completed: AtomicUsize,
        canceled: AtomicUsize,
        releases: AtomicUsize,
        release_notify: Notify,
    }

    impl PublishState {
        fn allow_attempts(&self, count: usize) {
            self.releases.store(count, Ordering::SeqCst);
            self.release_notify.notify_waiters();
        }
    }

    struct AttemptGuard {
        state: Arc<PublishState>,
        completed: AtomicBool,
    }

    impl AttemptGuard {
        fn new(state: Arc<PublishState>) -> Self {
            Self {
                state,
                completed: AtomicBool::new(false),
            }
        }

        fn complete(&self) {
            self.completed.store(true, Ordering::SeqCst);
        }
    }

    impl Drop for AttemptGuard {
        fn drop(&mut self) {
            if !self.completed.load(Ordering::SeqCst) {
                self.state.canceled.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    #[derive(Debug)]
    struct BlockingPublisher {
        state: Arc<PublishState>,
    }

    impl fmt::Display for BlockingPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("blocking publisher")
        }
    }

    impl Publish for BlockingPublisher {
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            let state = self.state.clone();
            async move {
                let attempt = state.started.fetch_add(1, Ordering::SeqCst) + 1;

                let guard = AttemptGuard::new(state.clone());
                loop {
                    if state.releases.load(Ordering::SeqCst) >= attempt {
                        guard.complete();
                        state.completed.fetch_add(1, Ordering::SeqCst);
                        return Ok(());
                    }

                    state.release_notify.notified().await;
                }
            }
            .boxed()
        }
    }

    #[derive(Debug)]
    struct DelayedPublisher {
        delay: Duration,
    }

    impl fmt::Display for DelayedPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("delayed publisher")
        }
    }

    impl Publish for DelayedPublisher {
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            let delay = self.delay;
            async move {
                tokio::time::sleep(delay).await;
                Ok(())
            }
            .boxed()
        }
    }

    #[derive(Clone)]
    struct TestSource {
        bind_uri: BindUri,
        local_endpoints: Arc<LocalEndpoints>,
        addresses: PublishAddresses,
    }

    impl TestSource {
        fn new(bind_uri: BindUri) -> Self {
            Self {
                bind_uri,
                local_endpoints: Arc::new(LocalEndpoints::new()),
                addresses: PublishAddresses::new().wide_area([EndpointAddr::direct(
                    "127.0.0.1:4433".parse().expect("socket address"),
                )]),
            }
        }

        fn notify_publishable_local_endpoint(&self) {
            let publishers = self.local_endpoints.publisher(self.bind_uri.clone());
            let mut direct = publishers
                .direct_endpoint_publisher()
                .expect("direct endpoint publisher");
            assert!(direct.upsert("127.0.0.1:4433".parse().expect("socket address")));
        }
    }

    impl AddressViewSource for TestSource {
        fn address_view(&self) -> impl AddressView + Send + Sync + '_ {
            self.addresses.clone()
        }

        fn subscribe(&self) -> LocalEndpointSubscriber {
            self.local_endpoints.subscribe()
        }

        fn observes(&self, bind_uri: &BindUri) -> bool {
            bind_uri == &self.bind_uri
        }
    }

    async fn wait_until(description: &str, timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if predicate() {
                return;
            }

            if tokio::time::Instant::now() >= deadline {
                panic!("timed out waiting for {description}");
            }

            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn name() -> Name<'static> {
        "alice.dhttp.net".parse().expect("valid name")
    }

    #[test]
    fn typed_local_endpoint_updates_require_publication_refresh() {
        let direct = InterfaceEndpointUpdate::Upsert {
            key: InterfaceEndpointKey::Direct,
            endpoint: EndpointAddr::direct("127.0.0.1:12345".parse().expect("addr")),
        };
        let remove = InterfaceEndpointUpdate::Remove {
            key: InterfaceEndpointKey::Direct,
        };
        let close = InterfaceEndpointUpdate::Close;

        assert!(
            EndpointPublicationLoop::<TestSource>::local_endpoint_update_requires_publish(&direct)
        );
        assert!(
            EndpointPublicationLoop::<TestSource>::local_endpoint_update_requires_publish(&remove)
        );
        assert!(
            EndpointPublicationLoop::<TestSource>::local_endpoint_update_requires_publish(&close)
        );
    }

    #[tokio::test]
    async fn publication_loop_replaces_inflight_publish_when_location_changes() {
        let bind_uri: BindUri = "iface://v4.eth0:0/".parse().expect("bind uri");
        let source = TestSource::new(bind_uri);
        let state = Arc::new(PublishState::default());
        let publishers = Publishers::new().with(Publisher::new(
            PublishScope::WideArea,
            Arc::new(BlockingPublisher {
                state: state.clone(),
            }),
        ));
        let loop_ = EndpointPublicationLoop::new(name(), publishers, source.clone())
            .with_interval(Duration::from_secs(60))
            .with_publish_timeout(Duration::from_secs(60));

        let task = tokio::spawn(async move {
            loop_.run().await;
        });

        wait_until(
            "initial publish attempt to start",
            Duration::from_secs(1),
            || state.started.load(Ordering::SeqCst) == 1,
        )
        .await;

        source.notify_publishable_local_endpoint();

        wait_until(
            "replacement publish attempt to start after the location update",
            Duration::from_secs(1),
            || state.started.load(Ordering::SeqCst) == 2,
        )
        .await;

        assert_eq!(
            state.canceled.load(Ordering::SeqCst),
            1,
            "location updates should cancel the stale in-flight publish attempt"
        );

        state.allow_attempts(2);
        wait_until(
            "replacement publish attempt to complete",
            Duration::from_secs(1),
            || state.completed.load(Ordering::SeqCst) == 1,
        )
        .await;

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn publication_loop_interval_does_not_cancel_active_publish_attempt() {
        let bind_uri: BindUri = "iface://v4.eth0:0/".parse().expect("bind uri");
        let source = TestSource::new(bind_uri);
        let state = Arc::new(PublishState::default());
        let publishers = Publishers::new().with(Publisher::new(
            PublishScope::WideArea,
            Arc::new(BlockingPublisher {
                state: state.clone(),
            }),
        ));
        let loop_ = EndpointPublicationLoop::new(name(), publishers, source)
            .with_interval(Duration::from_millis(120))
            .with_publish_timeout(Duration::from_secs(1));

        let task = tokio::spawn(async move {
            loop_.run().await;
        });

        wait_until(
            "initial publish attempt to start",
            Duration::from_secs(1),
            || state.started.load(Ordering::SeqCst) == 1,
        )
        .await;

        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            state.started.load(Ordering::SeqCst),
            1,
            "interval ticks should not schedule a replacement while the publish is still active"
        );
        assert_eq!(
            state.canceled.load(Ordering::SeqCst),
            0,
            "interval ticks should not cancel the active publish attempt"
        );

        state.allow_attempts(1);
        wait_until(
            "active publish attempt to complete",
            Duration::from_secs(1),
            || state.completed.load(Ordering::SeqCst) == 1,
        )
        .await;

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn default_publish_timeout_allows_slow_publish_attempts_to_finish() {
        let bind_uri: BindUri = "iface://v4.eth0:0/".parse().expect("bind uri");
        let source = TestSource::new(bind_uri);
        let publishers = Publishers::new().with(Publisher::new(
            PublishScope::WideArea,
            Arc::new(DelayedPublisher {
                delay: Duration::from_secs(11),
            }),
        ));
        let loop_ = EndpointPublicationLoop::new(name(), publishers, source);

        assert!(
            loop_.publish_attempt().await,
            "default publish timeout should allow a slow publish attempt to finish"
        );
    }
}
