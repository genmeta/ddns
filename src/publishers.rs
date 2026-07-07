#[cfg(feature = "publishers")]
mod address;
#[cfg(feature = "publishers")]
mod aggregate;
#[cfg(feature = "publishers")]
pub(crate) mod packet;
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
pub use aggregate::{PublishReport, PublisherSuccess, Publishers, PublishersError};
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
            Ok(Ok(report)) if report.is_complete() => {
                tracing::debug!(name = %self.name, publishers = %report, "published resolver endpoints");
                true
            }
            Ok(Ok(report)) => {
                tracing::warn!(error = %report, name = %self.name, "dns publish partially failed");
                true
            }
            Ok(Err(error)) => {
                let report = snafu::Report::from_error(&error);
                tracing::error!(error = %report, name = %self.name, "dns publish failed");
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
        fmt, io,
        sync::{
            Arc, Mutex,
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
    use tracing::{Event, Level, Subscriber, field::Visit};
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

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
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let _endpoints: Vec<_> = endpoints.collect();
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
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let _endpoints: Vec<_> = endpoints.collect();
            let delay = self.delay;
            async move {
                tokio::time::sleep(delay).await;
                Ok(())
            }
            .boxed()
        }
    }

    #[derive(Debug)]
    struct OkPublisher(&'static str);

    impl fmt::Display for OkPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Publish for OkPublisher {
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let _endpoints: Vec<_> = endpoints.collect();
            async move { Ok(()) }.boxed()
        }
    }

    #[derive(Debug)]
    struct FailingPublisher(&'static str);

    impl fmt::Display for FailingPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Publish for FailingPublisher {
        fn publish<'a>(
            &'a self,
            _name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let _endpoints: Vec<_> = endpoints.collect();
            async move { Err(io::Error::other("publish rejected")) }.boxed()
        }
    }

    #[derive(Clone, Debug)]
    struct CapturedLog {
        level: Level,
        message: String,
    }

    #[derive(Clone, Debug, Default)]
    struct CapturedLogs {
        logs: Arc<Mutex<Vec<CapturedLog>>>,
    }

    impl CapturedLogs {
        fn records(&self) -> Vec<CapturedLog> {
            self.logs.lock().expect("captured logs lock").clone()
        }
    }

    impl<S> Layer<S> for CapturedLogs
    where
        S: Subscriber,
    {
        fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
            let mut visitor = MessageVisitor::default();
            event.record(&mut visitor);
            self.logs
                .lock()
                .expect("captured logs lock")
                .push(CapturedLog {
                    level: *event.metadata().level(),
                    message: visitor.message.unwrap_or_default(),
                });
        }
    }

    #[derive(Default)]
    struct MessageVisitor {
        message: Option<String>,
    }

    impl Visit for MessageVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.message = Some(value.to_owned());
            }
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
            if field.name() == "message" {
                self.message = Some(format!("{value:?}"));
            }
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

    fn bind_uri() -> BindUri {
        "iface://v4.eth0:0/".parse().expect("bind uri")
    }

    async fn capture_publish_attempt_logs(publishers: Publishers) -> Vec<CapturedLog> {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::registry().with(logs.clone());
        let _guard = tracing::subscriber::set_default(subscriber);
        let loop_ = EndpointPublicationLoop::new(name(), publishers, TestSource::new(bind_uri()));

        let _ = loop_.publish_attempt().await;

        logs.records()
    }

    fn level_for_message(logs: &[CapturedLog], message: &str) -> Option<Level> {
        logs.iter()
            .find(|log| log.message == message)
            .map(|log| log.level)
    }

    #[tokio::test]
    async fn publication_loop_logs_complete_success_at_debug() {
        let publishers = Publishers::new().with(Publisher::new(
            PublishScope::WideArea,
            Arc::new(OkPublisher("working publisher")),
        ));

        let logs = capture_publish_attempt_logs(publishers).await;

        assert_eq!(
            level_for_message(&logs, "published resolver endpoints"),
            Some(Level::DEBUG)
        );
    }

    #[tokio::test]
    async fn publication_loop_logs_partial_success_at_warn() {
        let publishers = Publishers::new()
            .with(Publisher::new(
                PublishScope::WideArea,
                Arc::new(OkPublisher("working publisher")),
            ))
            .with(Publisher::new(
                PublishScope::WideArea,
                Arc::new(FailingPublisher("failing publisher")),
            ));

        let logs = capture_publish_attempt_logs(publishers).await;

        assert_eq!(
            level_for_message(&logs, "dns publish partially failed"),
            Some(Level::WARN)
        );
    }

    #[tokio::test]
    async fn publication_loop_logs_all_failures_at_error() {
        let publishers = Publishers::new().with(Publisher::new(
            PublishScope::WideArea,
            Arc::new(FailingPublisher("failing publisher")),
        ));

        let logs = capture_publish_attempt_logs(publishers).await;

        assert_eq!(
            level_for_message(&logs, "dns publish failed"),
            Some(Level::ERROR)
        );
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
