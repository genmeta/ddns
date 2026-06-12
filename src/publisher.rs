mod address;
mod dispatch;
mod packet;

use std::{any::TypeId, future::Future, io, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

pub use address::{
    AddressSelector, AddressView, AddressViewSource, EndpointBindingAddresses, FnAddressView,
    PublishAddressGroup, PublishAddressScope, PublishAddresses,
};
use dhttp_identity::{identity::LocalAuthority, name::Name};
use dquic::{
    qinterface::component::location::AddressEvent, qresolve::Resolve,
    qtraversal::nat::client::ClientLocationData,
};
pub use packet::{EndpointRecordSigner, SignEndpointRecordsError};
use snafu::Snafu;

pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::from_secs(20);
/// Upper bound for a single publish attempt in the background loop.
///
/// Network changes can leave an in-flight H3 publish waiting on paths that no
/// longer exist. Timing out the attempt keeps consecutive publishes
/// independent: the next interval observes the current bindings again.
pub const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLISH_CHANGE_DEBOUNCE: Duration = Duration::from_millis(50);

type PublishLoopFuture<'a> = Pin<Box<dyn Future<Output = ()> + Send + 'a>>;

#[derive(Debug, Snafu)]
#[snafu(module(create_publisher_error))]
pub enum CreatePublisherError {
    #[snafu(display("anonymous endpoint cannot publish dns records"))]
    AnonymousEndpoint,
}

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

/// Deprecated compatibility options for the old endpoint publisher API.
///
/// `server_id` is ignored. Endpoint record selectors are derived from the
/// publisher certificate's DHTTP subject key identifier.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PublishOptions {
    pub server_id: Option<u8>,
}

pub trait PublisherResolver: Send + Sync + 'static {
    fn as_resolver(&self) -> &(dyn Resolve + Send + Sync);
}

impl<T> PublisherResolver for T
where
    T: Resolve + Send + Sync + Sized + 'static,
{
    fn as_resolver(&self) -> &(dyn Resolve + Send + Sync) {
        self
    }
}

impl PublisherResolver for dyn Resolve + Send + Sync {
    fn as_resolver(&self) -> &(dyn Resolve + Send + Sync) {
        self
    }
}

pub struct Publisher<A: ?Sized, R: ?Sized> {
    signer: EndpointRecordSigner<A>,
    resolver: Arc<R>,
}

impl<A, R> std::fmt::Debug for Publisher<A, R>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: PublisherResolver + ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("signer", &self.signer)
            .field("resolver", &self.resolver.as_resolver().to_string())
            .finish()
    }
}

pub type EndpointPublisher = Publisher<dyn LocalAuthority + Send + Sync, dyn Resolve + Send + Sync>;

impl<A, R> Publisher<A, R>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: PublisherResolver + ?Sized,
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

    pub async fn publish_once<V>(
        &self,
        name: &Name<'_>,
        addresses: &V,
    ) -> Result<(), PublishOnceError>
    where
        V: AddressView + Sync,
    {
        let mut published = false;
        published |= self
            .publish_to_resolver(self.resolver.as_resolver(), name, addresses)
            .await?;

        if !published {
            return publish_once_error::NoPublisherResolverSnafu.fail();
        }

        Ok(())
    }
}

pub struct EndpointPublicationLoop<A: ?Sized, R: ?Sized, S> {
    name: Name<'static>,
    publisher: Publisher<A, R>,
    source: S,
    interval: Duration,
    publish_timeout: Duration,
}

impl<A, R, S> std::fmt::Debug for EndpointPublicationLoop<A, R, S>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: PublisherResolver + ?Sized,
    S: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointPublicationLoop")
            .field("name", &self.name)
            .field("publisher", &self.publisher)
            .field("source", &self.source)
            .field("interval", &self.interval)
            .field("publish_timeout", &self.publish_timeout)
            .finish()
    }
}

impl<A, R, S> EndpointPublicationLoop<A, R, S>
where
    A: LocalAuthority + Send + Sync + ?Sized,
    R: PublisherResolver + ?Sized,
    S: AddressViewSource + Send + Sync,
{
    pub fn new(name: Name<'static>, publisher: Publisher<A, R>, source: S) -> Self {
        Self {
            name,
            publisher,
            source,
            interval: DEFAULT_PUBLISH_INTERVAL,
            publish_timeout: DEFAULT_PUBLISH_TIMEOUT,
        }
    }

    pub fn name(&self) -> &Name<'static> {
        &self.name
    }

    pub fn publisher(&self) -> &Publisher<A, R> {
        &self.publisher
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn publish_timeout(&self) -> Duration {
        self.publish_timeout
    }

    pub fn with_publish_timeout(mut self, timeout: Duration) -> Self {
        self.publish_timeout = timeout;
        self
    }

    pub async fn run(&self) -> ! {
        let mut locations = self.source.subscribe();
        let interval = tokio::time::sleep(self.interval);
        tokio::pin!(interval);
        // Keep at most one publish attempt in flight. A timer tick or
        // publishable location change drops the current future and starts a new
        // debounced attempt so a stale H3 publish cannot block publication from
        // the latest bindings.
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

    fn new_publish_loop_future(&self) -> PublishLoopFuture<'_> {
        Box::pin(async move {
            tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE).await;
            let _ = self.publish_attempt().await;
        })
    }

    fn pending_publish_loop_future<'a>() -> PublishLoopFuture<'a> {
        Box::pin(std::future::pending())
    }

    async fn publish_attempt(&self) -> bool {
        tracing::trace!(
            timeout_ms = self.publish_timeout.as_millis(),
            "starting dns publish attempt"
        );
        let addresses = self.source.address_view();
        match tokio::time::timeout(
            self.publish_timeout,
            self.publisher.publish_once(&self.name, &addresses),
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
                // Dropping a timed-out publish future does not let the H3
                // resolver observe a request error. Reset resolver-owned
                // connection state so the next interval reconnects from
                // the current network bindings.
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

    fn clear_publish_state(&self) {
        dispatch::clear_resolver_publish_state(self.publisher.resolver.as_resolver());
    }

    fn location_event_requires_publish(event: &AddressEvent) -> bool {
        match event {
            AddressEvent::Upsert(data) => {
                // `Locations` also carries transient STUN failures. Those do
                // not add a publishable endpoint; treating them as publish
                // triggers creates a retry loop while the node is offline.
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
}

pub type EndpointPublisherLoop = EndpointPublicationLoop<
    dyn LocalAuthority + Send + Sync,
    dyn Resolve + Send + Sync,
    EndpointBindingAddresses,
>;

#[cfg(test)]
mod tests {
    #[cfg(feature = "http-resolver")]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::{fmt, sync::Arc, time::Duration};

    use dquic::qresolve::{ResolveFuture, Source};
    use futures::{FutureExt, StreamExt, future::BoxFuture, stream};
    use rustls::pki_types::{CertificateDer, SubjectPublicKeyInfoDer};
    #[cfg(feature = "http-resolver")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[derive(Debug)]
    struct TestAuthority;

    const ED25519_TEST_SPKI: [u8; 44] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    impl LocalAuthority for TestAuthority {
        fn name(&self) -> &str {
            "authority.example"
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            static CERTS: std::sync::LazyLock<Vec<CertificateDer<'static>>> =
                std::sync::LazyLock::new(|| {
                    vec![CertificateDer::from(
                        include_bytes!("../tests/fixtures/valid.der").to_vec(),
                    )]
                });
            CERTS.as_slice()
        }

        fn public_key(&self) -> SubjectPublicKeyInfoDer<'_> {
            SubjectPublicKeyInfoDer::from(ED25519_TEST_SPKI.as_slice())
        }

        fn sign(
            &self,
            _data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>> {
            // Match the Ed25519 signature length used by DHTTP's canonical
            // key-to-scheme policy. Short fake signatures can collide with
            // legacy E-record fixed RDLENGTH values during parser
            // compatibility dispatch.
            Box::pin(async move { Ok(vec![0x2a; 64]) })
        }
    }

    #[derive(Debug)]
    struct DisplayOnlyResolver;

    impl fmt::Display for DisplayOnlyResolver {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("display only resolver")
        }
    }

    impl Resolve for DisplayOnlyResolver {
        fn lookup<'l>(&'l self, _name: &'l str) -> ResolveFuture<'l> {
            async { Ok(stream::empty::<(Source, dquic::qbase::net::addr::EndpointAddr)>().boxed()) }
                .boxed()
        }
    }

    fn test_name() -> Name<'static> {
        "authority.example".parse().unwrap()
    }

    fn test_publisher<R>(resolver: Arc<R>) -> Publisher<TestAuthority, R>
    where
        R: Resolve + Send + Sync,
    {
        let signer = EndpointRecordSigner::new(Arc::new(TestAuthority));
        Publisher::new(signer, resolver)
    }

    fn test_source(network: Arc<h3x::dquic::Network>) -> EndpointBindingAddresses {
        EndpointBindingAddresses::new(
            network,
            Arc::new(vec![
                "inet://127.0.0.1:0".parse().expect("valid bind pattern"),
            ]),
        )
    }

    #[tokio::test]
    async fn publish_once_reports_no_publisher_resolver() {
        let publisher = test_publisher(Arc::new(DisplayOnlyResolver));
        let addresses =
            PublishAddresses::new().wide_area([dquic::qbase::net::addr::EndpointAddr::direct(
                "127.0.0.1:443".parse().unwrap(),
            )]);

        let error = publisher
            .publish_once(&test_name(), &addresses)
            .await
            .unwrap_err();

        assert!(matches!(error, PublishOnceError::NoPublisherResolver));
    }

    #[tokio::test]
    async fn publisher_timeout_is_configurable() {
        let network = h3x::dquic::Network::builder().build();
        let publisher = test_publisher(Arc::new(DisplayOnlyResolver));
        let publisher_loop =
            EndpointPublicationLoop::new(test_name(), publisher, test_source(network));
        assert_eq!(publisher_loop.publish_timeout(), DEFAULT_PUBLISH_TIMEOUT);

        let timeout = Duration::from_secs(3);
        let publisher_loop = publisher_loop.with_publish_timeout(timeout);
        assert_eq!(publisher_loop.publish_timeout(), timeout);
    }

    #[tokio::test]
    async fn signer_applies_certificate_selector_from_authority_ski() {
        let signer = EndpointRecordSigner::new(Arc::new(TestAuthority));
        let name: Name<'static> = "authority.example".parse().unwrap();

        let endpoint =
            dquic::qbase::net::addr::EndpointAddr::direct("127.0.0.1:443".parse().unwrap());
        let packet = signer.signed_packet(&name, &[endpoint]).await.unwrap();
        let (_remain, packet) = crate::core::parser::packet::be_packet(&packet).unwrap();
        let record = packet.answers.first().expect("endpoint answer");
        let crate::core::parser::record::RData::E(endpoint) = record.data() else {
            panic!("expected endpoint record");
        };

        assert!(endpoint.is_main());
        assert!(!endpoint.is_clustered());
        assert!(endpoint.is_signed());
        assert_eq!(
            endpoint.certificate_chain_key().unwrap().sequence().get(),
            0
        );
    }

    #[tokio::test]
    async fn signer_uses_supplied_record_owner_name() {
        let signer = EndpointRecordSigner::new(Arc::new(TestAuthority));
        let name: Name<'static> = "nat.genmeta.net".parse().unwrap();

        let endpoint =
            dquic::qbase::net::addr::EndpointAddr::direct("127.0.0.1:443".parse().unwrap());
        let packet = signer.signed_packet(&name, &[endpoint]).await.unwrap();
        let (_remain, packet) = crate::core::parser::packet::be_packet(&packet).unwrap();
        let record = packet.answers.first().expect("endpoint answer");
        let crate::core::parser::record::RData::E(endpoint) = record.data() else {
            panic!("expected endpoint record");
        };

        assert_eq!(record.name().to_string(), "nat.genmeta.net");
        assert!(endpoint.is_main());
        assert!(!endpoint.is_clustered());
        assert!(endpoint.is_signed());
    }

    #[tokio::test]
    async fn binding_address_view_does_not_expose_loopback_as_wide_area_without_stun() {
        let network = h3x::dquic::Network::builder().build();
        let bind_pattern: h3x::dquic::binds::BindPattern =
            "inet://127.0.0.1:0".parse().expect("valid bind pattern");
        let _bind = network.quic().bind(bind_pattern.clone()).await;
        let source = EndpointBindingAddresses::new(network, Arc::new(vec![bind_pattern]));
        let view = source.address_view();

        assert!(view.endpoints(AddressSelector::WideArea).next().is_none());
    }

    #[cfg(feature = "http-resolver")]
    #[tokio::test]
    async fn run_restarts_when_publish_attempt_observes_location_change() {
        async fn wait_for_count(count: &AtomicUsize, target: usize) {
            loop {
                if count.load(Ordering::SeqCst) >= target {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let network = h3x::dquic::Network::builder().build();
        let bind_uri: h3x::dquic::net::BindUri =
            "inet://127.0.0.1:0".parse().expect("valid bind uri");
        let publish_count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test http server");
        let port = listener.local_addr().expect("local addr").port();
        let server_network = network.clone();
        let server_bind_uri = bind_uri.clone();
        let server_count = publish_count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let current = server_count.fetch_add(1, Ordering::SeqCst) + 1;
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).await;
                if current == 2 {
                    server_network.quic().locations().upsert(
                        server_bind_uri.clone(),
                        Arc::new(Ok::<std::net::SocketAddr, io::Error>(
                            "127.0.0.1:10001".parse().expect("valid socket addr"),
                        )),
                    );
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });

        let resolver = Arc::new(
            crate::resolvers::http::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let publisher = test_publisher(resolver);
        let source = test_source(network.clone());
        let mut publisher_loop = EndpointPublicationLoop::new(test_name(), publisher, source);
        publisher_loop.interval = Duration::from_secs(60);

        let publisher = tokio::spawn(async move {
            publisher_loop.run().await;
        });

        wait_for_count(&publish_count, 1).await;
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(100)).await;
        network.quic().locations().upsert(
            bind_uri,
            Arc::new(Ok::<std::net::SocketAddr, io::Error>(
                "127.0.0.1:10000".parse().expect("valid socket addr"),
            )),
        );

        tokio::time::timeout(Duration::from_secs(2), wait_for_count(&publish_count, 2))
            .await
            .expect("publishable location changes should trigger the next independent publish");

        tokio::time::timeout(
            PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(500),
            wait_for_count(&publish_count, 3),
        )
        .await
        .expect("publishable location events should replace the current publish attempt");

        publisher.abort();
        server.abort();
    }

    #[cfg(feature = "http-resolver")]
    #[tokio::test]
    async fn run_ignores_transient_location_failures_generated_during_publish_attempt() {
        async fn wait_for_count(count: &AtomicUsize, target: usize) {
            loop {
                if count.load(Ordering::SeqCst) >= target {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let network = h3x::dquic::Network::builder().build();
        let bind_uri: h3x::dquic::net::BindUri =
            "inet://127.0.0.1:0".parse().expect("valid bind uri");
        let publish_count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test http server");
        let port = listener.local_addr().expect("local addr").port();
        let server_network = network.clone();
        let server_bind_uri = bind_uri.clone();
        let server_count = publish_count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).await;
                server_count.fetch_add(1, Ordering::SeqCst);
                server_network
                    .quic()
                    .locations()
                    .upsert::<ClientLocationData>(
                        server_bind_uri.clone(),
                        Arc::new(Err(
                            dquic::qtraversal::nat::client::DetectOuterAddrError::Rebinded {
                                bind_uri: server_bind_uri.clone(),
                            },
                        )),
                    );
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });

        let resolver = Arc::new(
            crate::resolvers::http::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let publisher = test_publisher(resolver);
        let source = test_source(network.clone());
        let publisher_loop = EndpointPublicationLoop::new(test_name(), publisher, source);
        let publisher = tokio::spawn(async move {
            publisher_loop.run().await;
        });

        wait_for_count(&publish_count, 1).await;
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(100)).await;

        network.quic().locations().upsert(
            bind_uri,
            Arc::new(Ok::<std::net::SocketAddr, io::Error>(
                "127.0.0.1:0".parse().expect("valid socket addr"),
            )),
        );
        wait_for_count(&publish_count, 2).await;

        let third_publish = tokio::time::timeout(
            PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(500),
            wait_for_count(&publish_count, 3),
        )
        .await;

        publisher.abort();
        server.abort();

        assert!(
            third_publish.is_err(),
            "publish-generated location events must not trigger another immediate publish"
        );
    }

    #[cfg(feature = "http-resolver")]
    #[tokio::test]
    async fn run_does_not_retry_location_publish_after_timeout() {
        async fn wait_for_count(count: &AtomicUsize, target: usize) {
            loop {
                if count.load(Ordering::SeqCst) >= target {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let network = h3x::dquic::Network::builder().build();
        let bind_uri: h3x::dquic::net::BindUri =
            "inet://127.0.0.1:0".parse().expect("valid bind uri");
        let publish_count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test http server");
        let port = listener.local_addr().expect("local addr").port();
        let server_count = publish_count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let current = server_count.fetch_add(1, Ordering::SeqCst) + 1;
                let mut buf = [0_u8; 1024];
                let _ = stream.read(&mut buf).await;
                if current == 2 {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });

        let resolver = Arc::new(
            crate::resolvers::http::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let publisher = test_publisher(resolver);
        let source = test_source(network.clone());
        let mut publisher_loop = EndpointPublicationLoop::new(test_name(), publisher, source)
            .with_publish_timeout(Duration::from_millis(50));
        publisher_loop.interval = Duration::from_secs(60);

        let publisher = tokio::spawn(async move {
            publisher_loop.run().await;
        });

        wait_for_count(&publish_count, 1).await;
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(100)).await;
        network.quic().locations().upsert(
            bind_uri,
            Arc::new(Ok::<std::net::SocketAddr, io::Error>(
                "127.0.0.1:0".parse().expect("valid socket addr"),
            )),
        );

        wait_for_count(&publish_count, 2).await;
        let third_publish = tokio::time::timeout(
            PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(500),
            wait_for_count(&publish_count, 3),
        )
        .await;

        publisher.abort();
        server.abort();

        assert!(
            third_publish.is_err(),
            "timed out location-triggered publish must not be retried before the next interval"
        );
    }

    #[cfg(feature = "http-resolver")]
    #[tokio::test]
    async fn run_replaces_in_flight_publish_on_publishable_location_change() {
        async fn wait_for_count(count: &AtomicUsize, target: usize) {
            loop {
                if count.load(Ordering::SeqCst) >= target {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }

        let network = h3x::dquic::Network::builder().build();
        let bind_uri: h3x::dquic::net::BindUri =
            "inet://127.0.0.1:0".parse().expect("valid bind uri");
        let publish_count = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test http server");
        let port = listener.local_addr().expect("local addr").port();
        let server_count = publish_count.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _peer)) = listener.accept().await else {
                    break;
                };
                let current = server_count.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let mut buf = [0_u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    if current == 1 {
                        std::future::pending::<()>().await;
                    }
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                        .await;
                });
            }
        });

        let resolver = Arc::new(
            crate::resolvers::http::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let publisher = test_publisher(resolver);
        let source = test_source(network.clone());
        let mut publisher_loop = EndpointPublicationLoop::new(test_name(), publisher, source)
            .with_publish_timeout(Duration::from_secs(30));
        publisher_loop.interval = Duration::from_secs(60);

        let publisher = tokio::spawn(async move {
            publisher_loop.run().await;
        });

        tokio::time::timeout(Duration::from_secs(2), wait_for_count(&publish_count, 1))
            .await
            .expect("initial publish should start");

        network.quic().locations().upsert(
            bind_uri,
            Arc::new(Ok::<std::net::SocketAddr, io::Error>(
                "127.0.0.1:10000".parse().expect("valid socket addr"),
            )),
        );

        tokio::time::timeout(
            PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(800),
            wait_for_count(&publish_count, 2),
        )
        .await
        .expect("publishable location change should replace the in-flight publish");

        publisher.abort();
        server.abort();
    }
}
