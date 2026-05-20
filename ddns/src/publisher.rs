use std::{
    any::{Any, TypeId},
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use ddns_core::{
    MdnsPacket,
    parser::record::endpoint::{EndpointAddr as DnsEndpointAddr, SignEndpointError},
};
use dhttp_identity::identity::LocalAgent;
#[cfg(feature = "mdns-resolver")]
use dquic::qbase::net::Family;
use dquic::{
    qbase::net::addr::EndpointAddr,
    qinterface::component::location::AddressEvent,
    qresolve::{Publish, Resolve},
    qtraversal::nat::client::{ClientLocationData, NatType},
};
use snafu::{ResultExt, Snafu};

use crate::resolvers::Resolvers;

pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::from_secs(20);
/// Upper bound for a single publish attempt in the background loop.
///
/// Network changes can leave an in-flight H3 publish waiting on paths that no
/// longer exist. Timing out the attempt keeps consecutive publishes
/// independent: the next interval observes the current bindings again.
pub const DEFAULT_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const PUBLISH_CHANGE_DEBOUNCE: Duration = Duration::from_millis(500);

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
    #[snafu(display("failed to encode endpoint address"))]
    EncodeEndpoint,
    #[snafu(display("failed to sign endpoint address"))]
    SignEndpoint { source: SignEndpointError },
    #[snafu(display("failed to publish dns packet with {publisher}"))]
    Publish {
        publisher: String,
        source: io::Error,
    },
}

/// Optional metadata applied to endpoint records before signing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PublishOptions {
    /// Stable server identifier for names served by multiple publishers.
    ///
    /// `0` marks the endpoint as the main record. Non-zero values mark the
    /// record as clustered and encode the identifier as its sequence number.
    pub server_id: Option<u8>,
}

pub struct Publisher {
    identity: Arc<dyn LocalAgent>,
    network: Arc<h3x::dquic::Network>,
    resolver: Arc<dyn Resolve + Send + Sync>,
    bind_patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    interval: Duration,
    publish_timeout: Duration,
    options: PublishOptions,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("identity", &self.identity.name())
            .field("bind_patterns", &self.bind_patterns)
            .field("interval", &self.interval)
            .field("publish_timeout", &self.publish_timeout)
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

impl Publisher {
    pub fn new(
        identity: Arc<dyn LocalAgent>,
        network: Arc<h3x::dquic::Network>,
        resolver: Arc<dyn Resolve + Send + Sync>,
        bind_patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    ) -> Self {
        Self {
            identity,
            network,
            resolver,
            bind_patterns,
            interval: DEFAULT_PUBLISH_INTERVAL,
            publish_timeout: DEFAULT_PUBLISH_TIMEOUT,
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

    pub async fn publish_once(&self) -> Result<(), PublishOnceError> {
        let mut published = false;
        let public_endpoints = self.public_endpoints();
        tracing::debug!(
            endpoint_count = public_endpoints.len(),
            endpoints = ?public_endpoints,
            "publishing public endpoints"
        );
        published |= self
            .publish_to_resolver(self.resolver.as_ref(), &public_endpoints)
            .await?;

        if !published {
            return publish_once_error::NoPublisherResolverSnafu.fail();
        }

        Ok(())
    }

    pub async fn run(&self) -> ! {
        let mut locations = self.network.locations().subscribe();
        let _ = self.publish_attempt().await;
        let _ = self.settle_publish_events(&mut locations).await;

        loop {
            self.wait_next_publish_trigger(&mut locations).await;
            let _ = self.publish_attempt().await;
            let _ = self.settle_publish_events(&mut locations).await;
        }
    }

    async fn publish_attempt(&self) -> bool {
        tracing::trace!(
            timeout_ms = self.publish_timeout.as_millis(),
            "starting dns publish attempt"
        );
        match tokio::time::timeout(self.publish_timeout, self.publish_once()).await {
            Ok(Ok(())) => {
                tracing::info!("published resolver endpoints");
                true
            }
            Ok(Err(error)) => {
                let report = snafu::Report::from_error(&error);
                tracing::warn!(error = %report, "dns publish failed");
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
                    "dns publish timed out"
                );
                false
            }
        }
    }

    async fn wait_next_publish_trigger(
        &self,
        locations: &mut h3x::dquic::qinterface::component::location::Observer,
    ) {
        let interval = tokio::time::sleep(self.interval);
        tokio::pin!(interval);

        loop {
            tokio::select! {
                _ = &mut interval => return,
                event = locations.recv() => {
                    let Some((bind_uri, event)) = event else {
                        interval.await;
                        return;
                    };
                    if !self.bind_patterns.iter().any(|pattern| pattern.matches(&bind_uri)) {
                        continue;
                    }
                    if !Self::location_event_requires_publish(&event) {
                        continue;
                    }

                    // A local-address change invalidates cached H3 DNS
                    // connections even if no request has failed yet. Clear
                    // resolver-owned connection state before publishing from
                    // the new binding set.
                    self.clear_publish_state();
                    tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE).await;
                    self.drain_location_events(locations);
                    return;
                }
            }
        }
    }

    fn drain_location_events(
        &self,
        locations: &mut h3x::dquic::qinterface::component::location::Observer,
    ) -> bool {
        let mut requires_publish = false;
        while let Ok((bind_uri, event)) = locations.try_recv() {
            if !self
                .bind_patterns
                .iter()
                .any(|pattern| pattern.matches(&bind_uri))
            {
                continue;
            }
            if Self::location_event_requires_publish(&event) {
                self.clear_publish_state();
                requires_publish = true;
            }
        }
        requires_publish
    }

    async fn settle_publish_events(
        &self,
        locations: &mut h3x::dquic::qinterface::component::location::Observer,
    ) -> bool {
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE).await;
        self.drain_location_events(locations)
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

    async fn publish_to_resolver(
        &self,
        resolver: &(dyn Resolve + Send + Sync),
        public_endpoints: &[EndpointAddr],
    ) -> Result<bool, PublishOnceError> {
        let any: &dyn Any = resolver;

        if let Some(resolvers) = any.downcast_ref::<Resolvers>() {
            let mut published = false;
            for resolver in resolvers.iter() {
                published |= self
                    .publish_single_resolver(resolver.as_ref(), public_endpoints)
                    .await?;
            }
            return Ok(published);
        }

        self.publish_single_resolver(resolver, public_endpoints)
            .await
    }

    fn clear_publish_state(&self) {
        Self::clear_resolver_publish_state(self.resolver.as_ref());
    }

    fn clear_resolver_publish_state(resolver: &(dyn Resolve + Send + Sync)) {
        let any: &dyn Any = resolver;

        if let Some(resolvers) = any.downcast_ref::<Resolvers>() {
            for resolver in resolvers.iter() {
                Self::clear_resolver_publish_state(resolver.as_ref());
            }
        }

        #[cfg(feature = "h3x-resolver")]
        if let Some(h3) =
            any.downcast_ref::<crate::resolvers::H3Resolver<h3x::dquic::QuicEndpoint>>()
        {
            h3.clear_pool();
        }
    }

    async fn publish_single_resolver(
        &self,
        resolver: &(dyn Resolve + Send + Sync),
        public_endpoints: &[EndpointAddr],
    ) -> Result<bool, PublishOnceError> {
        let any: &dyn Any = resolver;

        #[cfg(feature = "http-resolver")]
        if let Some(http) = any.downcast_ref::<crate::resolvers::HttpResolver>() {
            self.publish_endpoints(http, public_endpoints).await?;
            return Ok(true);
        }

        #[cfg(feature = "h3x-resolver")]
        if let Some(h3) =
            any.downcast_ref::<crate::resolvers::H3Resolver<h3x::dquic::QuicEndpoint>>()
        {
            self.publish_endpoints(h3, public_endpoints).await?;
            return Ok(true);
        }

        #[cfg(feature = "mdns-resolver")]
        if let Some(mdns) = any.downcast_ref::<crate::resolvers::MdnsResolvers>() {
            let mut published = false;
            for bound in mdns.bound_resolvers() {
                let endpoints = self.local_endpoints_for(&bound.device, bound.family);
                self.publish_endpoints(&bound.resolver, &endpoints).await?;
                published = true;
            }
            return Ok(published);
        }

        Ok(false)
    }

    async fn publish_endpoints(
        &self,
        publisher: &(dyn Publish + Send + Sync),
        endpoints: &[EndpointAddr],
    ) -> Result<(), PublishOnceError> {
        let packet = self.signed_packet(endpoints).await?;
        let name = self.identity.name();
        tracing::debug!(
            publisher = %publisher,
            name,
            endpoint_count = endpoints.len(),
            packet_len = packet.len(),
            "publishing dns packet"
        );
        publisher
            .publish(name, &packet)
            .await
            .context(publish_once_error::PublishSnafu {
                publisher: publisher.to_string(),
            })
    }

    async fn signed_packet(&self, endpoints: &[EndpointAddr]) -> Result<Vec<u8>, PublishOnceError> {
        let mut signed = Vec::with_capacity(endpoints.len());
        for endpoint in endpoints {
            let mut endpoint = DnsEndpointAddr::try_from(*endpoint)
                .map_err(|_| publish_once_error::EncodeEndpointSnafu.build())?;
            if let Some(server_id) = self.options.server_id {
                endpoint.set_main(server_id == 0);
                endpoint.set_sequence(server_id.into());
            }
            endpoint
                .sign_with_agent(self.identity.as_ref())
                .await
                .context(publish_once_error::SignEndpointSnafu)?;
            signed.push(endpoint);
        }

        let mut hosts = HashMap::new();
        hosts.insert(self.identity.name().to_owned(), signed);
        Ok(MdnsPacket::answer(0, &hosts).to_bytes())
    }

    fn public_endpoints(&self) -> Vec<EndpointAddr> {
        let mut endpoints = Vec::new();
        let mut seen = HashSet::new();
        for pattern in self.bind_patterns.iter() {
            let Some(ifaces) = self.network.get_interfaces(pattern) else {
                tracing::trace!(?pattern, "no interfaces for bind pattern");
                continue;
            };
            for iface in ifaces {
                for endpoint in public_endpoints_from_iface(&self.network, &iface) {
                    push_unique_endpoint(&mut endpoints, &mut seen, endpoint);
                }
            }
        }
        endpoints
    }

    #[cfg(feature = "mdns-resolver")]
    fn local_endpoints_for(&self, device: &str, family: Family) -> Vec<EndpointAddr> {
        let mut endpoints = HashSet::new();
        for pattern in self.bind_patterns.iter() {
            let Some(ifaces) = self.network.get_interfaces(pattern) else {
                continue;
            };
            for iface in ifaces {
                let bind_uri = iface.bind_uri();
                let Some((iface_family, iface_device, _port)) = bind_uri.as_iface_bind_uri() else {
                    continue;
                };
                if iface_family != family || iface_device != device {
                    continue;
                }
                if let Some(endpoint) = local_endpoint_from_iface(&iface, family) {
                    endpoints.insert(endpoint);
                }
            }
        }
        endpoints.into_iter().collect()
    }
}

fn push_unique_endpoint(
    endpoints: &mut Vec<EndpointAddr>,
    seen: &mut HashSet<EndpointAddr>,
    endpoint: EndpointAddr,
) {
    if seen.insert(endpoint) {
        endpoints.push(endpoint);
    }
}

fn public_endpoints_from_iface(
    network: &h3x::dquic::Network,
    iface: &h3x::dquic::net::BindInterface,
) -> Vec<EndpointAddr> {
    use h3x::dquic::{net::IO, qtraversal::nat::client::StunClientsComponent};

    iface.with_components(|components, current| {
        let bind_uri = current.bind_uri();
        let addr = current.bound_addr().ok();
        let mut endpoints: Vec<EndpointAddr> = components
            .get::<StunClientsComponent>()
            .map(|stun| {
                stun.with_clients(|clients| {
                    clients
                        .values()
                        .filter_map(|client| {
                            let outer = client.get_outer_addr()?.ok()?;
                            let bound = current.bound_addr().ok()?;
                            match client.get_nat_type() {
                                Some(Ok(nat_type)) => Some(publish_endpoint_from_stun(
                                    bound,
                                    client.agent_addr(),
                                    outer,
                                    nat_type,
                                )),
                                None => Some(EndpointAddr::with_agent(client.agent_addr(), outer)),
                                Some(Err(_)) => None,
                            }
                        })
                        .collect()
                })
            })
            .unwrap_or_default();
        let stun_endpoint_count = endpoints.len();

        // Also publish the current default-route address. STUN-derived
        // endpoints make the node reachable from outside the local network,
        // while the bound address is still the shortest valid path for peers
        // on the same link and for separate local client processes on the
        // same host. Keep it after STUN endpoints so translated-NAT peers get
        // the externally reachable candidate first.
        if let Some(addr) = addr
            && network.bound_addr_is_on_default_route(&bind_uri, addr)
        {
            endpoints.push(EndpointAddr::direct(addr));
        }

        tracing::trace!(
            bind_uri = %bind_uri,
            bound_addr = ?addr,
            stun_endpoint_count,
            endpoint_count = endpoints.len(),
            endpoints = ?endpoints,
            "collected public endpoints from interface"
        );

        endpoints
    })
}

fn publish_endpoint_from_stun(
    bound: SocketAddr,
    agent: SocketAddr,
    outer: SocketAddr,
    nat_type: NatType,
) -> EndpointAddr {
    if nat_type == NatType::FullCone && bound == outer {
        EndpointAddr::direct(outer)
    } else {
        EndpointAddr::with_agent(agent, outer)
    }
}

#[cfg(feature = "mdns-resolver")]
fn local_endpoint_from_iface(
    iface: &h3x::dquic::net::BindInterface,
    family: Family,
) -> Option<EndpointAddr> {
    use h3x::dquic::net::IO;

    iface.with_components(|_components, current| {
        let addr = current.bound_addr().ok()?;
        match (family, addr) {
            (Family::V4, std::net::SocketAddr::V4(_))
            | (Family::V6, std::net::SocketAddr::V6(_)) => Some(EndpointAddr::direct(addr)),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use dquic::qresolve::{ResolveFuture, Source};
    use futures::{FutureExt, StreamExt, future::BoxFuture, stream};
    use rustls::{SignatureAlgorithm, SignatureScheme, pki_types::CertificateDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[derive(Debug)]
    struct TestAgent;

    impl LocalAgent for TestAgent {
        fn name(&self) -> &str {
            "agent.example"
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &[]
        }

        fn sign_algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ED25519
        }

        fn sign(
            &self,
            scheme: SignatureScheme,
            _data: &[u8],
        ) -> BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>> {
            Box::pin(async move {
                match scheme {
                    SignatureScheme::ED25519 => Ok(vec![1, 2, 3]),
                    _ => Err(dhttp_identity::identity::SignError::UnsupportedScheme { scheme }),
                }
            })
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
            async { Ok(stream::empty::<(Source, EndpointAddr)>().boxed()) }.boxed()
        }
    }

    #[tokio::test]
    async fn publish_once_reports_no_publisher_resolver() {
        let publisher = Publisher::new(
            Arc::new(TestAgent),
            h3x::dquic::Network::builder().build(),
            Arc::new(DisplayOnlyResolver),
            Arc::new(Vec::new()),
        );

        let error = publisher.publish_once().await.unwrap_err();
        assert!(matches!(error, PublishOnceError::NoPublisherResolver));
    }

    #[tokio::test]
    async fn publisher_timeout_is_configurable() {
        let publisher = Publisher::new(
            Arc::new(TestAgent),
            h3x::dquic::Network::builder().build(),
            Arc::new(DisplayOnlyResolver),
            Arc::new(Vec::new()),
        );
        assert_eq!(publisher.publish_timeout(), DEFAULT_PUBLISH_TIMEOUT);

        let timeout = Duration::from_secs(3);
        let publisher = publisher.with_publish_timeout(timeout);
        assert_eq!(publisher.publish_timeout(), timeout);
    }

    #[tokio::test]
    async fn signed_packet_applies_publish_options_server_id() {
        let publisher = Publisher::new(
            Arc::new(TestAgent),
            h3x::dquic::Network::builder().build(),
            Arc::new(DisplayOnlyResolver),
            Arc::new(Vec::new()),
        )
        .with_options(PublishOptions { server_id: Some(2) });

        let endpoint = EndpointAddr::direct("127.0.0.1:443".parse().unwrap());
        let packet = publisher.signed_packet(&[endpoint]).await.unwrap();
        let (_remain, packet) = ddns_core::parser::packet::be_packet(&packet).unwrap();
        let record = packet.answers.first().expect("endpoint answer");
        let ddns_core::parser::record::RData::E(endpoint) = record.data() else {
            panic!("expected endpoint record");
        };

        assert!(!endpoint.is_main());
        assert!(endpoint.is_clustered());
        assert!(endpoint.is_signed());
    }

    #[tokio::test]
    async fn public_endpoints_do_not_fall_back_to_local_bound_addresses() {
        let network = h3x::dquic::Network::builder().build();
        let bind_pattern: h3x::dquic::binds::BindPattern =
            "inet://127.0.0.1:0".parse().expect("valid bind pattern");
        let _bind = network.bind(bind_pattern.clone()).await;
        let publisher = Publisher::new(
            Arc::new(TestAgent),
            network,
            Arc::new(DisplayOnlyResolver),
            Arc::new(vec![bind_pattern]),
        );

        assert!(
            publisher.public_endpoints().is_empty(),
            "public DNS publishing must wait for STUN-derived external endpoints; local addresses are published through mDNS"
        );
    }

    #[test]
    fn push_unique_endpoint_preserves_first_seen_order() {
        let agent = EndpointAddr::with_agent(
            "10.10.0.2:20004".parse().expect("valid agent addr"),
            "10.10.0.10:45635".parse().expect("valid outer addr"),
        );
        let direct = EndpointAddr::direct("10.110.0.10:45635".parse().expect("valid direct addr"));
        let mut endpoints = Vec::new();
        let mut seen = HashSet::new();

        push_unique_endpoint(&mut endpoints, &mut seen, agent);
        push_unique_endpoint(&mut endpoints, &mut seen, direct);
        push_unique_endpoint(&mut endpoints, &mut seen, agent);

        assert_eq!(endpoints, vec![agent, direct]);
    }

    #[test]
    fn full_cone_nat_endpoint_preserves_agent_when_outer_differs_from_bound_addr() {
        let bound = "10.110.0.10:45635".parse().expect("valid bound addr");
        let agent = "10.10.0.2:20004".parse().expect("valid agent addr");
        let outer = "10.10.0.10:45635".parse().expect("valid outer addr");

        let endpoint = publish_endpoint_from_stun(bound, agent, outer, NatType::FullCone);

        assert_eq!(endpoint, EndpointAddr::with_agent(agent, outer));
    }

    #[test]
    fn full_cone_endpoint_is_direct_without_address_translation() {
        let bound = "10.10.0.100:45635".parse().expect("valid bound addr");
        let agent = "10.10.0.2:20004".parse().expect("valid agent addr");

        let endpoint = publish_endpoint_from_stun(bound, agent, bound, NatType::FullCone);

        assert_eq!(endpoint, EndpointAddr::direct(bound));
    }

    #[cfg(feature = "http-resolver")]
    #[tokio::test]
    async fn run_treats_location_publish_attempts_as_independent() {
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
                    server_network.locations().upsert(
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
            crate::resolvers::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let mut publisher = Publisher::new(
            Arc::new(TestAgent),
            network.clone(),
            resolver,
            Arc::new(vec![
                "inet://127.0.0.1:0".parse().expect("valid bind pattern"),
            ]),
        );
        publisher.interval = Duration::from_secs(60);

        let publisher = tokio::spawn(async move {
            publisher.run().await;
        });

        wait_for_count(&publish_count, 1).await;
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(100)).await;
        network.locations().upsert(
            bind_uri,
            Arc::new(Ok::<std::net::SocketAddr, io::Error>(
                "127.0.0.1:10000".parse().expect("valid socket addr"),
            )),
        );

        tokio::time::timeout(Duration::from_secs(2), wait_for_count(&publish_count, 2))
            .await
            .expect("publishable location changes should trigger the next independent publish");

        let third_publish = tokio::time::timeout(
            PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(500),
            wait_for_count(&publish_count, 3),
        )
        .await;

        publisher.abort();
        server.abort();

        assert!(
            third_publish.is_err(),
            "location events generated by a publish attempt must not trigger an immediate retry"
        );
    }

    #[cfg(feature = "http-resolver")]
    #[tokio::test]
    async fn run_drains_events_generated_during_publish_attempt() {
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
                server_network.locations().upsert::<ClientLocationData>(
                    server_bind_uri.clone(),
                    Arc::new(Err(dquic::qtraversal::nat::client::ArcIoError::from(
                        io::Error::from(io::ErrorKind::NetworkUnreachable),
                    ))),
                );
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                    .await;
            }
        });

        let resolver = Arc::new(
            crate::resolvers::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let publisher = Publisher::new(
            Arc::new(TestAgent),
            network.clone(),
            resolver,
            Arc::new(vec![
                "inet://127.0.0.1:0".parse().expect("valid bind pattern"),
            ]),
        );
        let publisher = tokio::spawn(async move {
            publisher.run().await;
        });

        wait_for_count(&publish_count, 1).await;
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(100)).await;

        network.locations().upsert(
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
            crate::resolvers::HttpResolver::new(format!("http://127.0.0.1:{port}/"))
                .expect("valid http resolver"),
        );
        let mut publisher = Publisher::new(
            Arc::new(TestAgent),
            network.clone(),
            resolver,
            Arc::new(vec![
                "inet://127.0.0.1:0".parse().expect("valid bind pattern"),
            ]),
        )
        .with_publish_timeout(Duration::from_millis(50));
        publisher.interval = Duration::from_secs(60);

        let publisher = tokio::spawn(async move {
            publisher.run().await;
        });

        wait_for_count(&publish_count, 1).await;
        tokio::time::sleep(PUBLISH_CHANGE_DEBOUNCE + Duration::from_millis(100)).await;
        network.locations().upsert(
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
}
