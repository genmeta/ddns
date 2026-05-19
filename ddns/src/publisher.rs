use std::{
    any::Any,
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
    time::Duration,
};

use ddns_core::{
    MdnsPacket,
    parser::record::endpoint::{EndpointAddr as DnsEndpointAddr, SignEndpointError},
};
use dhttp_identity::identity::LocalAgent;
use dquic::{
    qbase::net::{Family, addr::EndpointAddr},
    qresolve::{Publish, Resolve},
};
use snafu::{ResultExt, Snafu};

use crate::resolvers::Resolvers;

pub const DEFAULT_PUBLISH_INTERVAL: Duration = Duration::from_secs(20);

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
    options: PublishOptions,
}

impl std::fmt::Debug for Publisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Publisher")
            .field("identity", &self.identity.name())
            .field("bind_patterns", &self.bind_patterns)
            .field("interval", &self.interval)
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

    pub async fn publish_once(&self) -> Result<(), PublishOnceError> {
        let mut published = false;
        let public_endpoints = self.public_endpoints();
        published |= self
            .publish_to_resolver(self.resolver.as_ref(), &public_endpoints)
            .await?;

        if !published {
            return publish_once_error::NoPublisherResolverSnafu.fail();
        }

        Ok(())
    }

    pub async fn run(&self) -> ! {
        loop {
            if let Err(error) = self.publish_once().await {
                let report = snafu::Report::from_error(&error);
                tracing::warn!(error = %report, "dns publish failed");
            }
            tokio::time::sleep(self.interval).await;
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
        let mut endpoints = HashSet::new();
        for pattern in self.bind_patterns.iter() {
            let Some(ifaces) = self.network.get_interfaces(pattern) else {
                continue;
            };
            for iface in ifaces {
                if let Some(endpoint) = endpoint_from_iface(&iface) {
                    endpoints.insert(endpoint);
                }
            }
        }
        endpoints.into_iter().collect()
    }

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

fn endpoint_from_iface(iface: &h3x::dquic::net::BindInterface) -> Option<EndpointAddr> {
    use h3x::dquic::{net::IO, qtraversal::nat::client::StunClientsComponent};

    iface.with_components(|components, current| {
        if let Some(stun) = components.get::<StunClientsComponent>()
            && let Some((agent, outer)) = stun.with_clients(|clients| {
                clients.values().find_map(|client| {
                    let outer = client.get_outer_addr()?.ok()?;
                    Some((client.agent_addr(), outer))
                })
            })
        {
            return Some(EndpointAddr::with_agent(agent, outer));
        }

        current.bound_addr().ok().map(EndpointAddr::direct)
    })
}

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
    use std::{fmt, sync::Arc};

    use dquic::qresolve::{ResolveFuture, Source};
    use futures::{FutureExt, StreamExt, future::BoxFuture, stream};
    use rustls::{SignatureAlgorithm, SignatureScheme, pki_types::CertificateDer};

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
}
