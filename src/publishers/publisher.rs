use std::{fmt, io, sync::Arc};

use dhttp_identity::name::Name;
use dquic::qresolve::Publish;
use snafu::{OptionExt, ResultExt, Snafu};

use super::{AddressView, PublishScope};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PublisherError {
    #[snafu(display("failed to publish dns records with {publisher}"))]
    Publish {
        publisher: String,
        source: io::Error,
    },
    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[snafu(display("all mdns publishers failed"))]
    Mdns { source: MdnsPublishersError },
    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[snafu(display("failed to get mdns publisher local authority"))]
    MdnsLocalAuthority { source: h3x::quic::ConnectionError },
    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[snafu(display("anonymous endpoint cannot publish mdns records"))]
    MdnsAnonymousEndpoint,
    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[snafu(display("failed to encode mdns dns records"))]
    MdnsEncode {
        source: crate::publishers::packet::EncodeAuthorityDnsPacketError,
    },
}

#[derive(Clone)]
pub struct Publisher {
    inner: PublisherKind,
}

#[derive(Clone)]
enum PublisherKind {
    Custom {
        scope: PublishScope,
        publisher: Arc<dyn Publish + Send + Sync>,
    },
    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    Mdns {
        resolvers: Arc<crate::mdns::MdnsResolvers>,
        authority: Arc<dyn h3x::quic::DynWithLocalAuthority>,
    },
}

#[cfg(all(feature = "mdns", feature = "dquic-network"))]
#[derive(Debug)]
pub struct MdnsPublishersError {
    errors: Vec<(String, io::Error)>,
}

#[cfg(all(feature = "mdns", feature = "dquic-network"))]
impl fmt::Display for MdnsPublishersError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "no mdns publishers available");
        }

        write!(f, "all mdns publishers failed")?;
        for (publisher, error) in &self.errors {
            write!(f, "\n  - {publisher}: {error}")?;
        }
        Ok(())
    }
}

#[cfg(all(feature = "mdns", feature = "dquic-network"))]
impl std::error::Error for MdnsPublishersError {}

impl fmt::Debug for Publisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            PublisherKind::Custom { scope, publisher } => f
                .debug_struct("Publisher")
                .field("scope", scope)
                .field("publisher", publisher)
                .finish(),
            #[cfg(all(feature = "mdns", feature = "dquic-network"))]
            PublisherKind::Mdns { resolvers, .. } => f
                .debug_struct("Publisher")
                .field("mdns", resolvers)
                .finish(),
        }
    }
}

impl fmt::Display for Publisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            PublisherKind::Custom { publisher, .. } => fmt::Display::fmt(publisher, f),
            #[cfg(all(feature = "mdns", feature = "dquic-network"))]
            PublisherKind::Mdns { resolvers, .. } => fmt::Display::fmt(resolvers, f),
        }
    }
}

impl Publisher {
    pub fn new(scope: PublishScope, publisher: Arc<dyn Publish + Send + Sync>) -> Self {
        Self {
            inner: PublisherKind::Custom { scope, publisher },
        }
    }

    #[cfg(feature = "http")]
    pub fn http(publisher: Arc<crate::http::HttpResolver>) -> Self {
        Self::new(PublishScope::WideArea, publisher)
    }

    #[cfg(feature = "h3")]
    pub fn h3<C>(publisher: Arc<crate::h3::H3Resolver<C>>) -> Self
    where
        C: h3x::quic::Connect + h3x::quic::WithLocalAuthority,
        crate::h3::H3Resolver<C>: Publish + Send + Sync + 'static,
    {
        Self::new(PublishScope::WideArea, publisher)
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    pub fn mdns<A>(resolvers: Arc<crate::mdns::MdnsResolvers>, authority: Arc<A>) -> Self
    where
        A: h3x::quic::DynWithLocalAuthority + 'static,
    {
        Self {
            inner: PublisherKind::Mdns {
                resolvers,
                authority,
            },
        }
    }

    pub async fn publish<V>(&self, name: &Name<'_>, view: &V) -> Result<(), PublisherError>
    where
        V: AddressView + Sync,
    {
        match &self.inner {
            PublisherKind::Custom { scope, publisher } => {
                publish_selected(publisher.as_ref(), scope, name, view).await
            }
            #[cfg(all(feature = "mdns", feature = "dquic-network"))]
            PublisherKind::Mdns {
                resolvers,
                authority,
            } => publish_mdns(resolvers, authority.as_ref(), name, view).await,
        }
    }
}

async fn publish_selected<V>(
    publisher: &(dyn Publish + Send + Sync),
    scope: &PublishScope,
    name: &Name<'_>,
    view: &V,
) -> Result<(), PublisherError>
where
    V: AddressView + Sync,
{
    tracing::debug!(
        publisher = %publisher,
        name = %name,
        "publishing dns records"
    );
    let publish = {
        let mut endpoints = view.endpoints(scope.selector());
        publisher.publish(name.as_str(), &mut endpoints)
    };
    publish.await.context(publisher_error::PublishSnafu {
        publisher: publisher.to_string(),
    })
}

#[cfg(all(feature = "mdns", feature = "dquic-network"))]
async fn publish_mdns<V>(
    resolvers: &crate::mdns::MdnsResolvers,
    authority_provider: &dyn h3x::quic::DynWithLocalAuthority,
    name: &Name<'_>,
    view: &V,
) -> Result<(), PublisherError>
where
    V: AddressView + Sync,
{
    let authority = authority_provider
        .local_authority()
        .await
        .context(publisher_error::MdnsLocalAuthoritySnafu)?
        .context(publisher_error::MdnsAnonymousEndpointSnafu)?;
    let mut no_endpoints = std::iter::empty();
    crate::publishers::packet::dns_endpoints_for_authority(
        authority.as_ref(),
        name.as_str(),
        &mut no_endpoints,
    )
    .context(publisher_error::MdnsEncodeSnafu)?;
    let bound_resolvers = resolvers.bound_resolvers();
    if bound_resolvers.is_empty() {
        tracing::debug!(name = %name, "no mdns publishers currently bound");
        return Ok(());
    }

    for bound in bound_resolvers {
        let scope = PublishScope::LocalLink {
            device: bound.device.clone().into(),
            family: bound.family,
        };
        let mut endpoints = view.endpoints(scope.selector());
        let endpoints = crate::publishers::packet::dns_endpoints_for_authority(
            authority.as_ref(),
            name.as_str(),
            &mut endpoints,
        )
        .context(publisher_error::MdnsEncodeSnafu)?;
        bound.resolver.insert_host(name.to_string(), endpoints);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::{
        fmt, io,
        net::{Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::{Arc, Mutex},
    };

    use dhttp_identity::name::Name;
    use dquic::{
        qbase::net::{Family, addr::EndpointAddr},
        qresolve::{Publish, PublishFuture},
    };
    use futures::FutureExt;

    use crate::publishers::{PublishScope, Publisher};

    #[derive(Debug, Default)]
    struct RecordingPublisher {
        calls: Mutex<Vec<(String, Vec<EndpointAddr>)>>,
    }

    impl RecordingPublisher {
        fn calls(&self) -> Vec<(String, Vec<EndpointAddr>)> {
            self.calls.lock().expect("calls lock poisoned").clone()
        }
    }

    impl fmt::Display for RecordingPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("recording publisher")
        }
    }

    impl Publish for RecordingPublisher {
        fn publish<'a>(
            &'a self,
            name: &'a str,
            endpoints: &mut dyn Iterator<Item = EndpointAddr>,
        ) -> PublishFuture<'a> {
            let endpoints: Vec<_> = endpoints.collect();
            async move {
                self.calls
                    .lock()
                    .expect("calls lock poisoned")
                    .push((name.to_owned(), endpoints));
                Ok(())
            }
            .boxed()
        }
    }

    #[derive(Debug)]
    struct FailingPublisher;

    impl fmt::Display for FailingPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("failing publisher")
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

    fn endpoint(ip: [u8; 4], port: u16) -> EndpointAddr {
        EndpointAddr::direct(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[derive(Debug)]
    struct RecordingAuthorityProvider {
        calls: AtomicUsize,
        authority: Arc<dyn dhttp_identity::identity::LocalAuthority>,
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    impl h3x::quic::DynWithLocalAuthority for RecordingAuthorityProvider {
        fn local_authority(
            &self,
        ) -> futures::future::BoxFuture<
            '_,
            Result<
                Option<Arc<dyn dhttp_identity::identity::LocalAuthority>>,
                h3x::quic::ConnectionError,
            >,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            futures::future::ready(Ok(Some(self.authority.clone()))).boxed()
        }
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[derive(Debug)]
    struct MdnsTestAuthority {
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    impl dhttp_identity::identity::LocalAuthority for MdnsTestAuthority {
        fn name(&self) -> &str {
            "alice.dhttp.net"
        }

        fn cert_chain(&self) -> &[rustls::pki_types::CertificateDer<'static>] {
            &self.cert_chain
        }

        fn sign(
            &self,
            _data: &[u8],
        ) -> futures::future::BoxFuture<'_, Result<Vec<u8>, dhttp_identity::identity::SignError>>
        {
            futures::future::ready(Ok(Vec::new())).boxed()
        }
    }

    #[cfg(all(feature = "mdns", feature = "dquic-network"))]
    #[tokio::test]
    async fn mdns_publish_uses_publisher_owned_authority() {
        use std::str::FromStr;

        let mut certificate = include_bytes!("../../tests/fixtures/valid.der").to_vec();
        let marker = b"0:0:0123456789abcdef";
        let offset = certificate
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("fixture contains dhttp subject key identifier");
        certificate[offset] = b'7';
        let authority = Arc::new(MdnsTestAuthority {
            cert_chain: vec![rustls::pki_types::CertificateDer::from(certificate)],
        });
        let provider = Arc::new(RecordingAuthorityProvider {
            calls: AtomicUsize::new(0),
            authority,
        });
        let pattern = h3x::dquic::binds::BindPattern::from_str("iface://v4.lo:0")
            .expect("valid loopback pattern");
        let resolvers = Arc::new(
            crate::mdns::MdnsResolvers::bind(
                h3x::dquic::Network::builder().build(),
                Arc::new(vec![pattern]),
                "_test._udp.local",
            )
            .await,
        );
        let publisher = Publisher::mdns(resolvers.clone(), provider.clone());
        let view = crate::publishers::PublishAddresses::new().local_link(
            "lo",
            Family::V4,
            [endpoint([127, 0, 0, 1], 4433)],
        );
        let name = Name::try_from("alice.dhttp.net").expect("valid name");

        publisher
            .publish(&name, &view)
            .await
            .expect("empty mdns publication succeeds");

        assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
        let bound = resolvers.bound_resolvers();
        assert!(!bound.is_empty(), "loopback mDNS resolver must be bound");
        let records = bound[0]
            .resolver
            .published_endpoints("alice.dhttp.net")
            .expect("published host exists");
        assert_eq!(records.len(), 1);
        assert!(!records[0].is_signed());
        assert!(records[0].is_main());
        assert_eq!(records[0].normalized_sequence().get(), 7);
    }

    #[tokio::test]
    async fn custom_publisher_selects_wide_area_addresses() {
        let wide = endpoint([203, 0, 113, 10], 4433);
        let local = endpoint([192, 168, 1, 20], 4433);
        let recorder = Arc::new(RecordingPublisher::default());
        let publisher = Publisher::new(PublishScope::WideArea, recorder.clone());
        let view = crate::publishers::PublishAddresses::new()
            .wide_area([wide])
            .local_link("en0", Family::V4, [local]);
        let name = Name::try_from("alice.dhttp.net").expect("valid name");

        publisher
            .publish(&name, &view)
            .await
            .expect("publish succeeds");

        assert_eq!(
            recorder.calls(),
            vec![("alice.dhttp.net".to_owned(), vec![wide])]
        );
    }

    #[tokio::test]
    async fn custom_publisher_selects_matching_local_link_addresses() {
        let en0 = endpoint([192, 168, 1, 20], 4433);
        let en1 = endpoint([192, 168, 2, 20], 4433);
        let recorder = Arc::new(RecordingPublisher::default());
        let publisher = Publisher::new(
            PublishScope::LocalLink {
                device: Arc::<str>::from("en1"),
                family: Family::V4,
            },
            recorder.clone(),
        );
        let view = crate::publishers::PublishAddresses::new()
            .local_link("en0", Family::V4, [en0])
            .local_link("en1", Family::V4, [en1]);
        let name = Name::try_from("alice.dhttp.net").expect("valid name");

        publisher
            .publish(&name, &view)
            .await
            .expect("publish succeeds");

        assert_eq!(
            recorder.calls(),
            vec![("alice.dhttp.net".to_owned(), vec![en1])]
        );
    }

    #[tokio::test]
    async fn custom_publisher_error_preserves_publish_source() {
        let publisher = Publisher::new(PublishScope::WideArea, Arc::new(FailingPublisher));
        let view = crate::publishers::PublishAddresses::new();
        let name = Name::try_from("alice.dhttp.net").expect("valid name");

        let error = publisher
            .publish(&name, &view)
            .await
            .expect_err("publish should fail");

        assert_eq!(
            error.to_string(),
            "failed to publish dns records with failing publisher"
        );
        assert_eq!(
            std::error::Error::source(&error)
                .expect("source")
                .to_string(),
            "publish rejected"
        );
    }
}
