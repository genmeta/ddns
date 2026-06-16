use std::{fmt, io, sync::Arc};

use dhttp_identity::name::Name;
use dquic::qresolve::Publish;
use snafu::{ResultExt, Snafu};

use super::{AddressView, PublishScope, packet};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PublisherError {
    #[snafu(display("failed to encode endpoint dns packet"))]
    EncodePacket {
        source: packet::EncodeEndpointPacketError,
    },
    #[snafu(display("failed to publish dns packet with {publisher}"))]
    Publish {
        publisher: String,
        source: io::Error,
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
}

impl fmt::Debug for Publisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            PublisherKind::Custom { scope, publisher } => f
                .debug_struct("Publisher")
                .field("scope", scope)
                .field("publisher", publisher)
                .finish(),
        }
    }
}

impl fmt::Display for Publisher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            PublisherKind::Custom { publisher, .. } => fmt::Display::fmt(publisher, f),
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

    pub async fn publish<V>(&self, name: &Name<'_>, view: &V) -> Result<(), PublisherError>
    where
        V: AddressView + Sync,
    {
        match &self.inner {
            PublisherKind::Custom { scope, publisher } => {
                publish_selected(publisher.as_ref(), scope, name, view).await
            }
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
    let endpoints: Vec<_> = view.endpoints(scope.selector()).collect();
    let packet =
        packet::endpoint_packet(name, endpoints).context(publisher_error::EncodePacketSnafu)?;
    tracing::debug!(
        publisher = %publisher,
        name = %name,
        packet_len = packet.len(),
        "publishing dns packet"
    );
    publisher
        .publish(name.as_str(), &packet)
        .await
        .context(publisher_error::PublishSnafu {
            publisher: publisher.to_string(),
        })
}

#[cfg(test)]
mod tests {
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

    use crate::{
        core::parser::{packet::be_packet, record::RData},
        publishers::{PublishScope, Publisher},
    };

    #[derive(Debug, Default)]
    struct RecordingPublisher {
        calls: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl RecordingPublisher {
        fn calls(&self) -> Vec<(String, Vec<u8>)> {
            self.calls.lock().expect("calls lock poisoned").clone()
        }
    }

    impl fmt::Display for RecordingPublisher {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("recording publisher")
        }
    }

    impl Publish for RecordingPublisher {
        fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
            async move {
                self.calls
                    .lock()
                    .expect("calls lock poisoned")
                    .push((name.to_owned(), packet.to_vec()));
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
        fn publish<'a>(&'a self, _name: &'a str, _packet: &'a [u8]) -> PublishFuture<'a> {
            async move { Err(io::Error::other("publish rejected")) }.boxed()
        }
    }

    fn endpoint(ip: [u8; 4], port: u16) -> EndpointAddr {
        EndpointAddr::direct(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
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

        let calls = recorder.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "alice.dhttp.net");
        let (_, packet) = be_packet(&calls[0].1).expect("packet parses");
        let endpoints: Vec<_> = packet
            .answers
            .iter()
            .filter_map(|answer| match answer.data() {
                RData::E(endpoint) => Some(endpoint.primary),
                _ => None,
            })
            .collect();
        assert_eq!(
            endpoints,
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(203, 0, 113, 10),
                4433
            ))]
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

        let calls = recorder.calls();
        assert_eq!(calls.len(), 1);
        let (_, packet) = be_packet(&calls[0].1).expect("packet parses");
        let endpoints: Vec<_> = packet
            .answers
            .iter()
            .filter_map(|answer| match answer.data() {
                RData::E(endpoint) => Some(endpoint.primary),
                _ => None,
            })
            .collect();
        assert_eq!(
            endpoints,
            vec![SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 2, 20),
                4433
            ))]
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
            "failed to publish dns packet with failing publisher"
        );
        assert_eq!(
            std::error::Error::source(&error)
                .expect("source")
                .to_string(),
            "publish rejected"
        );
    }
}
