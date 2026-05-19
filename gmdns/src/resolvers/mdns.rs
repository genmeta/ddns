use std::{fmt, io, net::IpAddr};
#[cfg(feature = "h3x-network")]
use std::{net::SocketAddr, sync::Arc};

#[cfg(feature = "h3x-network")]
use ddns_core::parser::packet::Packet;
use ddns_core::parser::record::RData;
#[cfg(feature = "h3x-network")]
use dquic::qresolve::RecordStream;
use dquic::{
    qbase::net::{Family, addr::EndpointAddr as DquicEndpointAddr},
    qresolve::{Publish, PublishFuture, Resolve, ResolveFuture, Source},
};
use futures::{FutureExt, StreamExt, TryFutureExt, future, stream};
#[cfg(feature = "h3x-network")]
use futures::{Stream, stream::FuturesUnordered};

pub use crate::mdns::Mdns as MdnsResolver;
#[cfg(feature = "h3x-network")]
use crate::protocol::MdnsProtocol;

impl MdnsResolver {
    pub fn source(&self) -> Source {
        Source::Mdns {
            nic: self.bound_nic().into(),
            family: match self.bound_ip() {
                IpAddr::V4(..) => Family::V4,
                IpAddr::V6(..) => Family::V6,
            },
        }
    }
}

impl fmt::Display for MdnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source(), f)
    }
}

impl Publish for MdnsResolver {
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        let endpoints = match endpoints_from_packet(packet) {
            Ok(endpoints) => endpoints,
            Err(error) => return future::ready(Err(error)).boxed(),
        };
        self.insert_host(name.to_string(), endpoints);
        future::ready(Ok(())).boxed()
    }
}

impl Resolve for MdnsResolver {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let source = self.source();
        self.query(name.to_owned())
            .map_ok(move |list| {
                stream::iter(list.into_iter().filter_map(move |ep| {
                    let ep = DquicEndpointAddr::try_from(ep).ok()?;
                    Some((source.clone(), ep))
                }))
                .boxed()
            })
            .boxed()
    }
}

fn endpoints_from_packet(packet: &[u8]) -> io::Result<Vec<ddns_core::MdnsEndpoint>> {
    use ddns_core::parser::packet::be_packet;

    be_packet(packet)
        .map(|(_, pkt)| {
            pkt.answers
                .iter()
                .filter_map(|rr| match rr.data() {
                    RData::E(ep) => Some(ep.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
}

#[cfg(feature = "h3x-network")]
pub struct MdnsBindDriver {
    iface_manager: Arc<h3x::dquic::net::InterfaceManager>,
    null_io_factory: Arc<h3x::dquic::NullIoFactory>,
    service_name: Arc<str>,
}

#[cfg(feature = "h3x-network")]
impl MdnsBindDriver {
    pub fn new(service_name: impl Into<Arc<str>>) -> Self {
        Self {
            iface_manager: Arc::new(h3x::dquic::net::InterfaceManager::new()),
            null_io_factory: Arc::new(h3x::dquic::NullIoFactory),
            service_name: service_name.into(),
        }
    }

    fn install_or_rebind_mdns(
        &self,
        network: &h3x::dquic::Network,
        bind_iface: &h3x::dquic::net::BindInterface,
    ) {
        let bind_uri = bind_iface.bind_uri();
        let Some((family, device, _port)) = bind_uri.as_iface_bind_uri() else {
            tracing::debug!(%bind_uri, "skipping mdns binding for non-interface bind uri");
            return;
        };
        let Some(ip) = network.resolve_device_addr(device, family) else {
            tracing::debug!(%bind_uri, "skipping mdns binding without local interface address");
            return;
        };

        bind_iface.with_components_mut(|components, _iface| {
            match components.try_init_with(|| crate::Mdns::new(&self.service_name, ip, device)) {
                Ok(mdns) => mdns.reinit_on(device, ip),
                Err(error) => {
                    let report = snafu::Report::from_error(&error);
                    tracing::debug!(error = %report, %bind_uri, "failed to initialize mdns binding");
                }
            }
        });
    }
}

#[cfg(feature = "h3x-network")]
impl h3x::dquic::BindDriver for MdnsBindDriver {
    fn bind<'a>(
        &'a self,
        network: &'a h3x::dquic::Network,
        uri: h3x::dquic::net::BindUri,
    ) -> futures::future::BoxFuture<'a, h3x::dquic::net::BindInterface> {
        async move {
            let iface = self
                .iface_manager
                .bind(uri, self.null_io_factory.clone())
                .await;
            self.install_or_rebind_mdns(network, &iface);
            iface
        }
        .boxed()
    }

    fn rebind<'a>(
        &'a self,
        network: &'a h3x::dquic::Network,
        iface: &'a h3x::dquic::net::BindInterface,
    ) -> futures::future::BoxFuture<'a, ()> {
        async move {
            self.install_or_rebind_mdns(network, iface);
        }
        .boxed()
    }
}

#[cfg(feature = "h3x-network")]
pub struct MdnsResolvers {
    network: Arc<h3x::dquic::Network>,
    driver: Arc<MdnsBindDriver>,
    patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    _handles: Vec<h3x::dquic::BindHandle>,
}

#[cfg(feature = "h3x-network")]
impl fmt::Debug for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResolvers")
            .field("patterns", &self.patterns)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "h3x-network")]
impl fmt::Display for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mDNS resolvers")
    }
}

#[cfg(feature = "h3x-network")]
impl MdnsResolvers {
    pub async fn bind(
        network: Arc<h3x::dquic::Network>,
        patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
        service_name: impl Into<Arc<str>>,
    ) -> Self {
        let driver = Arc::new(MdnsBindDriver::new(service_name));
        let mut handles = Vec::with_capacity(patterns.len());
        for pattern in patterns.iter() {
            handles.push(network.bind_with(driver.clone(), pattern.clone()).await);
        }

        Self {
            network,
            driver,
            patterns,
            _handles: handles,
        }
    }

    pub fn bound_interfaces(
        &self,
        pattern: &h3x::dquic::binds::BindPattern,
    ) -> Option<Vec<h3x::dquic::net::BindInterface>> {
        self.network.get_interfaces_with(&self.driver, pattern)
    }

    fn for_each_resolver(&self, mut f: impl FnMut(&MdnsResolver)) {
        for pattern in self.patterns.iter() {
            let Some(ifaces) = self.bound_interfaces(pattern) else {
                continue;
            };
            for iface in ifaces {
                iface.with_components(|components, _| {
                    if let Some(mdns) = components.get::<MdnsResolver>() {
                        f(mdns);
                    }
                });
            }
        }
    }

    pub async fn query(&self, name: &str) -> io::Result<RecordStream> {
        let mut lookup_futures = FuturesUnordered::new();
        self.for_each_resolver(|resolver| {
            let source = resolver.source();
            lookup_futures.push(resolver.query(name.to_owned()).map_ok(move |eps| {
                stream::iter(eps.into_iter().filter_map(move |ep| {
                    let ep = DquicEndpointAddr::try_from(ep).ok()?;
                    Some((source.clone(), ep))
                }))
            }));
        });

        let mut last_error = None;
        let no_resolver = || io::Error::other("no mdns resolvers available");
        let stream = loop {
            match lookup_futures.next().await {
                Some(Ok(stream)) => break stream,
                Some(Err(error)) => last_error = Some(error),
                None => return Err(last_error.unwrap_or_else(no_resolver)),
            }
        };

        Ok(stream
            .chain(lookup_futures.flat_map(stream::iter).flatten())
            .boxed())
    }

    /// Discover mDNS broadcasts from all active resolvers.
    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> + use<> {
        let mut protos = Vec::new();
        self.for_each_resolver(|resolver| {
            protos.push(resolver.protocol());
        });

        async fn receive_one(
            proto: Arc<MdnsProtocol>,
        ) -> Option<((SocketAddr, Packet), Arc<MdnsProtocol>)> {
            let result = proto.receive_boardcast().await.ok()?;
            Some((result, proto))
        }

        let mut pending = protos
            .into_iter()
            .map(receive_one)
            .collect::<FuturesUnordered<_>>();

        Box::pin(stream::poll_fn(move |cx| {
            use std::task::Poll;
            loop {
                match pending.poll_next_unpin(cx) {
                    Poll::Ready(Some(Some((item, proto)))) => {
                        pending.push(receive_one(proto));
                        return Poll::Ready(Some(item));
                    }
                    Poll::Ready(Some(None)) => continue,
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }))
    }
}

#[cfg(feature = "h3x-network")]
impl Publish for MdnsResolvers {
    fn publish<'a>(&'a self, name: &'a str, packet: &'a [u8]) -> PublishFuture<'a> {
        let endpoints = match endpoints_from_packet(packet) {
            Ok(endpoints) => endpoints,
            Err(error) => return future::ready(Err(error)).boxed(),
        };

        self.for_each_resolver(|resolver| {
            resolver.insert_host(name.to_string(), endpoints.clone());
        });

        future::ready(Ok(())).boxed()
    }
}

#[cfg(feature = "h3x-network")]
impl Resolve for MdnsResolvers {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        self.query(name).boxed()
    }
}
