mod if_nametoindex;
mod protocol;
pub mod service;

use std::{fmt, io, net::IpAddr};
#[cfg(feature = "dquic-network")]
use std::{net::SocketAddr, sync::Arc};

#[cfg(feature = "dquic-network")]
use dquic::qresolve::RecordStream;
use dquic::{
    qbase::net::Family,
    qresolve::{Publish, PublishFuture, Resolve, ResolveFuture, Source},
};
use futures::{FutureExt, StreamExt, TryFutureExt, future, stream};
#[cfg(feature = "dquic-network")]
use futures::{Stream, stream::FuturesUnordered};

#[cfg(feature = "dquic-network")]
use self::protocol::MdnsProtocol;
#[cfg(feature = "dquic-network")]
use crate::core::parser::packet::Packet;

pub type MdnsResolver = service::Mdns;
pub type MdnsPublisher = service::Mdns;

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

impl Publish for MdnsPublisher {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = dquic::qbase::net::addr::EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints = match mdns_endpoints_from_dquic(endpoints) {
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
        let Some((domain, sequence)) = crate::resolvers::endpoint_lookup_name_and_sequence(name)
        else {
            return future::ready(Err(io::Error::other("no DNS record found"))).boxed();
        };
        self.query(domain.to_owned())
            .map_ok(move |list| {
                let endpoints =
                    crate::resolvers::endpoint_group::selected_endpoint_addrs_for_sequence(
                        list, sequence,
                    );
                stream::iter(endpoints.into_iter().map(move |ep| (source.clone(), ep))).boxed()
            })
            .boxed()
    }
}

fn mdns_endpoints_from_dquic(
    endpoints: &mut dyn Iterator<Item = dquic::qbase::net::addr::EndpointAddr>,
) -> io::Result<Vec<crate::core::MdnsEndpoint>> {
    let mut records = Vec::new();
    for endpoint in endpoints {
        let endpoint = crate::core::parser::record::endpoint::EndpointAddr::try_from(endpoint)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed to encode endpoint address",
                )
            })?;
        records.push(endpoint);
    }
    Ok(records)
}

#[cfg(feature = "dquic-network")]
pub struct MdnsBindDriver {
    iface_manager: Arc<h3x::dquic::net::InterfaceManager>,
    null_io_factory: Arc<h3x::dquic::NullIoFactory>,
    service_name: Arc<str>,
}

#[cfg(feature = "dquic-network")]
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
            match components.try_init_with(|| service::Mdns::new(&self.service_name, ip, device)) {
                Ok(mdns) => mdns.reinit_on(device, ip),
                Err(error) => {
                    let report = snafu::Report::from_error(&error);
                    tracing::debug!(error = %report, %bind_uri, "failed to initialize mdns binding");
                }
            }
        });
    }
}

#[cfg(feature = "dquic-network")]
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

#[cfg(feature = "dquic-network")]
pub struct MdnsResolvers {
    network: Arc<h3x::dquic::Network>,
    driver: Arc<MdnsBindDriver>,
    patterns: Arc<Vec<h3x::dquic::binds::BindPattern>>,
    _handles: Vec<h3x::dquic::BindHandle>,
}

#[cfg(feature = "dquic-network")]
#[derive(Debug, Clone)]
pub struct BoundMdnsResolver {
    pub device: String,
    pub family: Family,
    pub resolver: MdnsResolver,
}

#[cfg(feature = "dquic-network")]
impl fmt::Debug for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResolvers")
            .field("patterns", &self.patterns)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dquic-network")]
impl fmt::Display for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mDNS resolvers")
    }
}

#[cfg(feature = "dquic-network")]
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

    pub fn bound_resolvers(&self) -> Vec<BoundMdnsResolver> {
        let mut resolvers = Vec::new();
        for pattern in self.patterns.iter() {
            let Some(ifaces) = self.bound_interfaces(pattern) else {
                continue;
            };
            for iface in ifaces {
                let bind_uri = iface.bind_uri();
                let Some((family, device, _port)) = bind_uri.as_iface_bind_uri() else {
                    continue;
                };
                iface.with_components(|components, _| {
                    if let Some(resolver) = components.get::<MdnsResolver>() {
                        resolvers.push(BoundMdnsResolver {
                            device: device.to_owned(),
                            family,
                            resolver: resolver.clone(),
                        });
                    }
                });
            }
        }
        resolvers
    }

    pub async fn query(&self, name: &str) -> io::Result<RecordStream> {
        self.query_with_sequence(name, None).await
    }

    pub async fn query_with_sequence(
        &self,
        name: &str,
        sequence: Option<dhttp_identity::certificate::CertificateSequence>,
    ) -> io::Result<RecordStream> {
        let mut lookup_futures = FuturesUnordered::new();
        let mut has_resolver = false;
        self.for_each_resolver(|resolver| {
            has_resolver = true;
            let source = resolver.source();
            lookup_futures.push(
                resolver
                    .query(name.to_owned())
                    .map_ok(move |eps| (source, eps)),
            );
        });
        if !has_resolver {
            return Err(io::Error::other("no mdns resolvers available"));
        }

        let mut last_error = None;
        let mut has_success = false;
        let mut records = Vec::new();
        while let Some(result) = lookup_futures.next().await {
            match result {
                Ok((source, endpoints)) => {
                    has_success = true;
                    records.extend(
                        endpoints
                            .into_iter()
                            .map(|endpoint| (source.clone(), endpoint)),
                    );
                }
                Err(error) => last_error = Some(error),
            }
        }

        if !has_success {
            return Err(
                last_error.unwrap_or_else(|| io::Error::other("no mdns resolvers available"))
            );
        }

        let records = crate::resolvers::endpoint_group::selected_endpoint_records_for_sequence(
            records, sequence,
        );

        Ok(stream::iter(records).boxed())
    }

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

#[cfg(feature = "dquic-network")]
impl Publish for MdnsResolvers {
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &mut dyn Iterator<Item = dquic::qbase::net::addr::EndpointAddr>,
    ) -> PublishFuture<'a> {
        let endpoints = match mdns_endpoints_from_dquic(endpoints) {
            Ok(endpoints) => endpoints,
            Err(error) => return future::ready(Err(error)).boxed(),
        };

        self.for_each_resolver(|resolver| {
            resolver.insert_host(name.to_string(), endpoints.clone());
        });

        future::ready(Ok(())).boxed()
    }
}

#[cfg(feature = "dquic-network")]
impl Resolve for MdnsResolvers {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        let Some((domain, sequence)) = crate::resolvers::endpoint_lookup_name_and_sequence(name)
        else {
            return future::ready(Err(io::Error::other("no DNS record found"))).boxed();
        };
        self.query_with_sequence(domain, sequence).boxed()
    }
}
