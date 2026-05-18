use std::{
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use dashmap::DashMap;
use ddns_core::parser::{packet::Packet, record::RData};
use dquic::{
    qbase::net::{Family, addr::EndpointAddr as DquicEndpointAddr},
    qinterface::{BindInterface, WeakInterface, bind_uri::BindUri, io::IO},
    qresolve::{Publish, PublishFuture, RecordStream, Resolve, ResolveFuture, Source},
};
use futures::{
    FutureExt, Stream, StreamExt, TryFutureExt, future,
    stream::{self, FuturesUnordered},
};

pub use crate::mdns::Mdns as MdnsResolver;
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
        use ddns_core::parser::packet::be_packet;
        let endpoints = be_packet(packet)
            .map(|(_, pkt)| {
                pkt.answers
                    .iter()
                    .filter_map(|rr| match rr.data() {
                        RData::E(ep) => Some(ep.clone()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.insert_host(name.to_string(), endpoints);
        Box::pin(future::ready(Ok(())))
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

#[derive(Default, Clone, Debug)]
pub struct MdnsResolvers {
    ifaces: DashMap<BindUri, WeakInterface>,
}

impl fmt::Display for MdnsResolvers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MDNS Resolvers")
    }
}

impl MdnsResolvers {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_iface(&self, iface: BindInterface) {
        let Some(iface) = iface.with_components(|component, iface| {
            component.exist::<MdnsResolver>().then(|| iface.downgrade())
        }) else {
            return;
        };
        self.ifaces.insert(iface.bind_uri(), iface);
    }

    fn for_each_resolver(&self, mut f: impl FnMut(&MdnsResolver)) {
        self.ifaces.retain(|_, iface| {
            iface
                .upgrade()
                .ok()
                .and_then(|iface| {
                    iface.bind_interface().with_components(|components, _| {
                        components.get::<MdnsResolver>().map(&mut f)
                    })
                })
                .is_some()
        });
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

    pub fn merge(&self, other: &Self) {
        other.ifaces.iter().for_each(|entry| {
            self.ifaces
                .entry(entry.key().clone())
                .or_insert_with(|| entry.value().clone());
        });
    }

    /// Discover mDNS broadcasts from all active resolvers.
    ///
    /// Returns a stream of `(SocketAddr, Packet)` pairs by polling all
    /// underlying protocols concurrently. Unlike per-resolver `discover()`,
    /// this uses a single `Box::pin` allocation for the combined stream.
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
                    Poll::Ready(Some(None)) => {
                        // This resolver's protocol disconnected, skip it
                        continue;
                    }
                    Poll::Ready(None) => return Poll::Ready(None),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }))
    }
}

impl Resolve for MdnsResolvers {
    fn lookup<'l>(&'l self, name: &'l str) -> ResolveFuture<'l> {
        self.query(name).boxed()
    }
}
