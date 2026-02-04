use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZero,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

use dashmap::DashMap;
use futures::{Stream, StreamExt};
use nix::net::if_::if_nametoindex;
use socket2::{Domain, Socket, Type};
use thiserror::Error;
use tokio::{io, net::UdpSocket, task::JoinSet, time};
use tokio_util::task::AbortOnDropHandle;

use crate::parser::{
    packet::{Packet, be_packet},
    record::endpoint::EndpointAddr,
};

#[derive(Debug)]
pub struct MdnsSocket(UdpSocket);

const MULTICAST_PORT: u16 = 5353;
const MULTICAST_ADDR_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MULTICAST_ADDR_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const MAX_DEQUE_SIZE: usize = 64;

impl MdnsSocket {
    pub fn new(device: &str, ip: IpAddr) -> io::Result<Self> {
        tracing::debug!(target: "mdns", device, %ip, "Add mdns device");
        let socket = match ip {
            IpAddr::V4(ip) => {
                let socket = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                #[cfg(not(target_os = "windows"))]
                socket.set_reuse_port(true)?;

                let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), MULTICAST_PORT);
                socket.bind(&bind.into())?;
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                socket.bind_device(Some(device.as_bytes()))?;
                socket.set_multicast_loop_v4(ip.is_loopback())?;
                socket.join_multicast_v4(&MULTICAST_ADDR_V4, &Ipv4Addr::UNSPECIFIED)?;
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                socket.set_multicast_if_v4(&ip)?;
                socket
            }
            IpAddr::V6(ip) => {
                let socket = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
                socket.set_nonblocking(true)?;
                socket.set_reuse_address(true)?;
                #[cfg(not(target_os = "windows"))]
                socket.set_reuse_port(true)?;

                let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), MULTICAST_PORT);
                socket.bind(&bind.into())?;
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                socket.bind_device(Some(device.as_bytes()))?;
                socket.set_multicast_loop_v6(ip.is_loopback())?;
                // TODO: 外面传进来
                let ifindex = if_nametoindex(device)?;
                socket.join_multicast_v6(&MULTICAST_ADDR_V6, ifindex)?;
                socket.set_multicast_if_v6(ifindex)?;

                socket
            }
        };

        UdpSocket::from_std(socket.into()).map(Self)
    }

    pub async fn receive(&self) -> io::Result<(SocketAddr, Packet)> {
        loop {
            let mut recv_buffer = [0u8; 2048];

            let (size, source) = self.0.recv_from(&mut recv_buffer).await?;

            let Ok((_remain, packet)) = be_packet(&recv_buffer[..size]) else {
                continue;
            };

            return Ok((source, packet));
        }
    }

    pub async fn broadcast_packet(&self, packet: Packet) -> io::Result<()> {
        let buf = packet.to_bytes();
        let target: SocketAddr = match self.0.local_addr()?.ip() {
            IpAddr::V4(_) => (MULTICAST_ADDR_V4, MULTICAST_PORT).into(),
            IpAddr::V6(_) => (MULTICAST_ADDR_V6, MULTICAST_PORT).into(),
        };
        self.0.send_to(&buf, target).await?;

        Ok(())
    }
}

#[allow(clippy::type_complexity)]
pub struct PacketRouter {
    requests: (
        flume::Sender<(SocketAddr, Packet)>,
        flume::Receiver<(SocketAddr, Packet)>,
    ),
    responses: (
        flume::Sender<(SocketAddr, Packet)>,
        flume::Receiver<(SocketAddr, Packet)>,
    ),
    queries: DashMap<NonZero<u16>, flume::Sender<(SocketAddr, Packet)>>,
}

impl PacketRouter {
    pub fn new() -> Self {
        Self {
            requests: flume::bounded(MAX_DEQUE_SIZE),
            responses: flume::bounded(MAX_DEQUE_SIZE),
            queries: DashMap::new(),
        }
    }

    pub fn receive_query(
        &self,
    ) -> impl Future<Output = Result<(SocketAddr, Packet), flume::RecvError>> + Send + use<> {
        self.requests.1.clone().into_recv_async()
    }

    pub fn receive_boardcast(
        &self,
    ) -> impl Future<Output = Result<(SocketAddr, Packet), flume::RecvError>> + Send + use<> {
        self.responses.1.clone().into_recv_async()
    }

    pub async fn register_query(
        self: &Arc<Self>,
        query_id: NonZero<u16>,
    ) -> impl Stream<Item = (SocketAddr, Packet)> {
        struct Responses {
            query_id: NonZero<u16>,
            router: Weak<PacketRouter>,
            recver: flume::r#async::RecvStream<'static, (SocketAddr, Packet)>,
        }

        impl Stream for Responses {
            type Item = (SocketAddr, Packet);

            fn poll_next(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                Pin::new(&mut self.recver).poll_next(cx)
            }
        }

        impl Drop for Responses {
            fn drop(&mut self) {
                if let Some(router) = self.router.upgrade() {
                    router.queries.remove(&self.query_id);
                }
            }
        }

        let (tx, rx) = flume::bounded(MAX_DEQUE_SIZE);
        self.queries.insert(query_id, tx);

        Responses {
            query_id,
            router: Arc::downgrade(self),
            recver: rx.into_stream(),
        }
    }

    pub fn deliver(&self, source: SocketAddr, packet: Packet) {
        match (packet.header.flags.query(), packet.header.id) {
            (true, 0) => {
                if self.responses.0.try_send((source, packet.clone())).is_err() {
                    // Queue is full, remove oldest message (FIFO)
                    let _ = self.responses.1.try_recv();
                    // Try to send again after removing oldest
                    let _ = self.responses.0.try_send((source, packet));
                }
            }
            (true, query_id) => match self.queries.get(&NonZero::new(query_id).unwrap()) {
                Some(tx) => {
                    if let Err(error) = tx.try_send((source, packet)) {
                        tracing::debug!(
                            target: "mdns",
                            %query_id, %error,
                            "Failed to route response for query id"
                        );
                    }
                }
                None => tracing::debug!(
                    target: "mdns",
                    %query_id,
                    "Received response for query id, but no such kquery registered"
                ),
            },
            (false, _) => {
                if self.requests.0.try_send((source, packet.clone())).is_err() {
                    // Queue is full, remove oldest message (FIFO)
                    let _ = self.requests.1.try_recv();
                    // Try to send again after removing oldest
                    let _ = self.requests.0.try_send((source, packet));
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct MdnsProtocol {
    socket: Arc<MdnsSocket>,
    router: Weak<PacketRouter>,
    _route: AbortOnDropHandle<()>,
}

#[derive(Debug, Error)]
#[error("MDns socket is not listening")]
pub struct Disconnected;

impl From<Disconnected> for io::Error {
    fn from(error: Disconnected) -> Self {
        io::Error::new(io::ErrorKind::NotConnected, error)
    }
}

impl MdnsProtocol {
    pub fn new(device: &str, ip: IpAddr) -> io::Result<Arc<Self>> {
        let socket = Arc::new(MdnsSocket::new(device, ip)?);
        let router = Arc::new(PacketRouter::new());

        let route = AbortOnDropHandle::new(tokio::spawn({
            let socket = socket.clone();
            let router = router.clone();
            async move {
                while let Ok((source, packet)) = socket.receive().await {
                    router.deliver(source, packet);
                }
            }
        }));
        Ok(Arc::new(Self {
            socket,
            router: Arc::downgrade(&router),
            _route: route,
        }))
    }

    pub async fn broadcast_packet(&self, packet: Packet) -> io::Result<()> {
        self.socket.broadcast_packet(packet).await
    }

    pub async fn query(
        self: &Arc<Self>,
        local_name: String,
    ) -> io::Result<(SocketAddr, Vec<EndpointAddr>)> {
        let router = self.router.upgrade().ok_or(Disconnected)?;

        let packet = Packet::query_with_id(local_name.clone());
        let query_id = NonZero::new(packet.header.id).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Query id should not be 0")
        })?;

        let mut packets = router.register_query(query_id).await;
        let mut broadcast_tasks = JoinSet::new();

        for _ in 0..3 {
            _ = broadcast_tasks.spawn({
                let this = self.clone();
                let packet = packet.clone();
                async move { this.broadcast_packet(packet).await }
            });

            if let Ok(Some((source, packet))) =
                time::timeout(Duration::from_millis(300), packets.next()).await
            {
                use crate::parser::record::RData::*;
                let endpoints = packet
                    .answers
                    .iter()
                    .inspect(|answer| {
                        tracing::debug!(target: "mdns", ?answer, "Recv response");
                    })
                    .filter(|answer| {
                        if answer.name != local_name {
                            tracing::debug!(
                                target: "mdns",
                                answer_name = answer.name,
                                local_name,
                                "Ignored answer for different service name",
                            );
                        }
                        answer.name == local_name
                    })
                    .filter_map(|answer| match &answer.data {
                        E(e) => Some(e.clone()),
                        _ => {
                            tracing::debug!(target: "mdns", ?answer, "Ignored record");
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                if !endpoints.is_empty() {
                    return Ok((source, endpoints));
                }
            }
        }

        broadcast_tasks.abort_all();
        Err(io::ErrorKind::TimedOut.into())
    }

    pub async fn receive_query(&self) -> Result<(SocketAddr, Packet), Disconnected> {
        let router = self.router.upgrade().ok_or(Disconnected)?;

        router.receive_query().await.map_err(|_| Disconnected)
    }
    pub async fn receive_boardcast(&self) -> Result<(SocketAddr, Packet), Disconnected> {
        let router = self.router.upgrade().ok_or(Disconnected)?;

        router.receive_boardcast().await.map_err(|_| Disconnected)
    }
}
