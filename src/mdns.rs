use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::Duration,
};

use futures::{Stream, stream};
#[cfg(feature = "h3x-resolver")]
use h3x::gm_quic::{
    qbase::net::addr::BoundAddr,
    qinterface::{Interface, component::Component, io::IO},
};
use tokio::{task::JoinSet, time};

use crate::{
    parser::{packet::Packet, record::endpoint::EndpointAddr},
    protocol::MdnsProtocol,
};

#[derive(Clone)]
pub struct Mdns {
    service_name: String,
    hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
    inner: Arc<Mutex<MdnsInner>>,
}

struct MdnsInner {
    proto: Arc<MdnsProtocol>,
    tasks: JoinSet<()>,
}

impl fmt::Debug for Mdns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (local_device, ip) = {
            let guard = self.inner.lock().expect("Mdns inner lock poisoned");
            (guard.proto.bound_nic().to_string(), guard.proto.bound_ip())
        };
        f.debug_struct("Mdns")
            .field("service_name", &self.service_name)
            .field("local_device", &local_device)
            .field("ip", &ip)
            .finish()
    }
}

impl Mdns {
    pub fn new(service_name: &str, ip: IpAddr, device: &str) -> io::Result<Self> {
        let service_name = service_name.to_string();
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<EndpointAddr>>::new()));
        let (proto, route) = MdnsProtocol::new(device, ip)?;
        let proto = Arc::new(proto);
        let mut tasks = JoinSet::new();
        tasks.spawn(route);
        Self::spawn_tasks(
            &mut tasks,
            proto.clone(),
            hosts.clone(),
            service_name.clone(),
        );

        Ok(Self {
            service_name,
            hosts,
            inner: Arc::new(Mutex::new(MdnsInner { proto, tasks })),
        })
    }

    #[cfg(feature = "h3x-resolver")]
    pub fn init(service_name: &str, iface: &(impl IO + ?Sized)) -> io::Result<Self> {
        let binding = iface.bind_uri();
        let Some((_family, device, _port)) = binding.as_iface_bind_uri() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interface is not bound to internet address",
            ));
        };
        let BoundAddr::Internet(bound_addr) = iface.bound_addr()? else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interface is not bound to internet address",
            ));
        };

        Self::new(service_name, bound_addr.ip(), device)
    }

    fn spawn_tasks(
        tasks: &mut JoinSet<()>,
        proto: Arc<MdnsProtocol>,
        hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
        service_name: String,
    ) {
        // (1) periodic broadcaster
        tasks.spawn({
            let proto = proto.clone();
            let service_name = service_name.clone();
            async move {
                let mut interval = time::interval(Duration::from_secs(10));
                interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
                loop {
                    interval.tick().await;
                    let packet = Packet::query(service_name.clone());
                    if let Err(e) = proto.broadcast_packet(packet).await {
                        tracing::debug!(target: "mdns", "Broadcast packet error: {}", e);
                    }
                }
            }
        });

        // (2) responder
        tasks.spawn({
            let proto = proto.clone();
            let hosts = hosts.clone();
            let service_name = service_name.clone();
            async move {
                loop {
                    let res = proto.receive_query().await;
                    let Ok((_src, query)) = res else {
                        break;
                    };

                    let packet = {
                        let guard = hosts.lock().unwrap();
                        let host_name = guard
                            .keys()
                            .cloned()
                            .map(|h| Self::local_name(service_name.clone(), h))
                            .collect::<HashSet<_>>();

                        query
                            .questions
                            .iter()
                            .any(|q| host_name.iter().any(|h| h.contains(q.name.as_str())))
                            .then(|| Packet::answer(query.header.id, &guard))
                    };

                    if let Some(packet) = packet
                        && let Err(e) = proto.broadcast_packet(packet).await
                    {
                        tracing::debug!(target: "mdns", "Send response error: {}", e);
                    }
                }
            }
        });
    }

    fn poll_close(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        inner.tasks.abort_all();
        while ready!(inner.tasks.poll_join_next(cx)).is_some() {}

        Poll::Ready(())
    }

    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn bound_nic(&self) -> String {
        let inner = self.inner.lock().expect("Mdns inner lock poisoned");
        inner.proto.bound_nic().to_string()
    }

    pub fn bound_ip(&self) -> IpAddr {
        let inner = self.inner.lock().expect("Mdns inner lock poisoned");
        inner.proto.bound_ip()
    }

    #[inline]
    pub fn insert_host(&self, host_name: String, eps: Vec<EndpointAddr>) {
        let local_name = Self::local_name(self.service_name.clone(), host_name.clone());
        let mut guard = self.hosts.lock().unwrap();
        tracing::trace!(
            target: "mdns",
            %local_name, ?eps,
            "Adding host with addresses",
        );
        guard.insert(local_name, eps);
    }

    #[inline]
    fn protocol(&self) -> Arc<MdnsProtocol> {
        self.inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .proto
            .clone()
    }

    #[inline]
    pub async fn query(&self, domain: &str) -> io::Result<Vec<EndpointAddr>> {
        let proto = self.protocol();
        let local_name = Self::local_name(self.service_name.clone(), domain.to_owned());
        let (src, mut endpoints) = proto.query(local_name).await?;
        if let Some(pos) = endpoints.iter().position(|ep| ep.addr().ip() == src.ip()) {
            endpoints.swap(0, pos);
        }
        if endpoints.is_empty() {
            return Err(io::Error::other("empty dns result"));
        }
        Ok(endpoints)
    }

    #[inline]
    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> + use<> {
        let proto = self.protocol();

        Box::pin(stream::unfold(proto, async move |proto| {
            Some((proto.receive_boardcast().await.ok()?, proto))
        }))
    }

    #[inline]
    fn local_name(service_name: String, name: String) -> String {
        name.split_once("genmeta.net")
            .map(|(prefix, _)| format!("{prefix}{service_name}"))
            .unwrap_or(name)
    }
}

#[cfg(feature = "h3x-resolver")]
impl Component for Mdns {
    fn poll_shutdown(&self, _cx: &mut Context<'_>) -> Poll<()> {
        self.poll_close(_cx)
    }

    fn reinit(&self, iface: &Interface) {
        // Extract interface info

        let binding = iface.bind_uri();
        let Some((_family, device, _port)) = binding.as_iface_bind_uri() else {
            return;
        };
        let Ok(BoundAddr::Internet(bound_addr)) = iface.bound_addr() else {
            return;
        };
        let ip = bound_addr.ip();

        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        // Skip if already using same device/IP with active protocol

        if inner.proto.bound_nic() == device && inner.proto.bound_ip() == ip {
            return;
        }

        let Ok((proto, route)) = MdnsProtocol::new(device, ip) else {
            tracing::debug!(target: "mdns", device, %ip, "Failed to reinit mdns protocol");
            return;
        };
        inner.proto = Arc::new(proto);

        inner.tasks.abort_all();
        while inner.tasks.try_join_next().is_some() {}

        inner.tasks.spawn(route);
        let proto = inner.proto.clone();
        Self::spawn_tasks(
            &mut inner.tasks,
            proto,
            self.hosts.clone(),
            self.service_name.clone(),
        );
        // Update state with new protocol and tasks
    }
}
