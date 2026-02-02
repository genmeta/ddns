use std::{
    collections::{HashMap, HashSet},
    fmt,
    fmt::Display,
    io::{self},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::{Stream, stream};
#[cfg(feature = "h3x-resolver")]
use gm_quic::qinterface::io::IO;
#[cfg(feature = "h3x-resolver")]
use gm_quic::qinterface::{Interface, component::Component};
use tokio::{task::JoinSet, time};
use tokio_util::task::AbortOnDropHandle;

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
    local_device: String,
    ip: IpAddr,
    proto: Option<Arc<MdnsProtocol>>,
    tasks: Option<AbortOnDropHandle<()>>,
    closing: bool,
}

impl fmt::Debug for Mdns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (local_device, ip, closing) = {
            let guard = self.inner.lock().expect("Mdns inner lock poisoned");
            (guard.local_device.clone(), guard.ip, guard.closing)
        };
        f.debug_struct("Mdns")
            .field("service_name", &self.service_name)
            .field("local_device", &local_device)
            .field("ip", &ip)
            .field("closing", &closing)
            .finish()
    }
}

impl Display for Mdns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let local_device = self
            .inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .local_device
            .clone();
        write!(f, "mDNS({})", local_device)
    }
}

impl Mdns {
    pub fn new(service_name: &str, ip: IpAddr, device: &str) -> io::Result<Self> {
        let service_name = service_name.to_string();
        let hosts = Arc::new(Mutex::new(HashMap::<String, Vec<EndpointAddr>>::new()));

        let proto = MdnsProtocol::new(device, ip)?;
        let tasks = Self::spawn_tasks(proto.clone(), hosts.clone(), service_name.clone());

        Ok(Self {
            service_name,
            hosts,
            inner: Arc::new(Mutex::new(MdnsInner {
                local_device: device.to_string(),
                ip,
                proto: Some(proto),
                tasks: Some(tasks),
                closing: false,
            })),
        })
    }

    fn spawn_tasks(
        proto: Arc<MdnsProtocol>,
        hosts: Arc<Mutex<HashMap<String, Vec<EndpointAddr>>>>,
        service_name: String,
    ) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let mut tasks = JoinSet::new();

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

            // Wait for all tasks to complete (they run indefinitely until cancelled)
            while tasks.join_next().await.is_some() {}
        }))
    }

    fn poll_close(&self, _cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        if !inner.closing {
            inner.closing = true;
            // Take the task handle to trigger shutdown
            inner.tasks.take();
        }

        inner.proto.take();
        Poll::Ready(())
    }

    #[inline]
    pub fn local_device(&self) -> String {
        self.inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .local_device
            .clone()
    }

    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[inline]
    pub fn insert_host(&self, host_name: String, eps: Vec<EndpointAddr>) {
        let local_name = Self::local_name(self.service_name.clone(), host_name.clone());
        let mut guard = self.hosts.lock().unwrap();
        tracing::debug!(
            target: "mdns",
            %local_name, ?eps,
            "Adding host with addresses",
        );
        guard.insert(local_name, eps);
    }

    #[inline]
    pub async fn query(&self, domain: String) -> io::Result<Vec<EndpointAddr>> {
        let proto = self
            .inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .proto
            .clone()
            .ok_or_else(|| io::Error::other("mdns is closed"))?;
        let local_name = Self::local_name(self.service_name.clone(), domain.clone());
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
    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> {
        let proto = self
            .inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .proto
            .clone();

        Box::pin(stream::unfold(proto, async move |proto| {
            let proto = proto?;
            Some((proto.receive_boardcast().await.ok()?, Some(proto)))
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

    fn reinit(&self, _iface: &Interface) {
        // Extract interface info
        let binding = _iface.bind_uri();
        let Some((_family, device, _port)) = binding.as_iface_bind_uri() else {
            return;
        };
        let Ok(real_addr) = _iface.real_addr() else {
            return;
        };
        let Ok(socket_addr) = real_addr.to_string().parse::<SocketAddr>() else {
            return;
        };
        let ip = socket_addr.ip();

        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        // Skip if already using same device/IP with active protocol
        if inner.local_device == device && inner.ip == ip && inner.proto.is_some() {
            return;
        }

        // Clean up existing tasks and create new protocol
        inner.tasks.take();

        let Ok(proto) = MdnsProtocol::new(device, ip) else {
            tracing::debug!(target: "mdns", device, %ip, "Failed to reinit mdns protocol");
            return;
        };

        // Update state with new protocol and tasks
        let tasks = Self::spawn_tasks(proto.clone(), self.hosts.clone(), self.service_name.clone());
        inner.local_device = device.to_string();
        inner.ip = ip;
        inner.proto = Some(proto);
        inner.tasks = Some(tasks);
        inner.closing = false;
    }
}
