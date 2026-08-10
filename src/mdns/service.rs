use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll, ready},
    time::Duration,
};

use dhttp_identity::name::DhttpName;
use dquic::qinterface::{Interface, component::Component, io::IO};
use futures::{Stream, stream};
use tokio::{task::JoinSet, time};
use tracing::Instrument;

use super::protocol::MdnsProtocol;
use crate::core::parser::{packet::Packet, record::endpoint::EndpointAddr};

/// Host records served by one concrete mDNS binding.
pub(crate) type HostRecords = Mutex<HashMap<String, Vec<EndpointAddr>>>;

/// Runs mDNS on one concrete interface and address-family binding.
#[derive(Clone)]
pub struct Mdns {
    /// Builds and matches local names served by this binding.
    service_name: String,

    /// Stores records published by every endpoint sharing this binding.
    hosts: Arc<HostRecords>,

    /// Owns the eager socket protocol and base tasks across clones.
    inner: Arc<Mutex<MdnsInner>>,
}

/// Mutable runtime state for one concrete mDNS binding.
struct MdnsInner {
    /// Owns the eagerly-created UDP 5353 socket.
    proto: Arc<MdnsProtocol>,

    /// Runs packet routing and responses, but no unconditional discovery timer.
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
        let hosts = Arc::new(HostRecords::new(HashMap::new()));
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

    pub fn from_iface(service_name: &str, iface: &(impl IO + ?Sized)) -> io::Result<Self> {
        let binding = iface.bind_uri();
        let Some((_family, device, _port)) = binding.as_iface_bind_uri() else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "interface is not bound to internet address",
            ));
        };
        let bound_addr = iface.bound_addr()?;

        Self::new(service_name, bound_addr.ip(), device)
    }

    pub fn reinit(&self, iface: &(impl IO + ?Sized)) {
        let binding = iface.bind_uri();
        let Some((_family, device, _port)) = binding.as_iface_bind_uri() else {
            return;
        };
        let Ok(bound_addr) = iface.bound_addr() else {
            return;
        };

        self.reinit_on(device, bound_addr.ip());
    }

    pub fn reinit_on(&self, device: &str, ip: IpAddr) {
        let mut inner = self.inner.lock().expect("Mdns inner lock poisoned");

        if inner.proto.bound_nic() == device && inner.proto.bound_ip() == ip {
            return;
        }

        let Ok((proto, route)) = MdnsProtocol::new(device, ip) else {
            tracing::debug!(device, %ip, "failed to reinit mdns protocol");
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
    }

    fn spawn_tasks(
        tasks: &mut JoinSet<()>,
        proto: Arc<MdnsProtocol>,
        hosts: Arc<HostRecords>,
        service_name: String,
    ) {
        let span = tracing::debug_span!(
            "mdns_tasks",
            service_name,
            nic = proto.bound_nic(),
            ip = %proto.bound_ip()
        );

        // The responder remains eager because a shared binding must answer external queries
        // even when this process has not started an explicit discovery stream.
        tasks.spawn(
            {
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
                                .any(|q| host_name.iter().any(|h| h.contains(q.name().as_str())))
                                .then(|| Packet::answer(query.id(), &guard))
                        };

                        if let Some(packet) = packet
                            && let Err(e) = proto.broadcast_packet(packet).await
                        {
                            tracing::debug!(
                                error = %snafu::Report::from_error(&e),
                                "send response error"
                            );
                        }
                    }
                }
            }
            .instrument(span.clone()),
        );
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
        tracing::trace!(%local_name, ?eps, "adding host with addresses");
        guard.insert(local_name, eps);
    }

    /// Insert a publication and return only the weak cleanup location it needs.
    pub(crate) fn insert_host_for_publication(
        &self,
        host_name: String,
        endpoints: Vec<EndpointAddr>,
    ) -> (Weak<HostRecords>, String) {
        let local_name = Self::local_name(self.service_name.clone(), host_name);
        self.hosts
            .lock()
            .expect("mDNS host records lock poisoned")
            .insert(local_name.clone(), endpoints);
        (Arc::downgrade(&self.hosts), local_name)
    }

    #[cfg(test)]
    pub(crate) fn published_endpoints(&self, host_name: &str) -> Option<Vec<EndpointAddr>> {
        let local_name = Self::local_name(self.service_name.clone(), host_name.to_owned());
        self.hosts.lock().unwrap().get(&local_name).cloned()
    }

    #[inline]
    pub(crate) fn protocol(&self) -> Arc<MdnsProtocol> {
        self.inner
            .lock()
            .expect("Mdns inner lock poisoned")
            .proto
            .clone()
    }

    #[inline]
    pub fn query(
        &self,
        domain: String,
    ) -> impl Future<Output = io::Result<Vec<EndpointAddr>>> + use<> {
        let proto = self.protocol();
        let local_name = Self::local_name(self.service_name.clone(), domain);
        async move {
            let (src, mut endpoints) = proto.query(local_name).await?;
            if let Some(pos) = endpoints.iter().position(|ep| ep.addr().ip() == src.ip()) {
                endpoints.swap(0, pos);
            }
            if endpoints.is_empty() {
                return Err(io::Error::other("empty dns result"));
            }
            Ok(endpoints)
        }
    }

    #[inline]
    pub fn discover(&self) -> impl Stream<Item = (SocketAddr, Packet)> + use<> {
        Box::pin(discovery_stream(self.protocol(), self.service_name.clone()))
    }

    #[inline]
    fn local_name(service_name: String, name: String) -> String {
        name.strip_suffix(DhttpName::SUFFIX)
            .map(|prefix| format!("{prefix}.{service_name}"))
            .unwrap_or_else(|| name)
    }
}

/// Receives answers and queries immediately and every ten seconds while polled.
fn discovery_stream(
    protocol: Arc<MdnsProtocol>,
    service_name: String,
) -> impl Stream<Item = (SocketAddr, Packet)> {
    stream::unfold(
        (
            protocol,
            service_name,
            time::interval(Duration::from_secs(10)),
        ),
        |(protocol, service_name, mut interval)| async move {
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let packet = Packet::query(service_name.clone());
                        let _ = protocol.broadcast_packet(packet).await;
                    }
                    answer = protocol.receive_boardcast() => {
                        return Some((
                            answer.ok()?,
                            (protocol, service_name, interval),
                        ));
                    }
                }
            }
        },
    )
}

impl Component for Mdns {
    fn poll_shutdown(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.poll_close(cx)
    }

    fn reinit(&self, iface: &Interface) {
        self.reinit(iface);
    }
}

#[cfg(test)]
mod tests {
    use super::Mdns;

    #[test]
    fn local_name_uses_dhttp_identity_suffix() {
        assert_eq!(
            Mdns::local_name(
                "_gensokyo.local".to_string(),
                "reimu.pilot.dhttp.net".to_string()
            ),
            "reimu.pilot._gensokyo.local"
        );
    }
}
