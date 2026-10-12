use std::{
    collections::{HashMap, HashSet},
    fmt, io,
    net::IpAddr,
    sync::{Arc, Mutex},
};

use tokio::task::JoinSet;
use tracing::Instrument;

use super::protocol::MdnsProtocol;
use crate::core::parser::{packet::Packet, record::endpoint::EndpointAddr};

type HostRecords = Mutex<HashMap<String, Vec<EndpointAddr>>>;

#[derive(Clone)]
pub struct MdnsResolver {
    service_name: Arc<str>,
    device: Arc<str>,
    ip: IpAddr,
    hosts: Arc<HostRecords>,
    inner: Arc<Mutex<MdnsInner>>,
}

struct MdnsInner {
    proto: Option<Arc<MdnsProtocol>>,
    tasks: JoinSet<()>,
}

impl Drop for MdnsInner {
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

impl fmt::Debug for MdnsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MdnsResolver")
            .field("service_name", &self.service_name)
            .field("device", &self.device)
            .field("ip", &self.ip)
            .finish_non_exhaustive()
    }
}

impl MdnsResolver {
    pub(super) fn new(service_name: Arc<str>, device: Arc<str>, ip: IpAddr) -> io::Result<Self> {
        let hosts = Arc::new(HostRecords::new(HashMap::new()));
        let (proto, route) = MdnsProtocol::new(&device, ip)?;
        let proto = Arc::new(proto);
        let mut tasks = JoinSet::new();
        tasks.spawn(route);
        spawn_responder(
            &mut tasks,
            proto.clone(),
            hosts.clone(),
            service_name.clone(),
        );
        Ok(Self {
            service_name,
            device,
            ip,
            hosts,
            inner: Arc::new(Mutex::new(MdnsInner {
                proto: Some(proto),
                tasks,
            })),
        })
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn bound_device(&self) -> &str {
        &self.device
    }

    pub fn bound_ip(&self) -> IpAddr {
        self.ip
    }

    pub(super) fn insert_host(&self, host_name: &str, endpoints: Vec<EndpointAddr>) {
        let local_name = Self::local_name(&self.service_name, host_name);
        self.hosts
            .lock()
            .expect("mDNS host records lock poisoned")
            .insert(local_name, endpoints);
    }

    pub(super) fn remove_host(&self, host_name: &str) {
        let local_name = Self::local_name(&self.service_name, host_name);
        self.hosts
            .lock()
            .expect("mDNS host records lock poisoned")
            .remove(&local_name);
    }

    pub(super) async fn query(&self, domain: &str) -> io::Result<Vec<EndpointAddr>> {
        let proto = self
            .inner
            .lock()
            .expect("mDNS inner lock poisoned")
            .proto
            .clone()
            .ok_or_else(|| io::Error::other("mDNS resolver is shut down"))?;
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        let local_name = Self::local_name(&self.service_name, &domain);
        let (source, mut endpoints) = proto.query(local_name).await?;
        if let Some(index) = endpoints
            .iter()
            .position(|endpoint| endpoint.addr().ip() == source.ip())
        {
            endpoints.swap(0, index);
        }
        if endpoints.is_empty() {
            Err(io::Error::other("empty DNS result"))
        } else {
            Ok(endpoints)
        }
    }

    pub(super) async fn shutdown_tasks(&self) -> Result<(), tokio::task::JoinError> {
        let mut tasks = {
            let mut inner = self.inner.lock().expect("mDNS inner lock poisoned");
            if inner.proto.take().is_none() {
                return Ok(());
            }
            inner.tasks.abort_all();
            std::mem::replace(&mut inner.tasks, JoinSet::new())
        };
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result
                && !error.is_cancelled()
            {
                return Err(error);
            }
        }
        Ok(())
    }

    fn local_name(service_name: &str, name: &str) -> String {
        name.strip_suffix(dhttp_home::DHTTP_SUFFIX)
            .map(|prefix| format!("{prefix}.{service_name}"))
            .unwrap_or_else(|| name.to_owned())
    }
}

fn spawn_responder(
    tasks: &mut JoinSet<()>,
    proto: Arc<MdnsProtocol>,
    hosts: Arc<HostRecords>,
    service_name: Arc<str>,
) {
    let span = tracing::debug_span!(
        "mdns_tasks",
        service_name = %service_name,
        nic = proto.bound_nic(),
        ip = %proto.bound_ip()
    );
    tasks.spawn(
        async move {
            while let Ok((_source, query)) = proto.receive_query().await {
                let packet = {
                    let hosts = hosts.lock().expect("mDNS host records lock poisoned");
                    let local_names = hosts
                        .keys()
                        .map(|name| MdnsResolver::local_name(&service_name, name))
                        .collect::<HashSet<_>>();
                    query
                        .questions
                        .iter()
                        .any(|question| {
                            local_names
                                .iter()
                                .any(|name| name.contains(question.name().as_str()))
                        })
                        .then(|| Packet::answer(query.id(), &hosts))
                };
                if let Some(packet) = packet {
                    let _ = proto.broadcast_packet(packet).await;
                }
            }
        }
        .instrument(span),
    );
}

#[cfg(test)]
mod tests {
    use super::MdnsResolver;

    #[test]
    fn local_name_replaces_dhttp_suffix() {
        assert_eq!(
            MdnsResolver::local_name("_gensokyo.local", "reimu.pilot.dhttp.net"),
            "reimu.pilot._gensokyo.local"
        );
    }
}
