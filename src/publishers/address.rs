#[cfg(feature = "dquic-network")]
use std::collections::HashSet;
use std::sync::Arc;
#[cfg(feature = "dquic-network")]
use std::{net::SocketAddr, sync::OnceLock};

use dquic::qbase::net::{Family, addr::EndpointAddr};
#[cfg(feature = "dquic-network")]
use dquic::qinterface::component::local_endpoint::LocalEndpointSubscriber;
#[cfg(feature = "dquic-network")]
use h3x::dquic::{
    Network,
    binds::BindPattern,
    net::{BindInterface, BindUri, IO, Scheme},
    qtraversal::nat::client::{NatType, StunClientsComponent},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSelector<'a> {
    WideArea,
    LocalLink { device: &'a str, family: Family },
}

pub trait AddressView {
    fn endpoints<'a>(
        &'a self,
        selector: AddressSelector<'a>,
    ) -> impl Iterator<Item = EndpointAddr> + 'a;
}

pub struct FnAddressView<F> {
    f: F,
}

impl<F> FnAddressView<F> {
    pub fn new(f: F) -> Self {
        Self { f }
    }
}

impl<F, I> AddressView for FnAddressView<F>
where
    F: for<'a> Fn(AddressSelector<'a>) -> I,
    I: IntoIterator<Item = EndpointAddr>,
    I::IntoIter: 'static,
{
    fn endpoints<'a>(
        &'a self,
        selector: AddressSelector<'a>,
    ) -> impl Iterator<Item = EndpointAddr> + 'a {
        (self.f)(selector).into_iter()
    }
}

#[cfg(feature = "dquic-network")]
pub trait AddressViewSource {
    fn address_view(&self) -> impl AddressView + Send + Sync + '_;
    fn subscribe(&self) -> LocalEndpointSubscriber;
    fn observes(&self, bind_uri: &BindUri) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishScope {
    WideArea,
    LocalLink { device: Arc<str>, family: Family },
}

impl PublishScope {
    pub(crate) fn selector(&self) -> AddressSelector<'_> {
        match self {
            Self::WideArea => AddressSelector::WideArea,
            Self::LocalLink { device, family } => AddressSelector::LocalLink {
                device: device.as_ref(),
                family: *family,
            },
        }
    }
}

#[allow(dead_code)]
pub type PublishAddressScope = PublishScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishAddressGroup {
    scope: PublishScope,
    endpoints: Vec<EndpointAddr>,
}

impl PublishAddressGroup {
    pub fn wide_area<I>(endpoints: I) -> Self
    where
        I: IntoIterator<Item = EndpointAddr>,
    {
        Self {
            scope: PublishScope::WideArea,
            endpoints: endpoints.into_iter().collect(),
        }
    }

    pub fn local_link<I>(device: impl Into<Arc<str>>, family: Family, endpoints: I) -> Self
    where
        I: IntoIterator<Item = EndpointAddr>,
    {
        Self {
            scope: PublishScope::LocalLink {
                device: device.into(),
                family,
            },
            endpoints: endpoints.into_iter().collect(),
        }
    }

    fn matches(&self, selector: AddressSelector<'_>) -> bool {
        match (&self.scope, selector) {
            (PublishScope::WideArea, AddressSelector::WideArea) => true,
            (
                PublishScope::LocalLink { device, family },
                AddressSelector::LocalLink {
                    device: selected_device,
                    family: selected_family,
                },
            ) => device.as_ref() == selected_device && *family == selected_family,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishAddresses {
    groups: Vec<PublishAddressGroup>,
}

impl PublishAddresses {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn group(mut self, group: PublishAddressGroup) -> Self {
        self.groups.push(group);
        self
    }

    pub fn wide_area<I>(self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = EndpointAddr>,
    {
        self.group(PublishAddressGroup::wide_area(endpoints))
    }

    pub fn local_link<I>(self, device: impl Into<Arc<str>>, family: Family, endpoints: I) -> Self
    where
        I: IntoIterator<Item = EndpointAddr>,
    {
        self.group(PublishAddressGroup::local_link(device, family, endpoints))
    }
}

impl AddressView for PublishAddresses {
    fn endpoints<'a>(
        &'a self,
        selector: AddressSelector<'a>,
    ) -> impl Iterator<Item = EndpointAddr> + 'a {
        self.groups
            .iter()
            .filter(move |group| group.matches(selector))
            .flat_map(move |group| group.endpoints.iter().copied())
    }
}

#[derive(Clone)]
#[cfg(feature = "dquic-network")]
pub struct EndpointBindingAddresses {
    network: Arc<Network>,
    bind_patterns: Arc<Vec<BindPattern>>,
}

#[cfg(feature = "dquic-network")]
impl std::fmt::Debug for EndpointBindingAddresses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointBindingAddresses")
            .field("bind_patterns", &self.bind_patterns)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "dquic-network")]
impl EndpointBindingAddresses {
    pub fn new(network: Arc<Network>, bind_patterns: Arc<Vec<BindPattern>>) -> Self {
        Self {
            network,
            bind_patterns,
        }
    }
}

#[cfg(feature = "dquic-network")]
impl AddressViewSource for EndpointBindingAddresses {
    fn address_view(&self) -> impl AddressView + Send + Sync + '_ {
        EndpointBindingAddressView::new(self.network.clone(), self.bind_patterns.clone())
    }

    fn subscribe(&self) -> LocalEndpointSubscriber {
        self.network.quic().local_endpoints().subscribe()
    }

    fn observes(&self, bind_uri: &BindUri) -> bool {
        self.bind_patterns
            .iter()
            .any(|pattern| pattern.matches(bind_uri))
    }
}

#[cfg(feature = "dquic-network")]
struct EndpointBindingAddressView {
    bindings: Vec<BindingAddress>,
}

#[cfg(feature = "dquic-network")]
impl EndpointBindingAddressView {
    fn new(network: Arc<Network>, bind_patterns: Arc<Vec<BindPattern>>) -> Self {
        let mut bindings = Vec::new();
        for pattern in bind_patterns.iter() {
            let Some(ifaces) = network.quic().get_interfaces(pattern) else {
                tracing::trace!(?pattern, "no interfaces for bind pattern");
                continue;
            };
            for iface in ifaces {
                bindings.push(BindingAddress::new(network.clone(), pattern.clone(), iface));
            }
        }
        Self { bindings }
    }
}

#[cfg(feature = "dquic-network")]
impl AddressView for EndpointBindingAddressView {
    fn endpoints<'a>(
        &'a self,
        selector: AddressSelector<'a>,
    ) -> impl Iterator<Item = EndpointAddr> + 'a {
        let mut seen = HashSet::new();
        self.bindings
            .iter()
            .filter(move |binding| binding.may_match(selector))
            .flat_map(move |binding| binding.endpoints(selector))
            .filter(move |endpoint| seen.insert(*endpoint))
    }
}

#[cfg(feature = "dquic-network")]
struct BindingAddress {
    network: Arc<Network>,
    pattern: BindPattern,
    bind_uri: BindUri,
    iface: BindInterface,
    wide_area: OnceLock<Vec<EndpointAddr>>,
    local_link: OnceLock<Vec<EndpointAddr>>,
}

#[cfg(feature = "dquic-network")]
impl BindingAddress {
    fn new(network: Arc<Network>, pattern: BindPattern, iface: BindInterface) -> Self {
        let bind_uri = iface.bind_uri();
        Self {
            network,
            pattern,
            bind_uri,
            iface,
            wide_area: OnceLock::new(),
            local_link: OnceLock::new(),
        }
    }

    fn may_match(&self, selector: AddressSelector<'_>) -> bool {
        match selector {
            AddressSelector::WideArea => true,
            AddressSelector::LocalLink { device, family } => {
                pattern_may_match_local_link(&self.pattern, device, family)
                    && bind_uri_matches_local_link(&self.bind_uri, device, family)
            }
        }
    }

    fn endpoints<'a>(
        &'a self,
        selector: AddressSelector<'a>,
    ) -> impl Iterator<Item = EndpointAddr> + 'a {
        let endpoints = match selector {
            AddressSelector::WideArea => self
                .wide_area
                .get_or_init(|| public_endpoints_from_iface(&self.network, &self.iface)),
            AddressSelector::LocalLink { family, .. } => self
                .local_link
                .get_or_init(|| local_endpoints_from_iface(&self.iface, family)),
        };
        endpoints.iter().copied()
    }
}

#[cfg(feature = "dquic-network")]
fn pattern_may_match_local_link(pattern: &BindPattern, device: &str, family: Family) -> bool {
    if pattern.scheme != Scheme::Iface {
        return false;
    }
    if pattern
        .host
        .family()
        .is_some_and(|pattern_family| pattern_family != family)
    {
        return false;
    }
    pattern.host.matches(device)
}

#[cfg(feature = "dquic-network")]
fn bind_uri_matches_local_link(bind_uri: &BindUri, device: &str, family: Family) -> bool {
    bind_uri
        .as_iface_bind_uri()
        .is_some_and(|(iface_family, iface_device, _port)| {
            iface_family == family && iface_device == device
        })
}

#[cfg(feature = "dquic-network")]
fn public_endpoints_from_iface(network: &Network, iface: &BindInterface) -> Vec<EndpointAddr> {
    iface.with_components(|components, current| {
        let bind_uri = current.bind_uri();
        let addr = current.bound_addr().ok();
        let mut endpoints: Vec<EndpointAddr> = components
            .get::<StunClientsComponent>()
            .map(|stun| {
                stun.with_clients(|clients| {
                    clients
                        .values()
                        .filter_map(|client| {
                            let outer = client.get_outer_addr()?.ok()?;
                            let bound = current.bound_addr().ok()?;
                            match client.get_nat_type() {
                                Some(Ok(nat_type)) => Some(publish_endpoint_from_stun(
                                    bound,
                                    client.agent_addr(),
                                    outer,
                                    nat_type,
                                )),
                                None => Some(EndpointAddr::with_agent(client.agent_addr(), outer)),
                                Some(Err(_)) => None,
                            }
                        })
                        .collect()
                })
            })
            .unwrap_or_default();
        let stun_endpoint_count = endpoints.len();

        if let Some(addr) = addr
            && network.bound_addr_is_on_default_route(&bind_uri, addr)
        {
            endpoints.push(EndpointAddr::direct(addr));
        }

        tracing::trace!(
            bind_uri = %bind_uri,
            bound_addr = ?addr,
            stun_endpoint_count,
            endpoint_count = endpoints.len(),
            endpoints = ?endpoints,
            "collected wide-area endpoints from interface"
        );

        endpoints
    })
}

#[cfg(feature = "dquic-network")]
fn publish_endpoint_from_stun(
    bound: SocketAddr,
    agent: SocketAddr,
    outer: SocketAddr,
    nat_type: NatType,
) -> EndpointAddr {
    if nat_type == NatType::FullCone && bound == outer {
        EndpointAddr::direct(outer)
    } else {
        EndpointAddr::with_agent(agent, outer)
    }
}

#[cfg(feature = "dquic-network")]
fn local_endpoints_from_iface(iface: &BindInterface, family: Family) -> Vec<EndpointAddr> {
    iface.with_components(|_components, current| {
        let Some(addr) = current.bound_addr().ok() else {
            return Vec::new();
        };
        match (family, addr) {
            (Family::V4, SocketAddr::V4(_)) | (Family::V6, SocketAddr::V6(_)) => {
                vec![EndpointAddr::direct(addr)]
            }
            _ => Vec::new(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_scope_wide_area_converts_to_wide_area_selector() {
        let scope = PublishScope::WideArea;

        assert_eq!(scope.selector(), AddressSelector::WideArea);
    }

    #[test]
    fn publish_scope_local_link_converts_to_borrowed_selector() {
        let scope = PublishScope::LocalLink {
            device: Arc::<str>::from("en0"),
            family: Family::V4,
        };

        assert_eq!(
            scope.selector(),
            AddressSelector::LocalLink {
                device: "en0",
                family: Family::V4,
            }
        );
    }

    #[test]
    fn publish_addresses_select_wide_area_only_for_wide_area_selector() {
        let wide = EndpointAddr::direct("203.0.113.10:443".parse().unwrap());
        let local = EndpointAddr::direct("192.168.1.20:443".parse().unwrap());
        let addresses =
            PublishAddresses::new()
                .wide_area([wide])
                .local_link("en0", Family::V4, [local]);

        let selected: Vec<_> = addresses.endpoints(AddressSelector::WideArea).collect();

        assert_eq!(selected, vec![wide]);
    }

    #[test]
    fn publish_addresses_select_matching_local_link_group() {
        let en0 = EndpointAddr::direct("192.168.1.20:443".parse().unwrap());
        let en1 = EndpointAddr::direct("192.168.2.20:443".parse().unwrap());
        let addresses = PublishAddresses::new()
            .local_link("en0", Family::V4, [en0])
            .local_link("en1", Family::V4, [en1]);

        let selected: Vec<_> = addresses
            .endpoints(AddressSelector::LocalLink {
                device: "en1",
                family: Family::V4,
            })
            .collect();

        assert_eq!(selected, vec![en1]);
    }

    #[test]
    fn publish_addresses_reject_local_link_family_mismatch() {
        let endpoint = EndpointAddr::direct("192.168.1.20:443".parse().unwrap());
        let addresses = PublishAddresses::new().local_link("en0", Family::V4, [endpoint]);

        let selected: Vec<_> = addresses
            .endpoints(AddressSelector::LocalLink {
                device: "en0",
                family: Family::V6,
            })
            .collect();

        assert!(selected.is_empty());
    }

    #[cfg(feature = "dquic-network")]
    #[test]
    fn full_cone_nat_endpoint_preserves_agent_when_outer_differs_from_bound_addr() {
        let bound = "10.110.0.10:45635".parse().expect("valid bound addr");
        let agent = "10.10.0.2:20004".parse().expect("valid agent addr");
        let outer = "10.10.0.10:45635".parse().expect("valid outer addr");

        let endpoint = publish_endpoint_from_stun(bound, agent, outer, NatType::FullCone);

        assert_eq!(endpoint, EndpointAddr::with_agent(agent, outer));
    }

    #[cfg(feature = "dquic-network")]
    #[test]
    fn full_cone_endpoint_is_direct_without_address_translation() {
        let bound = "10.10.0.100:45635".parse().expect("valid bound addr");
        let agent = "10.10.0.2:20004".parse().expect("valid agent addr");

        let endpoint = publish_endpoint_from_stun(bound, agent, bound, NatType::FullCone);

        assert_eq!(endpoint, EndpointAddr::direct(bound));
    }
}
