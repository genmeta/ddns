use std::{fmt, net::IpAddr};

use futures::{StreamExt, future, stream};
use qdns::{EndpointAddr, Family, ResolveFuture, SocketEndpointAddr, Source};

use super::{Publish, Resolve};
pub use crate::mdns::Mdns as MdnsResolver;

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
    fn publish<'a>(
        &'a self,
        name: &'a str,
        endpoints: &'a [EndpointAddr],
    ) -> qdns::PublishFuture<'a> {
        self.insert_host(
            name.to_string(),
            endpoints
                .iter()
                .filter_map(|ep| match ep {
                    EndpointAddr::Socket(ep) => (*ep).try_into().ok(),
                    EndpointAddr::Ble(..) => None,
                })
                .collect(),
        );
        Box::pin(future::ready(Ok(())))
    }
}

impl Resolve for MdnsResolver {
    fn lookup<'r, 'n: 'r>(&'r self, name: &'n str) -> ResolveFuture<'r, 'n> {
        Box::pin(async move {
            let source = Source::Mdns {
                nic: self.bound_nic().into(),
                family: match self.bound_ip() {
                    IpAddr::V4(..) => Family::V4,
                    IpAddr::V6(..) => Family::V6,
                },
            };
            self.query(name).await.map(move |list| {
                stream::iter(list.into_iter().filter_map(move |ep| {
                    let ep = EndpointAddr::Socket(SocketEndpointAddr::try_from(ep).ok()?);
                    Some((source.clone(), ep))
                }))
                .boxed()
            })
        })
    }
}
