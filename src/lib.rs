mod bootstrap;

pub mod core;
pub mod mdns;
#[cfg(any(feature = "h3x-resolver", feature = "mdns-resolver"))]
mod publisher;
pub mod resolvers;

pub use core::{MdnsEndpoint, MdnsPacket, parser, sign_endponit_address, wire};

pub use mdns::{Mdns, MdnsResolver};
#[cfg(any(feature = "h3x-resolver", feature = "mdns-resolver"))]
pub use publisher::{
    CreatePublisherError, DEFAULT_PUBLISH_INTERVAL, DEFAULT_PUBLISH_TIMEOUT, PublishOnceError,
    PublishOptions, Publisher,
};
#[cfg(feature = "http-resolver")]
pub use resolvers::HttpResolver;
#[cfg(feature = "mdns-resolver")]
pub use resolvers::MdnsResolvers;
pub use resolvers::{
    DHTTP_H3_DNS_SERVER, DHTTP_HTTP_DNS_SERVER, DHTTP_MDNS_SERVICE, DnsErrors, DnsScheme,
    ParseDnsSchemeError, Resolvers, ResolversBuilder,
};
#[cfg(feature = "h3x-resolver")]
pub use resolvers::{H3Publisher, H3Resolver};
