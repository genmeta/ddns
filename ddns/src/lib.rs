pub mod resolvers;

pub use ddns_core::{MdnsEndpoint, MdnsPacket, parser, sign_endponit_address, wire};
pub use gmdns::{Mdns, MdnsResolver, mdns};
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
