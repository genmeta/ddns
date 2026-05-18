pub mod resolvers;

pub use ddns_core::{MdnsEndpoint, MdnsPacket, parser, sign_endponit_address, wire};
pub use gmdns::{Mdns, MdnsResolver, MdnsResolvers, mdns};
#[cfg(feature = "http-resolver")]
pub use resolvers::HttpResolver;
pub use resolvers::{DnsErrors, Resolvers};
#[cfg(feature = "h3x-resolver")]
pub use resolvers::{H3Publisher, H3Resolver};
