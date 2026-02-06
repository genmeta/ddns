pub mod mdns;
pub mod parser;
mod protocol;
pub mod resolvers;

pub const HTTP_DNS_SERVER: &str = "https://dns.genmeta.net/";
pub const H3_DNS_SERVER: &str = "https://localhost:4433";
pub const MDNS_SERVICE: &str = "_genmeta.local";

pub type MdnsEndpoint = crate::parser::record::endpoint::EndpointAddr;
pub type MdnsPacket = crate::parser::packet::Packet;

#[cfg(feature = "h3x-resolver")]
pub use parser::record::endpoint::sign_endponit_address;
