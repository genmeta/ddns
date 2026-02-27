pub mod mdns;
pub mod parser;
mod protocol;
pub mod resolvers;
pub mod wire;

pub type MdnsEndpoint = crate::parser::record::endpoint::EndpointAddr;
pub type MdnsPacket = crate::parser::packet::Packet;

#[cfg(feature = "h3x-resolver")]
pub use parser::record::endpoint::sign_endponit_address;
