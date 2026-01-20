pub mod mdns;
pub mod parser;
mod protocol;
pub mod resolver;

pub type MdnsEndpoint = crate::parser::record::endpoint::EndpointAddr;
pub type MdnsPacket = crate::parser::packet::Packet;
