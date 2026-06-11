pub mod parser;
pub mod signature;
pub mod wire;

pub type MdnsEndpoint = parser::record::endpoint::EndpointAddr;
pub type MdnsPacket = parser::packet::Packet;
