pub mod parser;
pub mod wire;

pub type MdnsEndpoint = crate::parser::record::endpoint::EndpointAddr;
pub type MdnsPacket = crate::parser::packet::Packet;

pub use parser::record::endpoint::sign_endponit_address;
