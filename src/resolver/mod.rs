use std::{
    fmt::{Debug, Display},
    io,
};

mod resolvers;

pub use resolvers::*;
use thiserror::Error;

use crate::parser::record::endpoint::EndpointAddr;
pub use crate::parser::record::*;

pub const HTTP_DNS_SERVER: &str = "https://dns.genmeta.net/";
pub const MDNS_SERVICE: &str = "_genmeta.local";

#[async_trait::async_trait(?Send)]
pub trait Publisher: Display + Debug {
    async fn publish(&self, name: &str, endpoint: EndpointAddr) -> io::Result<()>;
}

#[async_trait::async_trait(?Send)]
pub trait Resolver: Display + Debug {
    async fn lookup(&self, name: &str) -> io::Result<Vec<(Option<String>, EndpointAddr)>>;
}

#[derive(Debug, Error)]
pub enum UnsupportedEndpointAddressType {
    #[error("Signing error: {message}")]
    SignError { message: String },
}
