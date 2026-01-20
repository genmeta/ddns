use std::{
    fmt::{Debug, Display},
    io,
    net::SocketAddr,
};

mod resolvers;

pub use resolvers::*;
use rustls::{SignatureScheme, sign::SigningKey};
use thiserror::Error;

pub use crate::parser::record::*;

pub const HTTP_DNS_SERVER: &str = "https://dns.genmeta.net/";
pub const MDNS_SERVICE: &str = "_genmeta.local";

#[async_trait::async_trait]
pub trait Resolve: Display + Debug {
    async fn publish(
        &self,
        name: &str,
        is_main: bool,
        sequence: u64,
        key: Option<(&dyn SigningKey, SignatureScheme)>,
        addresses: &[SocketAddr],
    ) -> io::Result<()>;

    async fn lookup(&self, name: &str) -> io::Result<Vec<SocketAddr>>;
}

#[derive(Debug, Error)]
pub enum UnsupportedEndpointAddressType {
    #[error("Signing error: {message}")]
    SignError { message: String },
}
