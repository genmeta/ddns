use std::{
    fmt::{Debug, Display},
    io,
};

mod resolvers;

pub use resolvers::*;
use thiserror::Error;

use crate::parser::record::endpoint::EndpointAddr;
pub use crate::parser::record::*;

#[async_trait::async_trait]
pub trait Publisher: Display + Debug {
    async fn publish(&self, name: &str, endpoints: &[EndpointAddr]) -> io::Result<()>;
}

#[async_trait::async_trait]
pub trait Resolver: Display + Debug {
    async fn lookup(&self, name: &str) -> io::Result<Vec<(Option<String>, EndpointAddr)>>;
}

#[derive(Debug, Error)]
pub enum UnsupportedEndpointAddressType {
    #[error("Signing error: {message}")]
    SignError { message: String },
}
