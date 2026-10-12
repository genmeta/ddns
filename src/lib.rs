#[cfg(any(feature = "h3", feature = "http"))]
mod api;
mod bootstrap;

pub mod core;
#[cfg(feature = "h3")]
pub mod h3;
#[cfg(feature = "h3")]
pub use h3::H3Resolver;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "mdns")]
pub mod mdns;
pub mod publishers;
#[cfg(all(feature = "h3", feature = "http", feature = "mdns"))]
mod resolver_config;
pub mod resolvers;
#[cfg(all(feature = "h3", feature = "http", feature = "mdns"))]
pub use resolver_config::{DnsScheme, install_resolvers};

#[cfg(test)]
mod test_support;
