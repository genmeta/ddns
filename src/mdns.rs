mod if_nametoindex;
mod protocol;
pub mod resolvers;
mod service;

pub use resolvers::MdnsResolver;
#[cfg(feature = "mdns-resolver")]
pub use resolvers::{MdnsBindDriver, MdnsResolvers};
pub use service::Mdns;
