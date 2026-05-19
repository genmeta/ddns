mod mdns;

pub use mdns::MdnsResolver;
#[cfg(feature = "h3x-network")]
pub use mdns::{MdnsBindDriver, MdnsResolvers};
