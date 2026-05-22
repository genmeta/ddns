mod mdns;

pub use mdns::MdnsResolver;
#[cfg(feature = "mdns-resolver")]
pub use mdns::{MdnsBindDriver, MdnsResolvers};
