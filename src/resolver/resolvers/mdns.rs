use std::io;

use async_trait::async_trait;
use rustls::{SignatureScheme, sign::SigningKey};

use super::Resolve;
pub use crate::mdns::Mdns as MdnsResolver;

#[async_trait]
impl Resolve for MdnsResolver {
    async fn publish(
        &self,
        name: &str,
        _is_main: bool,
        _sequence: u64,
        _key: Option<(&dyn SigningKey, SignatureScheme)>,
        addresses: &[std::net::SocketAddr],
    ) -> io::Result<()> {
        let addresses: Vec<_> = addresses.iter().map(|&addr| addr).collect();
        self.insert_host(name.to_string(), addresses);
        Ok(())
    }

    async fn lookup(&self, name: &str) -> io::Result<Vec<std::net::SocketAddr>> {
        self.query(name.to_string())
            .await
            .map(|addr_list| addr_list.iter().map(|e| e.primary).collect::<Vec<_>>())
    }
}
