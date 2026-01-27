use std::io;

use super::{Publisher, Resolver};
pub use crate::mdns::Mdns as MdnsResolver;
use crate::parser::record::endpoint::EndpointAddr;

#[async_trait::async_trait]
impl Publisher for MdnsResolver {
    async fn publish(&self, name: &str, endpoint: EndpointAddr) -> io::Result<()> {
        self.insert_host(name.to_string(), vec![endpoint.primary]);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Resolver for MdnsResolver {
    async fn lookup(&self, name: &str) -> io::Result<Vec<(Option<String>, EndpointAddr)>> {
        let addr_list = self.query(name.to_string()).await?;
        Ok(addr_list.into_iter().map(|e| (None, e)).collect())
    }
}
