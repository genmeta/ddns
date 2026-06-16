use std::time::Duration;

use dashmap::DashMap;
use dquic::qbase::net::addr::EndpointAddr;
use tokio::time::Instant;

const POSITIVE_TTL: Duration = Duration::from_secs(10);
const NEGATIVE_TTL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct CachedRecord {
    addrs: Vec<EndpointAddr>,
    expire: Instant,
}

#[derive(Debug, Default)]
pub(super) struct LookupCache {
    positive: DashMap<String, CachedRecord>,
    negative: DashMap<String, Instant>,
}

impl LookupCache {
    pub(super) fn prune_expired(&self, now: Instant) {
        self.positive.retain(|_host, record| record.expire > now);
        self.negative.retain(|_host, expire| *expire > now);
    }

    pub(super) fn positive_hit(&self, domain: &str) -> Option<Vec<EndpointAddr>> {
        self.positive.get(domain).map(|record| record.addrs.clone())
    }

    pub(super) fn negative_hit(&self, domain: &str) -> bool {
        self.negative.get(domain).is_some()
    }

    pub(super) fn insert_positive(&self, domain: &str, addrs: Vec<EndpointAddr>) {
        self.positive.insert(
            domain.to_owned(),
            CachedRecord {
                addrs,
                expire: Instant::now() + POSITIVE_TTL,
            },
        );
        self.negative.remove(domain);
    }

    pub(super) fn insert_negative(&self, domain: &str) {
        self.negative
            .insert(domain.to_owned(), Instant::now() + NEGATIVE_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(addr: &str) -> EndpointAddr {
        EndpointAddr::direct(addr.parse().expect("socket addr"))
    }

    #[test]
    fn positive_cache_hit_returns_endpoints() {
        let cache = LookupCache::default();
        cache.insert_positive("demo.dhttp.net", vec![endpoint("192.0.2.10:4433")]);

        assert_eq!(
            cache.positive_hit("demo.dhttp.net").unwrap(),
            vec![endpoint("192.0.2.10:4433")]
        );
    }

    #[test]
    fn negative_cache_hit_blocks_lookup() {
        let cache = LookupCache::default();
        cache.insert_negative("missing.dhttp.net");

        assert!(cache.negative_hit("missing.dhttp.net"));
    }
}
