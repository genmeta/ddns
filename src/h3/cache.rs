use std::time::Duration;

use dashmap::DashMap;
use dquic::{qbase::net::addr::EndpointAddr, qresolve::Family};
use tokio::time::Instant;

const POSITIVE_TTL: Duration = Duration::from_secs(10);
const NEGATIVE_TTL: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(super) struct CachedRecord {
    addrs: Vec<EndpointAddr>,
    expire: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LookupKey {
    domain: String,
    family: Option<Family>,
}

impl LookupKey {
    fn new(domain: &str, family: Option<Family>) -> Self {
        Self {
            domain: domain.to_owned(),
            family,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct LookupCache {
    positive: DashMap<LookupKey, CachedRecord>,
    negative: DashMap<LookupKey, Instant>,
}

impl LookupCache {
    pub(super) fn prune_expired(&self, now: Instant) {
        self.positive.retain(|_host, record| record.expire > now);
        self.negative.retain(|_host, expire| *expire > now);
    }

    pub(super) fn positive_hit(
        &self,
        domain: &str,
        family: Option<Family>,
    ) -> Option<Vec<EndpointAddr>> {
        self.positive
            .get(&LookupKey::new(domain, family))
            .map(|record| record.addrs.clone())
    }

    pub(super) fn negative_hit(&self, domain: &str, family: Option<Family>) -> bool {
        self.negative.get(&LookupKey::new(domain, family)).is_some()
    }

    pub(super) fn insert_positive(
        &self,
        domain: &str,
        family: Option<Family>,
        addrs: Vec<EndpointAddr>,
    ) {
        let key = LookupKey::new(domain, family);
        self.positive.insert(
            key.clone(),
            CachedRecord {
                addrs,
                expire: Instant::now() + POSITIVE_TTL,
            },
        );
        self.negative.remove(&key);
    }

    pub(super) fn insert_negative(&self, domain: &str, family: Option<Family>) {
        self.negative.insert(
            LookupKey::new(domain, family),
            Instant::now() + NEGATIVE_TTL,
        );
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
        cache.insert_positive("demo.dhttp.net", None, vec![endpoint("192.0.2.10:4433")]);

        assert_eq!(
            cache.positive_hit("demo.dhttp.net", None).unwrap(),
            vec![endpoint("192.0.2.10:4433")]
        );
    }

    #[test]
    fn negative_cache_hit_blocks_lookup() {
        let cache = LookupCache::default();
        cache.insert_negative("missing.dhttp.net", None);

        assert!(cache.negative_hit("missing.dhttp.net", None));
    }

    #[test]
    fn positive_cache_hit_keeps_selector_entries_separate() {
        let cache = LookupCache::default();
        cache.insert_positive("demo.dhttp.net", None, vec![endpoint("192.0.2.10:4433")]);
        cache.insert_positive("demo.dhttp.net:1", None, vec![endpoint("192.0.2.11:4433")]);

        assert_eq!(
            cache.positive_hit("demo.dhttp.net", None).unwrap(),
            vec![endpoint("192.0.2.10:4433")]
        );
        assert_eq!(
            cache.positive_hit("demo.dhttp.net:1", None).unwrap(),
            vec![endpoint("192.0.2.11:4433")]
        );
    }

    #[test]
    fn cache_keeps_address_families_separate() {
        let cache = LookupCache::default();
        cache.insert_positive(
            "demo.dhttp.net",
            Some(Family::V4),
            vec![endpoint("192.0.2.10:4433")],
        );

        assert!(
            cache
                .positive_hit("demo.dhttp.net", Some(Family::V6))
                .is_none()
        );
    }
}
