use std::{sync::Arc, time::Duration};

use dashmap::DashMap;
use tokio::time::Instant;

use crate::resolvers::endpoint_candidates::{EndpointCandidates, EndpointLookup};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct LookupKey {
    name: String,
    lookup: EndpointLookup,
}

impl LookupKey {
    pub(super) fn new(name: &str, lookup: EndpointLookup) -> Self {
        Self {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            lookup,
        }
    }
}

#[derive(Clone, Debug)]
struct CachedAnswer {
    candidates: Arc<EndpointCandidates>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
pub(super) struct LookupCache {
    positive: DashMap<LookupKey, CachedAnswer>,
}

impl LookupCache {
    pub(super) fn get(&self, key: &LookupKey) -> Option<Arc<EndpointCandidates>> {
        let answer = self.positive.get(key)?;
        if answer.expires_at > Instant::now() {
            Some(answer.candidates.clone())
        } else {
            drop(answer);
            self.positive.remove(key);
            None
        }
    }

    pub(super) fn insert(
        &self,
        key: LookupKey,
        candidates: Arc<EndpointCandidates>,
        ttl: Duration,
    ) {
        if !ttl.is_zero() {
            self.positive.insert(
                key,
                CachedAnswer {
                    candidates,
                    expires_at: Instant::now() + ttl,
                },
            );
        }
    }

    pub(super) fn invalidate_name(&self, name: &str) {
        let name = name.trim_end_matches('.');
        self.positive
            .retain(|key, _| !key.name.eq_ignore_ascii_case(name));
    }

    pub(super) fn clear(&self) {
        self.positive.clear();
    }
}
