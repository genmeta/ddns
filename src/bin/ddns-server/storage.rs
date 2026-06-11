use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::BufMut;
use dashmap::{DashMap, DashSet};
use ddns::core::{
    parser::{packet::be_packet, record::RData},
    signature::SignatureFields,
    wire::ResponseRecord,
};
use deadpool_redis::Pool;
use nom::{
    IResult,
    bytes::streaming::take,
    number::streaming::{be_u32, be_u64},
};
use tokio::time::Instant;

use crate::{geo::GeoResolver, policy::DomainPolicies};

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of a DER-encoded certificate, used as per-source dedup key.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    use ring::digest::{SHA256, digest};
    let d = digest(&SHA256, cert_der);
    d.as_ref().try_into().expect("SHA-256 is always 32 bytes")
}

pub fn fingerprint_hex(fingerprint: &[u8; 32]) -> String {
    fingerprint.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn cert_fingerprint_hex(cert_der: &[u8]) -> String {
    fingerprint_hex(&cert_fingerprint(cert_der))
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn redis_primary_key(host: &str, fingerprint_hex: &str) -> String {
    format!("{host}:fp:{fingerprint_hex}")
}

pub fn redis_all_index_key(host: &str) -> String {
    format!("{host}:idx:all")
}

pub fn redis_country_index_key(host: &str, country: &str) -> String {
    format!("{host}:idx:country:{country}")
}

pub fn redis_asn_index_key(host: &str, asn: u32) -> String {
    format!("{host}:idx:asn:{asn}")
}

pub fn redis_blacklist_key() -> &'static str {
    "ddns:blacklist"
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordIndexTags {
    pub countries: Vec<String>,
    pub asns: Vec<u32>,
}

pub fn record_index_tags(dns_bytes: &[u8], geo: Option<&GeoResolver>) -> RecordIndexTags {
    let Some(geo) = geo else {
        return RecordIndexTags::default();
    };

    let Ok((_, packet)) = be_packet(dns_bytes) else {
        return RecordIndexTags::default();
    };

    let mut countries = HashSet::new();
    let mut asns = HashSet::new();

    for answer in &packet.answers {
        let RData::E(endpoint) = answer.data() else {
            continue;
        };

        let traits = geo.lookup_traits(endpoint.addr().ip());
        if let Some(country) = traits.country {
            countries.insert(country);
        }
        if let Some(asn) = traits.asn {
            asns.insert(asn);
        }
    }

    let mut countries = countries.into_iter().collect::<Vec<_>>();
    countries.sort();

    let mut asns = asns.into_iter().collect::<Vec<_>>();
    asns.sort_unstable();

    RecordIndexTags { countries, asns }
}

// ---------------------------------------------------------------------------
// Redis primary record wire type
// ---------------------------------------------------------------------------

/// One record as persisted in the Redis primary record value.
///
/// Wire layout (big-endian, contiguous):
/// ```text
/// +-----------+--------------+---------------+--------+-----------+------+-----------+------+-----------+------+-----------+------+
/// | expire    | fingerprint  | digest_len    | digest | input_len | input| sig_len   | sig  | dns_len   | dns  | cert_len  | cert |
/// | u64 BE    | 32 bytes     | u32 BE        | ...    | u32 BE    | ...  | u32 BE    | ...  | u32 BE    | ...  | u32 BE    | ...  |
/// +-----------+--------------+---------------+--------+-----------+------+-----------+------+-----------+------+-----------+------+
/// ```
#[derive(Debug, Clone)]
pub struct StoredRecord {
    /// Unix timestamp (seconds) after which this entry is considered stale.
    pub expire_unix_secs: u64,
    /// SHA-256 fingerprint of the publisher's leaf certificate.
    /// Serves as the publisher's identity: uniquely identifies a certificate among multiple
    /// valid certs that may be issued for the same domain (from different CAs, at different times,
    /// for different regions, etc.). Used as storage key to enable multi-publisher scenarios.
    pub fingerprint: [u8; 32],
    /// Serialised DNS packet bytes.
    pub dns: Vec<u8>,
    /// DER-encoded leaf certificate of the publisher.
    pub cert: Vec<u8>,
    /// Saved RFC-style publisher signature fields for the DNS packet.
    pub signature_fields: SignatureFields,
}

impl StoredRecord {
    /// Encode to a byte buffer suitable for use as a Redis primary record value.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            8 + 32
                + 4
                + self.signature_fields.content_digest.len()
                + 4
                + self.signature_fields.signature_input.len()
                + 4
                + self.signature_fields.signature.len()
                + 4
                + self.dns.len()
                + 4
                + self.cert.len(),
        );
        buf.put_u64(self.expire_unix_secs);
        buf.put_slice(&self.fingerprint);
        put_field(&mut buf, &self.signature_fields.content_digest);
        put_field(&mut buf, &self.signature_fields.signature_input);
        put_field(&mut buf, &self.signature_fields.signature);
        put_field(&mut buf, &self.dns);
        put_field(&mut buf, &self.cert);
        buf
    }

    /// Decode from a Redis primary record value. Returns `None` on malformed input.
    pub fn decode(data: &[u8]) -> Option<Self> {
        be_stored_record(data)
            .ok()
            .and_then(|(remain, r)| remain.is_empty().then_some(r))
    }
}

/// nom parser for [`StoredRecord`].
pub fn be_stored_record(input: &[u8]) -> IResult<&[u8], StoredRecord> {
    let (input, expire_unix_secs) = be_u64(input)?;
    let (input, fp_bytes) = take(32usize)(input)?;
    let (input, content_digest) = be_field(input)?;
    let (input, signature_input) = be_field(input)?;
    let (input, signature) = be_field(input)?;
    let (input, dns) = be_field(input)?;
    let (input, cert) = be_field(input)?;
    Ok((
        input,
        StoredRecord {
            expire_unix_secs,
            fingerprint: fp_bytes.try_into().expect("took exactly 32 bytes"),
            dns,
            cert,
            signature_fields: SignatureFields {
                content_digest,
                signature_input,
                signature,
            },
        },
    ))
}

fn put_field(buf: &mut Vec<u8>, value: &[u8]) {
    buf.put_u32(value.len() as u32);
    buf.put_slice(value);
}

fn be_field(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, len) = be_u32(input)?;
    let (input, value) = take(len as usize)(input)?;
    Ok((input, value.to_vec()))
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// A single record stored under a (host, server-fingerprint) key.
#[derive(Clone, Debug)]
pub struct Record {
    pub dns_bytes: Vec<u8>,
    pub cert_bytes: Vec<u8>,
    pub signature_fields: SignatureFields,
    /// Wall-clock expiry (for TTL eviction).
    pub expire: Instant,
    /// Precomputed country / ASN buckets used by the Lite indexes.
    pub index_tags: RecordIndexTags,
}

#[derive(Clone, Debug, Default)]
pub struct HostRecords {
    pub records: HashMap<[u8; 32], Record>,
    pub recent: Vec<[u8; 32]>,
    pub by_country: HashMap<String, Vec<[u8; 32]>>,
    pub by_asn: HashMap<u32, Vec<[u8; 32]>>,
}

impl HostRecords {
    fn remove_fingerprint(list: &mut Vec<[u8; 32]>, fingerprint: &[u8; 32]) {
        list.retain(|existing| existing != fingerprint);
    }

    fn remove_from_indexes(&mut self, fingerprint: &[u8; 32], tags: &RecordIndexTags) {
        Self::remove_fingerprint(&mut self.recent, fingerprint);

        for country in &tags.countries {
            let should_remove = if let Some(bucket) = self.by_country.get_mut(country) {
                Self::remove_fingerprint(bucket, fingerprint);
                bucket.is_empty()
            } else {
                false
            };

            if should_remove {
                self.by_country.remove(country);
            }
        }

        for asn in &tags.asns {
            let should_remove = if let Some(bucket) = self.by_asn.get_mut(asn) {
                Self::remove_fingerprint(bucket, fingerprint);
                bucket.is_empty()
            } else {
                false
            };

            if should_remove {
                self.by_asn.remove(asn);
            }
        }
    }

    pub fn insert(&mut self, fingerprint: [u8; 32], record: Record) {
        if let Some(old_record) = self.records.remove(&fingerprint) {
            self.remove_from_indexes(&fingerprint, &old_record.index_tags);
        }

        self.recent.insert(0, fingerprint);

        for country in &record.index_tags.countries {
            self.by_country
                .entry(country.clone())
                .or_default()
                .insert(0, fingerprint);
        }

        for asn in &record.index_tags.asns {
            self.by_asn.entry(*asn).or_default().insert(0, fingerprint);
        }

        self.records.insert(fingerprint, record);
    }

    pub fn remove(&mut self, fingerprint: &[u8; 32]) -> Option<Record> {
        let record = self.records.remove(fingerprint)?;
        self.remove_from_indexes(fingerprint, &record.index_tags);
        Some(record)
    }

    pub fn retain_active(&mut self, now: Instant) {
        let expired = self
            .records
            .iter()
            .filter_map(|(fingerprint, record)| (record.expire <= now).then_some(*fingerprint))
            .collect::<Vec<_>>();

        for fingerprint in expired {
            let _ = self.remove(&fingerprint);
        }
    }

    pub fn collect_candidates(
        &self,
        source_country: Option<&str>,
        source_asn: Option<u32>,
        total_cap: usize,
        asn_cap: usize,
        country_cap: usize,
        all_cap: usize,
    ) -> Vec<[u8; 32]> {
        let mut candidates = Vec::new();
        let mut seen = HashSet::new();

        let mut push_bucket = |bucket: Option<&Vec<[u8; 32]>>, bucket_cap: usize| {
            let Some(bucket) = bucket else {
                return;
            };

            for fingerprint in bucket.iter().take(bucket_cap) {
                if candidates.len() >= total_cap {
                    break;
                }

                if seen.insert(*fingerprint) {
                    candidates.push(*fingerprint);
                }
            }
        };

        if let Some(asn) = source_asn {
            push_bucket(self.by_asn.get(&asn), asn_cap.min(total_cap));
        }

        if let Some(country) = source_country {
            push_bucket(self.by_country.get(country), country_cap.min(total_cap));
        }

        push_bucket(Some(&self.recent), all_cap.min(total_cap));
        candidates
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// Unified in-memory storage: host → { cert_fingerprint → Record }.
/// Both Standard and OpenMulti policies share this map.
///
/// Per-fingerprint keying design supports PKI's multi-certificate model:
/// A single domain can have multiple valid certificates issued by different CAs,
/// or by the same CA at different times (certificate rotation, multi-region deployment, etc.).
/// Each certificate has a unique fingerprint as its identity.
///
/// - Same certificate (same fingerprint) republishing → overwrites the previous record
/// - Different certificates (different fingerprints) for same domain → coexist independently
/// - Clients query get all valid records and choose which one to use
#[derive(Clone)]
pub struct MemoryStorage {
    pub records: Arc<DashMap<String, HostRecords>>,
    pub blacklist: Arc<DashSet<String>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
            blacklist: Arc::new(DashSet::new()),
        }
    }

    pub fn with_blacklist(hosts: impl IntoIterator<Item = String>) -> Self {
        let storage = Self::new();
        for host in hosts {
            storage.blacklist_host(host);
        }
        storage
    }

    pub fn blacklist_host(&self, host: impl Into<String>) {
        self.blacklist.insert(host.into());
    }

    pub fn remove_blacklist_host(&self, host: &str) {
        self.blacklist.remove(host);
    }

    pub fn is_blacklisted(&self, host: &str) -> bool {
        self.blacklist.contains(host)
    }
}

#[derive(Clone)]
pub struct RedisStorage {
    pub write: Pool,
    pub read: Pool,
}

#[derive(Clone)]
pub enum Storage {
    Redis(RedisStorage),
    Memory(MemoryStorage),
}

pub type LookupRecord = ResponseRecord;
pub type SeedRecords = Arc<HashMap<String, Vec<LookupRecord>>>;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub host_allowlist: Arc<Vec<String>>,
    pub require_signature: bool,
    pub ttl_secs: u64,
    pub policies: Arc<DomainPolicies>,
    pub seed_records: SeedRecords,
    pub geo: Option<Arc<GeoResolver>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn record(country: Option<&str>, asn: Option<u32>) -> Record {
        Record {
            dns_bytes: Vec::new(),
            cert_bytes: Vec::new(),
            signature_fields: SignatureFields::empty(),
            expire: Instant::now() + tokio::time::Duration::from_secs(60),
            index_tags: RecordIndexTags {
                countries: country.into_iter().map(str::to_owned).collect(),
                asns: asn.into_iter().collect(),
            },
        }
    }

    #[test]
    fn host_records_collect_candidates_prefers_asn_then_country_then_recent() {
        let mut host = HostRecords::default();
        host.insert(fp(1), record(Some("US"), Some(64512)));
        host.insert(fp(2), record(Some("US"), None));
        host.insert(fp(3), record(Some("JP"), None));

        let candidates = host.collect_candidates(Some("US"), Some(64512), 8, 2, 2, 8);

        assert_eq!(candidates, vec![fp(1), fp(2), fp(3)]);
    }

    #[test]
    fn host_records_remove_cleans_secondary_indexes() {
        let mut host = HostRecords::default();
        let fingerprint = fp(9);
        host.insert(fingerprint, record(Some("US"), Some(64512)));

        let _ = host.remove(&fingerprint);

        assert!(host.recent.is_empty());
        assert!(host.by_country.is_empty());
        assert!(host.by_asn.is_empty());
        assert!(host.records.is_empty());
    }

    #[test]
    fn stored_record_roundtrips_signature_fields() {
        let record = StoredRecord {
            expire_unix_secs: 123,
            fingerprint: fp(7),
            dns: vec![1, 2, 3],
            cert: vec![4, 5, 6],
            signature_fields: SignatureFields {
                content_digest: b"sha-256=:abc:".to_vec(),
                signature_input:
                    b"dns=(\"content-digest\");created=1;keyid=\"sha256:abc\";alg=\"ed25519\""
                        .to_vec(),
                signature: b"dns=:sig:".to_vec(),
            },
        };

        let decoded = StoredRecord::decode(&record.encode()).expect("stored record decodes");

        assert_eq!(decoded.expire_unix_secs, record.expire_unix_secs);
        assert_eq!(decoded.fingerprint, record.fingerprint);
        assert_eq!(decoded.dns, record.dns);
        assert_eq!(decoded.cert, record.cert);
        assert_eq!(decoded.signature_fields, record.signature_fields);
    }

    #[test]
    fn redis_blacklist_key_is_stable() {
        assert_eq!(redis_blacklist_key(), "ddns:blacklist");
    }

    #[test]
    fn memory_storage_tracks_blacklisted_hosts() {
        let storage = MemoryStorage::with_blacklist(["blocked.example".to_string()]);

        assert!(storage.is_blacklisted("blocked.example"));
        assert!(!storage.is_blacklisted("allowed.example"));

        storage.blacklist_host("other.example");
        assert!(storage.is_blacklisted("other.example"));

        storage.remove_blacklist_host("blocked.example");
        assert!(!storage.is_blacklisted("blocked.example"));
    }
}
