use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::BufMut;
use dashmap::DashMap;
use deadpool_redis::Pool;
use nom::{
    IResult,
    bytes::streaming::take,
    number::streaming::{be_u32, be_u64},
};
use tokio::time::Instant;

use crate::policy::DomainPolicies;

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

/// SHA-256 fingerprint of a DER-encoded certificate, used as per-source dedup key.
pub fn cert_fingerprint(cert_der: &[u8]) -> [u8; 32] {
    use ring::digest::{SHA256, digest};
    let d = digest(&SHA256, cert_der);
    d.as_ref().try_into().expect("SHA-256 is always 32 bytes")
}

pub fn cert_fingerprint_hex(cert_der: &[u8]) -> String {
    cert_fingerprint(cert_der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Redis ZSET member wire type
// ---------------------------------------------------------------------------

/// One record as persisted in the Redis ZSET (or decoded from it).
///
/// Wire layout (big-endian, contiguous):
/// ```text
/// +-----------+--------------+-----------+------+-----------+------+
/// | expire    | fingerprint  | dns_len   | dns  | cert_len  | cert |
/// | u64 BE    | 32 bytes     | u32 BE    | ...  | u32 BE    | ...  |
/// +-----------+--------------+-----------+------+-----------+------+
/// ```
#[derive(Debug, Clone)]
pub struct StoredRecord {
    /// Unix timestamp (seconds) after which this entry is considered stale.
    pub expire_unix_secs: u64,
    /// SHA-256 fingerprint of the publisher's leaf certificate.
    pub fingerprint: [u8; 32],
    /// Serialised DNS packet bytes.
    pub dns: Vec<u8>,
    /// DER-encoded leaf certificate of the publisher.
    pub cert: Vec<u8>,
}

impl StoredRecord {
    pub fn encoding_size(&self) -> usize {
        8 + 32 + 4 + self.dns.len() + 4 + self.cert.len()
    }

    /// Encode to a byte buffer suitable for use as a Redis ZSET member.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoding_size());
        buf.put_stored_record(self);
        buf
    }

    /// Decode from a Redis ZSET member. Returns `None` on malformed input.
    pub fn decode(data: &[u8]) -> Option<Self> {
        be_stored_record(data).ok().map(|(_, r)| r)
    }
}

/// `BufMut` write extension for [`StoredRecord`].
pub trait WriteStoredRecord {
    fn put_stored_record(&mut self, record: &StoredRecord);
}

impl<B: BufMut> WriteStoredRecord for B {
    fn put_stored_record(&mut self, record: &StoredRecord) {
        self.put_u64(record.expire_unix_secs);
        self.put_slice(&record.fingerprint);
        self.put_u32(record.dns.len() as u32);
        self.put_slice(&record.dns);
        self.put_u32(record.cert.len() as u32);
        self.put_slice(&record.cert);
    }
}

/// nom parser for [`StoredRecord`].
pub fn be_stored_record(input: &[u8]) -> IResult<&[u8], StoredRecord> {
    let (input, expire_unix_secs) = be_u64(input)?;
    let (input, fp_bytes) = take(32usize)(input)?;
    let (input, dns_len) = be_u32(input)?;
    let (input, dns) = take(dns_len as usize)(input)?;
    let (input, cert_len) = be_u32(input)?;
    let (input, cert) = take(cert_len as usize)(input)?;
    Ok((
        input,
        StoredRecord {
            expire_unix_secs,
            fingerprint: fp_bytes.try_into().expect("took exactly 32 bytes"),
            dns: dns.to_vec(),
            cert: cert.to_vec(),
        },
    ))
}

// ---------------------------------------------------------------------------
// HTTP multi-record response wire type
// ---------------------------------------------------------------------------

/// One DNS + certificate pair inside a [`MultiResponse`].
#[derive(Debug, Clone)]
pub struct ResponseRecord {
    /// Serialised DNS packet bytes.
    pub dns: Vec<u8>,
    /// DER-encoded leaf certificate of the publisher (may be empty).
    pub cert: Vec<u8>,
}

/// HTTP response body carrying zero or more DNS records.
///
/// Wire layout (big-endian, contiguous):
/// ```text
/// +-----------+  (repeated `count` times)
/// | count     |  +-----------+------+-----------+------+
/// | u32 BE    |  | dns_len   | dns  | cert_len  | cert |
/// +-----------+  | u32 BE    | ...  | u32 BE    | ...  |
///                +-----------+------+-----------+------+
/// ```
#[derive(Debug, Clone)]
pub struct MultiResponse {
    pub records: Vec<ResponseRecord>,
}

impl MultiResponse {
    pub fn new(iter: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>) -> Self {
        Self {
            records: iter
                .into_iter()
                .map(|(dns, cert)| ResponseRecord { dns, cert })
                .collect(),
        }
    }

    pub fn encoding_size(&self) -> usize {
        4 + self
            .records
            .iter()
            .map(|r| 4 + r.dns.len() + 4 + r.cert.len())
            .sum::<usize>()
    }

    /// Encode to a byte buffer sent as the HTTP response body.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoding_size());
        buf.put_multi_response(self);
        buf
    }
}

/// `BufMut` write extension for [`MultiResponse`].
pub trait WriteMultiResponse {
    fn put_multi_response(&mut self, resp: &MultiResponse);
}

impl<B: BufMut> WriteMultiResponse for B {
    fn put_multi_response(&mut self, resp: &MultiResponse) {
        self.put_u32(resp.records.len() as u32);
        for r in &resp.records {
            self.put_u32(r.dns.len() as u32);
            self.put_slice(&r.dns);
            self.put_u32(r.cert.len() as u32);
            self.put_slice(&r.cert);
        }
    }
}

/// nom parser for [`MultiResponse`].
/// Used by the client-side decoder; provided here to keep the wire format symmetric and testable.
#[allow(dead_code)]
pub fn be_multi_response(input: &[u8]) -> IResult<&[u8], MultiResponse> {
    let (mut input, count) = be_u32(input)?;
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (rest, dns_len) = be_u32(input)?;
        let (rest, dns) = take(dns_len as usize)(rest)?;
        let (rest, cert_len) = be_u32(rest)?;
        let (rest, cert) = take(cert_len as usize)(rest)?;
        records.push(ResponseRecord {
            dns: dns.to_vec(),
            cert: cert.to_vec(),
        });
        input = rest;
    }
    Ok((input, MultiResponse { records }))
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// A single record stored under a (host, server-fingerprint) key.
#[derive(Clone, Debug)]
pub struct Record {
    pub dns_bytes: Vec<u8>,
    pub cert_bytes: Vec<u8>,
    /// Wall-clock expiry (for TTL eviction).
    pub expire: Instant,
    /// When this record was last published (for newest-first ordering).
    pub published_at: Instant,
}

/// Unified in-memory storage: host → { cert_fingerprint → Record }.
/// Both Standard and OpenMulti policies share this map.
/// Per-fingerprint keying ensures the same source overwrites its own entry
/// while different sources (different server IDs / certs) coexist independently.
#[derive(Clone)]
pub struct MemoryStorage {
    pub records: Arc<DashMap<String, HashMap<[u8; 32], Record>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            records: Arc::new(DashMap::new()),
        }
    }
}

#[derive(Clone)]
pub enum Storage {
    Redis(Pool),
    Memory(MemoryStorage),
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub storage: Storage,
    pub require_signature: bool,
    pub ttl_secs: u64,
    pub policies: Arc<DomainPolicies>,
}
