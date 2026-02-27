use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use deadpool_redis::Pool;
use tokio::time::Instant;

use crate::policy::DomainPolicies;

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn encode_redis_multi_member(dns: &[u8], cert: &[u8], expire_unix_secs: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 4 + dns.len() + 4 + cert.len());
    buf.extend_from_slice(&expire_unix_secs.to_be_bytes());
    buf.extend_from_slice(&(dns.len() as u32).to_be_bytes());
    buf.extend_from_slice(dns);
    buf.extend_from_slice(&(cert.len() as u32).to_be_bytes());
    buf.extend_from_slice(cert);
    buf
}

pub fn decode_redis_multi_member(data: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u64)> {
    if data.len() < 12 {
        return None;
    }
    let expire = u64::from_be_bytes(data[0..8].try_into().ok()?);
    let dns_len = u32::from_be_bytes(data[8..12].try_into().ok()?) as usize;
    if data.len() < 12 + dns_len + 4 {
        return None;
    }
    let dns = data[12..12 + dns_len].to_vec();
    let cert_offset = 12 + dns_len;
    let cert_len = u32::from_be_bytes(data[cert_offset..cert_offset + 4].try_into().ok()?) as usize;
    if data.len() < cert_offset + 4 + cert_len {
        return None;
    }
    let cert = data[cert_offset + 4..cert_offset + 4 + cert_len].to_vec();
    Some((dns, cert, expire))
}

/// Encode multiple (dns, cert) pairs into a single response body.
/// Format: [u32 count BE] ( [u32 dns_len BE][dns] [u32 cert_len BE][cert] )*
pub fn encode_multi_response(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let total = 4 + records
        .iter()
        .map(|(d, c)| 4 + d.len() + 4 + c.len())
        .sum::<usize>();
    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(&(records.len() as u32).to_be_bytes());
    for (dns, cert) in records {
        buf.extend_from_slice(&(dns.len() as u32).to_be_bytes());
        buf.extend_from_slice(dns);
        buf.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        buf.extend_from_slice(cert);
    }
    buf
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

/// A single entry in multi-record (OpenMulti) storage.
#[derive(Clone, Debug)]
pub struct MultiRecord {
    pub dns_bytes: Vec<u8>,
    pub cert_bytes: Vec<u8>,
    pub expire: Instant,
}

/// In-memory storage split into Standard (single-record) and OpenMulti maps.
#[derive(Clone)]
pub struct MemoryStorage {
    /// Standard single-record storage: host → (dns, cert, expire)
    pub standard: Arc<DashMap<String, (Vec<u8>, Vec<u8>, Instant)>>,
    /// OpenMulti storage: host → records newest-first
    pub multi: Arc<DashMap<String, Vec<MultiRecord>>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            standard: Arc::new(DashMap::new()),
            multi: Arc::new(DashMap::new()),
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
