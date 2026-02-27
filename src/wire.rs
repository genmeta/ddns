/// HTTP multi-record response wire format shared between server and all clients.
///
/// Wire layout (big-endian, contiguous):
/// ```text
/// +-----------+  (repeated `count` times)
/// | count     |  +-----------+------+-----------+------+
/// | u32 BE    |  | dns_len   | dns  | cert_len  | cert |
/// +-----------+  | u32 BE    | ...  | u32 BE    | ...  |
///                +-----------+------+-----------+------+
/// ```
use nom::{IResult, bytes::streaming::take, number::streaming::be_u32};

/// One DNS + certificate pair inside a [`MultiResponse`].
#[derive(Debug, Clone)]
pub struct ResponseRecord {
    /// Serialised DNS packet bytes.
    pub dns: Vec<u8>,
    /// DER-encoded leaf certificate of the publisher (may be empty).
    pub cert: Vec<u8>,
}

impl ResponseRecord {
    /// SHA-256 fingerprint of the publisher certificate, as a lowercase hex string.
    /// Returns `None` when the cert field is empty.
    pub fn cert_fingerprint_hex(&self) -> Option<String> {
        if self.cert.is_empty() {
            return None;
        }
        use ring::digest::{SHA256, digest};
        let d = digest(&SHA256, &self.cert);
        Some(d.as_ref().iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// Decoded HTTP response body carrying one or more DNS records.
#[derive(Debug, Clone)]
pub struct MultiResponse {
    pub records: Vec<ResponseRecord>,
}

/// nom parser for [`MultiResponse`].
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
