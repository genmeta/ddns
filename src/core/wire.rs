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
use bytes::BufMut;
use nom::{IResult, bytes::streaming::take, number::streaming::be_u32};

/// One DNS + certificate pair inside a [`MultiResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseRecord {
    /// Serialised DNS packet bytes.
    pub dns: Vec<u8>,
    /// DER-encoded leaf certificate of the publisher, or empty when unavailable.
    pub cert: Vec<u8>,
}

impl ResponseRecord {
    /// SHA-256 fingerprint of the publisher certificate as lowercase hex.
    /// Returns `None` when the cert field is empty.
    pub fn cert_fingerprint_hex(&self) -> Option<String> {
        if self.cert.is_empty() {
            return None;
        }
        use ring::digest::{SHA256, digest};
        let digest = digest(&SHA256, &self.cert);
        Some(digest.as_ref().iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// HTTP response body carrying zero or more DNS records.
#[derive(Debug, Clone, PartialEq, Eq)]
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
            .map(|record| 4 + record.dns.len() + 4 + record.cert.len())
            .sum::<usize>()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoding_size());
        buf.put_multi_response(self);
        buf
    }
}

pub trait WriteMultiResponse {
    fn put_multi_response(&mut self, response: &MultiResponse);
}

impl<B: BufMut> WriteMultiResponse for B {
    fn put_multi_response(&mut self, response: &MultiResponse) {
        self.put_u32(response.records.len() as u32);
        for record in &response.records {
            self.put_u32(record.dns.len() as u32);
            self.put_slice(&record.dns);
            self.put_u32(record.cert.len() as u32);
            self.put_slice(&record.cert);
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_response_roundtrips() {
        let response =
            MultiResponse::new([(vec![1, 2, 3], vec![4, 5]), (vec![6, 7, 8, 9], Vec::new())]);
        let encoded = response.encode();
        let (remain, decoded) = be_multi_response(&encoded).unwrap();
        assert!(remain.is_empty());
        assert_eq!(decoded, response);
    }
}
