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

use crate::core::signature::SignatureFields;

/// One DNS + certificate pair inside a [`MultiResponse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseRecord {
    /// RFC 9421/9530-style publisher signature fields. Empty for unsigned
    /// OpenMulti or static seed records.
    pub signature_fields: SignatureFields,
    /// Serialised DNS packet bytes.
    pub dns: Vec<u8>,
    /// DER-encoded leaf certificate of the publisher, or empty when unavailable.
    pub cert: Vec<u8>,
}

impl ResponseRecord {
    pub fn new(signature_fields: SignatureFields, dns: Vec<u8>, cert: Vec<u8>) -> Self {
        Self {
            signature_fields,
            dns,
            cert,
        }
    }

    pub fn unsigned(dns: Vec<u8>, cert: Vec<u8>) -> Self {
        Self::new(SignatureFields::empty(), dns, cert)
    }

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
    pub fn new(iter: impl IntoIterator<Item = ResponseRecord>) -> Self {
        Self {
            records: iter.into_iter().collect(),
        }
    }

    pub fn encoding_size(&self) -> usize {
        4 + self
            .records
            .iter()
            .map(|record| {
                4 + record.signature_fields.content_digest.len()
                    + 4
                    + record.signature_fields.signature_input.len()
                    + 4
                    + record.signature_fields.signature.len()
                    + 4
                    + record.dns.len()
                    + 4
                    + record.cert.len()
            })
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
            put_field(self, &record.signature_fields.content_digest);
            put_field(self, &record.signature_fields.signature_input);
            put_field(self, &record.signature_fields.signature);
            put_field(self, &record.dns);
            put_field(self, &record.cert);
        }
    }
}

fn put_field<B: BufMut>(buf: &mut B, value: &[u8]) {
    buf.put_u32(value.len() as u32);
    buf.put_slice(value);
}

pub fn be_multi_response(input: &[u8]) -> IResult<&[u8], MultiResponse> {
    let (mut input, count) = be_u32(input)?;
    let mut records = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (rest, content_digest) = be_field(input)?;
        let (rest, signature_input) = be_field(rest)?;
        let (rest, signature) = be_field(rest)?;
        let (rest, dns) = be_field(rest)?;
        let (rest, cert) = be_field(rest)?;
        records.push(ResponseRecord::new(
            SignatureFields {
                content_digest,
                signature_input,
                signature,
            },
            dns,
            cert,
        ));
        input = rest;
    }
    Ok((input, MultiResponse { records }))
}

fn be_field(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    let (input, len) = be_u32(input)?;
    let (input, value) = take(len as usize)(input)?;
    Ok((input, value.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_response_roundtrips() {
        let response = MultiResponse::new([
            ResponseRecord::new(
                SignatureFields {
                    content_digest: b"sha-256=:abc:".to_vec(),
                    signature_input:
                        b"dns=(\"content-digest\");created=1;keyid=\"sha256:abc\";alg=\"ed25519\""
                            .to_vec(),
                    signature: b"dns=:sig:".to_vec(),
                },
                vec![1, 2, 3],
                vec![4, 5],
            ),
            ResponseRecord::unsigned(vec![6, 7, 8, 9], Vec::new()),
        ]);
        let encoded = response.encode();
        let (remain, decoded) = be_multi_response(&encoded).unwrap();
        assert!(remain.is_empty());
        assert_eq!(decoded, response);
    }
}
