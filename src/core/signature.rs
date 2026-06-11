use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use dhttp_identity::identity::{LocalAuthority, SignError as AuthoritySignError};
use ring::digest::{SHA256, digest};
use rustls::{SignatureScheme, pki_types::SubjectPublicKeyInfoDer};
use snafu::Snafu;

use crate::core::parser::sigin;

pub const CONTENT_DIGEST_HEADER: &str = "content-digest";
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
pub const SIGNATURE_HEADER: &str = "signature";
pub const SIGNATURE_LABEL: &str = "dns";

const DIGEST_PREFIX: &str = "sha-256=:";
const SIGNATURE_PREFIX: &str = "dns=:";
const SIGNATURE_INPUT_PREFIX: &str = "dns=(\"content-digest\")";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureFields {
    pub content_digest: Vec<u8>,
    pub signature_input: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedSignatureInput<'a> {
    signature_params: &'a str,
    alg: &'a str,
    keyid: &'a str,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignatureFieldsError {
    #[snafu(display("missing publisher certificate"))]
    MissingCertificate,
    #[snafu(display("unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(display("unsupported signature algorithm {alg}"))]
    UnsupportedAlgorithm { alg: String },
    #[snafu(display("invalid {field} field"))]
    InvalidField { field: &'static str },
    #[snafu(display("invalid signature field utf-8"))]
    InvalidUtf8 { source: std::str::Utf8Error },
    #[snafu(display("invalid base64"))]
    InvalidBase64 { source: base64::DecodeError },
    #[snafu(display("content digest mismatch"))]
    DigestMismatch,
    #[snafu(display("signature keyid does not match publisher certificate"))]
    KeyIdMismatch,
    #[snafu(display("failed to sign DNS packet"))]
    Sign { source: AuthoritySignError },
    #[snafu(display("invalid certificate: {details}"))]
    InvalidCertificate { details: String },
    #[snafu(display("signature verification failed"))]
    Verify { source: sigin::VerifyError },
}

impl SignatureFields {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.content_digest.is_empty()
            && self.signature_input.is_empty()
            && self.signature.is_empty()
    }

    pub async fn sign(
        dns_bytes: &[u8],
        authority: &(impl LocalAuthority + ?Sized),
    ) -> Result<Self, SignatureFieldsError> {
        let cert = authority
            .cert_chain()
            .first()
            .ok_or(SignatureFieldsError::MissingCertificate)?;
        let keyid = keyid_for_cert(cert.as_ref());
        let content_digest = content_digest_value(dns_bytes);
        let created = unix_now_secs();

        let scheme = sigin::canonical_scheme_for_spki(authority.public_key()).ok_or(
            SignatureFieldsError::UnsupportedScheme {
                scheme: SignatureScheme::Unknown(0),
            },
        )?;
        let alg = sigin::alg_name_for_scheme(scheme)
            .ok_or(SignatureFieldsError::UnsupportedScheme { scheme })?;
        let signature_input = signature_input_value(created, &keyid, alg);
        let signature_base = signature_base(&content_digest, &signature_input)?;
        let signature = authority
            .sign(signature_base.as_bytes())
            .await
            .map_err(|source| SignatureFieldsError::Sign { source })?;
        let signature = signature_value(&signature);

        Ok(Self {
            content_digest: content_digest.into_bytes(),
            signature_input: signature_input.into_bytes(),
            signature: signature.into_bytes(),
        })
    }

    pub fn verify(&self, dns_bytes: &[u8], cert_der: &[u8]) -> Result<bool, SignatureFieldsError> {
        if self.is_empty() {
            return Ok(false);
        }

        let content_digest = field_str(&self.content_digest)?;
        verify_content_digest(content_digest, dns_bytes)?;

        let signature_input = field_str(&self.signature_input)?;
        let parsed_input = parse_signature_input(signature_input)?;
        let expected_keyid = keyid_for_cert(cert_der);
        if parsed_input.keyid != expected_keyid {
            return Ok(false);
        }

        let scheme = sigin::scheme_for_alg_name(parsed_input.alg).ok_or_else(|| {
            SignatureFieldsError::UnsupportedAlgorithm {
                alg: parsed_input.alg.to_string(),
            }
        })?;
        let signature = parse_signature(field_str(&self.signature)?)?;
        let signature_base = signature_base(content_digest, signature_input)?;

        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).map_err(|e| {
            SignatureFieldsError::InvalidCertificate {
                details: e.to_string(),
            }
        })?;
        let spki = SubjectPublicKeyInfoDer::from(cert.tbs_certificate.subject_pki.raw);
        sigin::verify(spki, scheme, signature_base.as_bytes(), &signature)
            .map_err(|source| SignatureFieldsError::Verify { source })
    }
}

pub fn content_digest_value(dns_bytes: &[u8]) -> String {
    let digest = digest(&SHA256, dns_bytes);
    let b64 = base64::engine::general_purpose::STANDARD.encode(digest.as_ref());
    format!("{DIGEST_PREFIX}{b64}:")
}

pub fn cert_fingerprint_hex(cert_der: &[u8]) -> String {
    digest(&SHA256, cert_der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn keyid_for_cert(cert_der: &[u8]) -> String {
    format!("sha256:{}", cert_fingerprint_hex(cert_der))
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn signature_input_value(created: u64, keyid: &str, alg: &str) -> String {
    format!(
        "{SIGNATURE_LABEL}=(\"content-digest\");created={created};keyid=\"{keyid}\";alg=\"{alg}\""
    )
}

fn signature_value(signature: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    format!("{SIGNATURE_PREFIX}{b64}:")
}

fn signature_base(
    content_digest: &str,
    signature_input: &str,
) -> Result<String, SignatureFieldsError> {
    let parsed = parse_signature_input(signature_input)?;
    Ok(format!(
        "\"content-digest\": {content_digest}\n\"@signature-params\": {}",
        parsed.signature_params
    ))
}

fn field_str(field: &[u8]) -> Result<&str, SignatureFieldsError> {
    std::str::from_utf8(field).map_err(|source| SignatureFieldsError::InvalidUtf8 { source })
}

fn verify_content_digest(
    content_digest: &str,
    dns_bytes: &[u8],
) -> Result<(), SignatureFieldsError> {
    let encoded = content_digest
        .strip_prefix(DIGEST_PREFIX)
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(SignatureFieldsError::InvalidField {
            field: CONTENT_DIGEST_HEADER,
        })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|source| SignatureFieldsError::InvalidBase64 { source })?;
    if decoded.as_slice() != digest(&SHA256, dns_bytes).as_ref() {
        return Err(SignatureFieldsError::DigestMismatch);
    }
    Ok(())
}

fn parse_signature(input: &str) -> Result<Vec<u8>, SignatureFieldsError> {
    let encoded = input
        .strip_prefix(SIGNATURE_PREFIX)
        .and_then(|rest| rest.strip_suffix(':'))
        .ok_or(SignatureFieldsError::InvalidField {
            field: SIGNATURE_HEADER,
        })?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|source| SignatureFieldsError::InvalidBase64 { source })
}

fn parse_signature_input(input: &str) -> Result<ParsedSignatureInput<'_>, SignatureFieldsError> {
    if !input.starts_with(SIGNATURE_INPUT_PREFIX) {
        return Err(SignatureFieldsError::InvalidField {
            field: SIGNATURE_INPUT_HEADER,
        });
    }

    let signature_params =
        input
            .strip_prefix("dns=")
            .ok_or(SignatureFieldsError::InvalidField {
                field: SIGNATURE_INPUT_HEADER,
            })?;
    let params = signature_params
        .strip_prefix("(\"content-digest\")")
        .ok_or(SignatureFieldsError::InvalidField {
            field: SIGNATURE_INPUT_HEADER,
        })?;

    let mut created = None;
    let mut keyid = None;
    let mut alg = None;

    for param in params.split(';').filter(|part| !part.is_empty()) {
        if let Some(value) = param.strip_prefix("created=") {
            created = value.parse::<u64>().ok();
        } else if let Some(value) = param.strip_prefix("keyid=") {
            keyid = unquote(value);
        } else if let Some(value) = param.strip_prefix("alg=") {
            alg = unquote(value);
        } else {
            return Err(SignatureFieldsError::InvalidField {
                field: SIGNATURE_INPUT_HEADER,
            });
        }
    }

    if created.is_none() {
        return Err(SignatureFieldsError::InvalidField {
            field: SIGNATURE_INPUT_HEADER,
        });
    }

    let keyid = keyid.ok_or(SignatureFieldsError::InvalidField {
        field: SIGNATURE_INPUT_HEADER,
    })?;
    let alg = alg.ok_or(SignatureFieldsError::InvalidField {
        field: SIGNATURE_INPUT_HEADER,
    })?;

    Ok(ParsedSignatureInput {
        signature_params,
        alg,
        keyid,
    })
}

fn unquote(value: &str) -> Option<&str> {
    value.strip_prefix('"')?.strip_suffix('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_digest_uses_sha256_dictionary_value() {
        let value = content_digest_value(b"dns");
        assert!(value.starts_with("sha-256=:"));
        assert!(value.ends_with(':'));
        verify_content_digest(&value, b"dns").unwrap();
        assert!(matches!(
            verify_content_digest(&value, b"changed"),
            Err(SignatureFieldsError::DigestMismatch)
        ));
    }

    #[test]
    fn signature_input_requires_alg_and_keyid() {
        let input = "dns=(\"content-digest\");created=1;keyid=\"sha256:abc\";alg=\"ed25519\"";
        let parsed = parse_signature_input(input).unwrap();
        assert_eq!(parsed.keyid, "sha256:abc");
        assert_eq!(parsed.alg, "ed25519");

        assert!(parse_signature_input("dns=(\"content-digest\");created=1").is_err());
        assert!(parse_signature_input("dns=(\"date\");created=1;alg=\"ed25519\"").is_err());
    }

    #[test]
    fn alg_names_are_explicitly_mapped() {
        assert_eq!(
            sigin::scheme_for_alg_name("ed25519"),
            Some(SignatureScheme::ED25519)
        );
        assert_eq!(
            sigin::alg_name_for_scheme(SignatureScheme::ECDSA_NISTP256_SHA256),
            Some("ecdsa-p256-sha256")
        );
        assert_eq!(sigin::scheme_for_alg_name("unknown"), None);
    }
}
