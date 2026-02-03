use rustls::{SignatureScheme, pki_types::SubjectPublicKeyInfoDer, sign::SigningKey};
use snafu::Snafu;
use x509_parser::prelude::FromDer;

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignError {
    #[snafu(display("Unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(display("Crypto error: {source}"))]
    Crypto {
        #[snafu(source(false))]
        source: rustls::Error,
    },
}

impl From<rustls::Error> for SignError {
    fn from(source: rustls::Error) -> Self {
        Self::Crypto { source }
    }
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum VerifyError {
    #[snafu(display("Unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(display("Invalid Certificate: {details}"))]
    InvalidCertificate { details: String },
    #[snafu(display("Invalid PEM: {source}"))]
    InvalidPem { source: std::io::Error },
    #[snafu(display("Invalid Base64: {source}"))]
    InvalidBase64 { source: base64::DecodeError },
    #[snafu(display("IO Error: {source}"))]
    Io { source: std::io::Error },
}

pub(crate) fn sign(
    key: &(impl SigningKey + ?Sized),
    scheme: SignatureScheme,
    data: &[u8],
) -> Result<Vec<u8>, SignError> {
    // FIXME: same as load spki then sign with ring?
    let signer = key
        .choose_scheme(&[scheme])
        .ok_or(SignError::UnsupportedScheme { scheme })?;
    Ok(signer.sign(data)?)
}

pub(crate) fn verify(
    spki: SubjectPublicKeyInfoDer,
    scheme: SignatureScheme,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let algorithm: &'static dyn ring::signature::VerificationAlgorithm = match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        SignatureScheme::ED25519 => &ring::signature::ED25519,
        SignatureScheme::RSA_PKCS1_SHA256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384 => &ring::signature::RSA_PKCS1_2048_8192_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512 => &ring::signature::RSA_PKCS1_2048_8192_SHA512,
        SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        SignatureScheme::RSA_PSS_SHA384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return Err(VerifyError::UnsupportedScheme { scheme }),
    };

    let public_key = match x509_parser::x509::SubjectPublicKeyInfo::from_der(&spki) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_error) => unreachable!("rustls returned an invalid peer_certificates."),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}
