use rustls::{pki_types::SubjectPublicKeyInfoDer, sign::SigningKey};
use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignError {
    #[snafu(display("failed to sign DHTTP identity data"))]
    Identity {
        source: dhttp_identity::identity::SignError,
    },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum VerifyError {
    #[snafu(display("failed to verify DHTTP identity signature"))]
    Identity {
        source: dhttp_identity::identity::VerifyError,
    },
    #[snafu(display("invalid certificate: {details}"))]
    InvalidCertificate { details: String },
    #[snafu(display("invalid PEM"))]
    InvalidPem { source: std::io::Error },
    #[snafu(display("invalid base64"))]
    InvalidBase64 { source: base64::DecodeError },
    #[snafu(display("io error"))]
    Io { source: std::io::Error },
}

pub fn sign_with_key(key: &(impl SigningKey + ?Sized), data: &[u8]) -> Result<Vec<u8>, SignError> {
    dhttp_identity::identity::sign_with_key(key, data).context(sign_error::IdentitySnafu)
}

pub(crate) fn verify(
    spki: SubjectPublicKeyInfoDer,
    data: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    dhttp_identity::identity::verify_signature(spki, data, signature)
        .context(verify_error::IdentitySnafu)
}
