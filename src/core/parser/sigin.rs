use rustls::{SignatureScheme, pki_types::SubjectPublicKeyInfoDer, sign::SigningKey};
use snafu::{ResultExt, Snafu};
use x509_parser::{
    oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSAENCRYPTION,
        OID_SIG_ED25519,
    },
    prelude::FromDer,
    x509::SubjectPublicKeyInfo,
};

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
    #[snafu(display("unsupported signature scheme {scheme:?}"))]
    UnsupportedScheme { scheme: SignatureScheme },
    #[snafu(display("invalid certificate: {details}"))]
    InvalidCertificate { details: String },
    #[snafu(display("invalid PEM"))]
    InvalidPem { source: std::io::Error },
    #[snafu(display("invalid base64"))]
    InvalidBase64 { source: base64::DecodeError },
    #[snafu(display("io error"))]
    Io { source: std::io::Error },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SignatureSchemeError {
    #[snafu(display("unsupported public key type"))]
    UnsupportedKey,
}

pub fn sign_with_key(key: &(impl SigningKey + ?Sized), data: &[u8]) -> Result<Vec<u8>, SignError> {
    dhttp_identity::identity::sign_with_key(key, data).context(sign_error::IdentitySnafu)
}

pub(crate) fn signature_scheme(
    spki: SubjectPublicKeyInfoDer<'_>,
) -> Result<SignatureScheme, SignatureSchemeError> {
    let Ok((_remain, spki)) = SubjectPublicKeyInfo::from_der(spki.as_ref()) else {
        return signature_scheme_error::UnsupportedKeySnafu.fail();
    };

    if spki.algorithm.algorithm == OID_SIG_ED25519 {
        return Ok(SignatureScheme::ED25519);
    }

    if spki.algorithm.algorithm == OID_PKCS1_RSAENCRYPTION {
        return Ok(SignatureScheme::RSA_PSS_SHA512);
    }

    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        return signature_scheme_error::UnsupportedKeySnafu.fail();
    }

    let Some(curve) = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.as_oid().ok())
    else {
        return signature_scheme_error::UnsupportedKeySnafu.fail();
    };

    if curve == OID_EC_P256 {
        Ok(SignatureScheme::ECDSA_NISTP256_SHA256)
    } else if curve == OID_NIST_EC_P384 {
        Ok(SignatureScheme::ECDSA_NISTP384_SHA384)
    } else {
        signature_scheme_error::UnsupportedKeySnafu.fail()
    }
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
        SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
        _ => return verify_error::UnsupportedSchemeSnafu { scheme }.fail(),
    };

    let public_key = match SubjectPublicKeyInfo::from_der(spki.as_ref()) {
        Ok((_remain, spki)) => spki.subject_public_key,
        Err(_) => return Ok(false),
    };

    Ok(
        ring::signature::UnparsedPublicKey::new(algorithm, public_key)
            .verify(data, signature)
            .is_ok(),
    )
}
