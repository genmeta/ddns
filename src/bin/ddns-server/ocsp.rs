use std::{io, path::Path, time::Duration};

use der::{
    Choice, Decode, Encode, Enumerated, Sequence,
    asn1::{Any, GeneralizedTime, Null, ObjectIdentifier, OctetString},
    oid::db::{rfc5912::ID_SHA_1, rfc6960::ID_PKIX_OCSP_BASIC},
};
use h3x::dquic::QuicEndpoint;
use reqwest::{
    Url,
    header::{ACCEPT, CONTENT_TYPE},
};
use rustls::pki_types::{CertificateDer, UnixTime};
use sha1::{Digest, Sha1};
use tokio::time::sleep;
use tracing::{info, warn};
use x509_cert::{
    Certificate, ext::Extensions, serial_number::SerialNumber, spki::AlgorithmIdentifierOwned,
};
use x509_parser::{
    asn1_rs::{BitString as X509BitString, FromDer as X509FromDer},
    parse_x509_certificate,
    verify::verify_signature as verify_x509_signature,
    x509::AlgorithmIdentifier as X509AlgorithmIdentifier,
};

use crate::config::Config;

pub const DEFAULT_OCSP_RESPONDER_BASE_URL: &str = "https://license.genmeta.net";
pub const OCSP_STAPLING_TTL: Duration = Duration::from_secs(3 * 60 * 60);
pub const OCSP_REFRESH_EXPIRY_SKEW: Duration = Duration::from_secs(5 * 60);
pub const OCSP_REFRESH_RETRY_DELAY: Duration = Duration::from_secs(5 * 60);

pub struct OcspAutoRefresh {
    responder_url: String,
    http_client: reqwest::Client,
    request_der: Vec<u8>,
    leaf_der: CertificateDer<'static>,
    issuer_der: CertificateDer<'static>,
}

impl OcspAutoRefresh {
    pub fn from_config(config: &Config, cert_pem: &[u8], root_cert_pem: &[u8]) -> io::Result<Self> {
        let base_url = config
            .ocsp_responder_base_url
            .as_deref()
            .unwrap_or(DEFAULT_OCSP_RESPONDER_BASE_URL);
        let responder_url = normalize_base_url(base_url)?;
        let (request_der, leaf_der, issuer_der) =
            build_ocsp_request_context(cert_pem, config.ocsp_issuer_cert.as_deref())?;
        let root_cert = reqwest::Certificate::from_pem(root_cert_pem)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let http_client = reqwest::Client::builder()
            .add_root_certificate(root_cert)
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(io::Error::other)?;

        Ok(Self {
            responder_url,
            http_client,
            request_der,
            leaf_der,
            issuer_der,
        })
    }

    pub fn responder_url(&self) -> &str {
        &self.responder_url
    }

    pub async fn refresh_once(&self, quic: &mut QuicEndpoint) -> Duration {
        match self.fetch_response().await {
            Ok(response_der) => match self.validate_response(&response_der) {
                Ok(OcspCertStatus::Good) => {
                    let response_len = response_der.len();
                    quic.update_ocsp(Some(response_der));
                    info!(
                        responder_url = %self.responder_url,
                        response_len,
                        refresh_in_secs = refresh_success_delay().as_secs(),
                        "ocsp.staple_refreshed"
                    );
                    refresh_success_delay()
                }
                Ok(OcspCertStatus::Unknown) => {
                    warn!(
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp response status is unknown; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
                Ok(OcspCertStatus::Revoked) => {
                    warn!(
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp response status is revoked; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
                Err(ValidateError::ResponderStatus(OcspResponseStatus::Unauthorized)) => {
                    warn!(
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp responder returned unauthorized; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
                Err(ValidateError::ResponderStatus(OcspResponseStatus::MalformedRequest)) => {
                    warn!(
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp responder returned malformed_request; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
                Err(ValidateError::ResponderStatus(status)) => {
                    warn!(
                        responder_url = %self.responder_url,
                        ocsp_status = %status.as_str(),
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp responder returned a non-success status; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
                Err(error) => {
                    warn!(
                        error = %error,
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp response validation failed; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
            },
            Err(error) => {
                warn!(
                    error = %error,
                    responder_url = %self.responder_url,
                    retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                    "ocsp.refresh_failed"
                );
                OCSP_REFRESH_RETRY_DELAY
            }
        }
    }

    pub async fn run(self, mut quic: QuicEndpoint) {
        loop {
            let delay = self.refresh_once(&mut quic).await;
            sleep(delay).await;
        }
    }

    async fn fetch_response(&self) -> io::Result<Vec<u8>> {
        let response = self
            .http_client
            .post(&self.responder_url)
            .header(CONTENT_TYPE, "application/ocsp-request")
            .header(ACCEPT, "application/ocsp-response")
            .body(self.request_der.clone())
            .send()
            .await
            .map_err(request_error)?;

        if !response.status().is_success() {
            let status = response.status();
            let message = response.text().await.unwrap_or_default();
            return Err(io::Error::other(format!(
                "OCSP responder returned HTTP status {status}: {message}"
            )));
        }

        let body = response.bytes().await.map_err(request_error)?;
        if body.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "OCSP responder returned an empty body",
            ));
        }

        Ok(body.to_vec())
    }

    fn validate_response(&self, response_der: &[u8]) -> Result<OcspCertStatus, ValidateError> {
        verify_stapled_ocsp_response(&self.leaf_der, &self.issuer_der, response_der, now())
    }
}

pub fn refresh_success_delay() -> Duration {
    OCSP_STAPLING_TTL.saturating_sub(OCSP_REFRESH_EXPIRY_SKEW)
}

fn build_ocsp_request_context(
    cert_pem: &[u8],
    issuer_override: Option<&Path>,
) -> io::Result<(Vec<u8>, CertificateDer<'static>, CertificateDer<'static>)> {
    let chain = load_pem_certificates(cert_pem)?;
    let leaf_der = chain.first().cloned().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "server certificate PEM does not contain a certificate",
        )
    })?;
    let issuer_der = match chain.get(1) {
        Some(issuer) => issuer.clone(),
        None => load_issuer_certificate(issuer_override)?,
    };

    let leaf = Certificate::from_der(leaf_der.as_ref())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let issuer = Certificate::from_der(issuer_der.as_ref())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let request_der = build_request_der(&leaf, &issuer).map_err(io::Error::other)?;

    Ok((request_der, leaf_der, issuer_der))
}

fn load_issuer_certificate(issuer_override: Option<&Path>) -> io::Result<CertificateDer<'static>> {
    let issuer_path = issuer_override.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "OCSP auto-refresh requires the server cert PEM to include the issuer cert or ocsp_issuer_cert to be configured",
        )
    })?;
    let issuer_pem = std::fs::read(issuer_path)?;
    let issuer_chain = load_pem_certificates(&issuer_pem)?;
    issuer_chain.into_iter().next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "ocsp_issuer_cert does not contain a certificate",
        )
    })
}

fn load_pem_certificates(cert_pem: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::Cursor::new(cert_pem);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn normalize_base_url(base_url: &str) -> io::Result<String> {
    let parsed =
        Url::parse(base_url).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    if parsed.scheme() != "https" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ocsp_responder_base_url must use https",
        ));
    }
    if parsed.host_str().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ocsp_responder_base_url must include a host",
        ));
    }

    Ok(format!("{}/ocsp", parsed.as_str().trim_end_matches('/')))
}

fn request_error(error: reqwest::Error) -> io::Error {
    io::Error::other(format!("failed to query OCSP responder: {error}"))
}

fn now() -> UnixTime {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    UnixTime::since_unix_epoch(now)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

#[derive(Debug)]
enum ValidateError {
    ResponderStatus(OcspResponseStatus),
    Invalid(String),
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResponderStatus(status) => {
                write!(f, "OCSP responder returned status {}", status.as_str())
            }
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ValidateError {}

#[derive(Debug, Clone)]
struct ParsedOcspResponse {
    status: OcspCertStatus,
    basic: BasicOcspResponse,
}

fn verify_stapled_ocsp_response(
    end_entity: &CertificateDer<'_>,
    issuer: &CertificateDer<'_>,
    response_der: &[u8],
    now: UnixTime,
) -> Result<OcspCertStatus, ValidateError> {
    let end_entity_cert = Certificate::from_der(end_entity.as_ref()).map_err(|error| {
        ValidateError::Invalid(format!("failed to decode end-entity cert: {error}"))
    })?;
    let issuer_cert = Certificate::from_der(issuer.as_ref()).map_err(|error| {
        ValidateError::Invalid(format!("failed to decode issuer cert: {error}"))
    })?;
    let parsed = decode_unvalidated_ocsp_response_der(response_der, now)?;
    let single = parsed
        .basic
        .tbs_response_data
        .responses
        .first()
        .expect("single response checked during OCSP decode");
    let expected_cert_id = build_cert_id_local(&end_entity_cert, &issuer_cert)?;

    if !matches_cert_id(&single.cert_id, &expected_cert_id) {
        return Err(ValidateError::Invalid(
            "OCSP response cert_id does not match the server certificate".to_owned(),
        ));
    }

    if !responder_id_matches_certificate(
        &parsed.basic.tbs_response_data.responder_id,
        &issuer_cert,
    )? {
        return Err(ValidateError::Invalid(
            "OCSP responder identifier does not match the issuer certificate".to_owned(),
        ));
    }

    verify_basic_ocsp_signature(&parsed.basic, issuer.as_ref())?;

    Ok(parsed.status)
}

fn decode_unvalidated_ocsp_response_der(
    response_der: &[u8],
    now: UnixTime,
) -> Result<ParsedOcspResponse, ValidateError> {
    let response = OcspResponse::from_der(response_der).map_err(der_error_string)?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(ValidateError::ResponderStatus(response.response_status));
    }

    let response_bytes = response.response_bytes.ok_or_else(|| {
        ValidateError::Invalid("OCSP response is missing response bytes".to_owned())
    })?;
    if response_bytes.response_type != ID_PKIX_OCSP_BASIC {
        return Err(ValidateError::Invalid(
            "unsupported OCSP response type".to_owned(),
        ));
    }

    let basic = BasicOcspResponse::from_der(response_bytes.response.as_bytes())
        .map_err(der_error_string)?;
    let [single] = basic.tbs_response_data.responses.as_slice() else {
        return Err(ValidateError::Invalid(
            "OCSP response must contain exactly one single response".to_owned(),
        ));
    };

    let produced_at = as_unix_time(&basic.tbs_response_data.produced_at);
    if produced_at.as_secs() > now.as_secs() {
        return Err(ValidateError::Invalid(
            "OCSP response produced_at is in the future".to_owned(),
        ));
    }

    let this_update = as_unix_time(&single.this_update);
    if this_update.as_secs() > now.as_secs() {
        return Err(ValidateError::Invalid(
            "OCSP response this_update is in the future".to_owned(),
        ));
    }

    let valid_until = single
        .next_update
        .as_ref()
        .map(as_unix_time)
        .unwrap_or(this_update);
    if valid_until.as_secs() < this_update.as_secs() {
        return Err(ValidateError::Invalid(
            "OCSP response next_update is earlier than this_update".to_owned(),
        ));
    }
    if valid_until.as_secs() < now.as_secs() {
        return Err(ValidateError::Invalid(
            "OCSP response is already expired".to_owned(),
        ));
    }

    let status = match &single.cert_status {
        CertStatus::Good(_) => OcspCertStatus::Good,
        CertStatus::Revoked(_) => OcspCertStatus::Revoked,
        CertStatus::Unknown(_) => OcspCertStatus::Unknown,
    };

    Ok(ParsedOcspResponse { status, basic })
}

fn verify_basic_ocsp_signature(
    basic: &BasicOcspResponse,
    signer_der: &[u8],
) -> Result<(), ValidateError> {
    let signer = parse_x509_certificate_der(signer_der, "OCSP signer certificate")?;
    let signature_algorithm_der = basic
        .signature_algorithm
        .to_der()
        .map_err(der_error_string)?;
    let (_, signature_algorithm) = X509AlgorithmIdentifier::from_der(&signature_algorithm_der)
        .map_err(|error| {
            ValidateError::Invalid(format!(
                "failed to parse OCSP response signature algorithm: {error}"
            ))
        })?;
    let signature_der = basic.signature.to_der().map_err(der_error_string)?;
    let (_, signature_value) = X509BitString::from_der(&signature_der).map_err(|error| {
        ValidateError::Invalid(format!(
            "failed to parse OCSP response signature value: {error}"
        ))
    })?;
    let tbs_der = basic.tbs_response_data.to_der().map_err(der_error_string)?;

    verify_x509_signature(
        signer.public_key(),
        &signature_algorithm,
        &signature_value,
        &tbs_der,
    )
    .map_err(|error| {
        ValidateError::Invalid(format!("failed to verify OCSP response signature: {error}"))
    })
}

fn parse_x509_certificate_der<'a>(
    cert_der: &'a [u8],
    label: &str,
) -> Result<x509_parser::certificate::X509Certificate<'a>, ValidateError> {
    parse_x509_certificate(cert_der)
        .map(|(_, cert)| cert)
        .map_err(|error| ValidateError::Invalid(format!("failed to parse {label}: {error:?}")))
}

fn responder_id_matches_certificate(
    responder_id: &ResponderId,
    certificate: &Certificate,
) -> Result<bool, ValidateError> {
    match responder_id {
        ResponderId::ByName(name) => Ok(name.to_der().map_err(der_error_string)?
            == certificate
                .tbs_certificate()
                .subject()
                .to_der()
                .map_err(der_error_string)?),
        ResponderId::ByKey(key_hash) => Ok(key_hash.as_bytes()
            == Sha1::digest(
                certificate
                    .tbs_certificate()
                    .subject_public_key_info()
                    .subject_public_key
                    .raw_bytes(),
            )
            .as_slice()),
    }
}

fn build_cert_id_local(
    end_entity: &Certificate,
    issuer: &Certificate,
) -> Result<CertId, ValidateError> {
    let issuer_name_hash = Sha1::digest(
        issuer
            .tbs_certificate()
            .subject()
            .to_der()
            .map_err(der_error_string)?,
    );
    let issuer_key_hash = Sha1::digest(
        issuer
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    );

    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA_1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.as_slice())
            .map_err(der_error_string)?,
        issuer_key_hash: OctetString::new(issuer_key_hash.as_slice()).map_err(der_error_string)?,
        serial_number: end_entity.tbs_certificate().serial_number().clone(),
    })
}

fn matches_cert_id(actual: &CertId, expected: &CertId) -> bool {
    actual.hash_algorithm.oid == expected.hash_algorithm.oid
        && actual.issuer_name_hash == expected.issuer_name_hash
        && actual.issuer_key_hash == expected.issuer_key_hash
        && actual.serial_number == expected.serial_number
}

fn build_request_der(end_entity: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, String> {
    OcspRequest {
        tbs_request: TbsRequest {
            version: Version::default(),
            requestor_name: None,
            request_list: vec![RequestEntry {
                req_cert: build_request_cert_id(end_entity, issuer)?,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    }
    .to_der()
    .map_err(der_error)
}

fn build_request_cert_id(end_entity: &Certificate, issuer: &Certificate) -> Result<CertId, String> {
    let issuer_name_hash = Sha1::digest(
        issuer
            .tbs_certificate()
            .subject()
            .to_der()
            .map_err(der_error)?,
    );
    let issuer_key_hash = Sha1::digest(
        issuer
            .tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes(),
    );

    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: ID_SHA_1,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(issuer_name_hash.as_slice()).map_err(der_error)?,
        issuer_key_hash: OctetString::new(issuer_key_hash.as_slice()).map_err(der_error)?,
        serial_number: end_entity.tbs_certificate().serial_number().clone(),
    })
}

fn as_unix_time(time: &GeneralizedTime) -> UnixTime {
    UnixTime::since_unix_epoch(time.to_unix_duration())
}

fn der_error(error: impl std::fmt::Display) -> String {
    format!("failed to process OCSP DER: {error}")
}

fn der_error_string(error: impl std::fmt::Display) -> ValidateError {
    ValidateError::Invalid(der_error(error))
}

#[derive(Clone, Debug, Default, Copy, PartialEq, Eq, Enumerated)]
#[asn1(type = "INTEGER")]
#[repr(u8)]
enum Version {
    #[default]
    V1 = 0,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OcspRequest {
    tbs_request: TbsRequest,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    optional_signature: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct TbsRequest {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    version: Version,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    requestor_name: Option<Any>,

    request_list: Vec<RequestEntry>,

    #[asn1(context_specific = "2", optional = "true", tag_mode = "EXPLICIT")]
    request_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct RequestEntry {
    req_cert: CertId,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    single_request_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CertId {
    hash_algorithm: AlgorithmIdentifierOwned,
    issuer_name_hash: OctetString,
    issuer_key_hash: OctetString,
    serial_number: SerialNumber,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum CertStatus {
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT")]
    Good(Null),

    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", constructed = "true")]
    Revoked(RevokedInfo),

    #[asn1(context_specific = "2", tag_mode = "IMPLICIT")]
    Unknown(Null),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct RevokedInfo {
    revocation_time: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    revocation_reason: Option<Any>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SingleResponse {
    cert_id: CertId,
    cert_status: CertStatus,
    this_update: GeneralizedTime,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    next_update: Option<GeneralizedTime>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    single_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Choice)]
enum ResponderId {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", constructed = "true")]
    ByName(Any),

    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", constructed = "true")]
    ByKey(OctetString),
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ResponseData {
    #[asn1(
        context_specific = "0",
        default = "Default::default",
        tag_mode = "EXPLICIT"
    )]
    version: Version,
    responder_id: ResponderId,
    produced_at: GeneralizedTime,
    responses: Vec<SingleResponse>,

    #[asn1(context_specific = "1", optional = "true", tag_mode = "EXPLICIT")]
    response_extensions: Option<Extensions>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct BasicOcspResponse {
    tbs_response_data: ResponseData,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: der::asn1::BitString,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    certs: Option<Vec<Certificate>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct ResponseBytes {
    response_type: ObjectIdentifier,
    response: OctetString,
}

#[derive(Enumerated, Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
enum OcspResponseStatus {
    Successful = 0,
    MalformedRequest = 1,
    InternalError = 2,
    TryLater = 3,
    SigRequired = 5,
    Unauthorized = 6,
}

impl OcspResponseStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Successful => "successful",
            Self::MalformedRequest => "malformed_request",
            Self::InternalError => "internal_error",
            Self::TryLater => "try_later",
            Self::SigRequired => "sig_required",
            Self::Unauthorized => "unauthorized",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct OcspResponse {
    response_status: OcspResponseStatus,

    #[asn1(context_specific = "0", optional = "true", tag_mode = "EXPLICIT")]
    response_bytes: Option<ResponseBytes>,
}
