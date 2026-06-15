use std::{io, path::Path, time::Duration};

use dhttp_identity::ocsp::{OcspStatus, build_ocsp_request_der, verify_stapled_ocsp_response};
use h3x::dquic::QuicEndpoint;
use reqwest::{
    Url,
    header::{ACCEPT, CONTENT_TYPE},
};
use rustls::pki_types::{CertificateDer, UnixTime};
use tokio::time::sleep;
use tracing::{info, warn};

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
                Ok(OcspStatus::Good) => {
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
                Ok(OcspStatus::Unknown) => {
                    warn!(
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp response status is unknown; skipping staple update"
                    );
                    OCSP_REFRESH_RETRY_DELAY
                }
                Ok(OcspStatus::Revoked) => {
                    warn!(
                        responder_url = %self.responder_url,
                        retry_in_secs = OCSP_REFRESH_RETRY_DELAY.as_secs(),
                        "ocsp response status is revoked; skipping staple update"
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

    fn validate_response(&self, response_der: &[u8]) -> Result<OcspStatus, rustls::Error> {
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

    let request_der = build_ocsp_request_der(&leaf_der, &issuer_der)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

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
