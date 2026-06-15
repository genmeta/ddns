use std::collections::HashMap;

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum AppError {
    #[snafu(display("missing host parameter"))]
    MissingHostParam,
    #[snafu(display("invalid host"))]
    InvalidHost,
    #[snafu(display("forbidden host"))]
    ForbiddenHost,
    #[snafu(display("domain not allowed"))]
    DomainNotAllowed,
    #[snafu(display("host mismatch"))]
    HostMismatch,
    #[snafu(display("missing client certificate"))]
    MissingClientCertificate,
    #[snafu(display("client certificate domain not allowed"))]
    ClientCertDomainNotAllowed,
    #[snafu(display("invalid DNS packet: {message}"))]
    InvalidDnsPacket { message: String },
    #[snafu(display("publisher certificate selector is invalid"))]
    PublisherCertificateSelector {
        source: dhttp_identity::identity::ExtractDhttpSubjectKeyIdentifierError,
    },
    #[snafu(display("endpoint record selector is invalid"))]
    EndpointRecordSelector {
        source: ddns::core::parser::record::endpoint::EndpointSelectorError,
    },
    #[snafu(display("endpoint record selector does not match publisher certificate selector"))]
    EndpointSelectorMismatch,
    #[snafu(display("no answers in packet"))]
    NoAnswersInPacket,
    #[snafu(display("signature required"))]
    SignatureRequired,
    #[snafu(display("invalid signature"))]
    InvalidSignature,
    #[snafu(display("redis error: {message}"))]
    Redis { message: String },
}

impl AppError {
    pub fn status(&self) -> http::StatusCode {
        match self {
            AppError::MissingHostParam => http::StatusCode::BAD_REQUEST,
            AppError::InvalidHost => http::StatusCode::BAD_REQUEST,
            AppError::ForbiddenHost => http::StatusCode::BAD_REQUEST,
            AppError::DomainNotAllowed => http::StatusCode::FORBIDDEN,
            AppError::HostMismatch => http::StatusCode::BAD_REQUEST,
            AppError::MissingClientCertificate => http::StatusCode::UNAUTHORIZED,
            AppError::ClientCertDomainNotAllowed => http::StatusCode::FORBIDDEN,
            AppError::InvalidDnsPacket { .. } => http::StatusCode::BAD_REQUEST,
            AppError::PublisherCertificateSelector { .. } => http::StatusCode::BAD_REQUEST,
            AppError::EndpointRecordSelector { .. } => http::StatusCode::BAD_REQUEST,
            AppError::EndpointSelectorMismatch => http::StatusCode::BAD_REQUEST,
            AppError::NoAnswersInPacket => http::StatusCode::UNPROCESSABLE_ENTITY,
            AppError::SignatureRequired => http::StatusCode::BAD_REQUEST,
            AppError::InvalidSignature => http::StatusCode::BAD_REQUEST,
            AppError::Redis { .. } => http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub fn normalize_host_allowlist(entries: &[String]) -> Result<Vec<String>, AppError> {
    let mut allowlist = entries
        .iter()
        .map(|entry| normalize_host_raw(entry))
        .collect::<Result<Vec<_>, _>>()?;
    allowlist.sort();
    allowlist.dedup();
    Ok(allowlist)
}

pub fn normalize_host(host: &str, allowlist: &[String]) -> Result<String, AppError> {
    let host = normalize_host_raw(host)?;
    if allowlist.iter().any(|suffix| host_matches_suffix(&host, suffix)) {
        Ok(host)
    } else {
        Err(AppError::DomainNotAllowed)
    }
}

pub fn normalize_host_raw(host: &str) -> Result<String, AppError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(AppError::InvalidHost);
    }
    if host.contains('*') {
        return Err(AppError::ForbiddenHost);
    }

    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    let host = idna::domain_to_ascii(host).map_err(|_| AppError::InvalidHost)?;
    Ok(host.to_ascii_lowercase())
}

pub fn parse_query_params(uri: &http::Uri) -> HashMap<String, String> {
    let query = uri.query().unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}

fn host_matches_suffix(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

