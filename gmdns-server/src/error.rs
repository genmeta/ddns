use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Missing host parameter")]
    MissingHostParam,
    #[error("Invalid host")]
    InvalidHost,
    #[error("Forbidden host")]
    ForbiddenHost,
    #[error("Domain not allowed")]
    DomainNotAllowed,
    #[error("Host mismatch")]
    HostMismatch,
    #[error("Missing client certificate")]
    MissingClientCertificate,
    #[error("Client certificate domain not allowed")]
    ClientCertDomainNotAllowed,
    #[error("Invalid DNS packet: {0}")]
    InvalidDnsPacket(String),
    #[error("No answers in packet")]
    NoAnswersInPacket,
    #[error("Signature required")]
    SignatureRequired,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Redis error: {0}")]
    Redis(String),
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
            AppError::InvalidDnsPacket(_) => http::StatusCode::BAD_REQUEST,
            AppError::NoAnswersInPacket => http::StatusCode::UNPROCESSABLE_ENTITY,
            AppError::SignatureRequired => http::StatusCode::BAD_REQUEST,
            AppError::InvalidSignature => http::StatusCode::BAD_REQUEST,
            AppError::Redis(_) => http::StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

pub fn normalize_host(host: &str) -> Result<String, AppError> {
    let host = host.trim();
    if host.is_empty() {
        return Err(AppError::InvalidHost);
    }
    if host.contains('*') {
        return Err(AppError::ForbiddenHost);
    }

    // 剥离端口号（如 "example.com:443" -> "example.com"）
    let host = match host.rsplit_once(':') {
        Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => host,
    };

    // 允许末尾 '.'（FQDN 写法）
    let host = host.strip_suffix('.').unwrap_or(host);

    let host = idna::domain_to_ascii(host).map_err(|_| AppError::InvalidHost)?;
    let host = host.to_ascii_lowercase();

    // 校验是否为 genmeta.net 域名
    if !host.ends_with("genmeta.net") {
        return Err(AppError::DomainNotAllowed);
    }

    Ok(host)
}

pub fn parse_query_params(uri: &http::Uri) -> HashMap<String, String> {
    let query = uri.query().unwrap_or("");
    url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect()
}
