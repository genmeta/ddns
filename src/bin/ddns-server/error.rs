use std::collections::HashMap;

use dhttp_identity::name::DhttpName;

#[derive(Debug, snafu::Snafu)]
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
            AppError::NoAnswersInPacket => http::StatusCode::UNPROCESSABLE_ENTITY,
            AppError::SignatureRequired => http::StatusCode::BAD_REQUEST,
            AppError::InvalidSignature => http::StatusCode::BAD_REQUEST,
            AppError::Redis { .. } => http::StatusCode::SERVICE_UNAVAILABLE,
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

    // 校验是否为 DHTTP identity 域名
    if !host.ends_with(DhttpName::SUFFIX) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_uses_dhttp_identity_suffix() {
        assert_eq!(
            normalize_host("Reimu.Pilot.Dhttp.Net:443").unwrap(),
            "reimu.pilot.dhttp.net"
        );
        assert!(matches!(
            normalize_host("reimu.pilot.genmeta.net"),
            Err(AppError::DomainNotAllowed)
        ));
    }
}
