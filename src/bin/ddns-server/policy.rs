use ddns::core::{
    parser::{packet::be_packet, record::RData},
    signature::SignatureFields,
};
use dhttp_identity::identity::RemoteAuthority;
use tracing::{debug, warn};

use crate::error::{AppError, app_error, normalize_host};

#[derive(Clone, Debug, PartialEq)]
pub enum DomainPolicy {
    Standard,
    OpenMulti,
}

#[derive(Clone, Debug)]
pub enum PolicyRule {
    Exact(String),
    #[allow(dead_code)]
    Suffix(String),
}

impl PolicyRule {
    pub fn matches(&self, host: &str) -> bool {
        match self {
            PolicyRule::Exact(exact) => host == exact,
            PolicyRule::Suffix(suffix) => {
                host == suffix.as_str() || host.ends_with(&format!(".{suffix}"))
            }
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct DomainPolicies(pub Vec<(PolicyRule, DomainPolicy)>);

impl DomainPolicies {
    pub fn policy_for(&self, host: &str) -> &DomainPolicy {
        for (rule, policy) in &self.0 {
            if rule.matches(host) {
                return policy;
            }
        }
        &DomainPolicy::Standard
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedDnsPacket {
    Records { host: String },
    Empty,
}

pub fn extract_client_dns_sans(authority: &(impl RemoteAuthority + ?Sized)) -> Vec<String> {
    use x509_parser::prelude::*;

    let Some(leaf) = authority.cert_chain().first() else {
        return vec![];
    };

    let Ok((_remain, cert)) = X509Certificate::from_der(leaf.as_ref()) else {
        return vec![];
    };

    let mut out = vec![];
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in san.value.general_names.iter() {
            if let GeneralName::DNSName(dns) = name {
                out.push(dns.to_string());
            }
        }
    }
    out
}

pub fn client_allowed_host(
    authority: &(impl RemoteAuthority + ?Sized),
) -> Result<String, AppError> {
    let mut sans = extract_client_dns_sans(authority)
        .into_iter()
        .filter_map(|h| normalize_host(&h).ok())
        .collect::<Vec<_>>();

    sans.sort();
    sans.dedup();

    match sans.len() {
        1 => Ok(sans.remove(0)),
        _ => Err(AppError::ClientCertDomainNotAllowed),
    }
}

pub fn validate_dns_packet(
    packet: &[u8],
    require_signature: bool,
    authority: &(impl RemoteAuthority + ?Sized),
    signature_fields: &SignatureFields,
    expected_host: &str,
) -> Result<ValidatedDnsPacket, AppError> {
    let (remaining, dns_packet) = be_packet(packet).map_err(|e| AppError::InvalidDnsPacket {
        message: e.to_string(),
    })?;
    if !remaining.is_empty() {
        warn!(remain = remaining.len(), "dns.parse.extra_bytes");
    }
    debug!(
        answers = dns_packet.answers.len(),
        require_signature,
        "validating dns packet"
    );

    if require_signature {
        if signature_fields.is_empty() {
            return Err(AppError::SignatureRequired);
        }

        let cert = authority
            .cert_chain()
            .first()
            .ok_or(AppError::MissingClientCertificate)?;
        let ok = signature_fields
            .verify(packet, cert.as_ref())
            .map_err(|_| AppError::InvalidSignature)?;
        if !ok {
            return Err(AppError::InvalidSignature);
        }

        for record in &dns_packet.answers {
            if let RData::E(endpoint) = record.data()
                && endpoint.is_signed()
            {
                return Err(AppError::InvalidSignature);
            }
        }
    }

    let Some(first_answer) = dns_packet.answers.first() else {
        debug!("dns packet has no answers");
        return Ok(ValidatedDnsPacket::Empty);
    };

    for answer in &dns_packet.answers {
        let answer_host = normalize_host(&answer.name())?;
        if answer_host != expected_host {
            return Err(AppError::HostMismatch);
        }
    }

    Ok(ValidatedDnsPacket::Records {
        host: first_answer.name().to_string(),
    })
}
