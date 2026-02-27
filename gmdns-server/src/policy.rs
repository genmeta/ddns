use gmdns::parser::{packet::be_packet, record::RData};
use h3x::agent::RemoteAgent;
use tracing::warn;

use crate::error::{AppError, normalize_host};

// ---------------------------------------------------------------------------
// Domain policy
// ---------------------------------------------------------------------------

/// Per-domain publish / lookup behaviour.
#[derive(Clone, Debug, PartialEq)]
pub enum DomainPolicy {
    /// Signature check controlled by `require_signature` flag; single record
    /// per host; each publish overwrites the previous one.
    Standard,
    /// No signature check; any authenticated node may publish; multiple records
    /// with individual TTLs; ordered newest-first on lookup.
    OpenMulti,
}

/// One rule in the domain-policy list.
#[derive(Clone, Debug)]
pub enum PolicyRule {
    /// Matches only this exact (normalised) host.
    Exact(String),
    /// Matches the host itself or any label-subdomain (future use).
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

/// Ordered list of (rule, policy) pairs; first match wins; default is Standard.
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

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

pub fn extract_client_dns_sans(agent: &RemoteAgent) -> Vec<String> {
    use x509_parser::prelude::*;

    let Some(leaf) = agent.cert_chain().first() else {
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

pub fn client_allowed_host(agent: &RemoteAgent) -> Result<String, AppError> {
    let mut sans = extract_client_dns_sans(agent)
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
    agent: &RemoteAgent,
) -> Result<String, AppError> {
    let (remaining, dns_packet) =
        be_packet(packet).map_err(|e| AppError::InvalidDnsPacket(e.to_string()))?;
    if !remaining.is_empty() {
        warn!(remain = remaining.len(), "dns.parse.extra_bytes");
    }

    if require_signature {
        let has_signature = dns_packet
            .answers
            .iter()
            .any(|record| matches!(record.data(), RData::E(endpoint) if endpoint.is_signed()));

        if !has_signature {
            return Err(AppError::SignatureRequired);
        }

        for record in &dns_packet.answers {
            if let RData::E(endpoint) = record.data()
                && endpoint.is_signed()
            {
                let cert = agent
                    .cert_chain()
                    .first()
                    .ok_or(AppError::MissingClientCertificate)?;
                let ok = endpoint
                    .verify_signature_from_der(cert.as_ref())
                    .map_err(|_| AppError::InvalidSignature)?;
                if !ok {
                    return Err(AppError::InvalidSignature);
                }
            }
        }
    }

    dns_packet
        .answers
        .first()
        .map(|record| record.name().to_string())
        .ok_or(AppError::NoAnswersInPacket)
}
