use ddns::parser::{packet::be_packet, record::RData};
use dhttp_identity::identity::RemoteAgent;
use tracing::{debug, warn};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedDnsPacket {
    Records { host: String },
    Empty,
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

pub fn extract_client_dns_sans(agent: &(impl RemoteAgent + ?Sized)) -> Vec<String> {
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

pub fn client_allowed_host(agent: &(impl RemoteAgent + ?Sized)) -> Result<String, AppError> {
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
    agent: &(impl RemoteAgent + ?Sized),
) -> Result<ValidatedDnsPacket, AppError> {
    let (remaining, dns_packet) = be_packet(packet).map_err(|e| AppError::InvalidDnsPacket {
        message: e.to_string(),
    })?;
    if !remaining.is_empty() {
        warn!(remain = remaining.len(), "dns.parse.extra_bytes");
    }
    debug!(
        answers = dns_packet.answers.len(),
        require_signature, "validating dns packet"
    );

    let Some(first_answer) = dns_packet.answers.first() else {
        debug!("dns packet has no answers");
        return Ok(ValidatedDnsPacket::Empty);
    };

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

    Ok(ValidatedDnsPacket::Records {
        host: first_answer.name().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ddns::MdnsPacket;
    use dhttp_identity::identity::RemoteAgent;
    use rustls::pki_types::CertificateDer;

    use super::*;

    #[derive(Debug)]
    struct TestAgent;

    impl RemoteAgent for TestAgent {
        fn name(&self) -> &str {
            "agent.example"
        }

        fn cert_chain(&self) -> &[CertificateDer<'static>] {
            &[]
        }
    }

    #[test]
    fn validate_dns_packet_accepts_empty_packet_as_clear_operation() {
        let hosts: HashMap<String, Vec<ddns::parser::record::endpoint::EndpointAddr>> =
            HashMap::from([("reimu.pilot.genmeta.net".to_owned(), Vec::new())]);
        let packet = MdnsPacket::answer(0, &hosts).to_bytes();

        let validated = validate_dns_packet(&packet, true, &TestAgent).unwrap();

        assert!(matches!(validated, ValidatedDnsPacket::Empty));
    }
}
