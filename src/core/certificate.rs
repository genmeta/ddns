use dhttp_identity::certificate::{CertificateChainKey, CertificateSequence, CertificateUsage};

const PRIMARY_KIND_FLAG: &str = "0";
const SECONDARY_KIND_FLAG: &str = "1";

pub(crate) fn primary_chain_key(sequence: CertificateSequence) -> CertificateChainKey {
    chain_key(sequence, PRIMARY_KIND_FLAG)
}

pub(crate) fn secondary_chain_key(sequence: CertificateSequence) -> CertificateChainKey {
    chain_key(sequence, SECONDARY_KIND_FLAG)
}

pub(crate) fn is_primary_chain_key(chain_key: &CertificateChainKey) -> bool {
    chain_key.usage().kind_flag() == PRIMARY_KIND_FLAG
}

fn chain_key(sequence: CertificateSequence, kind_flag: &str) -> CertificateChainKey {
    let usage = match kind_flag {
        "0" => CertificateUsage::ClientOnly,
        "1" => CertificateUsage::ClientAndServer,
        _ => unreachable!("unsupported certificate kind flag"),
    };
    CertificateChainKey::new(sequence, usage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_keys_preserve_primary_secondary_wire_flags() {
        let sequence = CertificateSequence::from(7u8);
        let primary = primary_chain_key(sequence);
        let secondary = secondary_chain_key(sequence);

        assert_eq!(primary.usage().kind_flag(), "0");
        assert_eq!(secondary.usage().kind_flag(), "1");
        assert!(is_primary_chain_key(&primary));
        assert!(!is_primary_chain_key(&secondary));
    }
}
