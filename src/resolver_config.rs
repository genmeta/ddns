use std::{io, sync::Arc};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DnsScheme {
    System,
    Mdns,
    H3,
    Http,
}
impl std::str::FromStr for DnsScheme {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "system" => Ok(Self::System),
            "mdns" => Ok(Self::Mdns),
            "h3" => Ok(Self::H3),
            "http" => Ok(Self::Http),
            _ => Err(format!("unsupported DNS scheme: {s}")),
        }
    }
}
impl std::fmt::Display for DnsScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::System => "system",
            Self::Mdns => "mdns",
            Self::H3 => "h3",
            Self::Http => "http",
        })
    }
}

pub fn install_resolvers(
    schemes: &[DnsScheme],
) -> io::Result<Option<crate::mdns::MdnsResolverSet>> {
    #[derive(Default)]
    struct Installed {
        schemes: std::collections::HashSet<DnsScheme>,
        mdns: Option<crate::mdns::MdnsResolverSet>,
    }
    static INSTALLED: std::sync::OnceLock<std::sync::Mutex<Installed>> = std::sync::OnceLock::new();
    let mut installed = INSTALLED
        .get_or_init(Default::default)
        .lock()
        .map_err(|e| io::Error::other(e.to_string()))?;
    let mut requested = schemes.to_vec();
    // H3/HTTP DNS needs ordinary DNS for its bootstrap server; SystemResolver excludes DHTTP names.
    if schemes
        .iter()
        .any(|s| matches!(s, DnsScheme::H3 | DnsScheme::Http))
    {
        requested.push(DnsScheme::System);
    }
    for scheme in requested {
        if installed.schemes.contains(&scheme) {
            continue;
        }
        match scheme {
            DnsScheme::System => qresolve::Resolver::add(Arc::new(qresolve::SystemResolver)),
            DnsScheme::H3 => qresolve::Resolver::add(Arc::new(
                crate::H3Resolver::anonymous(
                    crate::resolvers::DHTTP_NAME_SERVICE
                        .parse()
                        .map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?,
            )),
            DnsScheme::Http => qresolve::Resolver::add(Arc::new(
                crate::http::HttpResolver::new(
                    crate::resolvers::DHTTP_NAME_SERVICE
                        .parse()
                        .map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?,
            )),
            DnsScheme::Mdns => {
                let set =
                    crate::mdns::MdnsResolverSet::new(crate::resolvers::DHTTP_MDNS_SERVICE_DOMAIN);
                qresolve::Resolver::add(Arc::new(set.clone()));
                installed.mdns = Some(set);
            }
        }
        installed.schemes.insert(scheme);
    }
    Ok(schemes
        .contains(&DnsScheme::Mdns)
        .then(|| installed.mdns.clone())
        .flatten())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_installation_does_not_duplicate_sources() {
        let schemes = [DnsScheme::System];
        install_resolvers(&schemes).unwrap();
        let before = qresolve::Resolver::get().to_string();
        install_resolvers(&schemes).unwrap();
        assert_eq!(qresolve::Resolver::get().to_string(), before);
    }
}
