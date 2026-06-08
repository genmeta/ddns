use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use clap::Parser;
use h3x::dquic::binds::BindPattern;
use serde::{Deserialize, Deserializer, de::Error as _};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Clone, Debug)]
#[command(version, about, long_about = None)]
pub struct Options {
    /// Path to the TOML configuration file.
    #[arg(long, default_value = "server.toml")]
    pub config: PathBuf,
}

// ---------------------------------------------------------------------------
// Configuration file schema
// ---------------------------------------------------------------------------

/// Top-level configuration loaded from the TOML file.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Redis URL (e.g. "redis://127.0.0.1/"). Omit to use in-memory storage.
    pub redis: Option<String>,

    /// Bind patterns to listen on.
    #[serde(
        default = "Config::default_binds",
        deserialize_with = "deserialize_bind_patterns"
    )]
    pub binds: Vec<BindPattern>,

    /// Server name (used as TLS SNI).
    #[serde(default = "Config::default_server_name")]
    pub server_name: String,

    /// Path to the server TLS certificate (PEM).
    #[serde(default = "Config::default_cert")]
    pub cert: PathBuf,

    /// Path to the server TLS private key (PEM).
    #[serde(default = "Config::default_key")]
    pub key: PathBuf,

    /// Path to the root CA that signs client certificates (PEM).
    #[serde(default = "Config::default_root_cert")]
    pub root_cert: PathBuf,

    /// Optional issuer certificate used for OCSP requests when `cert` does not include a chain.
    #[serde(default)]
    pub ocsp_issuer_cert: Option<PathBuf>,

    /// Optional OCSP responder base URL. Defaults to the cert-server public responder.
    #[serde(default)]
    pub ocsp_responder_base_url: Option<String>,

    /// Whether to require DNS record signatures on Standard domains.
    #[serde(default = "Config::default_require_signature")]
    pub require_signature: bool,

    /// Default TTL (seconds) for published records.
    #[serde(default = "Config::default_ttl_secs")]
    pub ttl_secs: u64,

    /// Domain-policy rules (first match wins; unlisted domains use Standard).
    #[serde(default)]
    pub domain_policies: Vec<PolicyConfig>,

    /// Static seed records returned on lookup in addition to dynamic published records.
    #[serde(default)]
    pub seed_records: Vec<SeedRecordConfig>,

    /// Path to the GeoLite2 City database.
    #[serde(default)]
    pub geoip_city_db: Option<PathBuf>,

    /// Path to the GeoLite2 ASN database.
    #[serde(default)]
    pub geoip_asn_db: Option<PathBuf>,
}

impl Config {
    pub fn expand_paths(mut self) -> Self {
        self.cert = expand_home_dir(&self.cert);
        self.key = expand_home_dir(&self.key);
        self.root_cert = expand_home_dir(&self.root_cert);
        self.ocsp_issuer_cert = self.ocsp_issuer_cert.map(|path| expand_home_dir(&path));
        self.geoip_city_db = self.geoip_city_db.map(|path| expand_home_dir(&path));
        self.geoip_asn_db = self.geoip_asn_db.map(|path| expand_home_dir(&path));
        self
    }

    pub fn default_binds() -> Vec<BindPattern> {
        ["0.0.0.0:4433", "[::]:4433"]
            .into_iter()
            .map(|value| {
                BindPattern::from_str(value).expect("default bind pattern should be valid")
            })
            .collect()
    }
    pub fn default_server_name() -> String {
        "localhost".into()
    }
    pub fn default_cert() -> PathBuf {
        "examples/keychain/localhost/localhost-ECC.crt".into()
    }
    pub fn default_key() -> PathBuf {
        "examples/keychain/localhost/localhost-ECC.key".into()
    }
    pub fn default_root_cert() -> PathBuf {
        "examples/keychain/root/rootCA-ECC.crt".into()
    }
    pub fn default_require_signature() -> bool {
        true
    }
    pub fn default_ttl_secs() -> u64 {
        30
    }
}

fn deserialize_bind_patterns<'de, D>(deserializer: D) -> Result<Vec<BindPattern>, D::Error>
where
    D: Deserializer<'de>,
{
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            BindPattern::from_str(&value).map_err(|error| {
                D::Error::custom(format!("invalid bind pattern `{value}`: {error}"))
            })
        })
        .collect()
}

fn expand_home_dir(path: &Path) -> PathBuf {
    let Some(path_str) = path.to_str() else {
        return path.to_path_buf();
    };

    if path_str == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| path.to_path_buf());
    }

    if let Some(stripped) = path_str.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(stripped);
    }

    path.to_path_buf()
}

/// One domain-policy rule in the configuration file.
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Exact host to match (after normalisation).
    pub host: String,
    /// Policy to apply.
    pub policy: PolicyKind,
}

/// One statically configured seed record group.
#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
pub struct SeedRecordConfig {
    /// Exact host to seed.
    pub host: String,
    /// Preloaded endpoint list for this host.
    pub endpoints: Vec<SocketAddr>,
}

/// Serialisable policy kind.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    Standard,
    OpenMulti,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_binds_are_explicit_dual_stack() {
        let binds = Config::default_binds();

        assert_eq!(binds.len(), 2);
        assert_eq!(binds[0].to_string(), "inet://0.0.0.0:4433");
        assert_eq!(binds[1].to_string(), "inet://[::]:4433");
    }

    #[test]
    fn config_parses_bare_socket_bind_patterns() {
        let config: Config = toml::from_str(
            r#"
            binds = ["0.0.0.0:4433", "[::]:4433"]
            "#,
        )
        .expect("config should parse");

        assert_eq!(config.binds.len(), 2);
        assert_eq!(config.binds[0].to_string(), "inet://0.0.0.0:4433");
        assert_eq!(config.binds[1].to_string(), "inet://[::]:4433");
    }

    #[test]
    fn legacy_listen_field_is_rejected() {
        let error = toml::from_str::<Config>(
            r#"
            listen = "0.0.0.0:4433"
            "#,
        )
        .expect_err("legacy listen should be rejected");

        assert!(error.to_string().contains("unknown field `listen`"));
    }
}
