use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use clap::Parser;
use serde::Deserialize;

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

    /// Socket to listen on.
    #[serde(default = "Config::default_listen")]
    pub listen: SocketAddr,

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
}

impl Config {
    pub fn expand_paths(mut self) -> Self {
        self.cert = expand_home_dir(&self.cert);
        self.key = expand_home_dir(&self.key);
        self.root_cert = expand_home_dir(&self.root_cert);
        self
    }

    pub fn default_listen() -> SocketAddr {
        "0.0.0.0:4433".parse().unwrap()
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
