//! PKI model types, configuration, and errors.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration for on-demand credential management.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PkiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pki_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_server_validity_days")]
    pub server_validity_days: u32,
    #[serde(default = "default_client_validity_days")]
    pub client_validity_days: u32,
    #[serde(default = "default_require_https")]
    pub require_https_for_download: bool,
}

fn default_pki_dir() -> PathBuf {
    PathBuf::from("pki")
}
fn default_server_validity_days() -> u32 {
    397
}
fn default_client_validity_days() -> u32 {
    90
}
fn default_require_https() -> bool {
    true
}

impl Default for PkiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            dir: default_pki_dir(),
            server_validity_days: default_server_validity_days(),
            client_validity_days: default_client_validity_days(),
            require_https_for_download: default_require_https(),
        }
    }
}

impl PkiConfig {
    pub fn validate(&self) -> Result<(), PkiError> {
        if !(1..=3650).contains(&self.server_validity_days) {
            return Err(PkiError::Invalid(
                "server_validity_days must be 1..=3650".into(),
            ));
        }
        if !(1..=3650).contains(&self.client_validity_days) {
            return Err(PkiError::Invalid(
                "client_validity_days must be 1..=3650".into(),
            ));
        }
        if self.dir.as_os_str().is_empty() {
            return Err(PkiError::Invalid("pki.dir must not be empty".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PkiStatus {
    pub enabled: bool,
    pub credentials: usize,
    pub tunnel_ready: bool,
    pub waiting_for_credentials: bool,
}

#[derive(Debug, Error)]
pub enum PkiError {
    #[error("pki: {0}")]
    Invalid(String),
    #[error("pki I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("pki certificate generation: {0}")]
    Generate(String),
    #[error("pki storage: {0}")]
    Storage(String),
    #[error("pki pair not found")]
    NotFound,
    #[error("pki conflict: {0}")]
    Conflict(String),
    #[error("client private key has already been downloaded; create a new pair")]
    DownloadConsumed,
    #[error("credential pair has expired; create a new pair")]
    Expired,
    #[error("client private key download requires HTTPS or loopback/SSH tunnel access")]
    HttpsRequired,
}

pub(crate) fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub(crate) fn fingerprint_hex(cert: &rustls::pki_types::CertificateDer<'_>) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(cert.as_ref());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn random_id() -> String {
    rand::random::<[u8; 16]>()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

pub(crate) fn valid_server_name(server_name: &str) -> bool {
    if server_name.is_empty() || server_name.len() > 253 || !server_name.is_ascii() {
        return false;
    }
    if server_name.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    server_name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}
