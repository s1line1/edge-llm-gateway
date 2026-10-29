//! On-demand client/server credential pairs.
//!
//! Nothing in this module generates a certificate from `open`, `Default`, or startup. A pair is
//! created only by an explicit admin request; the server half is loaded into the live TLS state
//! immediately, and the client half is a one-time download.

mod generate;
mod resolver;
mod service;
mod store;
mod verify;

use std::{path::PathBuf, sync::Arc};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use generate::{generate_pair, GeneratedPair};
pub use resolver::PkiServerCerts;
pub use service::{DownloadBundle, PkiService};
pub use store::{LoadedPair, PkiFiles};
pub use verify::PkiClientVerifier;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairState {
    Waiting,
    Connected,
    Revoked,
    Expired,
}

impl PairState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Connected => "connected",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CredentialRecord {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub server_name: String,
    pub ca_fingerprint_sha256: String,
    pub server_fingerprint_sha256: String,
    pub client_fingerprint_sha256: String,
    pub serial: String,
    pub status: String,
    pub created_at: i64,
    pub created_by: String,
    pub downloaded_at: Option<i64>,
    pub last_connected_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub client_not_after: i64,
}

#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub record: CredentialRecord,
    pub download_url: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PkiStatus {
    pub enabled: bool,
    pub credentials: usize,
    pub tunnel_ready: bool,
    pub waiting_for_credentials: bool,
}

#[derive(Debug)]
pub struct ServerIdentity {
    pub pair_id: String,
    pub server_name: String,
    pub cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
    pub key: rustls::pki_types::PrivateKeyDer<'static>,
    pub ca_cert: rustls::pki_types::CertificateDer<'static>,
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

/// Runtime TLS state shared by the QUIC listener, the verifier, and admin handlers.
#[derive(Clone, Default)]
pub struct PkiRuntime {
    pub resolver: Arc<PkiServerCerts>,
    pub verifier: Arc<PkiClientVerifier>,
    pub pairs_by_server: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
}

impl PkiRuntime {
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, PkiError> {
        use rustls::server::danger::ClientCertVerifier;
        let verifier: Arc<dyn ClientCertVerifier> = self.verifier.clone();
        let mut config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(self.resolver.clone());
        config.alpn_protocols = vec![proto::ALPN.to_vec()];
        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests;
