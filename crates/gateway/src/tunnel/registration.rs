//! Registration policy and registry insertion. No persistence or TLS types belong here.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use crate::registry::{Registration, Registry};

/// The application-level tenant-token verification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RegistrationError {
    Rejected(String),
}

impl fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(reason) => f.write_str(reason),
        }
    }
}

type TenantVerifier = Arc<dyn Fn(&str, &str) -> Result<(), RegistrationError> + Send + Sync>;

/// Configuration and tenant verification for the tunnel control plane.
///
/// The verifier is supplied by the composition root, so this module does not know `Storage`.
#[derive(Clone)]
pub struct RegistrationPolicy {
    allow_legacy: bool,
    verify_tenant: TenantVerifier,
}

impl RegistrationPolicy {
    pub(crate) fn new(allow_legacy: bool, verify_tenant: TenantVerifier) -> Self {
        Self {
            allow_legacy,
            verify_tenant,
        }
    }

    pub(crate) fn allow_legacy(&self) -> bool {
        self.allow_legacy
    }

    pub(crate) fn verify_tenant(
        &self,
        tenant_id: &str,
        token: &str,
    ) -> Result<(), RegistrationError> {
        (self.verify_tenant)(tenant_id, token)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn register_agent(
    registry: &Registry,
    registration: &mut Registration<'_>,
    handle: &s2n_quic::connection::Handle,
    mut send: s2n_quic::stream::SendStream,
    tenant_id: &str,
    id: String,
    models: Vec<String>,
    max_concurrency: u32,
    peer_ip: IpAddr,
    stream_ceiling: u32,
    evict_close_grace: std::time::Duration,
) {
    if max_concurrency > stream_ceiling {
        tracing::warn!(
            agent = %id,
            max_concurrency,
            stream_ceiling,
            "agent declares more concurrency than the gateway's per-connection stream ceiling; \
             raise max_open_tunnel_streams (gateway) or lower max_concurrency (agent), \
             otherwise tunnel opens will queue and time out before capacity is reached"
        );
    }
    if !registration.accepts_for_tenant(tenant_id, &id, peer_ip) {
        tracing::warn!(
            agent = %id,
            tenant = %tenant_id,
            limit = crate::registry::MAX_REGISTRATIONS_PER_CONNECTION,
            "connection tried to register agents for a different tenant or exceeded the per-connection cap; closing it"
        );
        let _ = send.finish();
        handle.close(0u32.into());
        return;
    }
    let stable_id = registry.register_with_grace_in_tenant(
        tenant_id,
        id.clone(),
        peer_ip,
        models,
        max_concurrency,
        handle.clone(),
        evict_close_grace,
        None,
    );
    registration.note_for_tenant(tenant_id, id.clone(), peer_ip, stable_id);
    let _ = send.finish();
    tracing::info!(agent = %id, tenant = %tenant_id, ip = %peer_ip, "agent registered");
}
