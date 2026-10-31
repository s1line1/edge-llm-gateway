//! First-frame protocol dispatch for a tunnel control stream.

use std::net::IpAddr;

use proto::{io::FrameReader, Frame};
use tracing::{debug, warn};

use crate::registry::{Registration, Registry};

use super::registration::{register_agent, RegistrationPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlFlow {
    Continue,
    CloseConnection,
}

/// Handle exactly one control frame. The caller owns the accept loop and stream lifetime.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_control_stream(
    handle: &s2n_quic::connection::Handle,
    recv: s2n_quic::stream::ReceiveStream,
    mut send: s2n_quic::stream::SendStream,
    registry: &Registry,
    registration: &mut Registration<'_>,
    policy: &RegistrationPolicy,
    peer_ip: IpAddr,
    stream_ceiling: u32,
    evict_close_grace: std::time::Duration,
) -> anyhow::Result<ControlFlow> {
    let first = FrameReader::new(recv).next().await?;
    match first {
        Some(Frame::Register {
            agent_id: id,
            models,
            max_concurrency,
            ..
        }) => {
            if !policy.allow_legacy() {
                warn!(
                    agent = %id,
                    "legacy Register rejected: allow_legacy_agent_registration is false"
                );
                let _ = send.finish();
                handle.close(0u32.into());
                return Ok(ControlFlow::CloseConnection);
            }
            register_agent(
                registry,
                registration,
                handle,
                send,
                crate::tenant::DEFAULT_TENANT_ID,
                id,
                models,
                max_concurrency,
                peer_ip,
                stream_ceiling,
                evict_close_grace,
            );
            Ok(ControlFlow::Continue)
        }
        Some(Frame::RegisterWithTenant {
            agent_id: id,
            tenant_id,
            agent_token,
            models,
            max_concurrency,
            ..
        }) => match policy.verify_tenant(&tenant_id, &agent_token) {
            Ok(()) => {
                register_agent(
                    registry,
                    registration,
                    handle,
                    send,
                    &tenant_id,
                    id,
                    models,
                    max_concurrency,
                    peer_ip,
                    stream_ceiling,
                    evict_close_grace,
                );
                Ok(ControlFlow::Continue)
            }
            Err(e) => {
                warn!(
                    agent = %id,
                    tenant = %tenant_id,
                    error = %e,
                    "tenant agent registration rejected"
                );
                let _ = send.finish();
                handle.close(0u32.into());
                Ok(ControlFlow::CloseConnection)
            }
        },
        Some(Frame::Heartbeat {
            agent_id: id,
            inflight,
            ..
        }) => {
            match registration
                .tenant()
                .and_then(|tenant| registration.owned_stable_id_for_tenant(tenant, &id, peer_ip))
            {
                Some(stable_id) => {
                    let tenant = registration
                        .tenant()
                        .unwrap_or(crate::tenant::DEFAULT_TENANT_ID);
                    let _ = registry.heartbeat_if_same_for_tenant(tenant, &id, peer_ip, stable_id);
                    debug!(agent = %id, ip = %peer_ip, tenant = %tenant, inflight, "heartbeat");
                }
                None => warn!(
                    frame_agent = %id,
                    ip = %peer_ip,
                    "heartbeat names an agent this connection never registered; ignored"
                ),
            }
            let _ = send.finish();
            Ok(ControlFlow::Continue)
        }
        Some(other) => {
            warn!(frame = other.kind(), "unexpected frame on control stream");
            let _ = send.finish();
            Ok(ControlFlow::Continue)
        }
        None => {
            let _ = send.finish();
            Ok(ControlFlow::Continue)
        }
    }
}
