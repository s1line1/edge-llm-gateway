//! Per-connection lifetime and control-stream accept loop.

use tracing::warn;

use crate::registry::{Registration, Registry};

use super::protocol::{handle_control_stream, ControlFlow};
use super::registration::RegistrationPolicy;

pub(crate) async fn handle_conn(
    conn: s2n_quic::Connection,
    registry: Registry,
    policy: RegistrationPolicy,
    stream_ceiling: u32,
    evict_close_grace: std::time::Duration,
) -> anyhow::Result<()> {
    let (handle, mut acceptor) = conn.split();
    let mut registration = Registration::new(&registry);
    handle_conn_inner(
        &handle,
        &mut acceptor,
        &registry,
        &mut registration,
        &policy,
        stream_ceiling,
        evict_close_grace,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_conn_inner(
    handle: &s2n_quic::connection::Handle,
    acceptor: &mut s2n_quic::connection::StreamAcceptor,
    registry: &Registry,
    registration: &mut Registration<'_>,
    policy: &RegistrationPolicy,
    stream_ceiling: u32,
    evict_close_grace: std::time::Duration,
) -> anyhow::Result<()> {
    // Source IP is a connection property, not a frame self-report. If it cannot be read,
    // the registration would have no trustworthy identity, so close instead of routing it.
    let peer_ip = match handle.remote_addr() {
        Ok(addr) => crate::registry::normalize_socket_addr(addr),
        Err(e) => {
            warn!(error = %e, "cannot read the peer address; closing the connection");
            handle.close(0u32.into());
            return Ok(());
        }
    };

    loop {
        match acceptor.accept_bidirectional_stream().await {
            Ok(Some(stream)) => {
                let (recv, send) = stream.split();
                match handle_control_stream(
                    handle,
                    recv,
                    send,
                    registry,
                    registration,
                    policy,
                    peer_ip,
                    stream_ceiling,
                    evict_close_grace,
                )
                .await?
                {
                    ControlFlow::Continue => {}
                    ControlFlow::CloseConnection => return Ok(()),
                }
            }
            Ok(None) => return Ok(()),
            Err(e) => {
                warn!("accept stream failed: {e}");
                return Ok(());
            }
        }
    }
}
