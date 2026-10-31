//! QUIC endpoint accept loop and admission of new agent connections.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::metrics::Metrics;
use crate::registry::Registry;
use crate::shutdown::{self, ShutdownPhase};
use crate::task_scope::TaskScope;

use super::connection::handle_conn;
use super::registration::RegistrationPolicy;

pub async fn await_accepting(metrics: &Metrics, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while metrics.quic_accepting() == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    metrics.quic_accepting() == 1
}

#[allow(clippy::too_many_arguments)]
pub async fn accept_loop(
    mut server: s2n_quic::Server,
    registry: Registry,
    metrics: Metrics,
    policy: RegistrationPolicy,
    stream_ceiling: u32,
    evict_close_grace: Duration,
    mut shutdown: watch::Receiver<ShutdownPhase>,
    pki: Option<Arc<crate::pki::PkiService>>,
) {
    let _accepting = metrics.mark_accepting();
    let connections = TaskScope::new("quic-connections");
    loop {
        connections.reap();
        let accepted = tokio::select! {
            _ = shutdown::wait_closed(&mut shutdown) => {
                debug!("the gateway is gone; the tunnel entry stops accepting new agents");
                return;
            }
            accepted = server.accept() => accepted,
        };
        let Some(conn) = accepted else {
            break;
        };
        if let (Some(pki), Ok(Some(name))) = (pki.as_ref(), conn.server_name()) {
            if let Err(e) = pki.mark_connected(&name) {
                warn!(error = %e, "cannot mark PKI pair connected");
            }
        }
        let registry = registry.clone();
        let metrics = metrics.clone();
        let policy = policy.clone();
        let mut conn_shutdown = shutdown.clone();

        let remote = match conn.remote_addr() {
            Ok(remote) => remote,
            Err(e) => {
                debug!(%e, "connection closed before remote_addr; skipping");
                continue;
            }
        };
        info!(%remote, "edge connected");

        connections.spawn(async move {
            let _connection = metrics.mark_agent_connected();
            let handle = async move {
                if let Err(e) =
                    handle_conn(conn, registry, policy, stream_ceiling, evict_close_grace).await
                {
                    warn!("agent connection error: {e}");
                }
            };
            tokio::select! {
                _ = shutdown::wait_closed(&mut conn_shutdown) => {
                    debug!(%remote, "gateway dropped; closing an agent connection");
                }
                _ = handle => {}
            }
        });
    }

    error!(
        "QUIC 隧道入口已停止接受连接（端点被关闭或 UDP 驱动已失效）：已有 agent 连接不受影响，\
         但新的 edge 节点将无法接入，需要重启网关；hlmg_quic_accepting=0 可用于告警"
    );
}
