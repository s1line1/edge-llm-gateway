//! Online agent admin resource.

use axum::{
    extract::{Extension, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;

use crate::{
    rbac::{authorize, effective_tenant, response as rbac_response, Action, Principal},
    state::AdminRuntime,
};

/// 列出在线 agent 明细（注册表快照，按 agent_id 排序）。
#[derive(Debug, Deserialize)]
pub struct AgentQuery {
    pub(crate) tenant_id: Option<String>,
}

pub async fn list_agents(
    State(state): State<AdminRuntime>,
    Extension(principal): Extension<Principal>,
    Query(query): Query<AgentQuery>,
) -> Response {
    if let Err(e) = authorize(&principal, Action::AgentRead, query.tenant_id.as_deref()) {
        return rbac_response(e);
    }
    let tenant = match effective_tenant(&principal, query.tenant_id.as_deref()) {
        Ok(t) => t,
        Err(e) => return rbac_response(e),
    };
    let mut agents = state.registry.snapshot(state.policy.agent_stale_after);
    if let Some(tenant_id) = tenant {
        agents.retain(|a| a.tenant_id == tenant_id);
    }
    Json(agents).into_response()
}
