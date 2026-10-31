//! Admin HTTP resources. The root `admin` module remains a compatibility re-export.

mod agents;
mod keys;
mod shared;
mod tenants;
mod usage;
pub mod users;

pub use agents::{list_agents, AgentQuery};
pub use keys::{create_key, delete_key, list_keys, list_keys_filtered, TenantFilter};
pub use tenants::{
    create_tenant, delete_tenant, list_tenants, rotate_agent_token, tenant_by_id, update_tenant,
};
pub use usage::{usage_filtered, usage_route};
pub use users::{create_user, delete_user, list_audit, list_users, update_user};
