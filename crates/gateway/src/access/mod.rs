//! Access domain: API-key authentication, dashboard sessions, RBAC, and limiters.
//!
//! The root `auth`, `rbac`, and `admin_auth` modules remain compatibility re-exports so
//! existing handler paths and public imports keep working while callers migrate.

pub mod api_key;
pub mod limits;
pub mod rbac;
pub mod session;
