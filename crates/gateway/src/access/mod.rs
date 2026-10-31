//! Access domain: API-key authentication, dashboard sessions, RBAC, and limiters.
//!
//! The root `auth` and `rbac` paths remain module aliases so existing public imports keep
//! working; `admin_auth` is now only the session middleware function, not a root module.

pub mod api_key;
pub mod limits;
pub mod rbac;
pub mod session;
