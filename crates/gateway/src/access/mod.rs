//! Access domain: API-key authentication, dashboard sessions, RBAC, and limiters.
//!
//! The root `auth` and `rbac` paths remain module aliases so existing public imports keep
//! working; `console_auth` is the session middleware and the role guards are explicit namespace helpers, not a root module.

pub mod api_key;
pub mod limits;
pub mod rbac;
pub mod session;
