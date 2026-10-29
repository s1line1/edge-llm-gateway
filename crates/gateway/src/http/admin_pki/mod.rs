//! On-demand credential-pair admin API.

mod download;
mod dto;
mod errors;
mod handlers;

pub(crate) use download::download;
pub(crate) use handlers::{create, list, revoke, status};
