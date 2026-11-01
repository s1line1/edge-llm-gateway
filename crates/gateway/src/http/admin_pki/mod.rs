//! On-demand credential-pair admin API.

mod download;
mod dto;
mod errors;
mod handlers;

#[derive(Clone, Copy, Debug)]
pub(crate) enum PkiScope {
    Admin,
    System,
}

impl PkiScope {
    pub(crate) fn download_url(self, id: &str) -> String {
        let base = match self {
            Self::Admin => "/admin",
            Self::System => "/system",
        };
        format!("{base}/pki/pairs/{id}/download")
    }
}

pub(crate) use download::download;
pub(crate) use handlers::{create, list, revoke, status};
