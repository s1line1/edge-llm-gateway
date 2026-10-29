//! SNI-based server certificate resolver. Empty is a valid, fail-closed state.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

#[derive(Default)]
pub struct PkiServerCerts {
    certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for PkiServerCerts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiServerCerts")
            .field("count", &self.len())
            .finish()
    }
}

impl PkiServerCerts {
    pub fn insert(&self, server_name: &str, key: Arc<CertifiedKey>) {
        self.certs
            .write()
            .expect("pki resolver lock poisoned")
            .insert(server_name.to_ascii_lowercase(), key);
    }

    pub fn remove(&self, server_name: &str) {
        self.certs
            .write()
            .expect("pki resolver lock poisoned")
            .remove(&server_name.to_ascii_lowercase());
    }

    pub fn contains(&self, server_name: &str) -> bool {
        self.certs
            .read()
            .expect("pki resolver lock poisoned")
            .contains_key(&server_name.to_ascii_lowercase())
    }

    pub fn len(&self) -> usize {
        self.certs.read().expect("pki resolver lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ResolvesServerCert for PkiServerCerts {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?;
        self.certs
            .read()
            .expect("pki resolver lock poisoned")
            .get(&name.to_ascii_lowercase())
            .cloned()
    }
}
