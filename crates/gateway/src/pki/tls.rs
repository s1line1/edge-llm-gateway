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
// Dynamic client certificate verification + fingerprint revocation.

use std::collections::HashSet;

use rustls::{
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        WebPkiClientVerifier,
    },
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore,
    SignatureScheme,
};

use super::{fingerprint_hex, PkiError};

#[derive(Default)]
pub struct PkiClientVerifier {
    inner: RwLock<Option<Arc<dyn ClientCertVerifier>>>,
    roots: RwLock<Vec<CertificateDer<'static>>>,
    revoked: RwLock<HashSet<String>>,
}

impl std::fmt::Debug for PkiClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PkiClientVerifier")
            .field("roots", &self.roots.read().map(|r| r.len()).unwrap_or(0))
            .field(
                "revoked",
                &self.revoked.read().map(|r| r.len()).unwrap_or(0),
            )
            .finish()
    }
}

fn rebuild(
    roots: &[CertificateDer<'static>],
) -> Result<Option<Arc<dyn ClientCertVerifier>>, PkiError> {
    if roots.is_empty() {
        return Ok(None);
    }
    let mut store = RootCertStore::empty();
    for cert in roots {
        store
            .add(cert.clone())
            .map_err(|e| PkiError::Invalid(format!("invalid client CA: {e}")))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(store))
        .build()
        .map_err(|e| PkiError::Invalid(format!("client verifier: {e}")))?;
    Ok(Some(verifier as Arc<dyn ClientCertVerifier>))
}

impl PkiClientVerifier {
    pub fn add_ca(&self, cert: CertificateDer<'static>) -> Result<(), PkiError> {
        let fp = fingerprint_hex(&cert);
        {
            let mut roots = self.roots.write().expect("pki roots lock poisoned");
            if roots.iter().any(|c| fingerprint_hex(c) == fp) {
                return Ok(());
            }
            roots.push(cert);
        }
        let rebuilt = {
            let roots = self.roots.read().expect("pki roots lock poisoned");
            rebuild(&roots)?
        };
        *self.inner.write().expect("pki verifier lock poisoned") = rebuilt;
        Ok(())
    }

    pub fn remove_ca(&self, cert: &CertificateDer<'static>) -> Result<(), PkiError> {
        let fp = fingerprint_hex(cert);
        self.roots
            .write()
            .expect("pki roots lock poisoned")
            .retain(|c| fingerprint_hex(c) != fp);
        let rebuilt = {
            let roots = self.roots.read().expect("pki roots lock poisoned");
            rebuild(&roots)?
        };
        *self.inner.write().expect("pki verifier lock poisoned") = rebuilt;
        Ok(())
    }

    pub fn revoke(&self, cert: &CertificateDer<'_>) {
        self.revoked
            .write()
            .expect("pki revocation lock poisoned")
            .insert(fingerprint_hex(cert));
    }

    pub fn is_revoked(&self, cert: &CertificateDer<'_>) -> bool {
        self.revoked
            .read()
            .expect("pki revocation lock poisoned")
            .contains(&fingerprint_hex(cert))
    }

    fn inner(&self) -> Option<Arc<dyn ClientCertVerifier>> {
        self.inner
            .read()
            .expect("pki verifier lock poisoned")
            .clone()
    }
}

fn fail_closed() -> TlsError {
    TlsError::InvalidCertificate(CertificateError::UnknownIssuer)
}

impl ClientCertVerifier for PkiClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // Hints are optional; the client must still present its certificate.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        if self.is_revoked(end_entity) {
            return Err(TlsError::InvalidCertificate(CertificateError::Revoked));
        }
        let inner = self.inner().ok_or_else(fail_closed)?;
        inner.verify_client_cert(end_entity, intermediates, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let inner = self.inner().ok_or_else(fail_closed)?;
        inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        let inner = self.inner().ok_or_else(fail_closed)?;
        inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner()
            .map(|inner| inner.supported_verify_schemes())
            .unwrap_or_default()
    }
}

/// Runtime TLS state shared by the QUIC listener, the verifier, and admin handlers.
#[derive(Clone, Default)]
pub struct PkiRuntime {
    resolver: Arc<PkiServerCerts>,
    verifier: Arc<PkiClientVerifier>,
    pairs_by_server: Arc<std::sync::RwLock<std::collections::HashMap<String, String>>>,
}

impl PkiRuntime {
    pub(crate) fn add_pair(
        &self,
        server_name: &str,
        pair_id: &str,
        key: rustls::sign::CertifiedKey,
        ca: rustls::pki_types::CertificateDer<'static>,
    ) -> Result<(), PkiError> {
        self.verifier.add_ca(ca)?;
        self.resolver.insert(server_name, Arc::new(key));
        self.pairs_by_server
            .write()
            .expect("pki pair map lock poisoned")
            .insert(server_name.to_ascii_lowercase(), pair_id.to_string());
        Ok(())
    }

    pub(crate) fn remove_pair(
        &self,
        server_name: &str,
        ca: &rustls::pki_types::CertificateDer<'static>,
        client_cert: &rustls::pki_types::CertificateDer<'_>,
    ) -> Result<(), PkiError> {
        self.resolver.remove(server_name);
        self.verifier.remove_ca(ca)?;
        self.verifier.revoke(client_cert);
        self.pairs_by_server
            .write()
            .expect("pki pair map lock poisoned")
            .remove(&server_name.to_ascii_lowercase());
        Ok(())
    }

    pub(crate) fn tunnel_ready(&self) -> bool {
        !self.resolver.is_empty()
    }

    pub(crate) fn has_server(&self, server_name: &str) -> bool {
        self.resolver.contains(server_name)
    }

    pub(crate) fn pair_id_for_server(&self, server_name: &str) -> Option<String> {
        self.pairs_by_server
            .read()
            .expect("pki pair map lock poisoned")
            .get(&server_name.to_ascii_lowercase())
            .cloned()
    }

    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, PkiError> {
        use rustls::server::danger::ClientCertVerifier;
        let verifier: Arc<dyn ClientCertVerifier> = self.verifier.clone();
        let mut config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_cert_resolver(self.resolver.clone());
        config.alpn_protocols = vec![proto::ALPN.to_vec()];
        Ok(Arc::new(config))
    }
}
