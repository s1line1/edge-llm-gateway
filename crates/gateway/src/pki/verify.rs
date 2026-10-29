//! Dynamic client certificate verification + fingerprint revocation.

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

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
