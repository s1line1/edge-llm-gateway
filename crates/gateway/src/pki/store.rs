//! Secure, atomically written pair directory. Opening the store never creates a certificate.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    sign::CertifiedKey,
};

use super::{GeneratedPair, PkiError};

#[derive(Debug, Clone)]
pub struct PkiFiles {
    dir: PathBuf,
}

#[derive(Debug)]
pub struct LoadedPair {
    pub id: String,
    pub server_name: String,
    pub ca_cert: CertificateDer<'static>,
    pub server_chain: Vec<CertificateDer<'static>>,
    pub server_key: PrivateKeyDer<'static>,
    pub ca_cert_pem: Vec<u8>,
    pub client_cert_pem: Vec<u8>,
}

impl PkiFiles {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn pair_dir(&self, id: &str) -> PathBuf {
        self.dir.join("pairs").join(id)
    }

    pub fn client_key_path(&self, id: &str) -> PathBuf {
        self.pair_dir(id).join("client.key")
    }

    pub fn write_pair(&self, pair: &GeneratedPair) -> Result<(), PkiError> {
        let dir = self.pair_dir(&pair.id);
        create_secure_dir(&self.dir)?;
        create_secure_dir(&self.dir.join("pairs"))?;
        create_secure_dir(&dir)?;
        let files = [
            ("ca.crt", pair.ca_cert_pem.as_bytes()),
            ("ca.key", pair.ca_key_pem.as_bytes()),
            ("server.crt", pair.server_cert_pem.as_bytes()),
            ("server.key", pair.server_key_pem.as_bytes()),
            ("client.crt", pair.client_cert_pem.as_bytes()),
            ("client.key", pair.client_key_pem.as_bytes()),
        ];
        for (name, contents) in files {
            if let Err(e) = atomic_write(&dir.join(name), contents) {
                let _ = fs::remove_dir_all(&dir);
                return Err(e);
            }
        }
        Ok(())
    }

    pub fn load_pair(&self, id: &str, server_name: &str) -> Result<LoadedPair, PkiError> {
        let dir = self.pair_dir(id);
        let ca_cert_pem = read_secure(&dir.join("ca.crt"))?;
        let server_cert_pem = read_secure(&dir.join("server.crt"))?;
        let server_key_pem = read_secure(&dir.join("server.key"))?;
        let client_cert_pem = read_secure(&dir.join("client.crt"))?;
        let ca_certs = parse_certs(&ca_cert_pem)?;
        let server_chain = parse_certs(&server_cert_pem)?;
        let ca_cert = ca_certs
            .into_iter()
            .next()
            .ok_or_else(|| PkiError::Invalid(format!("pair {id}: empty ca.crt")))?;
        let server_key = parse_key(&server_key_pem)?;
        Ok(LoadedPair {
            id: id.to_string(),
            server_name: server_name.to_string(),
            ca_cert,
            server_chain,
            server_key,
            ca_cert_pem,
            client_cert_pem,
        })
    }

    pub fn load_client_key(&self, id: &str) -> Result<Vec<u8>, PkiError> {
        let path = self.client_key_path(id);
        if !path.exists() {
            return Err(PkiError::DownloadConsumed);
        }
        read_secure(&path)
    }

    pub fn remove_client_key(&self, id: &str) -> Result<(), PkiError> {
        let path = self.client_key_path(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(PkiError::Io(e)),
        }
    }

    pub fn remove_pair(&self, id: &str) {
        let _ = fs::remove_dir_all(self.pair_dir(id));
    }
}

impl LoadedPair {
    pub fn certified_key(&self) -> Result<CertifiedKey, PkiError> {
        let key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&self.server_key)
            .map_err(|e| PkiError::Invalid(format!("pair {}: server key: {e}", self.id)))?;
        let mut chain = self.server_chain.clone();
        // Include the pair CA in the served chain where present; clients also have it in their
        // bundle, so a missing intermediate is not fatal.
        if !chain.iter().any(|c| c.as_ref() == self.ca_cert.as_ref()) {
            chain.push(self.ca_cert.clone());
        }
        Ok(CertifiedKey::new(chain, key))
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

fn parse_certs(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, PkiError> {
    let mut cursor = std::io::Cursor::new(pem);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PkiError::Invalid(format!("certificate PEM: {e}")))
}

fn parse_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, PkiError> {
    let mut cursor = std::io::Cursor::new(pem);
    rustls_pemfile::private_key(&mut cursor)
        .map_err(|e| PkiError::Invalid(format!("private key PEM: {e}")))?
        .ok_or_else(|| PkiError::Invalid("private key PEM is empty".into()))
}

fn create_secure_dir(path: &Path) -> Result<(), PkiError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(PkiError::Invalid(format!(
                "refusing symlinked PKI path {}",
                path.display()
            )));
        }
        if !meta.is_dir() {
            return Err(PkiError::Invalid(format!(
                "PKI path is not a directory: {}",
                path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(path)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), PkiError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(PkiError::Invalid(format!(
                "refusing symlinked PKI file {}",
                path.display()
            )));
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| PkiError::Invalid("PKI path has no parent".into()))?;
    let tmp = parent.join(format!(
        ".tmp-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| -> Result<(), PkiError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_secure(path: &Path) -> Result<Vec<u8>, PkiError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(PkiError::Invalid(format!(
                "refusing symlinked PKI file {}",
                path.display()
            )));
        }
    }
    fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            PkiError::Storage(format!("missing PKI file {}", path.display()))
        } else {
            PkiError::Io(e)
        }
    })
}
