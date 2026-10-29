//! Generate a complete credential pair. This file is never called from startup.

use std::collections::BTreeSet;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use super::{PkiConfig, PkiError};

#[derive(Debug)]
pub struct GeneratedPair {
    pub id: String,
    pub name: String,
    pub tenant_id: String,
    pub server_name: String,
    pub serial: String,
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub ca_fingerprint_sha256: String,
    pub server_fingerprint_sha256: String,
    pub client_fingerprint_sha256: String,
    pub not_before: i64,
    pub client_not_after: i64,
    pub server_not_after: i64,
}

fn fingerprint(cert: &rcgen::Certificate) -> String {
    let digest = Sha256::digest(cert.der());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn validity(days: u32) -> (OffsetDateTime, OffsetDateTime) {
    let now = OffsetDateTime::now_utc();
    let not_before = now - Duration::hours(1);
    let not_after = now + Duration::days(i64::from(days));
    (not_before, not_after)
}

fn common_name(params: &mut CertificateParams, value: &str) {
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, value);
}

pub fn generate_pair(
    config: &PkiConfig,
    id: &str,
    name: &str,
    tenant_id: &str,
    server_name: &str,
    server_sans: &[String],
    ca_common_name: &str,
) -> Result<GeneratedPair, PkiError> {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generate(e.to_string()))?;
    let (ca_not_before, ca_not_after) = validity(3650);
    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| PkiError::Generate(e.to_string()))?;
    common_name(&mut ca_params, ca_common_name);
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = ca_not_before;
    ca_params.not_after = ca_not_after;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| PkiError::Generate(e.to_string()))?;

    let serial_bytes: [u8; 16] = rand::random();
    let serial = serial_bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<String>();

    let mut sans = BTreeSet::new();
    sans.insert(server_name.to_string());
    for san in server_sans {
        let trimmed = san.trim();
        if !trimmed.is_empty() {
            sans.insert(trimmed.to_string());
        }
    }
    let (server_not_before, server_not_after) = validity(config.server_validity_days);
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generate(e.to_string()))?;
    let mut server_params = CertificateParams::new(sans.into_iter().collect::<Vec<_>>())
        .map_err(|e| PkiError::Generate(e.to_string()))?;
    common_name(&mut server_params, server_name);
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.serial_number = Some(SerialNumber::from_slice(&serial_bytes));
    server_params.not_before = server_not_before;
    server_params.not_after = server_not_after;
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(|e| PkiError::Generate(e.to_string()))?;

    let (client_not_before, client_not_after) = validity(config.client_validity_days);
    let client_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| PkiError::Generate(e.to_string()))?;
    let mut client_params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| PkiError::Generate(e.to_string()))?;
    common_name(
        &mut client_params,
        &format!("hlmg-client:{tenant_id}:{name}"),
    );
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.serial_number = Some(SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    client_params.not_before = client_not_before;
    client_params.not_after = client_not_after;
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .map_err(|e| PkiError::Generate(e.to_string()))?;

    Ok(GeneratedPair {
        id: id.to_string(),
        name: name.to_string(),
        tenant_id: tenant_id.to_string(),
        server_name: server_name.to_string(),
        serial,
        ca_cert_pem: ca_cert.pem(),
        ca_key_pem: ca_key.serialize_pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
        ca_fingerprint_sha256: fingerprint(&ca_cert),
        server_fingerprint_sha256: fingerprint(&server_cert),
        client_fingerprint_sha256: fingerprint(&client_cert),
        not_before: client_not_before.unix_timestamp(),
        client_not_after: client_not_after.unix_timestamp(),
        server_not_after: server_not_after.unix_timestamp(),
    })
}
