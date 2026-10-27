//! 测试用 PKI：一套 CA + 服务端 + 客户端身份，PEM 形态。
//!
//! 原先 `e2e/common/pki.rs`、`agent/src/tests/mod.rs`、`agent/src/main.rs`、
//! `agent/src/config.rs`、`agent/tests/sighup.rs` 各有一份 rcgen 脚手架，且已经
//! 漂移过（CA 的 key_usages 一处 3 项、一处 2 项）。这里只保留一份。

use std::net::{IpAddr, Ipv4Addr};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// 一套测试证书的 PEM 文本。
pub struct PemCerts {
    pub ca: String,
    pub server_cert: String,
    pub server_key: String,
    pub client_cert: String,
    pub client_key: String,
}

/// 生成一套新的测试 PKI。
///
/// CA 的用途取**并集**（KeyCertSign/CrlSign/DigitalSignature）；服务端 SAN 同时覆盖
/// `localhost` 与 `127.0.0.1`，这样 `with_server_name("localhost")` 和 IP 直连都能握手。
pub fn generate() -> PemCerts {
    let ca_key = KeyPair::generate().expect("generate CA key");
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-sign CA");

    let server_key = KeyPair::generate().expect("generate server key");
    let mut server = CertificateParams::default();
    server
        .distinguished_name
        .push(DnType::CommonName, "gateway");
    server.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().expect("valid DNS name")),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    server.is_ca = IsCa::NoCa;
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let server_cert = server
        .signed_by(&server_key, &ca_cert, &ca_key)
        .expect("sign server cert");

    let client_key = KeyPair::generate().expect("generate client key");
    let mut client = CertificateParams::default();
    client
        .distinguished_name
        .push(DnType::CommonName, "test-agent");
    client.is_ca = IsCa::NoCa;
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_cert = client
        .signed_by(&client_key, &ca_cert, &ca_key)
        .expect("sign client cert");

    PemCerts {
        ca: ca_cert.pem(),
        server_cert: server_cert.pem(),
        server_key: server_key.serialize_pem(),
        client_cert: client_cert.pem(),
        client_key: client_key.serialize_pem(),
    }
}

/// 在 `dir` 下写 `ca.crt` / `client.crt` / `client.key` 三个文件并返回路径。
///
/// agent 的配置测试与 `sighup` 进程测试只需要"一份能装进去的客户端身份"；原先三处各抄
/// 一遍这段 rcgen + 写文件。注意这里生成的是**整套** PKI，服务端材料不写盘。
pub fn write_cert_files(
    dir: &std::path::Path,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let pki = generate();
    let write = |name: &str, content: &str| {
        let path = dir.join(name);
        std::fs::write(&path, content).expect("write test certificate");
        path
    };
    (
        write("ca.crt", &pki.ca),
        write("client.crt", &pki.client_cert),
        write("client.key", &pki.client_key),
    )
}

/// 解析 PEM 证书链。
pub fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse PEM certificates")
}

/// 解析 PEM 私钥。
pub fn parse_key(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))
        .expect("parse PEM private key")
        .expect("PEM contains a private key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_material_parses_back() {
        let pki = generate();
        assert_eq!(parse_certs(&pki.ca).len(), 1);
        assert_eq!(parse_certs(&pki.server_cert).len(), 1);
        assert_eq!(parse_certs(&pki.client_cert).len(), 1);
        let _ = parse_key(&pki.server_key);
        let _ = parse_key(&pki.client_key);
    }
}
