//! e2e 的证书工厂与 `TestCerts`（CA + 服务端 DER/PEM + 客户端身份）。

use super::*;

/// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥) 的 DER 形态。
///
/// 与 [`gen_certs_pem`] 是**同一套**material，只是编码不同：这里转成 DER，
/// 以前它是一份独立的 60 行复制品（两份只差 CA 的 key_usages，见下）。
pub fn gen_certs() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let (ca, srv, srv_key, cli, cli_key) = gen_certs_pem();
    (
        parse_certs_pem(&ca).remove(0),
        parse_certs_pem(&srv).remove(0),
        parse_key_pem(&srv_key),
        parse_certs_pem(&cli).remove(0),
        parse_key_pem(&cli_key),
    )
}

/// 生成同一套证书的 PEM 文本（HTTPS 公网入口需要 PEM 字节）。
pub fn gen_certs_pem() -> (String, String, String, String, String) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "e2e CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    // CA 的用途取并集：DER 路径原先多一项 DigitalSignature，PEM 路径没有。
    // 合并成一份之后按**更宽**的那个来——给 CA 加用途不会让原本通过的握手失败。
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let server_key = KeyPair::generate().unwrap();
    let mut srv = CertificateParams::default();
    srv.distinguished_name.push(DnType::CommonName, "gateway");
    srv.subject_alt_names = vec![
        SanType::DnsName("localhost".try_into().unwrap()),
        SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ];
    srv.is_ca = IsCa::NoCa;
    srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    srv.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let server_cert = srv.signed_by(&server_key, &ca_cert, &ca_key).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut cli = CertificateParams::default();
    cli.distinguished_name
        .push(DnType::CommonName, "test-agent");
    cli.is_ca = IsCa::NoCa;
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let client_cert = cli.signed_by(&client_key, &ca_cert, &ca_key).unwrap();

    (
        ca_cert.pem(),
        server_cert.pem(),
        server_key.serialize_pem(),
        client_cert.pem(),
        client_key.serialize_pem(),
    )
}

pub fn parse_certs_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    rustls_pemfile::certs(&mut std::io::Cursor::new(pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

pub fn parse_key_pem(pem: &str) -> PrivateKeyDer<'static> {
    rustls_pemfile::private_key(&mut std::io::Cursor::new(pem.as_bytes()))
        .unwrap()
        .unwrap()
}

/// 一套测试用证书材料：CA + 一份 agent 客户端身份 + 服务端身份的两种编码形态。
///
/// 由 [`start_gateway`] 产出。多 agent 场景复用它给每个 agent 签身份（客户端私钥用
/// `clone_key()`，每个 agent 各拿一份）。HTTPS 公网入口要的是 **PEM 字节**而隧道侧要 DER，
/// 所以两种形态都在这里——省得各用例自己再跑一遍 `gen_certs_pem()` 并手工 parse。
pub struct TestCerts {
    pub ca: Vec<CertificateDer<'static>>,
    pub client_cert: Vec<CertificateDer<'static>>,
    pub client_key: PrivateKeyDer<'static>,
    /// 服务端身份（DER）：隧道侧 `TunnelTls` 用。
    server_cert_der: Vec<CertificateDer<'static>>,
    server_key_der: PrivateKeyDer<'static>,
    /// 服务端身份（PEM 字节）：HTTPS 公网入口用。
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
}

impl TestCerts {
    /// 新生成一套测试证书（CA + 服务端 DER/PEM + 客户端）。要**先看配置再决定是否启动**的
    /// 用例（例如断言零值旋钮在启动前失败）需要它。
    pub fn generate() -> Self {
        let (ca_pem, srv_pem, srv_key_pem, cli_pem, cli_key_pem) = gen_certs_pem();
        Self {
            ca: parse_certs_pem(&ca_pem),
            client_cert: parse_certs_pem(&cli_pem),
            client_key: parse_key_pem(&cli_key_pem),
            server_cert_der: parse_certs_pem(&srv_pem),
            server_key_der: parse_key_pem(&srv_key_pem),
            server_cert_pem: srv_pem.into_bytes(),
            server_key_pem: srv_key_pem.into_bytes(),
        }
    }

    /// 起一个 agent 接到 `gw`，上游是 `upstream` 上的 mock-llm。
    pub fn agent(
        &self,
        gw: &Gateway,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
        request_log: bool,
    ) -> Agent {
        Agent::start(AgentConfig {
            cloud_addr: gw.quic_addr,
            server_name: "localhost".into(),
            ca_cert: self.ca.clone(),
            client_cert: self.client_cert.clone(),
            client_key: self.client_key.clone_key(),
            agent_id: agent_id.into(),
            models: models.iter().map(|m| (*m).to_string()).collect(),
            max_concurrency,
            upstream_base: format!("http://{upstream}"),
            heartbeat_interval: Duration::from_millis(200),
            request_log,
        })
        .unwrap()
    }

    /// 公网入口的 HTTPS 材料（PEM 字节，见 [`gateway::TlsPem`]）。
    ///
    /// 放进 `Options::https` 即可让入口走 TLS——但材料要**生成之后**才知道，所以那种用例得用
    /// [`start_gateway_with`]，它的 `tune` 能拿到 `&TestCerts`。
    pub fn https_pem(&self) -> TlsPem {
        TlsPem {
            cert: self.server_cert_pem.clone(),
            key: self.server_key_pem.clone(),
        }
    }

    /// 隧道侧的 mTLS 身份材料。字段保持私有，由这里唯一地组装成已校验的 [`TunnelTls`]；
    /// `stack::gateway_config` 不再直接读 `server_cert_der` / `server_key_der`。
    pub fn tunnel_tls(&self) -> TunnelTls {
        TunnelTls::from_der(
            self.ca.clone(),
            self.server_cert_der.clone(),
            self.server_key_der.clone_key(),
        )
        .expect("e2e certs are non-empty")
    }
}
