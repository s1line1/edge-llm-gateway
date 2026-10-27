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
///
/// 实际生成在 `test-support` 里（e2e / agent 测试共用一份）；这里只把字段摊平成元组，
/// 免得所有调用点都改成解构 `PemCerts`。
pub fn gen_certs_pem() -> (String, String, String, String, String) {
    let pki = test_support::pki::generate();
    (
        pki.ca,
        pki.server_cert,
        pki.server_key,
        pki.client_cert,
        pki.client_key,
    )
}

pub fn parse_certs_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    test_support::pki::parse_certs(pem)
}

pub fn parse_key_pem(pem: &str) -> PrivateKeyDer<'static> {
    test_support::pki::parse_key(pem)
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
        self.agent_with_identity(
            gw,
            agent_id,
            models,
            upstream,
            max_concurrency,
            request_log,
            None,
            None,
        )
    }

    /// 起一个带 tenant 归属的 agent（发送 `RegisterWithTenant`）。
    #[allow(clippy::too_many_arguments)]
    pub fn agent_for_tenant(
        &self,
        gw: &Gateway,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
        request_log: bool,
        tenant_id: &str,
        agent_token: &str,
    ) -> Agent {
        self.agent_with_identity(
            gw,
            agent_id,
            models,
            upstream,
            max_concurrency,
            request_log,
            Some(tenant_id),
            Some(agent_token),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn agent_with_identity(
        &self,
        gw: &Gateway,
        agent_id: &str,
        models: &[&str],
        upstream: SocketAddr,
        max_concurrency: u32,
        request_log: bool,
        tenant_id: Option<&str>,
        agent_token: Option<&str>,
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
            tenant_id: tenant_id.map(str::to_string),
            tenant_agent_token: agent_token.map(str::to_string),
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
