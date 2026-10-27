//! registry 的单元测试：从 `registry/mod.rs` 的内联 `mod tests` 原样搬出，并按变更理由分文件。
//!
//! 这些测试通过 `use super::*;` 访问 `registry` 的私有项（`Entry` 的 `pub(super)` 字段、
//! `NEXT_CONN_ID`、`SlotGuard` 等）；`tests` 仍是 `registry` 的子模块，所以可见性不变。
//! 共享夹具（日志捕获、QUIC 句柄、宽限/来源常量）留在这里，各主题文件只放测试函数。

use super::*;
use crate::registry::entry::now_millis;
use crate::registry::entry::EvictCause;
use crate::registry::eviction::EvictOutcome;
use crate::registry::routing::pick;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::IpAddr;
use std::time::Duration;

/// 测试用的日志捕获：断言"这一条 warn 到底有没有打"。
///
/// 为什么不用 `tracing_subscriber::fmt::init()` 之类：那会装**全局** subscriber，与同进程
/// 其它测试互相覆盖。`set_default` 是**线程局部**的，所以要用它的测试必须是
/// `#[tokio::test(flavor = "current_thread")]`（多线程 runtime 会把任务调度到别的 worker 上，
/// 事件就抓不到了）。这与 agent 侧 `crate::test_log::CapturedLogs` 是同一个理由。
#[derive(Clone, Default)]
struct CapturedLogs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// 装一个线程局部的捕获 subscriber，返回 `(守卫, 读文本的句柄)`。
/// **必须**在 `flavor = "current_thread"` 的测试里用（见 [`CapturedLogs`]）。
fn capture_logs() -> (
    tracing::subscriber::DefaultGuard,
    std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
) {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("debug")
        // 关颜色：带 ANSI 时字段名被画成斜体、字节里就没有字面量可 grep（agent 侧踩过同样的坑）。
        .with_ansi(false)
        .finish();
    (tracing::subscriber::set_default(subscriber), logs.0.clone())
}

fn captured_text(handle: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> String {
    String::from_utf8(handle.lock().unwrap().clone()).unwrap()
}

/// 捕获里是否出现过 **WARN 级别**的事件。
///
/// 为什么按级别判而不是按消息文本判：只 grep 某条消息时，"该 warn 的没 warn"能测出来，
/// 但"**不该 warn 的 warn 了别的内容**"测不出来（实测：把接管那条 debug 改成 warn 之后，
/// 文本断言照样通过）。这一层的契约本来就是"什么级别"，所以判据也应该是级别。
fn has_warn(handle: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> bool {
    captured_text(handle)
        .lines()
        .any(|l| l.split_whitespace().any(|w| w == "WARN"))
}

/// 摘除宽限：单测不关心具体时长（那由 `Options::evict_close_grace` 决定，默认 15s），
/// 给一个固定值即可。
const GRACE: Duration = Duration::from_secs(5);

/// 单测里的默认来源 IP。绝大多数用例只关心"键正确"，来源是哪台机器无所谓；
/// 需要"同名不同来源"的用例（见 `same_id_from_two_ips_is_two_nodes`）自己传第二个 IP。
const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
const OTHER_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2));

/// 建一对本地 s2n-quic 端点，返回**客户端连接句柄**（无 mTLS，只为构造 Handle）。
///
/// 返回 `Handle` 而不是 `Connection`，因为注册表里存的就是 Handle（`Entry.conn`）：
/// Handle 是 `#[derive(Clone, Debug)]`（s2n-quic/src/connection/handle.rs:431），
/// 既能进 HashMap 也能被 `try_acquire` clone 出来；而 `Connection` 没有 Clone。
///
/// 返回后端点随作用域结束 drop、连接随之关闭，但测试只读 `id()` 与 `inflight`：
/// `Handle::id()` 是无锁的字段读取、也不返回 Result
/// （s2n-quic-transport/src/connection/connection_container.rs:319-321），
/// 所以连接死掉之后读 id 依然有效——注册表测试不依赖连接可用性。
async fn test_connection() -> s2n_quic::connection::Handle {
    // 服务端：自签证书；ALPN 两端必须一致，否则握手协商不上
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let mut stls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    stls.alpn_protocols = vec![proto::ALPN.to_vec()];

    let mut server = s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
            stls,
        )))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap();
    let server_addr = server.local_addr().unwrap();

    // 必须驱动服务端 accept，否则 QUIC 握手永远无法完成；
    // 握完把两半句柄挂在 pending 上——返回会 drop 句柄、立刻关掉连接。
    tokio::spawn(async move {
        if let Some(conn) = server.accept().await {
            let (_handle, _acceptor) = conn.split();
            std::future::pending::<()>().await;
        }
    });

    // 客户端：信任自签证书（无 mTLS），ALPN 与服务端一致
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut ctls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ctls.alpn_protocols = vec![proto::ALPN.to_vec()];

    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
            ctls,
        )))
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();

    let conn = client
        .connect(s2n_quic::client::Connect::new(server_addr).with_server_name("localhost"))
        .await
        .unwrap();
    let (handle, _acceptor) = conn.split();
    handle
}

// 按主题拆分的测试模块（每个文件只覆盖一个变更理由）。
mod admission;
mod eviction;
mod health;
mod identity;
mod logging;
mod poison;
mod registration;
mod routing;
mod snapshot;
mod takeover;
