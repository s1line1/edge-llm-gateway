//! agent 的单元测试：从 `agent/src/tests.rs` 搬出，并按变更理由分文件。
//!
//! `tests` 仍是 crate 根的子模块，所以 `use super::*` 仍能看到 `next_backoff` /
//! `ConcurrencyGate` / `connect_once` 等私有项。共享的 QUIC/PKI 夹具留在这里。

use super::*;
use crate::test_log::CapturedLogs;
use proto::ALPN;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use s2n_quic::connection::{Handle, StreamAcceptor};
use std::sync::Arc;

/// 生成 (CA, 服务端证书, 服务端私钥, 客户端证书, 客户端私钥) 的 DER。
fn gen_pki() -> (
    CertificateDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let srv_key = KeyPair::generate().unwrap();
    let mut srv = CertificateParams::default();
    srv.distinguished_name.push(DnType::CommonName, "gw");
    srv.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
    srv.is_ca = IsCa::NoCa;
    srv.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    srv.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let srv_cert = srv.signed_by(&srv_key, &ca_cert, &ca_key).unwrap();

    let cli_key = KeyPair::generate().unwrap();
    let mut cli = CertificateParams::default();
    cli.distinguished_name.push(DnType::CommonName, "agent");
    cli.is_ca = IsCa::NoCa;
    cli.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    cli.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let cli_cert = cli.signed_by(&cli_key, &ca_cert, &ca_key).unwrap();

    (
        ca_cert.der().clone(),
        srv_cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(srv_key.serialize_der())),
        cli_cert.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cli_key.serialize_der())),
    )
}

/// 建立一个本地的 s2n-quic 连接对（无 mTLS），返回客户端 [`Handle`]。
/// 服务端只保活连接、不读流。
async fn test_connection() -> Handle {
    // 服务端：自签证书 + 无客户端认证
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
    stls.alpn_protocols = vec![ALPN.to_vec()];

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

    // 服务端 accept 一条连接并保活：别返回，返回会 drop 句柄导致连接关闭
    tokio::spawn(async move {
        let conn = server.accept().await.expect("client should connect");
        let (_handle, _acceptor) = conn.split();
        std::future::pending::<()>().await;
    });

    // 客户端：信任自签证书，无客户端证书
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut ctls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    ctls.alpn_protocols = vec![ALPN.to_vec()];

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

/// 用 CA 签发的服务端证书建 mTLS s2n-quic server，把每条接入连接的 [`Handle`] 发给测试。
async fn test_server(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<Handle>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut stls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    stls.alpn_protocols = vec![ALPN.to_vec()];

    let mut server = s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
            stls,
        )))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap();
    let addr = server.local_addr().unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        while let Some(conn) = server.accept().await {
            let tx = tx.clone();
            let (handle, _acceptor) = conn.split();
            let _ = tx.send(handle).await;
        }
    });
    (addr, rx)
}

/// 假网关：接受连接后**只服务注册流**（读一帧 → finish，让 agent 的 register 拿到 EOF），
/// 此后的流（心跳）一律 `reset` 掉 —— 心跳读立刻报错，于是心跳任务结束。
///
/// 每条接入连接都会往 channel 发一个信号：测试用它数"重连了几次"。用 reset 而不是
/// 干脆不读，是为了避开 `heartbeat_loop` 里那个 5s 的 ack 超时，测试才跑得快。
async fn test_server_that_only_serves_register(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<()>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut stls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    stls.alpn_protocols = vec![ALPN.to_vec()];

    let mut server = s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
            stls,
        )))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap();
    let addr = server.local_addr().unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        while let Some(conn) = server.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let (_handle, mut acceptor) = conn.split();
                if let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                    let (mut recv, mut send) = stream.split();
                    let _ = proto::io::FrameReader::new(&mut recv).next().await; // 注册帧
                    let _ = send.finish(); // 让 agent 侧读到 EOF，注册成功
                }
                let _ = tx.send(()).await; // "这条连接已经注册完成"
                                           // 之后的心跳流：reset 掉，让 agent 的心跳任务立刻失败
                while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                    let (_recv, mut send) = stream.split();
                    let _ = send.reset(0u32.into());
                }
            });
        }
    });
    (addr, rx)
}

/// 假网关：服务注册流（读一帧 → finish，让 `register()` 拿到 EOF），**并把连接句柄交回测试**，
/// 好让测试自己开一条流写请求 —— 于是走的是**真的 accept 循环**（`connect_once` 里的
/// `handle_stream` + 那行 `warn!("proxy stream failed")`），而不是测试直接调 `handle_stream`。
///
/// 之后的心跳流照 `test_server_that_only_serves_register` 的做法 reset 掉，避开 5s ack 超时。
async fn test_server_that_serves_register_and_returns_the_connection(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<Handle>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut stls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    stls.alpn_protocols = vec![ALPN.to_vec()];

    let mut server = s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
            stls,
        )))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap();
    let addr = server.local_addr().unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        while let Some(conn) = server.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let (handle, mut acceptor) = conn.split();
                // 第一条流 = 注册流：读一帧就 finish（agent 侧读到 EOF = 注册成功）
                if let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                    let (mut recv, mut send) = stream.split();
                    let _ = proto::io::FrameReader::new(&mut recv).next().await;
                    let _ = send.finish();
                }
                let _ = tx.send(handle).await;
                // 之后是 agent 自己开的心跳流：reset，别让它们拖成 5s 超时
                while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                    let (_recv, mut send) = stream.split();
                    let _ = send.reset(0u32.into());
                }
            });
        }
    });
    (addr, rx)
}

/// 假网关：服务注册流，之后**消费心跳流但不回包**（读到帧后按 `reply_delay` 决定何时 finish）。
///
/// 用途是复现"心跳等待超时"：`reply_delay` > 心跳等待上限时，这次心跳必然超时，
/// 但**连接本身是健康的**（没有 reset、没有断开）——这正是要区分的那条路径。
async fn test_server_that_delays_heartbeat_reply(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    first_reply_delay: Duration,
) -> SocketAddr {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut stls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    stls.alpn_protocols = vec![ALPN.to_vec()];

    let mut server = s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
            stls,
        )))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap();
    let addr = server.local_addr().unwrap();

    tokio::spawn(async move {
        while let Some(conn) = server.accept().await {
            tokio::spawn(async move {
                let (_handle, mut acceptor) = conn.split();
                let mut first = true;
                let mut first_hb = true;
                while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                    // ⚠️ 每条流**独立**处理：若在 accept 循环里串行 sleep，第一次
                    // 心跳的延迟会把后续心跳的回包一起堵住，导致连续多次超时。
                    let registration = std::mem::take(&mut first);
                    let delay_long = if registration {
                        None
                    } else {
                        Some(std::mem::take(&mut first_hb))
                    };
                    tokio::spawn(async move {
                        let (mut recv, mut send) = stream.split();
                        let _ = proto::io::FrameReader::new(&mut recv).next().await;
                        match delay_long {
                            None => {}                                                 // 注册流：立刻回
                            Some(true) => tokio::time::sleep(first_reply_delay).await, // 首次心跳：拖长
                            Some(false) => {} // 其后心跳：立刻回
                        }
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    addr
}

/// 建立一条到假网关的连接（注册已在 `connect_once` 之外单独调用，这里只连）。
async fn connect_for_test(
    cfg: &AgentConfig,
    client_config: rustls::ClientConfig,
) -> s2n_quic::connection::Handle {
    connect_for_test_with_acceptor(cfg, client_config).await.0
}

/// 同 [`connect_for_test`]，但把 agent 侧的 [`Acceptor`] 一起交出来。
///
/// [`handle_stream`] 收的是**已经 accept 出来的流**（生产里由 `run_loop` 的 acceptor 给），
/// 所以要真跑它就得自己 accept 一次——而 `conn.split()` 出来的那个 acceptor 此前被丢掉了。
async fn connect_for_test_with_acceptor(
    cfg: &AgentConfig,
    client_config: rustls::ClientConfig,
) -> (s2n_quic::connection::Handle, StreamAcceptor) {
    let client = s2n_quic::Client::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
            client_config,
        )))
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();
    let conn = client
        .connect(Connect::new(cfg.cloud_addr).with_server_name(cfg.server_name.clone()))
        .await
        .unwrap();
    let (handle, acceptor) = conn.split();
    (handle, acceptor)
}

fn test_agent_config(
    cloud_addr: SocketAddr,
    ca: CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> AgentConfig {
    AgentConfig {
        cloud_addr,
        server_name: "localhost".into(),
        ca_cert: vec![ca],
        client_cert: vec![cert],
        client_key: key,
        agent_id: "t".into(),
        models: vec!["m".into()],
        max_concurrency: 2,
        upstream_base: "http://127.0.0.1:1".into(),
        heartbeat_interval: Duration::from_millis(50),
        request_log: true,
    }
}

/// 一发就走的假 HTTP 服务器：接连接 → 读掉请求（至少读到请求头结束）→ 回**给定的原始
/// 响应字节** → 关连接。返回 `(地址, 收到的请求文本)`——测试用它回答"agent 到底连了谁、
/// 送了什么"。
async fn one_shot_http(
    response: String,
) -> (std::net::SocketAddr, tokio::sync::mpsc::Receiver<String>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake upstream");
    let addr = listener.local_addr().expect("addr");
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            // 请求体可能还没到齐，但本测试只关心"连没连、头里有什么"，读一小段就够
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            // 为了让 307/308 的请求体能被看到，再给一小段时间补读
            if head.starts_with("POST") {
                let n = tokio::time::timeout(Duration::from_millis(200), sock.read(&mut buf))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .unwrap_or(0);
                let mut all = head;
                all.push_str(&String::from_utf8_lossy(&buf[..n]));
                let _ = tx.send(all).await;
            } else {
                let _ = tx.send(head).await;
            }
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
    });
    (addr, rx)
}

/// 假网关（比 `test_server` 完整）：接受连接后**服务控制流**（注册/心跳：每流读一帧就
/// `finish`，等价于真网关的"收到即 ack"），同时把 [`Handle`] 交给测试，于是测试能像真网关
/// 那样开请求流。
///
/// 为什么不能直接用 `test_server`：它把 acceptor 丢掉了 ⇒ agent 的注册流永远等不到 EOF，
/// `register()` 会卡满 10s，测试根本走不到 accept 循环（实测 `served=0` 就是这个原因）。
async fn test_server_with_handle(
    ca: &CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> (SocketAddr, tokio::sync::mpsc::Receiver<Handle>) {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .unwrap();
    let mut stls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![cert], key)
        .unwrap();
    stls.alpn_protocols = vec![ALPN.to_vec()];

    let mut server = s2n_quic::Server::builder()
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
            stls,
        )))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap();
    let addr = server.local_addr().unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        while let Some(conn) = server.accept().await {
            let tx = tx.clone();
            let (handle, mut acceptor) = conn.split();
            let _ = tx.send(handle).await;
            tokio::spawn(async move {
                while let Ok(Some(stream)) = acceptor.accept_bidirectional_stream().await {
                    let (mut recv, mut send) = stream.split();
                    let _ = proto::io::FrameReader::new(&mut recv).next().await;
                    let _ = send.finish();
                }
            });
        }
    });
    (addr, rx)
}

/// 计数用的假上游：每个请求睡 `sleep`，记录观察到的**最大同时在途数**。
///
/// 返回 `(base_url, max_inflight, served)`。
async fn counting_upstream(
    sleep: Duration,
) -> (
    String,
    Arc<std::sync::atomic::AtomicU32>,
    Arc<std::sync::atomic::AtomicU32>,
) {
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let inflight = Arc::new(AtomicU32::new(0));
    let max_inflight = Arc::new(AtomicU32::new(0));
    let served = Arc::new(AtomicU32::new(0));
    let (i2, m2, s2) = (inflight.clone(), max_inflight.clone(), served.clone());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let (i, m, s) = (i2.clone(), m2.clone(), s2.clone());
            tokio::spawn(async move {
                // 读掉请求（至少读到头结束）；reqwest 会带 Content-Length
                let mut buf = vec![0u8; 8192];
                let mut acc = Vec::new();
                while !acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => acc.extend_from_slice(&buf[..n]),
                    }
                }
                let now = i.fetch_add(1, Ordering::SeqCst) + 1;
                m.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(sleep).await;
                let body = br#"{"ok":true}"#;
                let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.shutdown().await;
                i.fetch_sub(1, Ordering::SeqCst);
                s.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (url, max_inflight, served)
}

mod backoff;
mod exit;
mod gate;
mod heartbeat;
mod lifecycle;
mod logging;
mod path;
mod relay;
mod upstream;
