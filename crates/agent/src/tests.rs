use super::*;
use crate::test_log::CapturedLogs;
use proto::ALPN;

/// 规格（记录 P2-1）：**"连上就被踢"不许把退避重置回 500ms**。
///
/// 这是同名 `agent_id` 互踢"每 ~500ms 一次、永不收敛"的根因：`connect_once` 返回
/// `Ok(())` 有两种语义，旧代码把"刚注册就被踢"也当成"健康跑了很久后断开"。
/// 判据：会话只活了毫秒级时，退避必须**继续增长/保持在上限**，绝不能回到基准。
#[test]
fn a_short_lived_session_does_not_reset_the_backoff() {
    let short = Duration::from_millis(5);
    assert_eq!(
        next_backoff(BACKOFF_BASE, short),
        BACKOFF_BASE * 2,
        "短命会话必须继续退避"
    );
    assert_eq!(
        next_backoff(Duration::from_secs(2), short),
        Duration::from_secs(4)
    );
    assert_eq!(
        next_backoff(BACKOFF_MAX, short),
        BACKOFF_MAX,
        "已经到顶就保持在顶，而不是被打回基准（这正是互踢风暴的形状）"
    );
}

/// 规格：会话活得够久 = 真的健康过，断开时才把退避重置回基准。
#[test]
fn a_long_lived_session_resets_the_backoff() {
    assert_eq!(next_backoff(BACKOFF_MAX, BACKOFF_RESET_AFTER), BACKOFF_BASE);
    assert_eq!(
        next_backoff(Duration::from_secs(4), BACKOFF_RESET_AFTER * 10),
        BACKOFF_BASE
    );
    // 边界：差一毫秒不算健康
    assert_eq!(
        next_backoff(BACKOFF_MAX, BACKOFF_RESET_AFTER - Duration::from_millis(1)),
        BACKOFF_MAX
    );
}

/// 规格：连续失败/短命会话下退避**单调增长到上限并停在那儿**（旧代码在每条
/// `Ok(())` 上都重置，所以永远停在 500ms）。
#[test]
fn the_backoff_grows_to_the_cap_and_stays_there() {
    let mut backoff = BACKOFF_BASE;
    let mut seen = vec![backoff];
    for _ in 0..12 {
        backoff = next_backoff(backoff, Duration::from_millis(1));
        seen.push(backoff);
    }
    assert_eq!(
        seen,
        vec![
            Duration::from_millis(500),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4),
            Duration::from_secs(8),
            Duration::from_secs(16),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_secs(30),
        ],
        "退避序列必须是 500ms 起翻倍、封顶 30s"
    );
}

/// 规格（二轮审计发现的**接线**缺口）：`run()` 真的把 `session_alive` 交给了 `next_backoff`。
///
/// 上面四条是纯函数单测，钉不住这一步：把 `run()` 末尾的
/// `backoff = next_backoff(backoff, session_alive)` 换成 `backoff = BACKOFF_BASE`，
/// 那四条**照样全绿**，而线上退回"每 ~500ms 重连一次"的互踢风暴。
///
/// 判据用 `run()` 自己打的 `wait_ms`（`:218-219` 的不变量：日志里的值**就是**它接下来要睡的值）
/// + 真墙钟：连续两次连接失败之间，第三次的等待必须已经涨到 1s 量级（抖动 ±20% ⇒ ≥800ms），
/// 而固定基准最多 600ms。这条测试跑 ~2s（500ms + 1s 两次真实睡眠）。
///
/// **夹具用 `test_server_that_only_serves_register`**（`dead_heartbeat_forces_a_reconnect`
/// 用的同一个，CI 上稳定）：注册流被服务后端 reset 心跳流 ⇒ 会话两三百毫秒就结束，重连是
/// 确定性的。**不要**图省事用"接上就立刻关连接"那版（第一版就是），它把首轮的失败押在
/// "关连接能让 `register()` 立刻报错"上——一旦那个 close 没赶上，`register()` 会走它自己的
/// **10s** 超时，而这条测试的等待上限也正好是 10s，于是日志一条都还没打出来就判定失败
/// （2026-09-24 全量 nextest 高负载下实测偶发）。现在每次重连都有注册信号可等，上限放宽到 30s。
#[tokio::test(flavor = "current_thread")]
async fn the_run_loop_actually_grows_the_backoff_between_short_sessions() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        // 这份捕获是**当文本读**的（要 grep `wait_ms=`）。带 ANSI 时 `tracing-subscriber`
        // 会把**字段名**画成斜体、`=` 画成暗色，于是字节里根本没有字面量 `wait_ms=`
        // （终端里渲染出来一模一样）——而是否上色取决于环境：`Layer::default()` 的
        // `cfg!(feature="ansi") && env::var("NO_COLOR")…`。本地设了 NO_COLOR（绿）、CI 没设
        // （红），于是这条测试成了"只在 CI 失败"（2026-09-24 实测复现）。别赌运行环境的
        // NO_COLOR：显式关掉颜色。
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut registrations) =
        test_server_that_only_serves_register(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));

    // 每次"注册成功 + 心跳被 reset"= 一次短命会话（`session_alive` ≈ 毫秒级），正是
    // "同名 agent 互踢"的形状 ⇒ 退避必须逐次翻倍。三个阶段：等注册信号（墙钟锚点）→
    // 等这次会话对应的那条 retry 日志（`run()` 先打日志、再照它睡）。
    let mut stamps: Vec<(tokio::time::Instant, u64)> = Vec::new();
    for attempt in 1..=3u32 {
        tokio::time::timeout(Duration::from_secs(30), registrations.recv())
            .await
            .unwrap_or_else(|_| panic!("第 {attempt} 次注册超时：run loop 没在重连吗？"))
            .expect("假网关应当收到连接");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut wait = None;
        while tokio::time::Instant::now() < deadline {
            if let Some(value) = parse_wait_ms(&logs.text()).get(attempt as usize - 1) {
                wait = Some(*value);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let wait = wait.unwrap_or_else(|| {
            panic!(
                "第 {attempt} 次重连没有留下 `wait_ms` 日志：\n{}",
                logs.text()
            )
        });
        stamps.push((tokio::time::Instant::now(), wait));
    }
    task.abort();

    let (_, w0) = stamps[0];
    let (_, w1) = stamps[1];
    assert!(
        (400..=650).contains(&w0),
        "第一次等待应当是基准 500ms（±20% 抖动），实际 {w0}ms"
    );
    assert!(
        (800..=1250).contains(&w1),
        "第二次等待必须是翻倍后的 ~1s（固定基准的实现最多 600ms）：实际 {w1}ms —— \
             接线 `backoff = next_backoff(backoff, session_alive)` 是否还在？"
    );
    // 墙钟复核：相邻两条日志之间隔着"上一条日志承诺的等待"（先打日志、随后才 sleep）。
    // 计时只会被负载拉长、不会被压短，所以下界是硬判据。
    let gap = stamps[2].0.duration_since(stamps[1].0);
    assert!(
        gap >= Duration::from_millis(700),
        "日志里的 wait_ms 必须就是真正睡的值（`run()` 的既有不变量），实测间隔 {gap:?}"
    );
}

/// 从捕获的日志里按出现顺序取出所有 `wait_ms=<n>`。
///
/// 先剥掉 ANSI 转义序列再按字面量匹配：带 ANSI 时字段名是斜体、`=` 是暗色，字节里根本没有
/// `wait_ms=`（终端里渲染出来一模一样）。上面已经显式 `with_ansi(false)`，这里是第二道——
/// 万一有人删了那行，也不会再变成“只在 CI 红”。
///
/// **不要用“跳过非数字字符”那种写法**：ANSI 序列自己就含数字（`\x1b[0m`、`\x1b[2m`），
/// 那样会解析出 `0, 2, 405…` 的垃圾（这版第一稿就是这么写的，实测把断言喂成了 `w0 == 0`）。
fn parse_wait_ms(text: &str) -> Vec<u64> {
    let plain = strip_ansi(text);
    plain
        .match_indices("wait_ms=")
        .filter_map(|(at, key)| {
            let rest = &plain[at + key.len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

/// 去掉 CSI 转义序列（`ESC [ 参数字节… 终止字节`）——`tracing-subscriber` 的配色只用这一族。
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            // 参数/中间字节是 0x20–0x3F，遇到 0x40–0x7E 即序列结束
            for c in chars.by_ref() {
                if ('\x40'..='\x7e').contains(&c) {
                    break;
                }
            }
        }
        // 其它 ESC 序列本测试用不到：丢掉这个 ESC 即可
    }
    out
}

/// 规格：抖动必须在 ±20% 之内、**两端都能取到**（否则就是"加了抖动"的自述），
/// 且封顶之后不许超过上限。
#[test]
fn jitter_stays_within_bounds_reaches_both_ends_and_respects_the_cap() {
    let base = Duration::from_secs(1);
    let values: Vec<Duration> = (0..=40).map(|e| jittered(base, e)).collect();
    for v in &values {
        assert!(
            *v >= Duration::from_millis(800) && *v <= Duration::from_millis(1200),
            "抖动越界：{v:?}（基准 {base:?}）"
        );
    }
    assert!(
        values.iter().any(|v| *v < base),
        "必须能取到向下的一侧：{values:?}"
    );
    assert!(
        values.iter().any(|v| *v > base),
        "必须能取到向上的一侧：{values:?}"
    );
    // 熵只影响结果、不该把结果挤成常量（"抖了但都一样"等于没抖）
    let distinct: std::collections::BTreeSet<u128> = values.iter().map(|v| v.as_micros()).collect();
    assert!(distinct.len() >= 5, "抖动值太集中：{distinct:?}");

    // 顶上单边缩小：仍然封顶，不会超过标称上限
    for e in 0..=40 {
        let capped = jittered(BACKOFF_MAX, e);
        assert!(
            capped <= BACKOFF_MAX,
            "抖动后不得超过标称上限（e={e}）：{capped:?}"
        );
        assert!(
            capped >= BACKOFF_MAX * 4 / 5,
            "顶上也不该掉太多：{capped:?}"
        );
    }
}

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

/// 回归测试：**单次心跳超时不得立刻拆掉连接**。
///
/// 旧实现把心跳等待硬编码成 5s（等于默认心跳间隔），一次超时就返回 Err → `run()`
/// 视为致命 → 主动断开 → 重连又撞握手限时，实测在高并发下形成风暴，期间网关没有
/// 任何健康 agent（所有请求 503）。
///
/// 服务器只把**第一次**心跳的回包拖长（> 等待上限），之后一律立刻回包；于是
/// "成功会重置失败计数"这一点与测试里掐的时刻无关：第一次必超时、其后必成功。
/// 若容忍逻辑被改回"一次失败即退出"，循环会在第一次超时后结束，断言立刻失败。
#[tokio::test]
async fn a_single_heartbeat_timeout_does_not_immediately_tear_down_the_connection() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let addr = test_server_that_delays_heartbeat_reply(
        &ca,
        srv_cert,
        srv_key,
        // 远大于等待上限（interval 40ms × 3 = 120ms），保证第一次心跳必然超时；
        // 注意服务器每条流独立处理，所以这次延迟只影响第一次心跳。
        Duration::from_millis(200),
    )
    .await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();

    let mut handle = connect_for_test(&cfg, cc).await;
    let task = tokio::spawn(heartbeat_loop(
        handle.clone(),
        "agent-z".into(),
        Duration::from_millis(40),
    ));

    // 第一次心跳在 ≈160ms 超时；其后每次心跳都在 40ms 内立刻回包并重置计数。
    // 跨到 1.2s：若"单次失败就退出"的旧行为回来了，任务早已结束。
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        !task.is_finished(),
        "单次心跳超时就拆了连接：应当容忍失败，把「连接是否真死」交给网关 stale 判定"
    );
    assert!(
        handle.open_bidirectional_stream().await.is_ok(),
        "连接应当仍然可用"
    );
    task.abort();
}

/// 规格（`PROJECT_SCAN` P1-2 的 agent 侧）：越权路径**不得到达上游**，且客户端拿到 400。
///
/// `stream.rs` 里那几条纯函数测试证明判据对；这条证明它**真接在数据路径上**：假网关往一条
/// 双向流里写记录里的 PoC（`DELETE /v1/../api/delete`），真跑 [`handle_stream`]，断言
/// ① 回包是一条 `code: 400` 的 Error 帧（网关据此让客户端看到 400，而不是无因果的 502），
/// ② 上游那个 listener **一次连接都没有**——这才是漏洞本身（上游通常是 agent 同机的
/// Ollama，`/api/delete` 会直接删模型）。
#[tokio::test]
async fn a_traversal_path_never_reaches_the_upstream_and_returns_400() {
    // 上游：只用来数连接，正常实现里 agent 不该连它
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let upstream_url = format!("http://{}", upstream.local_addr().expect("addr"));

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    // 假网关：开一条双向流，写一个越权的 ProxyRequest
    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 7,
            method: "DELETE".into(),
            path: "/v1/../api/delete".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    // agent 侧：accept 出流（生产里 `run_loop` 就是这么给的）并真跑
    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("应当在 5s 内收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    let task = tokio::spawn(handle_stream(
        agent_stream,
        // 与生产同一条构造路径：测试不该复制一份"没加固的客户端"（那正是 P2-4 的形状）
        upstream_client().unwrap(),
        upstream_url,
        false,
    ));

    // ① 回包 = 400 Error 帧
    let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
        .await
        .expect("拒绝不该拖延")
        .expect("读帧不该出错")
        .expect("应当有回帧");
    match reply {
        Frame::Error {
            request_id,
            code,
            message,
        } => {
            assert_eq!(request_id, Some(7), "错误帧要能对上请求");
            assert_eq!(code, 400, "网关拿这个 code 当客户端看到的状态码");
            assert!(message.contains("path"), "文案要指出是路径问题：{message}");
        }
        other => panic!("越权路径应当被拒，实际收到 {other:?}"),
    }

    // ② 上游一次都没被连（300ms 内 accept 必须超时）
    assert!(
        tokio::time::timeout(Duration::from_millis(300), upstream.accept())
            .await
            .is_err(),
        "越权路径到达了上游——这正是 P1-2"
    );

    task.await
        .expect("handle_stream 不该 panic")
        .expect("拒绝是正常结束，不该是 Err");
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

#[tokio::test]
async fn dead_heartbeat_forces_a_reconnect() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut rx) = test_server_that_only_serves_register(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));

    // 第一条连接：注册流被服务端读掉并 finish，所以注册能正常完成
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("agent should connect")
        .expect("first connection");

    // 之后的心跳流会被服务端 reset → 心跳任务结束。这条连接此时在网关眼里已经死了
    // （心跳是网关判定存活状态的唯一依据），所以 agent 必须主动断开重连 ——
    // 而不是抱着一条"看起来还开着"的连接静默等下去（那种状态下网关会把所有请求判 503，
    // 两侧都没有日志，只能人工重启）。没有这个断言，这条静默路径可以再次溜回去。
    tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("a dead heartbeat must force a reconnect, not a silent zombie")
        .expect("second connection");

    task.abort();
}

#[tokio::test]
async fn heartbeat_loop_breaks_when_connection_closed() {
    let handle = test_connection().await;
    // 关闭连接：之后 open_bidirectional_stream 必然失败 → 心跳循环返回 Err
    handle.close(0u32.into());
    let result = heartbeat_loop(handle, "agent-x".into(), Duration::from_millis(10)).await;
    assert!(
        result.is_err(),
        "heartbeat should fail after connection closed"
    );
}

#[tokio::test]
async fn heartbeat_loop_sends_frames_on_live_connection() {
    let mut handle = test_connection().await;
    // 间隔 20ms、运行 120ms：心跳任务会反复开流（写帧 + 等 EOF）
    let task = tokio::spawn(heartbeat_loop(
        handle.clone(),
        "agent-y".into(),
        Duration::from_millis(20),
    ));
    tokio::time::sleep(Duration::from_millis(120)).await;
    // 连接仍存活（未被心跳逻辑破坏）
    assert!(handle.open_bidirectional_stream().await.is_ok());
    task.abort();
}

/// 规格（2026-09-25 复扫 E1）：**等闸门许可期间心跳仍必须被观察**。
///
/// `tokio::select!` 的分支体一旦 await，其它分支就不再被 poll。原先把 `g.acquire().await`
/// 直接写在 accept 分支体里，于是"闸门打满（许可被长 SSE 持有）"时心跳失败/panic 无人
/// 观察 ⇒ 连接不会被拆 ⇒ agent 自认连着、网关把每个请求判 503，两侧都没日志。
///
/// 控制点：许只有一个且已被占住，心跳任务已经结束。`acquire_slot` 必须**立刻**回
/// `HeartbeatDown`，而不是一直排队等许可。
#[tokio::test]
async fn waiting_for_a_slot_still_notices_a_dead_heartbeat() {
    let mut gate = ConcurrencyGate::new(1);
    let held = gate
        .as_mut()
        .expect("max_concurrency = 1 应当建闸门")
        .acquire()
        .await;
    // 已经结束的心跳任务（真实场景里是心跳失败/panic 之后退出的那个）。
    let mut hb = tokio::spawn(async { Ok::<(), anyhow::Error>(()) });

    let outcome = tokio::time::timeout(Duration::from_secs(2), acquire_slot(&mut gate, &mut hb))
        .await
        .expect("等许可时心跳结束必须立刻返回，而不是一直排队");
    assert!(
        matches!(outcome, SlotOutcome::HeartbeatDown),
        "应当报心跳结束以拆掉这条连接"
    );
    drop(held);
}

/// 对照：心跳**还活着**时，许可没空出来就不该返回（别把上面那条修成"总是立刻放弃"）。
#[tokio::test]
async fn waiting_for_a_slot_does_not_return_early_while_the_heartbeat_is_alive() {
    let mut gate = ConcurrencyGate::new(1);
    let held = gate.as_mut().unwrap().acquire().await;
    let mut hb = tokio::spawn(async { std::future::pending::<anyhow::Result<()>>().await });

    let raced =
        tokio::time::timeout(Duration::from_millis(200), acquire_slot(&mut gate, &mut hb)).await;
    assert!(raced.is_err(), "许可没空出来、心跳也没死 ⇒ 不该返回");

    hb.abort();
    drop(held);
}

/// 对照：有空位就发许可；`max_concurrency = 0`（不限）时没有闸门，返回 `None`。
#[tokio::test]
async fn a_free_slot_is_granted_and_no_gate_means_no_permit() {
    let mut gate = ConcurrencyGate::new(2);
    let mut hb = tokio::spawn(async { std::future::pending::<anyhow::Result<()>>().await });
    assert!(matches!(
        acquire_slot(&mut gate, &mut hb).await,
        SlotOutcome::Permit(Some(_))
    ));

    let mut no_gate: Option<ConcurrencyGate> = None;
    assert!(matches!(
        acquire_slot(&mut no_gate, &mut hb).await,
        SlotOutcome::Permit(None)
    ));
    hb.abort();
}

#[tokio::test]
async fn run_loop_retries_when_connect_fails() {
    let (ca, _srv_cert, _srv_key, cli_cert, cli_key) = gen_pki();
    let cfg = test_agent_config(
        SocketAddr::from(([127, 0, 0, 1], 1)), // 必然连接失败
        ca,
        cli_cert,
        cli_key,
    );
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));
    // 第一次连接失败 → Err 分支 → 退避重试（覆盖 71/73-74 行）
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(!task.is_finished(), "run loop should keep retrying");
    task.abort();
}

#[tokio::test]
async fn run_loop_handles_clean_disconnect() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut rx) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));
    // 等 agent 连上
    let server_handle = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("agent should connect")
        .unwrap();
    // 服务端主动关闭连接 → agent 干净断开（Ok 分支）→ 退避重连
    server_handle.close(0u32.into());
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        !task.is_finished(),
        "run loop should keep running after disconnect"
    );
    task.abort();
}

/// Agent::start 在客户端证书/私钥无效时报错（不 panic）。
#[test]
fn start_rejects_invalid_client_key() {
    use rustls::pki_types::PrivatePkcs8KeyDer;
    let (ca, _srv_cert, _srv_key, cli_cert, _cli_key) = gen_pki();
    let bad_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(vec![0x01; 16]));
    let cfg = AgentConfig {
        cloud_addr: "127.0.0.1:1".parse().unwrap(),
        server_name: "localhost".into(),
        ca_cert: vec![ca],
        client_cert: vec![cli_cert],
        client_key: bad_key,
        agent_id: "t".into(),
        models: vec!["m".into()],
        max_concurrency: 2,
        upstream_base: "http://127.0.0.1:1".into(),
        heartbeat_interval: Duration::from_millis(50),
        request_log: true,
    };
    assert!(Agent::start(cfg).is_err(), "invalid key should fail start");
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

/// 规格（P3-5）：**run 循环结束由调用方得知，库自己不再退出进程。**
///
/// 这条测试在旧实现下**根本不可能存在**：守护任务末尾是 `std::process::exit(1)`，任何在进程内
/// 触发该路径的测试都会把整个测试二进制带走（报告丢失）。现在结局走一个 watch 通道。
#[tokio::test]
async fn a_finished_run_loop_is_reported_instead_of_exiting_the_process() {
    let mut agent = Agent::supervise(async {});
    assert_eq!(
        agent.wait_for_abnormal_exit().await,
        Some(AgentExit::LoopExited),
        "run 循环返回必须被报成异常结局"
    );
}

/// 同上，panic 那一支（`JoinError::is_panic`）。注意 panic 发生在 `tokio::spawn` 的任务里，
/// 所以它**只**通过 `JoinHandle` 传出来，不会让测试进程失败——这正是要钉住的语义。
#[tokio::test]
async fn a_panicking_run_loop_is_reported() {
    let mut agent = Agent::supervise(async { panic!("run loop 炸了") });
    assert_eq!(
        agent.wait_for_abnormal_exit().await,
        Some(AgentExit::Panicked),
        "run 循环 panic 必须被报成异常结局"
    );
}

/// 对照：**跑着的** agent 不该被误报（`run` 是无限重连循环，连不上网关也是活着）。
#[tokio::test]
async fn a_running_agent_reports_no_abnormal_exit() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, _server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let mut agent = Agent::start(cfg).expect("启动应当成功");

    assert!(
        tokio::time::timeout(Duration::from_millis(300), agent.wait_for_abnormal_exit())
            .await
            .is_err(),
        "跑着的 agent 不该报异常结局"
    );
    agent.shutdown().await;
}

/// 规格（P3-5）：`Cancelled`（我们自己 `shutdown()` 关的）**不算**异常结局 ⇒ 调用方不必
/// 以非 0 退出；另外两种必须算。
#[test]
fn only_a_self_inflicted_stop_is_not_an_abnormal_exit() {
    assert_eq!(AgentExit::Cancelled.as_abnormal(), None);
    assert_eq!(
        AgentExit::LoopExited.as_abnormal(),
        Some(AgentExit::LoopExited)
    );
    assert_eq!(AgentExit::Panicked.as_abnormal(), Some(AgentExit::Panicked));
}

/// 规格（记录 P2-4）：**上游的重定向不许被跟随**。
///
/// 跟随的代价不是"多一跳"：307/308 会把方法与 **prompt 原样重发**到 `Location` 指定的地址
/// （内网服务、`169.254.169.254` 云元数据），并把那边的响应回给调用方。判据有两条，缺一不可：
/// ① 客户端拿到的是上游自己回的 307（而不是被跟随后的 200）；
/// ② "第二个服务器"**一次连接都没有**——这才是"prompt 没被送出去"。
#[tokio::test]
async fn the_upstream_client_does_not_follow_redirects() {
    let (victim, mut victim_rx) =
        one_shot_http("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nexfiltr".to_string()).await;
    let (attacker, _attacker_rx) = one_shot_http(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{victim}/steal\r\nContent-Length: 0\r\n\r\n"
        ))
        .await;

    let client = upstream_client().unwrap();
    let resp = client
        .post(format!("http://{attacker}/v1/chat/completions"))
        .body(r#"{"model":"m","messages":[{"role":"user","content":"TOPSECRET"}]}"#)
        .send()
        .await
        .expect("上游能连上，请求本身必须成功");

    assert_eq!(
        resp.status().as_u16(),
        307,
        "不跟随重定向：把上游自己的 3xx 原样返回，而不是替它去访问 Location"
    );

    // ② 关键判据：prompt 绝不得到达 Location 指向的地址
    if let Ok(Some(request)) =
        tokio::time::timeout(Duration::from_millis(500), victim_rx.recv()).await
    {
        panic!("agent 跟随了重定向：prompt 被送到 {victim}，请求内容：{request}");
    }
}

/// 规格（记录 P2-4 的另一半）：上游客户端**不读环境代理**。
///
/// ⚠️ 今天这条测试**通过的原因**是 `reqwest` 在本仓库关了默认特性、`system-proxy` 未启用
/// （`cargo tree -p reqwest -f "{f}"` 可复核），而不是因为 `.no_proxy()` 真的被验证了——
/// 特性没开时环境代理根本不会被读，观测不到差别。它的价值是**日后**：谁把 `reqwest` 的
/// 默认特性打开、又删掉 `upstream_client()` 里的 `.no_proxy()`，这条测试就会红。
#[tokio::test]
async fn the_upstream_client_ignores_environment_proxies() {
    let (proxy, mut proxy_rx) =
        one_shot_http("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".to_string()).await;
    let (upstream, _upstream_rx) =
        one_shot_http("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_string()).await;

    let saved = std::env::var("HTTP_PROXY").ok();
    std::env::set_var("HTTP_PROXY", format!("http://{proxy}"));
    let client = upstream_client().unwrap();
    let sent = client
        .post(format!("http://{upstream}/v1/chat/completions"))
        .body(r#"{"model":"m","messages":[{"role":"user","content":"TOPSECRET"}]}"#)
        .send()
        .await;
    match &saved {
        Some(v) => std::env::set_var("HTTP_PROXY", v),
        None => std::env::remove_var("HTTP_PROXY"),
    }

    let resp = sent.expect("必须直连上游成功（经代理会被拒）");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(
        proxy_rx.try_recv().is_err(),
        "prompt 不该出现在环境变量指定的代理上"
    );
}

/// 规格（记录 P2-3）：**闸门满了要排队**，而不是把请求放过去压垮本地 LLM。
#[tokio::test]
async fn the_concurrency_gate_queues_instead_of_admitting() {
    let mut gate = ConcurrencyGate::new(1).expect("max=1 应当有闸门");
    let held = gate.acquire().await; // 唯一许可，立刻拿到
    let second = {
        let fut = gate.acquire();
        tokio::pin!(fut);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut fut)
                .await
                .is_err(),
            "持有唯一许可时，第二次 acquire 不许成功"
        );
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), &mut fut)
            .await
            .expect("释放后应当立刻拿到许可")
    };
    assert_eq!(gate.queued(), 1, "等超 SLOT_WAIT_LOG_AFTER 要记一次排队");
    assert!(gate.last_log.is_some(), "排队要留下一条日志");
    drop(second);
}

/// 规格：`max_concurrency = 0` = **不限**（与网关侧 `0` 的语义一致）⇒ 不建闸门。
///
/// 这条钉的是"别把 0 当成 0 个许可"——那会让 agent 一个请求都不处理，比不设防更糟。
#[test]
fn a_zero_max_concurrency_builds_no_gate() {
    assert!(ConcurrencyGate::new(0).is_none(), "0 = 不限 ⇒ 没有闸门");
    assert!(ConcurrencyGate::new(4).is_some());
}

/// 规格：持续过载时**日志节流**（这个项目的日志单日 652MB），但排队计数照旧累加。
#[tokio::test]
async fn the_queue_log_is_throttled_while_the_counter_keeps_counting() {
    let mut gate = ConcurrencyGate::new(1).unwrap();
    let held = gate.acquire().await;
    let first_permit = {
        let fut = gate.acquire();
        tokio::pin!(fut);
        assert!(tokio::time::timeout(Duration::from_millis(150), &mut fut)
            .await
            .is_err());
        drop(held);
        tokio::time::timeout(Duration::from_secs(1), &mut fut)
            .await
            .expect("第一次排队应当拿到")
    };
    let first_log = gate.last_log.expect("第一次排队必须打日志");
    let second_permit = {
        let fut = gate.acquire();
        tokio::pin!(fut);
        assert!(tokio::time::timeout(Duration::from_millis(150), &mut fut)
            .await
            .is_err());
        drop(first_permit);
        tokio::time::timeout(Duration::from_secs(1), &mut fut)
            .await
            .expect("第二次排队应当拿到")
    };
    assert_eq!(gate.queued(), 2, "两次都超过阈值：计数要涨");
    assert_eq!(
        gate.last_log,
        Some(first_log),
        "同一个节流窗口内不得再打第二行"
    );
    drop(second_permit);
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

/// 规格（记录 P2-3，端到端）：**agent 自己执行它声明的 `max_concurrency`**。
///
/// 判据在上游侧：同时只有 1 个请求到达假上游。去掉 accept 路径上那道闸门后
/// `max_inflight` 会是 2——那正是"网关不守约（如配成 `0` = 不限）时，最多 1000 条并发
/// 全压进本地 LLM"的形状。判据放在上游而不是 agent 自己的计数上：agent 自述不算证据，
/// **真的只打了一个上游请求**才算。
#[tokio::test(flavor = "multi_thread")]
async fn the_agent_enforces_its_declared_max_concurrency_end_to_end() {
    use std::sync::atomic::Ordering;
    // 与 gateway 的 e2e 同一口径：让排队那条 WARN 在失败时看得见（rustls 的 debug 太吵）
    let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();

    let (upstream, max_inflight, served) = counting_upstream(Duration::from_millis(200)).await;
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server_with_handle(&ca, srv_cert, srv_key).await;
    let mut cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    cfg.max_concurrency = 1;
    cfg.upstream_base = upstream;
    // 心跳周期放大：本测试只活几百毫秒，别让"没人回心跳"把连接拆了（那是另一条测试的事）
    cfg.heartbeat_interval = Duration::from_secs(30);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let task = tokio::spawn(run(cfg, cc));

    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    // 两条请求流几乎同时发：闸门只该放一条过去。
    // 两个半边都必须**持有着**（第一版两个坑都踩了）：
    // ① drop `recv` 会停掉该方向，agent 写响应时报 "The Stream ID which was referenced is
    //    invalid"；
    // ② drop `send` 会给对端发 FIN —— agent 那边把"流结束"当**取消**，于是根本不发上游请求
    //    （`handle_stream` 直接 Ok 返回，而我们还在等下家服务）。
    let mut keep_recv = Vec::new();
    let mut keep_send = Vec::new();
    for request_id in 0..2u64 {
        let stream = gateway.open_bidirectional_stream().await.expect("开流");
        let (recv, mut send) = stream.split();
        keep_recv.push(recv);
        write_frame(
            &mut send,
            &Frame::ProxyRequest {
                request_id,
                method: "POST".into(),
                path: "/v1/chat/completions".into(),
                headers: vec![],
                body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
            },
        )
        .await
        .expect("写请求帧");
        keep_send.push(send);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while served.load(Ordering::SeqCst) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "两个请求没有都被服务：served={}",
            served.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        max_inflight.load(Ordering::SeqCst),
        1,
        "agent 必须自己执行 max_concurrency=1（没有闸门时这里会是 2）"
    );
    drop(keep_send);
    drop(keep_recv);
    task.abort();
}

/// 规格（记录 P3-16）：**非 ASCII（中文）响应头值必须原样回传给网关**。
///
/// 修好前 agent 回传上游响应头用的是 `v.to_str()`——它只认可见 ASCII，中文值会被**整条丢掉**
/// （不是变空串，是直接消失），于是客户端永远看不到这个头。判据放在**隧道帧**上：
/// 假网关读回 `ProxyResponseHead`，断言里面就是 `x-echo: 张三`。
#[tokio::test(flavor = "multi_thread")]
async fn a_utf8_response_header_survives_the_relay() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // 假上游：不管请求内容，回一个带中文响应头的 200
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let body = b"{}";
            let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Echo: 张三\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(body).await;
            let _ = sock.shutdown().await;
        }
    });

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, gw_send) = gw_stream.split();
    let mut gw_send = gw_send;
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 7,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    let task = tokio::spawn(handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        upstream_url,
        false,
    ));

    let mut reader = proto::io::FrameReader::new(gw_recv);
    let head = loop {
        match tokio::time::timeout(Duration::from_secs(5), reader.next())
            .await
            .expect("等响应头帧超时")
            .expect("读帧失败")
        {
            Some(Frame::ProxyResponseHead { headers, .. }) => break headers,
            Some(_) => continue,
            None => panic!("流在给出响应头之前就结束了"),
        }
    };
    assert!(
        head.iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("x-echo") && v == "张三"),
        "中文响应头必须原样回传，实际：{head:?}"
    );

    drop(gw_send);
    task.abort();
}

/// 规格（记录 P2-2）：**上游连不上时不许只给客户端一个"上游关了"的通用 502，
/// 也不许 agent 侧一行日志都没有**。
///
/// 判据两层：① 隧道里收到的是一条 `Frame::Error{code: 502}`，且消息**不含内网地址/端口**
/// （细节只进 agent 日志，别把内部拓扑透露给 API 调用方）；② 返回的错误链带上
/// `request_id` 与 `path`——accept 循环那行 `warn!("{e:#}")` 就是靠它说清"哪个请求"。
#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_upstream_reports_a_generic_502_and_a_contextual_error() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, gw_send) = gw_stream.split();
    let mut gw_send = gw_send;
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 9,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");

    // 上游指向一个必然拒绝连接的端口（本测试不监听它）
    let err = handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("上游连不上必须是 Err —— 以前这个 Err 被 spawn 处直接丢掉");

    // ① 客户端侧看到的是**点名原因但不含内部拓扑**的 502
    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    match frame {
        Frame::Error {
            request_id,
            code,
            message,
        } => {
            assert_eq!(request_id, Some(9));
            assert_eq!(code, 502, "上游不可达应当是 502");
            assert!(
                message.contains("local upstream"),
                "消息要点名是本地这一跳失败了：{message}"
            );
            assert!(
                !message.contains("127.0.0.1") && !message.contains(":1"),
                "不许把内网地址/端口写进客户端可见的错误里：{message}"
            );
        }
        other => panic!("期望 Frame::Error，实际：{other:?}"),
    }

    // ② 错误链带得起上下文（accept 循环打印的就是它）
    let chain = format!("{err:#}");
    assert!(
        chain.contains("request_id=9"),
        "错误链缺 request_id：{chain}"
    );
    assert!(
        chain.contains("/v1/chat/completions"),
        "错误链缺 path：{chain}"
    );
    drop(gw_send);
}

/// 规格（记录 P2-2 的另一条静默路径）：**方法非法的请求回 400，而不是静默变成 502**。
#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_method_is_rejected_with_400_instead_of_vanishing() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, gw_send) = gw_stream.split();
    let mut gw_send = gw_send;
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 11,
            method: "BAD METHOD".into(), // 含空格 ⇒ Method::from_bytes 必失败
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    let err = handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("非法方法必须是 Err");

    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    match frame {
        Frame::Error { code, message, .. } => {
            assert_eq!(code, 400, "非法方法是客户端的问题：{message}");
            assert!(message.contains("method"), "消息要指名道姓：{message}");
        }
        other => panic!("期望 Frame::Error，实际：{other:?}"),
    }
    assert!(format!("{err:#}").contains("request_id=11"));
    drop(gw_send);
}

/// 规格（P2-2 的第二轮缺口）：**accept 循环那行 `warn!("proxy stream failed")` 必须真的打出来**。
///
/// 既有两条（502 / 非法方法）都是**直接调 `handle_stream`**，于是只证明了"错误链带得上上下文"，
/// 而"调用方确实把它打了出来"这一步靠读码（`lib.rs` 里那行 warn）。这条走**真 accept 循环**：
/// 真跑 `run()`，让 `connect_once` 自己 accept 网关开的流、自己处理它的 Err。
///
/// 判据三层：客户端仍拿到 400（行为不变）→ 日志里有 `proxy stream failed` → 那行里带着
/// `request_id=21` 与路径（"哪个请求失败了"必须能从日志里读出来，这是 P2-2 的全部意义）。
#[tokio::test(flavor = "current_thread")]
async fn the_accept_loop_reports_a_failed_proxy_stream_with_its_context() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) =
        test_server_that_serves_register_and_returns_the_connection(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let agent = tokio::spawn(run(cfg, cc));

    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");
    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    // 含空格的方法名 ⇒ `Method::from_bytes` 必失败 ⇒ `handle_stream` 走 Err 分支（确定性，不碰上游）
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 21,
            method: "BAD METHOD".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    // 行为不变：客户端拿到的仍是 400
    let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    match reply {
        Frame::Error { code, .. } => assert_eq!(code, 400, "非法方法仍是客户端问题"),
        other => panic!("期望 Frame::Error，实际：{other:?}"),
    }

    // 关键断言：那行 warn 真的出现了，而且带得上"哪个请求、哪条路径"
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut text = String::new();
    while tokio::time::Instant::now() < deadline {
        text = logs.text();
        if text.contains("proxy stream failed") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        text.contains("proxy stream failed"),
        "accept 循环必须报告这条失败（P2-2 修的就是它以前被 `let _ =` 吞掉）：\n{text}"
    );
    assert!(
        text.contains("request_id=21") && text.contains("/v1/chat/completions"),
        "那行 warn 必须能说清是哪个请求、哪条路径：\n{text}"
    );

    agent.abort();
}

/// 规格（P2-2 的第二轮缺口）：**`cancelled` 这条 `request_log` 也要真的打出来**。
///
/// 既有那条只覆盖成功路径的 received / responded / done。取消路径的判据有两半，缺一不可：
/// 客户端必须收到 `499 cancelled by client`（而不是通用 502），agent 侧必须留下
/// `proxy request cancelled by client` —— 否则"这个请求为什么没了"在两侧都查不出来。
#[tokio::test(flavor = "current_thread")]
async fn a_cancelled_request_logs_its_own_line_and_answers_499() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 一个"接了不答"的上游：agent 停在等响应头上，取消正好落在**响应之前**那个 select 分支
    let hang = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑本地端口");
    let hang_addr = hang.local_addr().expect("取端口");
    tokio::spawn(async move {
        if let Ok((conn, _)) = hang.accept().await {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(conn);
        }
    });

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");
    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 33,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");
    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    // `request_log = true`：这条测试要看的就是那条 INFO
    let task = tokio::spawn(handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        format!("http://{hang_addr}"),
        true,
    ));

    // 先让请求真的打到上游，再发取消（否则测到的是别的路径）
    tokio::time::sleep(Duration::from_millis(200)).await;
    write_frame(&mut gw_send, &Frame::Cancel { request_id: 33 })
        .await
        .expect("写取消帧");

    let reply = tokio::time::timeout(Duration::from_secs(5), FrameReader::new(gw_recv).next())
        .await
        .expect("等取消回帧超时")
        .expect("读帧失败")
        .expect("应当有一条回帧");
    match reply {
        Frame::Error {
            request_id,
            code,
            message,
        } => {
            assert_eq!(request_id, Some(33), "取消回帧要能对上请求");
            assert_eq!(code, 499, "客户端取消不是服务端错误：{message}");
            assert!(
                message.contains("cancelled by client"),
                "文案要说清是客户端取消的：{message}"
            );
        }
        other => panic!("取消应当回 499 的 Frame::Error，实际：{other:?}"),
    }
    task.await
        .expect("handle_stream 不该 panic")
        .expect("取消是正常收尾，不该是 Err");

    let text = logs.text();
    assert!(
        text.contains("proxy request received"),
        "取消之前先要有 received：\n{text}"
    );
    assert!(
        text.contains("proxy request cancelled by client"),
        "取消路径必须留下它自己那条 INFO（P2-2；以前 request_log 是空操作）：\n{text}"
    );
}

/// 规格（P3-2）：**方法非法这条 `Err` 路径不能把监听任务留在那儿**。
///
/// 修复前，方法守卫排在 `tokio::spawn` 监听任务**之后**，而 `listener.abort()` 只在成功
/// 路径的末尾调用 ⇒ 这条 `return` 泄漏一个仍持有读半边的任务：它继续消费网关发来的帧
/// （于是下面这个探测里"网关再写帧"一直成功）。修复后读半边随作用域一起丢弃，QUIC 会回过
/// STOP_SENDING，网关这边的写就会失败。
#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_method_leaves_no_listener_holding_the_stream() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 12,
            method: "BAD METHOD".into(), // 含空格 ⇒ Method::from_bytes 必失败
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    let err = handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("非法方法必须是 Err");
    assert!(format!("{err:#}").contains("request_id=12"));

    // 先读掉那条 400（行为本身由上一个用例钉住），reader **留着不 drop**：免得"网关这半边
    // 关掉读方向"变成干扰项。
    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    assert!(matches!(frame, Frame::Error { code: 400, .. }), "{frame:?}");

    // 关键探测：故意挑一个**监听者会忽略**的帧型（Cancel/EOF 会让泄漏的监听任务自己退出，
    // 那就测不出泄漏了）。修复前写会一直成功（对端还有人在收），修复后应当变成 Err。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut stopped = false;
    while tokio::time::Instant::now() < deadline {
        let probe = write_frame(
            &mut gw_send,
            &Frame::Heartbeat {
                agent_id: "probe".into(),
                inflight: 0,
            },
        )
        .await;
        if probe.is_err() {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stopped,
        "非法方法返回后，agent 不该还留着持有读半边的监听任务（对端仍在收帧）"
    );
    drop(gw_send);
}

/// 规格（P3-2 的另一半）：**监听任务被 spawn 之后**的任何返回路径（这里是"上游连不上"，
/// 方法合法 ⇒ 走的是正常 spawn 分支）也必须把监听任务收掉。
///
/// 这条是 `AbortOnDrop` 守卫的**使用点**证明：把守卫换成裸 `tokio::spawn` 而保留"方法守卫
/// 上移"，只有这条会红（前一条探针测不到，因为那条路径压根不再 spawn）。
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_forward_leaves_no_listener_holding_the_stream() {
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 13,
            method: "POST".into(), // 合法 ⇒ 会走到 spawn 监听任务那一步
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    // 上游指向没人监听的端口 ⇒ forward 失败 ⇒ 返回 502 那条 Err
    handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        "http://127.0.0.1:1".into(),
        false,
    )
    .await
    .expect_err("上游连不上必须是 Err");

    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等错误帧超时")
        .expect("读帧失败")
        .expect("应当有一条错误帧");
    assert!(matches!(frame, Frame::Error { code: 502, .. }), "{frame:?}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut stopped = false;
    while tokio::time::Instant::now() < deadline {
        if write_frame(
            &mut gw_send,
            &Frame::Heartbeat {
                agent_id: "probe".into(),
                inflight: 0,
            },
        )
        .await
        .is_err()
        {
            stopped = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        stopped,
        "转发失败返回后，agent 不该还留着持有读半边的监听任务（对端仍在收帧）"
    );
    drop(gw_send);
}

/// 规格（P3-3）：**"网关提前半关请求流"必须是可观测的**。
///
/// 取消的契约是"网关显式发 `Frame::Cancel`"；而 agent 的监听任务把请求方向的**干净 EOF**
/// 也当成取消（兜底）。今天网关每条放弃在途请求的路径都先发 Cancel 再 `finish()`，所以 EOF
/// 兜底只在"响应还没开始"时被触发就意味着**契约被破坏**——这条测试就钉住"那一刻要留下 warn"。
///
/// 用 `current_thread` runtime：日志捕获依赖 `set_default` 的线程局部性（见 `CapturedLogs`）。
#[tokio::test(flavor = "current_thread")]
async fn a_gateway_half_close_before_the_response_leaves_a_warning() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 一个"接了不答"的上游：agent 会停在等响应头上，于是下面的半关一定发生在响应之前。
    let hang = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑本地端口");
    let hang_addr = hang.local_addr().expect("取端口");
    tokio::spawn(async move {
        if let Ok((conn, _)) = hang.accept().await {
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(conn);
        }
    });

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 14,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");
    // **故意不发 Cancel 就半关写半边** —— 契约违背现场。
    let _ = gw_recv;
    tokio::io::AsyncWriteExt::shutdown(&mut gw_send)
        .await
        .expect("半关应当成功");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    // 让 handle_stream 去等那个不答的上游；监听任务同时看到 FIN。
    let handle = tokio::spawn(async move {
        handle_stream(
            agent_stream,
            upstream_client().unwrap(),
            format!("http://{hang_addr}"),
            false,
        )
        .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut text = String::new();
    while tokio::time::Instant::now() < deadline {
        text = logs.text();
        if text.contains("before the response") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        text.contains("before the response"),
        "网关在响应之前半关请求流 = 契约违背，必须留下 warn；捕获到的日志：\n{text}"
    );

    handle.abort();
}

/// 规格（P3-3 的对照）：**响应已经开始之后对端半关 = 合法收尾，不该报契约违背。**
///
/// 与上一条互为对照：上一条钉"响应前 EOF ⇒ warn"，这条钉"响应后 EOF ⇒ 不 warn"；
/// 只满足一条的实现都是错的（永远 warn = 噪声，永远不 warn = 漏掉契约违背）。
/// 关键在时序：FIN 必须在**监听任务还活着**的时候到达（响应头已写出、响应体还在流），
/// 否则测试会因为"监听任务已被 AbortOnDrop 收掉"而假绿。
#[tokio::test(flavor = "current_thread")]
async fn a_gateway_half_close_after_the_response_is_not_a_warning() {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_env_filter("info")
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    // 一个"只回响应头、不结束响应体"的上游：agent 会停在流式回传阶段。
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("绑本地端口");
    let up_addr = upstream.local_addr().expect("取端口");
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        if let Ok((mut conn, _)) = upstream.accept().await {
            let mut buf = [0u8; 2048];
            let _ = conn.read(&mut buf).await;
            // 没有 content-length ⇒ 流式；**先只发头**，连接保持打开
            let _ = conn
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\r\n")
                .await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });

    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 15,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    let handle = tokio::spawn(async move {
        handle_stream(
            agent_stream,
            upstream_client().unwrap(),
            format!("http://{up_addr}"),
            false,
        )
        .await
    });

    // 等 agent 把响应头写出来（= `response_started` 已置位），再半关。
    let mut reader = proto::io::FrameReader::new(gw_recv);
    let frame = tokio::time::timeout(Duration::from_secs(5), reader.next())
        .await
        .expect("等响应头超时")
        .expect("读帧失败")
        .expect("应当有一条帧");
    assert!(
        matches!(frame, Frame::ProxyResponseHead { .. }),
        "先到的应当是响应头：{frame:?}"
    );

    tokio::io::AsyncWriteExt::shutdown(&mut gw_send)
        .await
        .expect("半关应当成功");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let text = logs.text();
    assert!(
        !text.contains("before the response"),
        "响应之后的半关是合法收尾，不该报契约违背；捕获到的日志：\n{text}"
    );

    handle.abort();
}

/// 跑完一次**成功**的代理请求（假网关 → agent → 假上游），返回时 agent 侧已经写完 done。
async fn run_one_proxied_request(request_log: bool) {
    let (upstream, _max_inflight, _served) = counting_upstream(Duration::from_millis(1)).await;
    let (ca, srv_cert, srv_key, cli_cert, cli_key) = gen_pki();
    let (addr, mut server_handles) = test_server(&ca, srv_cert, srv_key).await;
    let cfg = test_agent_config(addr, ca.clone(), cli_cert, cli_key);
    let cc = tls::rustls_client_tls(
        &cfg.ca_cert,
        cfg.client_cert.clone(),
        cfg.client_key.clone_key(),
    )
    .unwrap();
    let (_agent_handle, mut agent_acceptor) = connect_for_test_with_acceptor(&cfg, cc).await;
    let mut gateway = tokio::time::timeout(Duration::from_secs(5), server_handles.recv())
        .await
        .expect("agent 应当连上")
        .expect("假网关应当拿到连接句柄");

    let gw_stream = gateway.open_bidirectional_stream().await.expect("开流");
    let (_gw_recv, mut gw_send) = gw_stream.split();
    write_frame(
        &mut gw_send,
        &Frame::ProxyRequest {
            request_id: 21,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: vec![],
            body: bytes::Bytes::from_static(br#"{"model":"m"}"#),
        },
    )
    .await
    .expect("写请求帧");

    let agent_stream = tokio::time::timeout(
        Duration::from_secs(5),
        agent_acceptor.accept_bidirectional_stream(),
    )
    .await
    .expect("5s 内应当收到流")
    .expect("accept 不该失败")
    .expect("应当是 Some(stream)");
    handle_stream(
        agent_stream,
        upstream_client().unwrap(),
        upstream,
        request_log,
    )
    .await
    .expect("这次请求应当成功（假上游会正常回 200）");
    // `gw_recv`/`gw_send` 在这里 drop：请求已经跑完，不需要再读响应帧
}

/// 规格（记录 P2-2 的另一半）：**`request_log`（默认 true）不是空操作**——成功路径要按文档
/// 承诺打出 `received` / `responded` / `done`；关掉之后这三条一条都不许有。
///
/// 用 `current_thread` runtime：捕获依赖 `set_default` 的线程局部性（见 `CapturedLogs`）。
#[tokio::test(flavor = "current_thread")]
async fn request_log_controls_the_success_path_info_lines() {
    for (enabled, want) in [(true, true), (false, false)] {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_env_filter("info")
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        run_one_proxied_request(enabled).await;
        let text = logs.text();
        for line in [
            "proxy request received",
            "upstream responded",
            "proxy request done",
        ] {
            assert_eq!(
                text.contains(line),
                want,
                "request_log={enabled} 时 `{line}` 该不该出现不符；捕获到的日志：\n{text}"
            );
        }
    }
}
