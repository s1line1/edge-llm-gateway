use super::*;
use crate::{metrics::Metrics, registry::Registry, shutdown::ShutdownPhase};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

fn policy(allow_legacy: bool) -> RegistrationPolicy {
    RegistrationPolicy::new(allow_legacy, Arc::new(|_, _| Ok(())))
}

/// 起一个本地 s2n-quic server：只为把 accept 循环跑起来，不接任何连接。
/// 证书自签、不做客户端认证——本测试不握手，TLS 只要求能构造出配置。
fn test_server() -> s2n_quic::Server {
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_der = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    tls.alpn_protocols = vec![proto::ALPN.to_vec()];

    s2n_quic::Server::builder()
        // 传入的已经是 Provider，所以这里的错误类型是 Infallible
        // （s2n-quic/src/provider/macros.rs 的 blanket impl），unwrap 不会 panic。
        .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(tls)))
        .unwrap()
        .with_io("127.0.0.1:0")
        .unwrap()
        .start()
        .unwrap()
}

/// 规格：隧道入口「是否仍在接受新 agent」必须能从进程外看见——入口停摆时进程照常运行、
/// HTTP 入口照常服务、systemd 显示健康，网关日志里可能一行都没有，只有
/// `hlmg_quic_accepting` 能用来告警。
///
/// 本测试盯住守卫的两端：进入 accept 循环后置 1；任务结束后必须回到 0。
/// 后半段才是这条规格真正的保险：`mark_accepting` 用 Drop 而不是「循环之后写一句」，
/// 正因为任务被 abort（`Gateway::shutdown` 就是这么关停的）或 panic 时，
/// 循环之后的语句根本不会执行——那种情况下 gauge 会永远卡在 1，等于谎报健康。
#[tokio::test]
async fn accept_loop_marks_entry_accepting_and_releases_on_abort() {
    let metrics = Metrics::default();
    assert_eq!(metrics.quic_accepting(), 0, "未启动时不应是「接受中」");

    let (_shutdown_tx, shutdown_rx) = watch::channel(ShutdownPhase::Running);
    let task = tokio::spawn(accept_loop(
        test_server(),
        Registry::default(),
        metrics.clone(),
        policy(false),
        1024,
        Duration::from_secs(1),
        shutdown_rx,
        None,
    ));

    // 循环进入等待后应标记为「接受中」
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metrics.quic_accepting() == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(metrics.quic_accepting(), 1, "运行中应标记为接受中");

    // abort = 关停路径；await 到任务真正结束再断言，否则会读到竞态中间态。
    task.abort();
    let _ = task.await;
    assert_eq!(
        metrics.quic_accepting(),
        0,
        "任务被 abort 后必须回到 0（Drop 守卫的全部意义），否则会一直谎报「接受中」"
    );
}

/// 规格（复扫 D5）：**发送端消失（= `Gateway` 被 drop）时，接受循环自己要退出**，
/// 而不是等 abort 落下来。
///
/// 判据是"任务在 1s 内结束"与"gauge 回到 0"两件：前者证明循环真的观察到了那个信号
/// （`Drop` 只 abort 三个主任务句柄，派生任务全靠它），后者证明退出路径同样走了
/// `_accepting` 守卫。
#[tokio::test]
async fn accept_loop_returns_when_the_gateway_is_gone() {
    let metrics = Metrics::default();
    let (shutdown_tx, shutdown_rx) = watch::channel(ShutdownPhase::Running);
    let task = tokio::spawn(accept_loop(
        test_server(),
        Registry::default(),
        metrics.clone(),
        policy(false),
        1024,
        Duration::from_secs(1),
        shutdown_rx,
        None,
    ));

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while metrics.quic_accepting() == 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(metrics.quic_accepting(), 1, "前提：循环已经跑起来了");

    // `Gateway` 被 drop：唯一发送端消失，接收端看到 `Err`
    drop(shutdown_tx);
    let finished = tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("通道关闭后接受循环必须自己退出（不能等 abort）");
    assert!(finished.is_ok(), "任务应当正常结束而不是 panic");
    assert_eq!(metrics.quic_accepting(), 0, "退出后 gauge 必须回到 0");
}

// ⚠️ 覆盖退化，需要记号：quinn → s2n-quic 之后，这条测试少了一半。
//
// quinn 版还能测「端点被关闭 → accept() 返回 None → 循环结束并留下 error! 痕迹」，
// 靠的是 `endpoint.close(0u32.into(), b"test close")`。s2n-quic 没有对应物：
// `Server` 没有 close()，也没有可外传的关闭句柄——公开方法只有
// builder/accept/poll_accept/local_addr（s2n-quic-1.88.0/src/server.rs），
// 而 accept_loop 又是**按值**拿走 Server 的，测试侧拿不到任何能把 accept() 推成 None 的把手。
// （官方那个能造 I/O 故障的 provider 在 provider/io/testing.rs，但被
//  `#[cfg(any(test, feature = "unstable-provider-io-testing"))]` 挡着，要开 unstable feature
//  才可用——那已经超出「只改测试代码」的范围。）
//
// 因此 `accept_loop` 里那条 error!（"QUIC 隧道入口已停止接受连接…"）目前**只由代码审查
// 保证，不再由测试保证**。要恢复覆盖，得先给测试留个把手（都属非测试代码）：
//   ① 让 accept_loop 接收一个可被外部关闭的东西（例如自建包装类型持有 Server，
//      Gateway 与测试各持一份句柄）；
//   ② 或者用自定义 io provider（绑定后立即报错）构造 accept() == None 的场景。
// 在此之前，「入口停摆必须留下痕迹」这条规格只剩 abort 路径有测试覆盖。

/// 规格：`Gateway::start` 的不变量——**返回时隧道入口必须已经「接受中」**。
///
/// 两个方向都要：没人标记时到点返回 `false`（不能把启动卡死）；有人稍后标记时必须**等它**
/// （这里让标记延迟 60ms，断言确实等了 ≥50ms——否则"碰巧第一次读就是 1"也能通过）。
#[tokio::test]
async fn await_accepting_waits_for_the_mark_and_gives_up_on_timeout() {
    let metrics = Metrics::default();
    assert!(
        !await_accepting(&metrics, Duration::from_millis(20)).await,
        "没人标记时应当到点返回 false，而不是卡住 start()"
    );

    let delayed = metrics.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        let _guard = delayed.mark_accepting();
        std::future::pending::<()>().await; // 守卫要一直活着
    });

    let started = tokio::time::Instant::now();
    assert!(
        await_accepting(&metrics, Duration::from_secs(5)).await,
        "标记出现后应当返回 true"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(50),
        "必须在**等**标记，实测只花了 {:?}",
        started.elapsed()
    );
}
