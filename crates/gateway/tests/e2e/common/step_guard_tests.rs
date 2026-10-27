//! `STEP_TIMEOUT` 与有界 client 的夹具自检。
//!
//! 模块名保持 `common::step_guard_tests`，测试名不变。

use super::{bounded_within, test_client_within, STEP_TIMEOUT};
use std::time::Duration;

/// 守卫**不能吞掉结果**：正常完成的步骤原样返回。
#[tokio::test]
async fn a_step_that_finishes_returns_its_value() {
    let v = bounded_within(Duration::from_secs(5), "fast step", async { 7u8 }).await;
    assert_eq!(v, 7);
}

/// [`STEP_TIMEOUT`] 的取值不是随手挑的，两侧都是硬约束——把它钉住，免得日后有人
/// 顺着"再宽松点免抖动"把它调到 nextest 周期之上，于是失败又被报成 TIMEOUT、
/// 步骤名这个唯一有用的信息再次丢掉。
#[test]
fn the_step_window_sits_between_the_gateway_bound_and_the_nextest_period() {
    // 收尾窗口是 `gateway.rs` 的私有常量 END_EVENT_WINDOW（1s），按 1s 记。
    let worst_gateway_bound = gateway::Options::DEFAULT_SHUTDOWN_GRACE
        + gateway::Options::DEFAULT_SHUTDOWN_FLUSH_TIMEOUT
        + Duration::from_secs(1);
    assert!(
        STEP_TIMEOUT > worst_gateway_bound,
        "窗口 {STEP_TIMEOUT:?} 必须高于网关关闭路径的最坏上限 {worst_gateway_bound:?}"
    );
    assert!(
        STEP_TIMEOUT < Duration::from_secs(60),
        "窗口 {STEP_TIMEOUT:?} 必须低于 nextest 的 slow-timeout 周期(60s)，\
         否则失败会被 TIMEOUT 抢先、丢掉步骤名"
    );
}

/// 守卫自身的哨兵：卡住的步骤必须**带着步骤名**失败，而不是静静挂住。
///
/// 用 `bounded_within` 传毫秒级窗口，生产值 [`STEP_TIMEOUT`] 只在被测代码里生效
/// （30s 的窗口没法进单元测试）。
#[tokio::test]
#[should_panic(expected = "stalled step")]
async fn a_stalled_step_fails_with_its_name_instead_of_hanging() {
    bounded_within(
        Duration::from_millis(20),
        "stalled step",
        std::future::pending::<()>(),
    )
    .await;
}

/// **复现被报告的那个症状**：对端 accept 了连接却永远不说话（TLS 握手永远等不到
/// ServerHello），客户端一步卡死。这正是 `https::e2e_https_public_entry` 那次
/// 180s TIMEOUT 的形状——`slow-timeout` 只能告诉你"有个测试卡了 180s"，
/// 而带上守卫之后失败会点名是**哪一步**卡了。
#[tokio::test]
#[should_panic(expected = "GET /healthz over TLS")]
async fn a_black_hole_listener_fails_the_step_that_talks_to_it() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // accept 之后把 socket **留着不放**：关闭会变成 EOF（客户端立刻报错），
    // 而这里要的是"连上了但永远没有响应"。
    tokio::spawn(async move {
        let _held = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });

    // reqwest 的 no-provider 变体要求进程默认 provider 已在（见 proto::crypto 的说明）。
    proto::crypto::provider();
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    bounded_within(
        Duration::from_millis(300),
        "GET /healthz over TLS",
        client.get(format!("https://{addr}/healthz")).send(),
    )
    .await
    .unwrap();
}

/// 规格（`PROJECT_SCAN` P2-17 的剩余部分）：**裸 client 会一直等下去，
/// 带总超时的 client 会自己放弃**。
///
/// 前半句是这个缺陷本身（e2e 里绝大多数请求以前就是裸 client），后半句是
/// [`test_client`] 的契约。窗口取毫秒级，所以这条哨兵本身是毫秒级的。
#[tokio::test]
async fn a_bare_client_waits_forever_while_a_bounded_one_gives_up() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // 黑洞：accept 之后既不读也不写，永远不回响应
    tokio::spawn(async move {
        let _held = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let url = format!("http://{addr}/healthz");

    // 这条测试**不启网关**（只有黑洞监听器），没有别的东西替它装 rustls provider ⇒
    // 自己装，否则下面那个裸 `Client::new()` 直接 panic "No provider set"（见 proto::crypto）。
    // 启了网关的测试不用管：建 rustls 配置时 rustls 会自动装上那个唯一 provider。
    proto::crypto::provider();

    // ① 裸 client：500ms 的外层窗口内不会返回（这就是缺陷）
    // e2e-bare-client: 哨兵本身要证明"裸 client 对黑洞连接不会自己放弃"，必须不加超时
    let bare = reqwest::Client::new();
    let hung = tokio::time::timeout(Duration::from_millis(500), bare.get(&url).send()).await;
    assert!(
        hung.is_err(),
        "前提：裸 client 对黑洞连接不会自己放弃（否则这条哨兵没测到东西）"
    );

    // ② 带窗口的 client：在窗口量级返回错误，而不是陪着一起卡住
    let t0 = std::time::Instant::now();
    let gave_up = test_client_within(Duration::from_millis(200))
        .get(&url)
        .send()
        .await;
    assert!(gave_up.is_err(), "总超时到点必须报错");
    assert!(
        t0.elapsed() < Duration::from_millis(400),
        "应在超时量级返回，实际 {:?}",
        t0.elapsed()
    );
}

/// 规格（P2-17 的**机械守卫**）：e2e 里每一个裸 reqwest client（`Client::new()`，
/// 以及内部就是默认 client 的 `reqwest::get`）都必须带 `e2e-bare-client:` 标记说明理由。
///
/// 为什么值得一条守卫：这条不变量原本只靠代码评审维持 —— 2026-09-23 的审计正是这样发现
/// `lifecycle.rs`/`stalls.rs` 里又冒出裸 client 的（记录写完之后才加进来的提交），而 e2e 是
/// `#[serial]`、**`cargo test` 没有 per-test 超时**，一处卡住 = 整个套件无限期挂起
/// （nextest 只是被 `slow-timeout` 兜住，180 s 后才杀）。"本该完成"的一步请用
/// [`test_client()`]；确实要卡住的，加标记并把理由写清。
///
/// **两条 needle**（重扫 F2）：第一版只盯 `Client::new()`，于是 `reqwest::get` 这条更隐蔽的
/// 路（一行就能写出无界等待，内部同样是默认无超时的 client）整类漏了过去 —— 它当时就藏在
/// 共享 helper `metric_gauge` 里，被 `head_timeout`/`write_backpressure`/`stalls` 多条 e2e 调用。
#[test]
fn bare_reqwest_clients_carry_a_reason_marker() {
    // 拆开拼，免得守卫在**自己的源码里**匹配到自己（两个 needle 都由片段拼出来）。
    let needles = [
        format!("{}{}", "reqwest::Client::", "new()"),
        format!("{}{}", "reqwest::", "get("),
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/e2e");
    // **递归**扫描：共享夹具搬进 `tests/e2e/common/` 之后，只读顶层会静默漏掉
    // `common/raw_agent.rs` 与哨兵本身，`marked >= 4` 的断言恰好会红——但下一次如果
    // 只搬走一处，这个守卫就会"绿着失效"。递归是这个守卫能跟着文件移动的唯一前提。
    fn collect_sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read tests/e2e") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_sources(&path, out);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    let mut sources = Vec::new();
    collect_sources(&dir, &mut sources);

    let mut marked = 0usize;
    let mut offenders: Vec<String> = Vec::new();
    for path in sources {
        let text = std::fs::read_to_string(&path).expect("read source");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !needles.iter().any(|needle| line.contains(needle)) {
                continue;
            }
            let from = i.saturating_sub(3);
            if lines[from..=i]
                .iter()
                .any(|l| l.contains("e2e-bare-client:"))
            {
                marked += 1;
            } else {
                offenders.push(format!("{}:{}", path.display(), i + 1));
            }
        }
    }
    assert!(
        marked >= 4,
        "前提：刻意保持裸的 client 至少 4 处（现在只标了 {marked} 处）——守卫别被改瞎"
    );
    assert!(
        offenders.is_empty(),
        "这些裸 client 没说理由：{offenders:#?}\n\
         「本该完成」的一步用 `test_client()`；确实要卡住的加 `// e2e-bare-client: <理由>`"
    );
}
