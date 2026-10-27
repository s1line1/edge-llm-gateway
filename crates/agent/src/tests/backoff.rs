//! agent 测试：重连退避、抖动与 run 循环的退避增长。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

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
