//! agent 测试：`Agent` 的结局语义（run 循环返回/panic/主动关闭）。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

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
