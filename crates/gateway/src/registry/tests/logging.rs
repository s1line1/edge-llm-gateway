//! registry 测试：测试日志捕获夹具的自检。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享夹具与导入。

use super::*;

/// 自检：确认日志捕获**真的**在工作（否则后面那条用例的断言全是空的）。
#[tokio::test(flavor = "current_thread")]
async fn capture_logs_selftest() {
    let (_guard, logs) = capture_logs();
    tracing::warn!("SELFTEST-MARKER");
    let text = captured_text(&logs);
    assert!(text.contains("SELFTEST-MARKER"), "捕获没工作：{text:?}");
}
