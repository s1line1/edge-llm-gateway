/// 测试用的日志捕获（`#[cfg(test)]`）：断言"某一行日志到底有没有打"。
///
/// 为什么要有它：`request_log` 与启动期提醒这类承诺本身就是"打不打那几条日志"，而仓库没有
/// （也不打算为一条日志引入）tracing 捕获依赖——标准库 + `tracing-subscriber` 的 `MakeWriter`
/// 就够。提到 crate 级是因为**多个**测试模块要用（`lib::tests` 与 `config::tests`）。
///
/// ⚠️ 配合 `flavor = "current_thread"` 用：`set_default` 是**线程局部**的，多线程 runtime 里
/// 任务可能被调度到别的 worker 上，事件就抓不到了。
use std::sync::Arc;

#[derive(Clone, Default)]
pub(crate) struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl CapturedLogs {
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

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
