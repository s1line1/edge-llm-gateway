//! Explicit ownership and reaping for derived Tokio tasks.
//!
//! This is intentionally a small utility, not structured-concurrency framework: a task can be
//! detached at a lifecycle boundary (HTTP connection tasks outlive the accept loop), aborted at a
//! hard stop, or reaped as it finishes.

use std::future::Future;
use std::sync::Mutex;

use tokio::task::JoinSet;
use tracing::warn;

/// A named collection of tasks with explicit abort/detach semantics.
///
/// `JoinSet` aborts its remaining tasks when dropped. That is correct for the QUIC accept loop
/// and the forward-task owner, but not for HTTP connection tasks (they must outlive the accept
/// loop during draining); those call [`Self::detach_all`] first.
pub(crate) struct TaskScope {
    name: &'static str,
    tasks: Mutex<JoinSet<()>>,
}

impl TaskScope {
    pub(crate) fn new(name: &'static str) -> Self {
        Self {
            name,
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    /// Spawn a task into the scope. Panics inside the task are observed by [`Self::reap`].
    pub(crate) fn spawn<F>(&self, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.tasks
            .lock()
            .expect("task scope lock poisoned")
            .spawn(future);
    }

    /// Reap all currently finished tasks. Call from an owning loop; completed `JoinSet` entries
    /// otherwise accumulate until the next reap.
    pub(crate) fn reap(&self) {
        let mut tasks = self.tasks.lock().expect("task scope lock poisoned");
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result {
                warn!(scope = self.name, error = %e, "scoped task failed");
            }
        }
    }

    /// Number of tasks still owned by the scope, including finished-but-unreaped tasks.
    pub(crate) fn live(&self) -> usize {
        self.tasks.lock().expect("task scope lock poisoned").len()
    }

    /// Abort every task. Used only at a hard-stop boundary.
    pub(crate) fn abort_all(&self) {
        let mut tasks = self.tasks.lock().expect("task scope lock poisoned");
        tasks.abort_all();
        while tasks.try_join_next().is_some() {}
    }

    /// Give up ownership without aborting: tasks continue detached. Used when HTTP connection
    /// tasks must outlive the accept loop during graceful draining.
    pub(crate) fn detach_all(&self) {
        self.tasks
            .lock()
            .expect("task scope lock poisoned")
            .detach_all();
    }
}

/// Detach all tasks when dropped. This is the HTTP-entry counterpart to a `JoinSet` drop.
pub(crate) struct DetachOnDrop(pub TaskScope);

impl Drop for DetachOnDrop {
    fn drop(&mut self) {
        let live = self.0.live();
        self.0.detach_all();
        tracing::debug!(scope = self.0.name, live, "detached scoped tasks");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn scope_reaps_finished_and_aborts_remaining() {
        let scope = TaskScope::new("test");
        let done = std::sync::Arc::new(AtomicUsize::new(0));
        let d = done.clone();
        scope.spawn(async move {
            d.fetch_add(1, Ordering::SeqCst);
        });
        tokio::time::sleep(Duration::from_millis(10)).await;
        scope.reap();
        assert_eq!(done.load(Ordering::SeqCst), 1);
        assert_eq!(scope.live(), 0);

        scope.spawn(std::future::pending());
        assert_eq!(scope.live(), 1);
        scope.abort_all();
        tokio::task::yield_now().await;
        scope.reap();
        assert_eq!(scope.live(), 0);
    }

    #[tokio::test]
    async fn detach_keeps_a_task_alive_after_scope_drop() {
        let scope = TaskScope::new("detach");
        let flag = std::sync::Arc::new(AtomicUsize::new(0));
        let f = flag.clone();
        scope.spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            f.fetch_add(1, Ordering::SeqCst);
        });
        scope.detach_all();
        drop(scope);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(flag.load(Ordering::SeqCst), 1);
    }
}
