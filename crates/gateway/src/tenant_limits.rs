//! 租户级并发票：每个 tenant 的在途请求数上限。
//!
//! 与 HTTP 全局准入不同，tenant 只有在认证之后才知道，所以票是在 `proxy::prepare` 里
//! 领取、由 `ForwardCtx` 持有到响应 body 结束的。`limit == 0` 表示不限，返回一个
//! no-op 票，保证调用方不需要分支。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

use crate::sync::lock_or_recover;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TenantAtCapacity;

/// 归还 tenant 并发槽位；`counter == None` 表示该 tenant 当前不限并发。
pub(crate) struct TenantSlot {
    counter: Option<Arc<AtomicU32>>,
}

impl Drop for TenantSlot {
    fn drop(&mut self) {
        if let Some(counter) = &self.counter {
            counter.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

#[derive(Clone, Default)]
pub struct TenantLimiter {
    inner: Arc<Mutex<HashMap<String, Arc<AtomicU32>>>>,
}

impl TenantLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 领取一个 tenant 并发票；`limit == 0` 返回 no-op 票。
    pub(crate) fn try_enter(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<TenantSlot, TenantAtCapacity> {
        if limit == 0 {
            return Ok(TenantSlot { counter: None });
        }
        let counter = {
            let mut inner = lock_or_recover(&self.inner);
            inner
                .entry(tenant_id.to_string())
                .or_insert_with(|| Arc::new(AtomicU32::new(0)))
                .clone()
        };
        counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (n < limit).then_some(n + 1)
            })
            .map_err(|_| TenantAtCapacity)?;
        Ok(TenantSlot {
            counter: Some(counter),
        })
    }

    pub fn evict(&self, tenant_id: &str) -> bool {
        lock_or_recover(&self.inner).remove(tenant_id).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_limit_is_a_noop_slot() {
        let limiter = TenantLimiter::new();
        let _a = limiter.try_enter("t", 0).unwrap();
        let _b = limiter.try_enter("t", 0).unwrap();
    }

    #[test]
    fn tenant_limits_are_independent_and_released_on_drop() {
        let limiter = TenantLimiter::new();
        let a = limiter.try_enter("a", 1).unwrap();
        assert!(limiter.try_enter("a", 1).is_err());
        let b = limiter.try_enter("b", 1).unwrap();
        drop(a);
        assert!(limiter.try_enter("a", 1).is_ok());
        drop(b);
        assert!(limiter.evict("a"));
        assert!(limiter.try_enter("a", 1).is_ok());
    }
}
