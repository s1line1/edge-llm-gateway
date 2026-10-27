//! 登录失败限流：按规范化用户名 5 次/60s，进程全局 60 次/60s。
//!
//! 与 API key 的令牌桶分开：失败计数只在登录路径上产生，且成功的登录会清掉该用户名的
//! 失败窗口；全局窗口保留，避免一个攻击者轮换用户名绕过单用户限制。

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::storage::hash::now_secs;
use crate::sync::lock_or_recover;

const USER_WINDOW_SECS: u64 = 60;
const USER_LIMIT: u32 = 5;
const GLOBAL_WINDOW_SECS: u64 = 60;
const GLOBAL_LIMIT: u32 = 60;

#[derive(Clone, Copy)]
struct Window {
    count: u32,
    reset_at: u64,
}

impl Window {
    fn fresh(now: u64, window: u64) -> Self {
        Self {
            count: 0,
            reset_at: now + window,
        }
    }

    fn active(&self, now: u64) -> bool {
        self.reset_at > now
    }

    fn blocked(&self, now: u64, limit: u32) -> bool {
        self.active(now) && self.count >= limit
    }

    fn retry_after(&self, now: u64) -> u64 {
        self.reset_at.saturating_sub(now).max(1)
    }
}

#[derive(Clone, Default)]
pub struct LoginLimiter {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Default)]
struct Inner {
    users: HashMap<String, Window>,
    global: Option<Window>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 登录前检查；返回 `Err(retry_after_secs)` 表示 429。
    pub fn check(&self, username: &str) -> Result<(), u64> {
        let now = now_secs();
        let inner = lock_or_recover(&self.inner);
        if let Some(global) = inner.global {
            if global.blocked(now, GLOBAL_LIMIT) {
                return Err(global.retry_after(now));
            }
        }
        if let Some(window) = inner.users.get(&normalize(username)) {
            if window.blocked(now, USER_LIMIT) {
                return Err(window.retry_after(now));
            }
        }
        Ok(())
    }

    /// 记录一次失败。调用方应先 `check`；这里仍会防御性重置过期窗口。
    pub fn record_failure(&self, username: &str) {
        let now = now_secs();
        let mut inner = lock_or_recover(&self.inner);
        let key = normalize(username);
        let entry = inner
            .users
            .entry(key)
            .or_insert_with(|| Window::fresh(now, USER_WINDOW_SECS));
        if !entry.active(now) {
            *entry = Window::fresh(now, USER_WINDOW_SECS);
        }
        entry.count = entry.count.saturating_add(1);
        let global = inner
            .global
            .get_or_insert_with(|| Window::fresh(now, GLOBAL_WINDOW_SECS));
        if !global.active(now) {
            *global = Window::fresh(now, GLOBAL_WINDOW_SECS);
        }
        global.count = global.count.saturating_add(1);
    }

    /// 成功登录清掉该用户名的失败窗口（全局窗口不重置）。
    pub fn record_success(&self, username: &str) {
        lock_or_recover(&self.inner)
            .users
            .remove(&normalize(username));
    }

    /// 当前用户名窗口的 Retry-After（没有窗口时 1 秒）。
    pub fn retry_after_secs(&self, username: &str) -> u64 {
        let now = now_secs();
        lock_or_recover(&self.inner)
            .users
            .get(&normalize(username))
            .filter(|w| w.active(now))
            .map(|w| w.retry_after(now))
            .unwrap_or(1)
    }
}

fn normalize(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_failures_block_one_username_without_blocking_others() {
        let limiter = LoginLimiter::new();
        for _ in 0..USER_LIMIT {
            assert!(limiter.check("alice").is_ok());
            limiter.record_failure("alice");
        }
        let retry = limiter.check("ALICE ").expect_err("must block");
        assert!((1..=60).contains(&retry));
        assert!(limiter.check("bob").is_ok());
        limiter.record_success("alice");
        assert!(limiter.check("alice").is_ok());
    }

    #[test]
    fn global_failures_block_even_new_usernames() {
        let limiter = LoginLimiter::new();
        for i in 0..GLOBAL_LIMIT {
            limiter.record_failure(&format!("u{i}"));
        }
        let retry = limiter.check("new-user").expect_err("global must block");
        assert!((1..=60).contains(&retry));
    }
}
