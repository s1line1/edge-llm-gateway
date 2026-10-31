//! Persistence facade. Aggregate implementations live in `keys`, `tenants`, `users`, `sessions`,
//! and `audit`; `engine` owns opening/migration; SQLite remains the durable store.
//!
//! The API-key security model is unchanged: no plaintext keys at rest; only argon2 hashes plus
//! sha256 lookup indexes. The paragraphs below describe that hot path.
//!
//! 安全模型（argon2 哈希存储，不再存明文）：
//! - 明文 key 仅创建时返回一次，此后**只存 argon2 哈希**（PHC 格式）。拖库拿到的
//!   是哈希，不是可用的 key；且默认参数（Argon2id m=19456/t=2/p=1，OWASP 建议）
//!   让离线暴破成本极高。
//! - 授权热路径：`sha256(token)` 作为快速索引（lookup）O(1) 定位记录，再对**单条**
//!   记录做 argon2 校验——避免对每条记录都做昂贵的 argon2 验证。明文 key 是 192 位
//!   随机数，lookup 索引哈希本身不构成泄露；argon2 哈希才是防离线暴破的主体。
//! - 架构：内存索引（runtime HashMap，key=lookup）保证 `authorize()` 热路径零 IO；
//!   SQLite 负责持久化，创建/吊销时写穿（write-through）。
//!
//! 注意：argon2 校验每次约耗时 10-30ms，且**同时占用 19MiB 工作内存**（m=19456）。
//! 早期实现对**每个请求**都完整校验一次，于是内存峰值 ≈ `并发请求数 × 19MiB`
//! （实测：8 并发同 key 请求 → RSS 8.7MB→160.8MB；vmmap 里正好 8 块 19.0MB；
//! 换用无效 key（sha256 未命中、不跑 argon2）则零增长）。云端 2 核/1.6G 上 32 并发
//! 到 654MB 即由此而来，并因此被 OOM 杀掉。
//!
//! 现在走 `verified::VerifiedCache`：**缓存 + 单飞 + 凭据版本校验**——
//! argon2 降到"每(凭据版本)一次"，每请求只做 O(1) 的 enabled/版本核对，
//! 且吊销依然即时生效（版本不一致或记录消失即拒）。`verified_cache_max: 0` 可关闭。

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{atomic::AtomicU64, Arc, Mutex, RwLock},
    time::Duration,
};

use rusqlite::Connection;

use crate::error::GatewayError;

pub mod hash;
mod pki;
mod session;
mod tenant;
mod usage;
pub mod user;
mod verified;

pub use session::{CreatedSession, SessionRecord};
pub(crate) use tenant::DEFAULT_TENANT_ID;
pub use tenant::{CreatedTenant, TenantError, TenantPatch, TenantRecord};
pub use user::{AuditRecord, CreatedUser, UserError, UserPatch, UserRecord, UserRole};

#[cfg(test)]
pub(crate) use crate::storage::hash::{lookup_of, verify_argon2};
#[cfg(test)]
pub(crate) use keys::insert_api_key;
/// 用量记账/落库的类型由私有模块 `usage` 定义，路径 `crate::storage::UsageDelta` 保持不变。
pub use keys::{CreatedKey, KeyRecord};
pub use pki::PkiRecord;
pub use usage::{KeyUsageInfo, UsageDelta};

mod audit;
mod db;
mod engine;
mod keys;
mod schema;
mod sessions;
mod tenants;
mod users;

#[derive(Clone)]
pub struct Storage {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    /// 动态 key，key = lookup（sha256(token) 十六进制），value = 记录。
    runtime: RwLock<HashMap<String, KeyRecord>>,
    /// 租户；`default` 始终存在。
    tenants: RwLock<HashMap<String, tenant::TenantRecord>>,
    /// dashboard 用户，key = user id。
    users: RwLock<HashMap<String, user::UserRecord>>,
    /// 规范化用户名 → user id；与 `users` 同步维护。
    usernames: RwLock<HashMap<String, String>>,
    /// 服务端会话，key = sha256(token)。
    sessions: RwLock<HashMap<String, session::SessionRecord>>,
    /// SQLite 持久化连接（None = 仅内存，如 db 打开失败时降级）。
    ///
    /// **与用量记账共享**（`Arc`）：连接是**资源**（凭据写穿与用量落库都用它），
    /// 而状态刻意不共享——`runtime` 归凭据、`usage` 归 `usage::UsageStore`。
    db: Arc<Mutex<Option<Connection>>>,
    /// per-key 用量：记账 + 批量落库（独立模块，见 `usage`）。
    usage: usage::UsageStore,
    /// 已验证身份缓存（argon2 结果复用）+ 单飞 + 它自己的容量/有效期策略。
    verified: verified::VerifiedCache,
    /// 凭据代数：**只在凭据相关变更时**自增（创建/吊销/轮换）。
    /// 每条记录带一个 `cred_version`，变更后旧缓存条目的版本对不上 → 立即失效。
    cred_generation: AtomicU64,
    /// 启动期持久化自检：`None` = **没配 `keys_file`**（内存模式）；
    /// `Some(Ok(()))` = 库已就绪；`Some(Err(why))` = 已降级成内存模式，`why` 是原因。
    ///
    /// 库/测试语义：失败仍降级（构造器刻意保持不可失败）。**生产启动路径据此 fail-fast**
    /// ——见 [`Storage::persistence_state`] 与 `Gateway::start`：一个载不出任何 key 的网关
    /// 就是个空壳（每个请求 401），却会一直报健康。
    persistence: Option<Result<(), String>>,
}

/// 已验证身份缓存的默认容量：每条 ~100 字节，1650 条约 165KB。
pub const DEFAULT_VERIFIED_MAX: usize = 1650;
/// 已验证身份的默认有效期。注意：**吊销不依赖它**（版本校验优先），
/// 它只决定"多久之后重新付一次 argon2 的钱"。
const DEFAULT_VERIFIED_TTL: Duration = Duration::from_secs(30 * 60);

fn is_unique_violation(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(e, _)
            if e.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

impl Storage {
    /// tenant 的每 key 用量。
    pub fn usage_for_tenant(&self, tenant_id: &str) -> Vec<KeyUsageInfo> {
        self.inner.usage.usage_for_tenant(tenant_id)
    }

    /// 某用户拥有的 key 的用量（按 key id 排序，供普通用户视图）。
    pub fn usage_for_owner(&self, tenant_id: &str, owner_user_id: &str) -> Vec<KeyUsageInfo> {
        let ids: Vec<String> = self
            .list_for_owner(tenant_id, owner_user_id)
            .into_iter()
            .map(|k| k.id().to_string())
            .collect();
        let mut rows: Vec<KeyUsageInfo> = ids.iter().filter_map(|id| self.usage_of(id)).collect();
        rows.sort_by(|a, b| a.key_id.cmp(&b.key_id));
        rows
    }

    /// tenant 汇总 (prompt, completion, total, requests)。
    pub fn tenant_totals(&self, tenant_id: &str) -> (u64, u64, u64, u64) {
        self.inner.usage.tenant_totals(tenant_id)
    }

    /// 记录一次用量并**立即同步落库**（= 内存累加 + 落库）。
    /// 吊销的 key 也有可能在途请求刚结束——按 key_id 独立累计，记录保留可审计。
    ///
    /// 仅测试使用：生产路径只做内存累加，见 [`Self::accumulate_usage`]。
    #[cfg(test)]
    pub fn record_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let tenant_id = self
            .tenant_of_key(key_id)
            .unwrap_or_else(|| tenant::DEFAULT_TENANT_ID.to_string());
        self.inner.usage.record(key_id, &tenant_id, name, delta);
    }

    /// 本实例累计跑过多少次 argon2（测试断言用）。
    ///
    /// 它不单独计数：直接读 `VerifiedCache` 的计数器——也就是 `/metrics` 的
    /// `hlmg_key_verify_misses_total` 的来源，避免同一个事实在两处各记一份。
    /// 自增点见 `verified::VerifiedCache::probe_once`（"将要跑 argon2"那一处）。
    #[cfg(test)]
    pub fn argon2_runs(&self) -> usize {
        self.inner.verified.counters().1 as usize
    }

    /// 只做内存累加：纳秒级、无 IO，用于让 `/admin/usage`（读的正是这份内存计数）
    /// 在响应返回时立即一致。
    ///
    /// 实现与契约见 `usage::UsageStore::accumulate`：**这里只是转发**，不保留独立逻辑。
    pub fn accumulate_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let tenant_id = self
            .tenant_of_key(key_id)
            .unwrap_or_else(|| tenant::DEFAULT_TENANT_ID.to_string());
        self.inner.usage.accumulate(key_id, &tenant_id, name, delta);
    }

    /// 是否有"内存值尚未落库"的 key（静默期返回 false，调用方可跳过整轮 flush）。
    pub fn usage_has_pending(&self) -> bool {
        self.inner.usage.has_pending()
    }

    /// 把内存里的用量**绝对累计值**批量落库（实现与契约见 `usage::UsageStore::flush_once`：
    /// 绝对值 → 幂等、重启不重复累加；成功提交后才更新"已落库"标记 → 失败下轮重试）。
    ///
    /// 返回本轮写入的 key 数；`force = true` 时忽略"是否变化"（用于关闭前落库）。
    pub fn flush_usage_once(&self, force: bool) -> usize {
        self.inner.usage.flush_once(force)
    }

    /// 关闭前落库：把全部 key 的当前值无条件写一次（可能包含未变化的，代价可忽略）。
    pub fn flush_usage_blocking(&self) -> usize {
        self.inner.usage.flush_blocking()
    }

    /// 把一次用量**增量**写穿到 SQLite（旧的每请求写库路径，**仅测试用**）。
    ///
    /// 生产路径已改为 [`Self::flush_usage_once`]：按周期把各 key 的绝对累计值批量写一次。
    /// 增量写每次都要抢全局 `db` 锁并提交事务，实测把 2 vCPU 的吞吐摁在约 190 QPS，
    /// 所以只留给测试构造"库里已有某值"的场景。**阻塞调用**，不要放回请求路径。
    #[cfg(test)]
    pub fn persist_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        let tenant_id = self
            .tenant_of_key(key_id)
            .unwrap_or_else(|| tenant::DEFAULT_TENANT_ID.to_string());
        self.inner.usage.persist(key_id, &tenant_id, name, delta);
    }

    /// 单个 key 的用量快照（无记录 → None）。
    pub fn usage_of(&self, key_id: &str) -> Option<KeyUsageInfo> {
        self.inner.usage.of(key_id)
    }

    /// 全部 key 的用量快照（按 key_id 排序）。
    pub fn usage_snapshot(&self) -> Vec<KeyUsageInfo> {
        self.inner.usage.snapshot()
    }
}

#[cfg(test)]
mod tests;
