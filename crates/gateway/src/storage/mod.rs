//! API Key 存储：所有动态 key 持久化在 SQLite（无静态 key 列表）。
//! key 通过 Admin API 创建/吊销，立即生效，无需重启网关。
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
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use rusqlite::Connection;

use crate::error::GatewayError;

pub mod hash;
mod usage;
mod verified;

/// 用量记账/落库的类型由私有模块 `usage` 定义，路径 `crate::storage::UsageDelta` 保持不变。
pub use usage::{KeyUsageInfo, UsageDelta};

use crate::storage::hash::{generate_id_key, hash_argon2, lookup_of, now_secs, verify_argon2};
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

mod db;
mod schema;

use schema::load_keys;

#[derive(Clone)]
pub struct Storage {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    /// 动态 key，key = lookup（sha256(token) 十六进制），value = 记录。
    runtime: RwLock<HashMap<String, KeyRecord>>,
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

/// 一条动态 key 的记录。**凭据字段不出本模块**：`key_hash` 是 argon2 的 PHC 串、
/// `lookup` 是 sha256(明文)，两者都够用来做离线爆破，所以它们（以及内部代数
/// `cred_version`）都是 crate 可见，不对外暴露；外部能看到的只有 [`Self::id`]、
/// [`Self::name`]、[`Self::created_at`]、[`Self::enabled`] —— 与 `/admin/keys` 的
/// 线格式一致。
///
/// 刻意**不实现 `Debug`**：`{:?}` 会把 `key_hash` 打进日志，而记录本身没有任何需要
/// `Debug` 的场景（评估 §7 步骤 6）。
#[derive(Clone)]
pub struct KeyRecord {
    pub(crate) id: String,
    /// argon2 哈希（PHC 格式，如 `$argon2id$v=19$m=19456,t=2,p=1$...`），非明文。
    pub(crate) key_hash: String,
    /// 快速索引：sha256(明文 key) 的十六进制，授权时 O(1) 定位记录。
    pub(crate) lookup: String,
    pub(crate) name: String,
    pub(crate) created_at: u64,
    pub(crate) enabled: bool,
    /// 凭据版本：写入时取当时代数。任何凭据相关变更（吊销/轮换）都会让代数自增，
    /// 从而让基于旧版本建立的已验证缓存**立即失效**（见 `verified` 模块）。
    pub(crate) cred_version: u64,
}

impl KeyRecord {
    /// key id：对外标识（`/admin/keys`、访问日志、用量表都用它）。
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 展示用名字（建 key 时给的，可为空字符串）。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 创建时间（Unix 秒）。
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// 是否启用。注意**吊销**不是靠它：吊销会把记录从 `runtime` 表里删掉（见
    /// [`Storage::delete`]），所以"查得到 + enabled"才代表可用。
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// `create()` 的返回：记录 + 仅此一次的明文 key（之后不再可获取）。
pub struct CreatedKey {
    pub record: KeyRecord,
    pub plaintext: String,
}

/// 已验证身份缓存的默认容量：每条 ~100 字节，1650 条约 165KB。
pub const DEFAULT_VERIFIED_MAX: usize = 1650;
/// 已验证身份的默认有效期。注意：**吊销不依赖它**（版本校验优先），
/// 它只决定"多久之后重新付一次 argon2 的钱"。
const DEFAULT_VERIFIED_TTL: Duration = Duration::from_secs(30 * 60);

/// 写入一条 key 记录；**普通 INSERT**，冲突（id/lookup 重复）交给调用方重试。
///
/// 不能用 `INSERT OR REPLACE`：id 或 lookup 冲突时它会静默删掉另一行（S2-4）。
/// 只把 id/lookup 的 UNIQUE 冲突当作可重试；触发器 ABORT 等其它约束必须原样上报
/// （admin 需要把 `debug: forced insert failure` 这类诊断信息写进日志）。
fn is_unique_key_collision(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(e, Some(message)) => {
            e.code == rusqlite::ErrorCode::ConstraintViolation
                && (message.contains("api_keys.id") || message.contains("api_keys.lookup"))
        }
        _ => false,
    }
}

fn insert_api_key(conn: &Connection, record: &KeyRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            record.id,
            record.lookup,
            record.key_hash,
            record.name,
            record.created_at as i64,
            1i64
        ],
    )
    .map(|_| ())
}

impl Storage {
    /// 启动期持久化自检的结果：`None` = 没配 `keys_file`；`Some(Ok(()))` = 就绪；
    /// `Some(Err(why))` = 已降级为内存模式（磁盘/权限/损坏/迁移失败…）。
    ///
    /// 为什么单独暴露：构造器**刻意保持不可失败**（库与测试里"内存模式"是合法用法），
    /// 而**生产启动必须 fail-fast**——一个载不出任何 key 的网关是个空壳（每个请求 401），
    /// 却会一直报健康。判据由 [`crate::Gateway::start`] 执行。
    ///
    /// 注意：usage 表的载入失败**不**进入这个结果。它由 `UsageStore` 自己禁用落库
    /// （S2-5），不会因为用量账本读不出来而让一个仍能授权/转发的网关拒绝启动。
    pub fn persistence_state(&self) -> Option<Result<(), String>> {
        self.inner.persistence.clone()
    }

    pub fn new(file: Option<PathBuf>) -> Self {
        Self::with_verified(file, DEFAULT_VERIFIED_MAX, DEFAULT_VERIFIED_TTL)
    }

    pub fn default_verified_ttl() -> Duration {
        DEFAULT_VERIFIED_TTL
    }

    pub fn default_verified_max() -> usize {
        DEFAULT_VERIFIED_MAX
    }

    /// 指定已验证缓存容量与有效期；`max = 0` 关闭缓存（恢复"每请求都跑 argon2"的旧行为）。
    ///
    /// 默认（[`Self::new`]）：1650 条缓存、30 分钟有效期——够覆盖"同一批客户端持续打"的场景；
    /// **吊销不依赖它**（版本/记录消失的校验在缓存之前），TTL 只决定"多久之后重新付一次
    /// argon2 的钱"。
    pub fn with_verified(file: Option<PathBuf>, max: usize, ttl: Duration) -> Self {
        // 打开/收紧/建表/迁移都在 `db::open` 里；这里只把结果装进 `Storage`。
        let opened = db::open(file.as_deref());
        let mut persistence = opened.persistence;
        let db = opened.conn;
        let runtime = match &db {
            Some(conn) => match load_keys(conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!("keys db load failed: {e}; using empty store");
                    if matches!(persistence, Some(Ok(()))) {
                        persistence = Some(Err(format!("cannot load the keys db: {e}")));
                    }
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        // 连接是**资源**：凭据写穿与用量落库共用它，因此包一层 `Arc`；
        // 而状态各自独占——`runtime` 留在这里，用量账本交给 `usage::UsageStore`
        //（它在构造时自己从 `key_usage` 载入，失败只告警并按空账本继续）。
        let db = Arc::new(Mutex::new(db));
        let usage = usage::UsageStore::new(db.clone());
        Self {
            inner: Arc::new(StoreInner {
                runtime: RwLock::new(runtime),
                db,
                usage,
                verified: verified::VerifiedCache::new(max, ttl),
                cred_generation: AtomicU64::new(1),
                persistence,
            }),
        }
    }

    /// 推进凭据代数并返回新值。**任何**改变"某个 key 是否有效/其哈希"的写路径
    /// 都必须调用它，否则已验证缓存会继续放行旧身份（见 `verified` 模块的安全性说明）。
    fn bump_cred_generation(&self) -> u64 {
        self.inner
            .cred_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    /// 校验 token 是否为启用中的动态 key（sha256 定位 + argon2 校验）。
    ///
    /// 生产路径走 [`Self::authorize_record`]（`auth.rs` 需要 id 与 name）；这个布尔形态
    /// 是给 **benches 与库调用方**的便利入口，网关自身不调用它。
    pub fn authorize(&self, token: &str) -> bool {
        self.authorize_record(token).is_some()
    }

    /// 校验并返回 key 记录。
    ///
    /// **协议不在这里**：快路径 → 单飞 → 双检 → 校验 → 写缓存全在
    /// `verified::VerifiedCache::verify_or_cached` 里，本函数只提供两个动作——
    /// "按 lookup 取当前记录"（读 `runtime`）与"真跑一次 argon2"。
    ///
    /// 热路径（有缓存时）只做三件事：`sha256(token)` → O(1) 查表 → 比对凭据版本，
    /// **不跑 argon2**；只有缓存未命中（首次见到该 token、版本变了、或缓存关闭）才校验。
    ///
    /// 记录以**值**交给协议（`load_record` 里 `.cloned()`），于是 `runtime` 的读锁在 argon2
    /// 之前就放开了：建/吊销（写锁）不会再被一次 10–30ms 的冷校验堵住（评估 §5 N1）。
    /// 这不是"记得 drop"，是接口形状决定的——闭包没法把守卫借出去。
    pub fn authorize_record(&self, token: &str) -> Option<KeyRecord> {
        let lookup = lookup_of(token);
        self.inner.verified.verify_or_cached(
            &lookup,
            || read_or_recover(&self.inner.runtime).get(&lookup).cloned(),
            |rec| verify_argon2(token, &rec.key_hash),
        )
    }

    /// (缓存命中, 未命中/校验次数)：供 `/metrics` 观察 argon2 复用情况。
    pub fn verified_counters(&self) -> (u64, u64) {
        self.inner.verified.counters()
    }

    /// 创建动态 key 并持久化；返回记录与仅此一次的明文 key。
    ///
    /// **顺序是"先落库、后进内存"**：落库失败就返回 `Err`，内存与库都不变——否则会出现
    /// "管理页显示一把重启后就消失的 key"（评估 §5 H2 / 记录 P2-9），而且那把 key 的明文
    /// 已经交给了调用方，收不回来。
    ///
    /// 纯内存模式（`db = None`，库打不开时的降级）没有可落库的对象，直接成功。
    pub fn create(&self, name: String) -> Result<CreatedKey, GatewayError> {
        for _ in 0..3 {
            let (id, plaintext) = generate_id_key();
            let lookup = lookup_of(&plaintext);
            let key_hash = hash_argon2(&plaintext);
            let mut record = KeyRecord {
                id,
                key_hash,
                lookup,
                name: name.clone(),
                created_at: now_secs(),
                enabled: true,
                // 成功落库后才 bump；重试不能浪费凭据代数。
                cred_version: 0,
            };
            // ① 先落库。失败 → 直接把错误交给调用方（admin 映射 500），内存一个字都不改。
            if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
                match insert_api_key(conn, &record) {
                    Ok(()) => {}
                    Err(e) if is_unique_key_collision(&e) => {
                        // id 或 lookup 撞了：换一组随机值重试，绝不能 REPLACE 掉已有行。
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            record.cred_version = self.bump_cred_generation();
            // ② 再进内存：此后授权立即可用。
            write_or_recover(&self.inner.runtime).insert(record.lookup.clone(), record.clone());
            tracing::info!(id = %record.id, name = %record.name, "api key created");
            return Ok(CreatedKey { record, plaintext });
        }
        Err(GatewayError::Other(
            "could not allocate a unique key id".into(),
        ))
    }

    /// 列出动态 key（不含明文；由调用方决定展示形式）。
    pub fn list(&self) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = read_or_recover(&self.inner.runtime)
            .values()
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 吊销动态 key：`Ok(true)` = 真的删掉了，`Ok(false)` = 本来就不存在；
    /// `Err` = **没能落库，什么都没变**（key 仍然可用）。
    ///
    /// **顺序是"先落库、后改内存"**，理由与 [`Self::create`] 对称：内存先删的话，落库失败时
    /// 会出现"内存说没了、库还在"——重启后 `load_keys` 把 key 复活（评估 §5 H2 / 记录 P1-4）；
    /// 更糟的是**重试也救不回来**：内存里已经查不到它，重试只会返回"不存在"，而库里那行还在。
    /// 先落库之后，失败时内存原样（key 仍可用），重试会重新尝试删除并最终自愈。
    pub fn delete(&self, id: &str) -> Result<bool, GatewayError> {
        // 先看它在不在：不在就是 404，且**不碰库**（与旧语义一致）。
        if !read_or_recover(&self.inner.runtime)
            .values()
            .any(|r| r.id == id)
        {
            return Ok(false);
        }
        // ① 先落库。失败 → Err，内存原样。
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            conn.execute("DELETE FROM api_keys WHERE id = ?1", rusqlite::params![id])?;
        }
        // ② 再改内存 + 失效缓存 + 推进代数（并发双删时只有一个拿到 true）。
        let mut removed = false;
        {
            let mut runtime = write_or_recover(&self.inner.runtime);
            runtime.retain(|_, r| {
                if r.id == id {
                    removed = true;
                    false
                } else {
                    true
                }
            });
        }
        if removed {
            // 记录已从 runtime 表消失（查找直接 miss），这里再失效缓存并推进代数：
            // 双保险，且保证"任何凭据变更都会让旧身份失效"这条不变量成立。
            self.inner.verified.invalidate_by_id(id);
            self.bump_cred_generation();
            tracing::info!(id = %id, "api key revoked");
        }
        Ok(removed)
    }

    /// 记录一次用量并**立即同步落库**（= 内存累加 + 落库）。
    /// 吊销的 key 也有可能在途请求刚结束——按 key_id 独立累计，记录保留可审计。
    ///
    /// 仅测试使用：生产路径只做内存累加，见 [`Self::accumulate_usage`]。
    #[cfg(test)]
    pub fn record_usage(&self, key_id: &str, name: &str, delta: &UsageDelta) {
        self.inner.usage.record(key_id, name, delta);
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
        self.inner.usage.accumulate(key_id, name, delta);
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
        self.inner.usage.persist(key_id, name, delta);
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
