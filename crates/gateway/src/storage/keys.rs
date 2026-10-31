//! API key aggregate methods.

use super::*;
use std::sync::atomic::Ordering;

use crate::storage::hash::{generate_id_key, hash_argon2, lookup_of, now_secs, verify_argon2};
use crate::sync::{lock_or_recover, read_or_recover, write_or_recover};

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
    pub(crate) tenant_id: String,
    pub(crate) owner_user_id: Option<String>,
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

    /// 所属租户 id。
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// 归属的 dashboard 用户；`None` = tenant 级 key（迁移前或管理员创建）。
    pub fn owner_user_id(&self) -> Option<&str> {
        self.owner_user_id.as_deref()
    }
}

/// `create()` 的返回：记录 + 仅此一次的明文 key（之后不再可获取）。
pub struct CreatedKey {
    pub record: KeyRecord,
    pub plaintext: String,
}

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

pub(crate) fn insert_api_key(conn: &Connection, record: &KeyRecord) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled, tenant_id, owner_user_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            record.id,
            record.lookup,
            record.key_hash,
            record.name,
            record.created_at as i64,
            1i64,
            record.tenant_id,
            record.owner_user_id
        ],
    )
    .map(|_| ())
}

impl Storage {
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
        self.create_in(tenant::DEFAULT_TENANT_ID, None, name)
    }

    /// 在指定 tenant 下创建 key。tenant 必须存在且启用；`owner_user_id` 必须是同 tenant 用户。
    pub fn create_in(
        &self,
        tenant_id: &str,
        owner_user_id: Option<&str>,
        name: String,
    ) -> Result<CreatedKey, GatewayError> {
        if let Some(t) = self.tenant(tenant_id) {
            if !t.enabled() {
                return Err(GatewayError::Other("tenant is disabled".into()));
            }
        } else {
            return Err(GatewayError::Other("tenant not found".into()));
        }
        if let Some(owner) = owner_user_id {
            let Some(user) = self.user(owner) else {
                return Err(GatewayError::Other("key owner not found".into()));
            };
            if user.tenant_id() != Some(tenant_id) {
                return Err(GatewayError::Other(
                    "key owner must belong to the same tenant".into(),
                ));
            }
        }
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
                tenant_id: tenant_id.to_string(),
                owner_user_id: owner_user_id.map(str::to_string),
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

    /// 只列指定 tenant 的 key。
    pub fn list_for_tenant(&self, tenant_id: &str) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 按 id 取 key 快照（权限检查用；不暴露哈希）。
    pub fn key(&self, id: &str) -> Option<KeyRecord> {
        read_or_recover(&self.inner.runtime)
            .values()
            .find(|r| r.id == id)
            .cloned()
    }

    /// 只列某用户拥有的 key。
    pub fn list_for_owner(&self, tenant_id: &str, owner_user_id: &str) -> Vec<KeyRecord> {
        let mut v: Vec<KeyRecord> = read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| {
                r.tenant_id == tenant_id && r.owner_user_id.as_deref() == Some(owner_user_id)
            })
            .cloned()
            .collect();
        v.sort_by_key(|r| r.created_at);
        v
    }

    /// 停用某用户拥有的全部 key（禁用/删除用户时调用）。返回实际停用条数。
    pub fn disable_keys_for_owner(&self, owner_user_id: &str) -> Result<usize, GatewayError> {
        let ids: Vec<String> = read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| r.owner_user_id.as_deref() == Some(owner_user_id) && r.enabled)
            .map(|r| r.id.clone())
            .collect();
        if ids.is_empty() {
            return Ok(0);
        }
        if let Some(conn) = lock_or_recover(&self.inner.db).as_mut() {
            let tx = conn.transaction()?;
            for id in &ids {
                tx.execute(
                    "UPDATE api_keys SET enabled = 0 WHERE id = ?1",
                    rusqlite::params![id],
                )?;
            }
            tx.commit()?;
        }
        {
            let mut runtime = write_or_recover(&self.inner.runtime);
            for rec in runtime.values_mut() {
                if rec.owner_user_id.as_deref() == Some(owner_user_id) {
                    rec.enabled = false;
                }
            }
        }
        self.bump_cred_generation();
        for id in &ids {
            self.inner.verified.invalidate_by_id(id);
        }
        Ok(ids.len())
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
    /// key id → tenant id。
    pub fn tenant_of_key(&self, key_id: &str) -> Option<String> {
        read_or_recover(&self.inner.runtime)
            .values()
            .find(|r| r.id == key_id)
            .map(|r| r.tenant_id.clone())
    }

    /// 某 tenant 的当前 key 数（吊销后的 key 不在 runtime 里）。
    pub fn key_count_for_tenant(&self, tenant_id: &str) -> usize {
        read_or_recover(&self.inner.runtime)
            .values()
            .filter(|r| r.tenant_id == tenant_id)
            .count()
    }
}
