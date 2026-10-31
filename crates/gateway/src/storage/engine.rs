//! Storage construction: open, load aggregates, and retain the persistence health state.

use super::schema::{load_keys, load_sessions, load_tenants, load_users};
use super::*;
use super::{db, tenant, usage, verified};
use crate::storage::hash::now_secs;

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
        let mut tenants = match &db {
            Some(conn) => match load_tenants(conn) {
                Ok(map) => map,
                Err(e) => {
                    tracing::warn!("tenants db load failed: {e}; using only the default tenant");
                    if matches!(persistence, Some(Ok(()))) {
                        persistence = Some(Err(format!("cannot load the tenants db: {e}")));
                    }
                    HashMap::new()
                }
            },
            None => HashMap::new(),
        };
        tenants
            .entry(tenant::DEFAULT_TENANT_ID.to_string())
            .or_insert_with(tenant::default_tenant);
        let (users, sessions) = match &db {
            Some(conn) => {
                let users = match load_users(conn) {
                    Ok(map) => map,
                    Err(e) => {
                        tracing::warn!("users db load failed: {e}; using empty user store");
                        if matches!(persistence, Some(Ok(()))) {
                            persistence = Some(Err(format!("cannot load the users db: {e}")));
                        }
                        HashMap::new()
                    }
                };
                let now = now_secs();
                let sessions = match load_sessions(conn) {
                    Ok(map) => map
                        .into_iter()
                        .filter(|(_, s)| s.expires_at() > now)
                        .collect::<HashMap<_, _>>(),
                    Err(e) => {
                        tracing::warn!("sessions db load failed: {e}; using empty session store");
                        if matches!(persistence, Some(Ok(()))) {
                            persistence = Some(Err(format!("cannot load the sessions db: {e}")));
                        }
                        HashMap::new()
                    }
                };
                (users, sessions)
            }
            None => (HashMap::new(), HashMap::new()),
        };
        let mut usernames = HashMap::new();
        for user in users.values() {
            usernames.insert(user.username().to_ascii_lowercase(), user.id().to_string());
        }
        let db = Arc::new(Mutex::new(db));
        let usage = usage::UsageStore::new(db.clone());
        let storage = Self {
            inner: Arc::new(StoreInner {
                runtime: RwLock::new(runtime),
                tenants: RwLock::new(tenants),
                users: RwLock::new(users),
                usernames: RwLock::new(usernames),
                sessions: RwLock::new(sessions),
                db,
                usage,
                verified: verified::VerifiedCache::new(max, ttl),
                cred_generation: AtomicU64::new(1),
                persistence,
            }),
        };
        storage.prune_expired_sessions(now_secs());
        storage
    }
}
