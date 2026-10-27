//! SQLite 文件的打开、权限收紧、schema 初始化与旧库迁移。
//!
//! 从 `storage/mod.rs` 切出来的理由：这些代码的变更是**引擎/文件/版本**层面的（打开失败、
//! WAL、0600、加列、明文库迁移），而 `Storage` 的变更是**凭据语义**层面的。两者混在
//! `with_verified` 的 100 行里时，"磁盘坏了"与"吊销逻辑改了"在 diff 上长得一样。
//!
//! 本模块只回答"打开后手上有什么"：`OpenedDb { conn, persistence }`。凭据装载
//! （`load_keys`）仍由 `storage/mod.rs` 调用——它产出 `KeyRecord`，属于凭据语义。

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::schema::{
    add_column_if_missing, ensure_default_tenant, migrate_legacy_keys, table_has_column,
    ADMIN_AUDIT_SCHEMA, API_KEY_SCHEMA, SESSION_SCHEMA, SESSION_USER_INDEX, TENANT_SCHEMA,
    USAGE_SCHEMA, USERNAME_INDEX, USER_SCHEMA,
};

/// 打开后的库：连接（内存模式为 `None`）与持久化三态。
///
/// `persistence`：`None` = 没配文件（内存模式是合法配置）；`Some(Ok(()))` = 就绪；
/// `Some(Err(why))` = 已降级。`Storage` 原样保存它，`Gateway::start` 据此 fail-fast。
pub(super) struct OpenedDb {
    pub(super) conn: Option<Connection>,
    pub(super) persistence: Option<Result<(), String>>,
}

/// 打开库并把它修到可用状态；失败**不返回 Err**，而是降级成内存模式并记下原因。
///
/// 构造器刻意保持不可失败（库/测试里内存模式合法）；生产启动的 fail-fast 由
/// `Storage::persistence_state()` + `Gateway::start` 执行。
pub(super) fn open(file: Option<&Path>) -> OpenedDb {
    let mut persistence: Option<Result<(), String>> = file.map(|_| Ok(()));
    let conn = match file {
        Some(path) => match Connection::open(path) {
            Ok(mut conn) => {
                // ① 权限先收紧：主库（刚被创建，或已存在）与**遗留的** `-wal`/`-shm`
                //    都以 0600 收口，不靠运维记得 `chmod`。
                tighten_db_to_owner(path);
                // ② 持久化设置：WAL + synchronous=NORMAL。落库已改成按周期批量，提交次数
                //    从每请求一次降到每周期一次；这两条让剩下的提交不必每次都 fsync 主库。
                //    journal_mode 是持久属性，设一次即可；失败只告警（例如文件系统不支持 WAL）。
                if let Err(e) = conn.pragma_update(None, "journal_mode", "WAL") {
                    tracing::warn!("sqlite: enable WAL failed (non-fatal): {e}");
                }
                if let Err(e) = conn.pragma_update(None, "synchronous", "NORMAL") {
                    tracing::warn!("sqlite: set synchronous=NORMAL failed (non-fatal): {e}");
                }
                let init = (|| {
                    conn.execute_batch(API_KEY_SCHEMA)?;
                    conn.execute_batch(USAGE_SCHEMA)?;
                    conn.execute_batch(TENANT_SCHEMA)?;
                    conn.execute_batch(USER_SCHEMA)?;
                    conn.execute_batch(USERNAME_INDEX)?;
                    conn.execute_batch(SESSION_SCHEMA)?;
                    conn.execute_batch(SESSION_USER_INDEX)?;
                    conn.execute_batch(ADMIN_AUDIT_SCHEMA)?;
                    ensure_default_tenant(&conn)?;
                    // 老库（无 cred_version 列）→ 补列；新库上 API_KEY_SCHEMA 已建好，这里跳过。
                    if !table_has_column(&conn, "api_keys", "cred_version")? {
                        conn.execute_batch(
                            "ALTER TABLE api_keys ADD COLUMN cred_version INTEGER NOT NULL DEFAULT 1",
                        )?;
                    }
                    // 多租户迁移：老表补 tenant_id；新表已带该列，这里跳过。
                    add_column_if_missing(
                        &conn,
                        "api_keys",
                        "tenant_id",
                        "TEXT NOT NULL DEFAULT 'default'",
                    )?;
                    add_column_if_missing(
                        &conn,
                        "key_usage",
                        "tenant_id",
                        "TEXT NOT NULL DEFAULT 'default'",
                    )?;
                    add_column_if_missing(&conn, "api_keys", "owner_user_id", "TEXT NULL")?;
                    ensure_default_tenant(&conn)?;
                    Ok::<_, rusqlite::Error>(())
                })();
                match init {
                    Ok(()) => {
                        // 旧版库（明文 key 表，无 lookup 列）→ 无损迁移为 argon2 哈希
                        match migrate_legacy_keys(&mut conn) {
                            Ok(0) => {}
                            Ok(n) => tracing::info!(
                                count = n,
                                "migrated legacy plaintext keys to argon2 hashes"
                            ),
                            Err(e) => {
                                tracing::warn!("keys db migration failed: {e}; using empty store");
                                persistence = Some(Err(format!(
                                    "cannot migrate the legacy keys db {}: {e}",
                                    path.display()
                                )));
                            }
                        }
                        Some(conn)
                    }
                    Err(e) => {
                        tracing::warn!("keys db {:?} init failed: {e}; using memory only", path);
                        persistence =
                            Some(Err(format!("cannot initialise {}: {e}", path.display())));
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("keys db {:?} open failed: {e}; using memory only", path);
                persistence = Some(Err(format!("cannot open {}: {e}", path.display())));
                None
            }
        },
        None => None,
    };
    OpenedDb { conn, persistence }
}

/// 把库文件**及其 WAL 侧车**权限收紧到 `0600`（评估 §7 步骤 6 / P3-7；复扫 C2-1）。
///
/// 库文件是按调用方 umask 创建的（常见 0644），而它通常放在 `/etc/home-llm-gateway/`
/// 下（`DEPLOY.md` 的目录清单）。库里只有 argon2 哈希与 sha256 lookup，属纵深防御；
/// 但升级/拷贝过来的旧库往往仍是宽权限，所以**每次打开都收紧一次**。
///
/// **为什么连 `-wal`/`-shm` 一起收**：`-wal` 里是还没 checkpoint 回主库的页，与主库同级
/// 敏感；而侧车平时是 0600 **只是因为** SQLite 建它时继承了主库刚设好的 mode——它们自己
/// 从来没被 `chmod` 过。于是"从别处拷贝/迁移过来的旧库"会带着 0644 的侧车进来，而 SQLite
/// 打开时会**复用**一份还含有效帧的 WAL（不是删掉重建），宽权限就留了下来。所以三个路径都
/// 显式收一遍：已存在的当场收口，之后 SQLite 新建的侧车继续继承已经收好的主库 mode。
///
/// 失败只告警：只读挂载或某些文件系统不支持 `chmod` 不该让网关起不来。
#[cfg(unix)]
fn tighten_db_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    // 主库 + 两个 SQLite 侧车：`-wal`（预写日志）、`-shm`（共享内存索引）。
    let mut targets = vec![path.to_path_buf()];
    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        targets.push(PathBuf::from(sidecar));
    }
    for target in targets {
        match std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => {}
            // 侧车不一定存在（WAL 尚未启用，或已 checkpoint 清理过）——这不是错误。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                path = %target.display(),
                "sqlite: cannot tighten to 0600 (non-fatal): {e}"
            ),
        }
    }
}

/// 非 unix 平台没有 `0600` 这个语义（Windows 的 ACL 不按位表示），保持原样。
#[cfg(not(unix))]
fn tighten_db_to_owner(_path: &Path) {}
