//! storage 测试：打开/损坏/迁移/权限收紧/三态自检。
//!
//! 通过 `use super::*;` 拿到 `tests/mod.rs` 的共享导入。

use super::*;
#[test]
fn corrupt_keys_db_ignored() {
    // 文件存在但不是合法 SQLite → 警告并当作空库
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    std::fs::write(&path, "{ not a sqlite database !!!").unwrap();
    let store = Storage::new(Some(path.clone()));
    assert!(!store.authorize("anything"));
}

#[test]
fn unreadable_keys_db_ignored() {
    // 路径存在但无法打开（是目录）→ 警告并当作空库
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    std::fs::create_dir(&path).unwrap();
    let store = Storage::new(Some(path.clone()));
    assert!(!store.authorize("anything"));
    // 降级为仅内存后，动态 key 仍可用
    let created = store.create("mem".into()).unwrap();
    assert!(store.authorize(&created.plaintext));
}

#[test]
fn creates_sqlite_db_and_schema() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    let created = store.create("y".into()).unwrap();
    assert!(store.authorize(&created.plaintext));
    assert_eq!(store.list().len(), 1);
    assert!(path.exists(), "sqlite db file should be created");
    drop(store);
    // 文件确实是 SQLite 格式（magic 头 "SQLite format 3"）
    let head = std::fs::read(&path).unwrap();
    assert_eq!(
        &head[..16],
        b"SQLite format 3\x00",
        "expected sqlite header"
    );
}

#[test]
#[serial]
fn migrates_db_without_cred_version_column() {
    // 本次改动给 api_keys 加了 cred_version 列：已部署的库没有它，
    // 启动时必须**自动补列**，且旧 key 仍能通过校验（不能因为迁移把用户锁在门外）。
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let hash = {
        // 用同一套 argon2 参数造一条"升级前"的记录（表里没有 cred_version 列）
        let h = crate::storage::hash::hash_argon2("sk-upgrade-secret");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                lookup TEXT NOT NULL UNIQUE,
                key_hash TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO api_keys (id, lookup, key_hash, name, created_at, enabled)
             VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            rusqlite::params![
                "old-id",
                crate::storage::hash::lookup_of("sk-upgrade-secret"),
                h,
                "old",
                1700000000i64
            ],
        )
        .unwrap();
        let cols: Vec<String> = Connection::open(&path)
            .unwrap()
            .prepare("PRAGMA table_info(api_keys)")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(
            !cols.iter().any(|c| c == "cred_version"),
            "前提：旧库确实没有 cred_version 列，实际列 {cols:?}"
        );
        h
    };
    drop(hash);

    // 用新代码打开旧库 → 应自动补列，且旧 key 依旧可用
    let store = Storage::new(Some(path.clone()));
    assert!(
        store.authorize("sk-upgrade-secret"),
        "升级后旧 key 必须仍然有效"
    );
    assert!(!store.authorize("sk-wrong"));
    {
        let conn = Connection::open(&path).unwrap();
        assert!(
            table_has_column(&conn, "api_keys", "cred_version").unwrap(),
            "启动时应自动给旧库补上 cred_version 列"
        );
    }
    // 迁移后的记录代数有效（0 会被当成"从未校验过"，这里必须是 >=1）
    let rec = store
        .inner
        .runtime
        .read()
        .unwrap()
        .get(&lookup_of("sk-upgrade-secret"))
        .cloned()
        .unwrap();
    assert!(rec.cred_version >= 1, "cred_version 应为有效代数");
}

#[test]
fn migrates_legacy_plaintext_db() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    // 构造旧 schema 库（明文 key 列）+ 一条明文 key
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                key TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
             );
             INSERT INTO api_keys (id, key, name, created_at, enabled)
             VALUES ('abc123', 'sk-legacy-secret', 'old', 1700000000, 1);",
        )
        .unwrap();
    }

    let store = Storage::new(Some(path.clone()));
    assert!(
        store.authorize("sk-legacy-secret"),
        "migrated plaintext key should still authorize"
    );
    assert!(!store.authorize("sk-other"));

    // 迁移后：旧明文列已删除、lookup 列存在（确定性断言，不扫描文件字节）
    {
        let conn = Connection::open(&path).unwrap();
        assert!(
            !table_has_column(&conn, "api_keys", "key").unwrap(),
            "legacy plaintext column must be dropped"
        );
        assert!(table_has_column(&conn, "api_keys", "lookup").unwrap());
        assert!(table_has_column(&conn, "api_keys", "key_hash").unwrap());
    }

    // 重载后依然有效，且不再重复迁移
    let reloaded = Storage::new(Some(path.clone()));
    assert!(reloaded.authorize("sk-legacy-secret"));
    let list = reloaded.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, "old");
}

#[test]
fn migrates_empty_legacy_table_structure() {
    // 旧表存在但无数据：也要重建结构（否则 load_keys 仍会失败）
    let dir = tempdir().unwrap();
    let path = dir.path().join("keys.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE api_keys (
                id TEXT PRIMARY KEY,
                key TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
             );",
        )
        .unwrap();
    }
    let store = Storage::new(Some(path.clone()));
    assert_eq!(store.list().len(), 0);
    // 结构已修复：新 key 可正常创建并持久化
    let created = store.create("new".into()).unwrap();
    drop(store);
    let reloaded = Storage::new(Some(path.clone()));
    assert!(reloaded.authorize(&created.plaintext));
}

/// 规格（启动期持久化自检）：三种状态必须分得开——**没配 / 就绪 / 降级（带原因）**。
///
/// 为什么要有这个区分：`Gateway::start` 只对"配了 `keys_file` 却用不了"这一档 fail-fast；
/// 没配 keys_file 的内存模式（测试/开发）是合法配置，不能一起拒掉。而"坏库"必须能给出
/// **路径与原因**，否则运维只看到"起不来"三个字。
#[test]
fn persistence_state_distinguishes_unconfigured_ready_and_degraded() {
    // ① 没配 keys_file：内存模式，不是故障
    assert!(
        Storage::new(None).persistence_state().is_none(),
        "没配 keys_file 不该有'持久化状态'"
    );

    let dir = tempdir().unwrap();
    // ② 可用（会被自动创建）的库：就绪
    let path = dir.path().join("keys.db");
    assert_eq!(
        Storage::new(Some(path.clone())).persistence_state(),
        Some(Ok(())),
        "正常库应当是就绪"
    );

    // ③ 不是 SQLite 库的文件：降级，且原因里带路径
    let bogus = dir.path().join("bogus.db");
    std::fs::write(&bogus, b"this is definitely not a sqlite database").unwrap();
    let store = Storage::new(Some(bogus.clone()));
    let why = store
        .persistence_state()
        .expect("配了 keys_file 就该有状态")
        .expect_err("坏库必须报降级");
    assert!(why.contains("bogus.db"), "原因里要带路径，实际：{why}");
    assert!(!why.is_empty(), "原因不能是空串（运维要靠它定位）");
}

/// 规格（评估 §7 步骤 6 / P3-7）：`keys.db` 由网关自己收紧到 **0600**，不靠运维记得
/// `chmod`（`DEPLOY.md` 的检查清单今天就是这么要求的）。
///
/// 库里只有 argon2 哈希与 sha256 lookup，属纵深防御；但**升级/拷贝过来的旧库**往往是
/// 0644，所以打开已存在的文件时也要顺手收紧——这条才是确定性的红检（新建文件是否
/// 已经是 0600 取决于跑测试的 umask）。
#[cfg(unix)]
#[test]
#[serial]
fn keys_db_is_tightened_to_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let mode_of = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.db");
    let store = Storage::new(Some(path.clone()));
    store.create("perm".into()).unwrap(); // 让 WAL/SHM 也建起来

    assert_eq!(mode_of(&path), 0o600, "新建的 keys.db 必须是 0600");
    // WAL/SHM 装着同一份数据，权限不能比主库宽
    for suffix in ["-wal", "-shm"] {
        let side = dir.path().join(format!("keys.db{suffix}"));
        if side.exists() {
            assert_eq!(
                mode_of(&side),
                0o600,
                "keys.db{suffix} 的权限必须与主库一致"
            );
        }
    }

    // 已经存在的宽权限库：打开时也要收紧（升级/拷贝场景）
    drop(store);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _store = Storage::new(Some(path.clone()));
    assert_eq!(mode_of(&path), 0o600, "打开已存在的库也要收紧到 0600");
}

/// 规格（2026-09-25 复扫 C2-1）：`-wal`/`-shm` 必须被**显式**收紧，而不是"靠继承"。
///
/// 上面那条测试覆盖的是"主库收紧后由 SQLite 现建侧车"——那种场景下侧车继承主库刚设好的
/// 0600，所以**即使代码只 chmod 主库也会通过**。真正会漏的是迁移/拷贝过来的旧库：侧车早就
/// 躺在磁盘上、权限是旧的 0644，而 `tighten_db_to_owner` 只收主库 ⇒ 打开后侧车仍是 0644
/// （WAL 里是还没 checkpoint 回主库的页，与主库同级敏感）。
///
/// 怎么复刻：空侧车没用——SQLite 分辨得出那是"没有内容的 WAL"，会把它删掉重建，重建时
/// 主库已经被收紧了，于是"继承"又把它救回来（这正是这条缺陷长期没被发现的原因）。所以
/// 这里让第一个 store **保持打开**，使 `-wal` 里留着真实帧；再把它摆成 0644，然后用第二个
/// store 打开同一个库——SQLite 会**复用**这份 WAL 而不是重建，宽权限因此留了下来。
#[cfg(unix)]
#[test]
#[serial]
fn preexisting_wal_sidecars_are_tightened_too() {
    use std::os::unix::fs::PermissionsExt;

    let mode_of = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keys.db");

    // 第一个 store 故意不 drop：连接活着，WAL 里才有未 checkpoint 的帧。
    let live = Storage::new(Some(path.clone()));
    live.create("perm".into()).unwrap();

    let wal = dir.path().join("keys.db-wal");
    let shm = dir.path().join("keys.db-shm");
    assert!(wal.exists(), "前置条件：WAL 模式下 -wal 应该存在");
    assert!(shm.exists(), "前置条件：WAL 模式下 -shm 应该存在");

    // 复刻"从别处拷贝 / 迁移过来的旧库"：三个文件都是宽的 0644。
    for f in [&path, &wal, &shm] {
        std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(f), 0o644, "前置条件：先摆成宽权限");
    }

    // 第二个 store 打开同一个库：SQLite 复用现存的 WAL，三个文件都要被显式收紧。
    let _second = Storage::new(Some(path.clone()));
    assert_eq!(mode_of(&path), 0o600, "主库");
    assert_eq!(
        mode_of(&wal),
        0o600,
        "遗留的 -wal 必须显式收紧（不能只靠继承）"
    );
    assert_eq!(
        mode_of(&shm),
        0o600,
        "遗留的 -shm 必须显式收紧（不能只靠继承）"
    );
}
