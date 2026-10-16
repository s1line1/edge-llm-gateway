//! edge-agent 注册表：`agent_id → 连接 + 健康状态 + 并发占位`。
//!
//! **本文件只做组合**：类型与策略按变更理由分在四个子模块里——
//! `entry`（条目与健康判据）、`routing`（选路规则）、`table`（表的增删查、快照与并发占位）、
//! `eviction`（失败记账与摘除）——它们都是私有模块，公开路径仍是 `crate::registry::*`：
//! 下面的 `pub use` 逐个把子模块里的名字提到本模块，调用方一处都不用改。

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU32, AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

mod entry;
mod eviction;
mod routing;
mod table;

pub use entry::{Entry, HeadSilence};
pub use routing::{AcquireError, Disposition};
pub use table::{AgentInfo, Registration, RegistryStatus};

/// 连接身份发号器：给每条注册进来的连接发一个**进程内唯一且永不复用**的编号。
///
/// 为什么不用 `Handle::id()`：那是 s2n-quic 的**端点内部**连接序号，源码注释写的是
/// "stable and internally identifies a connection over the whole lifetime of **an endpoint**"，
/// 而生成器是每个端点各自从 0 开始（s2n-quic-transport/src/endpoint/mod.rs:79,323、
/// src/connection/internal_connection_id.rs:26-32）——跨端点必然撞号：注册表的单元测试
/// 里每次新建一对端点，两条连接的 id 都是 0，于是 `remove_if_same` 会误删同名新连接的条目。
/// 注册表要的是"同一进程内、对一条连接稳定、且不复用"的编号（复用同样会导致误删），自己发号最稳。
static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);

/// `agent_id → Entry` 的注册表，外加准入（`try_acquire*`）与隧道失败的判定/记账。
///
/// **两条锁纪律**（都是事故换来的，改动这里的任何方法前先看一眼）：
/// - **写锁下只碰 map 与原子量**：不 `spawn`、不调传输句柄。`tokio::spawn` 若在守卫内 panic，
///   守卫会在 unwind 中释放 → 锁**永久中毒**，之后每一次注册/心跳/选路都跟着 panic
///   （见 `Registry::evict` 与 [`Registry::register`] 的写法：动作一律留到锁外）。
/// - **心跳只取读锁**（见 [`Registry::heartbeat_if_same`]）：它只是刷新一个原子毫秒值，
///   不该与正在选路的读路径互斥。
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<RwLock<HashMap<String, Entry>>>,
}

/// Drop 时自动归还并发槽位。
pub struct SlotGuard(Arc<AtomicU32>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::entry::now_millis;
    use crate::registry::entry::EvictCause;
    use crate::registry::eviction::EvictOutcome;
    use crate::registry::routing::pick;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::time::Duration;

    /// 摘除宽限：单测不关心具体时长（那由 `Options::evict_close_grace` 决定，默认 15s），
    /// 给一个固定值即可。
    const GRACE: Duration = Duration::from_secs(5);

    /// 建一对本地 s2n-quic 端点，返回**客户端连接句柄**（无 mTLS，只为构造 Handle）。
    ///
    /// 返回 `Handle` 而不是 `Connection`，因为注册表里存的就是 Handle（`Entry.conn`）：
    /// Handle 是 `#[derive(Clone, Debug)]`（s2n-quic/src/connection/handle.rs:431），
    /// 既能进 HashMap 也能被 `try_acquire` clone 出来；而 `Connection` 没有 Clone。
    ///
    /// 返回后端点随作用域结束 drop、连接随之关闭，但测试只读 `id()` 与 `inflight`：
    /// `Handle::id()` 是无锁的字段读取、也不返回 Result
    /// （s2n-quic-transport/src/connection/connection_container.rs:319-321），
    /// 所以连接死掉之后读 id 依然有效——注册表测试不依赖连接可用性。
    async fn test_connection() -> s2n_quic::connection::Handle {
        // 服务端：自签证书；ALPN 两端必须一致，否则握手协商不上
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

        let mut stls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der.clone()], key_der)
            .unwrap();
        stls.alpn_protocols = vec![proto::ALPN.to_vec()];

        let mut server = s2n_quic::Server::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Server::from(Arc::new(
                stls,
            )))
            .unwrap()
            .with_io("127.0.0.1:0")
            .unwrap()
            .start()
            .unwrap();
        let server_addr = server.local_addr().unwrap();

        // 必须驱动服务端 accept，否则 QUIC 握手永远无法完成；
        // 握完把两半句柄挂在 pending 上——返回会 drop 句柄、立刻关掉连接。
        tokio::spawn(async move {
            if let Some(conn) = server.accept().await {
                let (_handle, _acceptor) = conn.split();
                std::future::pending::<()>().await;
            }
        });

        // 客户端：信任自签证书（无 mTLS），ALPN 与服务端一致
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).unwrap();
        let mut ctls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ctls.alpn_protocols = vec![proto::ALPN.to_vec()];

        let client = s2n_quic::Client::builder()
            .with_tls(s2n_quic::provider::tls::rustls::Client::from(Arc::new(
                ctls,
            )))
            .unwrap()
            .with_io("0.0.0.0:0")
            .unwrap()
            .start()
            .unwrap();

        let conn = client
            .connect(s2n_quic::client::Connect::new(server_addr).with_server_name("localhost"))
            .await
            .unwrap();
        let (handle, _acceptor) = conn.split();
        handle
    }

    /// 规格（评估 §7 步骤 6 的结转项 A / registry 评估 M2）：**表锁中毒后注册与选路
    /// 不能全挂**。
    ///
    /// 表只是内存映射，守卫内 panic 不会写坏它；而 `.read().unwrap()` 会把一次 panic
    /// 放大成"之后每个请求都无法选路"——进程活着、指标还在跑，但全站 503。
    #[tokio::test]
    async fn a_poisoned_registry_lock_does_not_take_routing_down() {
        let reg = Registry::default();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = reg.inner.write().unwrap();
            panic!("poison the registry table");
        }));
        assert!(poisoned.is_err(), "前提：panic 发生了");
        assert!(reg.inner.is_poisoned(), "前提：锁中毒了");

        let conn = test_connection().await;
        reg.register("home-1".into(), vec!["m".into()], 2, conn);
        assert_eq!(reg.len(), 1, "中毒后仍应能注册");
        let (_entry, _slot) = reg
            .try_acquire(Duration::from_secs(10), "m")
            .expect("中毒后仍应能选路");
    }

    /// 规格（评估 §8 passB）：选路规则的**次序**——精确声明 > `*` 通配，同级负载轻者优先；
    /// 排除/过期各自把候选滤空时要给出正确的那一种错误。
    ///
    /// 规则现在是纯函数 [`pick`]，所以这条测试直接用条目断言，不必再绕 `try_acquire` 的占位副作用
    /// （要造的负载直接用条目上的原子量写，测试与 `Entry` 同模块）。
    #[tokio::test]
    async fn pick_orders_exact_over_wildcard_then_lightest() {
        let reg = Registry::default();
        let stale = Duration::from_secs(10);
        reg.register("wild".into(), vec!["*".into()], 8, test_connection().await);
        let exact = reg.register("exact".into(), vec!["m".into()], 8, test_connection().await);
        let busy = reg.register(
            "exact-busy".into(),
            vec!["m".into()],
            8,
            test_connection().await,
        );

        // 直接给"忙"那条写负载：两条精确里它更重，所以应排在 exact 之后
        let inner = reg.inner.read().unwrap();
        inner
            .values()
            .find(|e| e.stable_id == busy)
            .unwrap()
            .inflight
            .store(2, Ordering::Relaxed);

        let ordered: Vec<&str> = pick(inner.values(), now_millis(), stale, "m", &[])
            .unwrap()
            .iter()
            .map(|e| e.agent_id.as_str())
            .collect();
        assert_eq!(
            ordered,
            vec!["exact", "exact-busy", "wild"],
            "精确声明必须排在通配之前，同级负载轻者优先；实际 {ordered:?}"
        );

        // 排掉两条精确的 → 只剩通配
        let only_wild = pick(inner.values(), now_millis(), stale, "m", &[exact, busy]).unwrap();
        assert_eq!(
            only_wild
                .iter()
                .map(|e| e.agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["wild"]
        );

        // 全部过期 → NoAgent（没人可用）
        assert!(matches!(
            pick(inner.values(), now_millis(), Duration::ZERO, "m", &[]),
            Err(AcquireError::NoAgent)
        ));
    }

    /// 规格：**有人但没有一个声明这个模型** → `NoModel`（调用方据此回 404/400 而不是 503）。
    ///
    /// 单独一条测试是刻意的：`NoModel` 需要一份**没有 `*` 通配者**的表（通配者在，任何模型
    /// 都能被服务），而 `pick` 的读锁不能跨 `await`（clippy `await_holding_lock`），
    /// 混在选路次序那条测试里会既难读又踩 lint。
    #[tokio::test]
    async fn pick_reports_no_model_when_none_declares_it() {
        let reg = Registry::default();
        reg.register(
            "only-m".into(),
            vec!["m".into()],
            8,
            test_connection().await,
        );
        let inner = reg.inner.read().unwrap();
        assert!(matches!(
            pick(
                inner.values(),
                now_millis(),
                Duration::from_secs(10),
                "other",
                &[]
            ),
            Err(AcquireError::NoModel)
        ));
    }

    /// 规格（P2-11）：注册条目随 [`Registration`] 的 Drop 摘除——**panic 展开也要摘**。
    ///
    /// 为什么重要：`quic::handle_conn` 原来在末尾写一句 `remove_if_same`，panic 时那句不执行，
    /// 条目就永久留在注册表里（本仓库没有 stale 清扫器），表现为 `hlmg_agents` 虚高 +
    /// `/admin/agents` 幽灵条目。
    #[tokio::test]
    async fn registration_guard_removes_the_entry_on_drop_and_on_panic() {
        let reg = Registry::default();

        // 正常路径：守卫出作用域即摘除
        {
            let mut registration = Registration::new(&reg);
            let stable_id = reg.register(
                "home-1".into(),
                vec!["m".into()],
                2,
                test_connection().await,
            );
            registration.note("home-1".into(), stable_id);
            assert_eq!(reg.len(), 1);
        }
        assert_eq!(reg.len(), 0, "守卫 drop 必须摘掉条目");

        // panic 路径：展开过程中也要摘
        let conn = test_connection().await;
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut registration = Registration::new(&reg);
            let stable_id = reg.register("home-2".into(), vec!["m".into()], 2, conn.clone());
            registration.note("home-2".into(), stable_id);
            assert_eq!(reg.len(), 1);
            panic!("connection task blew up");
        }));
        assert!(panicked.is_err(), "前提：panic 发生了");
        assert_eq!(
            reg.len(),
            0,
            "panic 展开也必须摘掉条目（否则是永远删不掉的幽灵 agent）"
        );
    }

    /// 规格：`note` 被后来的注册**覆盖**——同名重复注册时，只有最后一次的 `stable_id`
    /// 匹配条目，用旧的 stable_id 摘除是 no-op（`remove_if_same` 会比对）。
    #[tokio::test]
    async fn registration_guard_removes_only_the_last_registration() {
        let reg = Registry::default();
        let mut registration = Registration::new(&reg);
        let first = reg.register("x".into(), vec!["m".into()], 2, test_connection().await);
        registration.note("x".into(), first);
        let second = reg.register("x".into(), vec!["m".into()], 2, test_connection().await);
        registration.note("x".into(), second);
        assert_eq!(reg.len(), 1);

        drop(registration);
        assert_eq!(reg.len(), 0, "最后一次注册的条目必须被摘掉");

        // 反向：只记着旧 stable_id 时，摘除不许误删新条目
        let mut stale = Registration::new(&reg);
        let fresh = reg.register("y".into(), vec!["m".into()], 2, test_connection().await);
        stale.note("y".into(), fresh.wrapping_sub(1)); // 一个不存在的 stable_id
        drop(stale);
        assert_eq!(reg.len(), 1, "stable_id 不匹配时不得摘除别人的条目");
    }

    #[tokio::test]
    async fn register_duplicate_replaces_and_len() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let id1 = reg.register("home-1".into(), vec!["m".into()], 2, c1.clone());
        assert_eq!(reg.len(), 1);
        // 同名重复注册：旧连接被关闭，条目替换为新连接，长度仍为 1
        let c2 = test_connection().await;
        let id2 = reg.register("home-1".into(), vec!["m".into()], 2, c2.clone());
        assert_eq!(reg.len(), 1);
        let entry = reg.inner.read().unwrap().get("home-1").cloned().unwrap();
        assert_ne!(id1, id2, "每次注册都必须拿到新的 stable_id");
        assert_eq!(entry.stable_id, id2, "条目应属于后注册的那条连接");
    }

    #[tokio::test]
    async fn remove_if_same_guards_stable_id() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let id1 = reg.register("x".into(), vec![], 4, c1.clone());
        let id2 = reg.register("x".into(), vec![], 4, c2.clone()); // 条目换成 c2，c1 被关
                                                                   // 用旧连接的 stable_id 移除 → 不删除（条目现在属于 c2）
        reg.remove_if_same("x", id1);
        assert_eq!(reg.len(), 1);
        // 用当前连接的 stable_id 移除 → 删除
        reg.remove_if_same("x", id2);
        assert_eq!(reg.len(), 0);
        // 对不存在的 agent 移除 → 无害
        reg.remove_if_same("ghost", id2);
    }

    /// 契约：**摘除时若还有别的在途请求，不得立刻关闭连接**。
    ///
    /// 那些请求已经把请求帧完整送达 agent、模型正在生成——它们不满足"建立阶段失败"
    /// 的重试条件，被打断就是纯损失（客户花了算力还拿不到结果）。所以摘除只做
    /// "移出路由"，连接等 drain 完（或过宽限期）再关。
    ///
    /// 反过来，若只剩当前这一个失败请求占槽位，立刻关闭是安全的——而且要立刻关，
    /// 好让 agent 察觉并重连，别变回僵尸。
    #[tokio::test]
    async fn eviction_defers_close_while_other_requests_are_in_flight() {
        let stale = Duration::from_secs(10);

        // 情形一：还有别的在途请求（这里手工把 inflight 顶到 3）
        let reg = Registry::default();
        let conn = test_connection().await;
        let id = reg.register("busy".into(), vec!["*".into()], 8, conn.clone());
        let (_e, g1) = reg.try_acquire(stale, "m").unwrap();
        let (_e2, g2) = reg.try_acquire(stale, "m").unwrap();
        let (_e3, g3) = reg.try_acquire(stale, "m").unwrap();
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        );
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 2 }
        );
        match reg.evict(id, EvictCause::OpenTimeout, GRACE) {
            EvictOutcome::RemovedClosedLater { inflight } => {
                assert!(inflight >= 3, "应报出当时的在途数，实际 {inflight}")
            }
            other => panic!("还有在途请求时不应立即关闭连接，实际 {other:?}"),
        }
        assert_eq!(reg.len(), 0, "无论是否延迟关闭，条目都必须先移出路由");
        drop((g1, g2, g3));

        // 情形二：只剩当前请求 → 立即关闭
        let reg2 = Registry::default();
        let conn2 = test_connection().await;
        let id2 = reg2.register("idle".into(), vec!["*".into()], 8, conn2.clone());
        let (_e4, _g4) = reg2.try_acquire(stale, "m").unwrap();
        assert!(matches!(
            reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { .. }
        ));
        assert!(matches!(
            reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { .. }
        ));
        assert_eq!(
            reg2.evict(id2, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::RemovedClosed
        );
    }

    /// 契约：**换 agent 重试时必须排除刚失败的那条连接**。
    ///
    /// 否则"重试"会再次选中同一条坏连接，等于没重试——这在生产表现为"重试了但还是
    /// 502"，而日志里看不出原因。
    #[tokio::test]
    async fn try_acquire_excluding_skips_the_failed_connection() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let id1 = reg.register("a".into(), vec!["*".into()], 4, c1.clone());
        let id2 = reg.register("b".into(), vec!["*".into()], 4, c2.clone());
        let stale = Duration::from_secs(10);

        // 不排除任何连接：两次选取都会命中某个候选（不关心是哪个）
        assert!(reg.try_acquire(stale, "m").is_ok());

        // 排除 a → 只能选到 b
        let (e, _g) = reg.try_acquire_excluding(stale, "m", &[id1]).unwrap();
        assert_eq!(e.stable_id, id2, "排除 a 后应选中 b");

        // 排除 b → 只能选到 a
        let (e, _g) = reg.try_acquire_excluding(stale, "m", &[id2]).unwrap();
        assert_eq!(e.stable_id, id1, "排除 b 后应选中 a");

        // 两条都排除 → 候选**全被本轮排除**，这与"没人可用"是两件事（复扫 B1）：
        // 混成同一个 `NoAgent`，单 agent 忙时就会对外报 503 `no edge available`。
        assert!(matches!(
            reg.try_acquire_excluding(stale, "m", &[id1, id2]),
            Err(AcquireError::AllExcluded)
        ));

        // 对照：注册表里真的没人 → `NoAgent`（别把上面那条修成"什么都报 AllExcluded"）。
        let empty = Registry::default();
        assert!(matches!(
            empty.try_acquire_excluding(stale, "m", &[]),
            Err(AcquireError::NoAgent)
        ));
    }

    /// 契约：**单次隧道操作超时不得摘除条目**（高并发下那是排队假象），
    /// 连续超时达阈值才摘除；任何一次成功都要清零计数。
    ///
    /// 实测背景：768 并发下第一次超时就把条目摘掉，而连接完好、agent 不知情，
    /// 于是注册表里没有它、请求全部 503（占 92.6%），agent 因为心跳仍能通而永远
    /// 不重连 —— "僵尸"态。
    #[tokio::test]
    async fn tunnel_timeouts_evict_only_after_consecutive_failures() {
        let reg = Registry::default();
        let conn = test_connection().await;
        let id = reg.register("t".into(), vec!["*".into()], 4, conn.clone());

        // 前两次超时：条目保留
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        ));
        assert_eq!(reg.len(), 1);
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 2 }
        ));
        assert_eq!(reg.len(), 1);
        // 中途一次成功 → 计数清零，重新从头累计
        reg.note_tunnel_op_ok(id);
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        ));
        assert_eq!(reg.len(), 1);
        // 再来两次（累计到 3）→ 摘除；此时只有本请求占槽位 → 立即关闭
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::BelowThreshold { .. }
        ));
        assert!(matches!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::RemovedClosed
        ));
        assert_eq!(reg.len(), 0);
        // 已摘除后再调用：无害
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::NotFound
        );
    }

    /// 规格：**每一种失败原因各有自己的"连续"计数**。
    ///
    /// 计数混在一起时，三种**不同**的轻微失败会凑满同一个阈值，把一条其实健康的连接摘掉；
    /// 而且任何一种失败达到阈值后，另一种失败的"连续"语义就被无声地改写了。云端实测里
    /// "开流超时"与"响应头超时"是两条独立的事故线（`routing.rs:122-125`、
    /// `head_timeout.rs:3-9`），它们的阈值不能互相充值。
    #[tokio::test]
    async fn strike_counters_are_independent_per_cause() {
        let reg = Registry::default();
        let conn = test_connection().await;
        let id = reg.register("t".into(), vec!["*".into()], 4, conn.clone());

        // 两种失败各记两次：各自都还差一次，谁都不该摘除
        for expected in 1..=2 {
            assert!(
                matches!(
                    reg.evict(id, EvictCause::OpenTimeout, GRACE),
                    EvictOutcome::BelowThreshold { consecutive } if consecutive == expected
                ),
                "开流超时应独立计数到 {expected}"
            );
            assert!(
                matches!(
                    reg.evict(id, EvictCause::HeadTimeout, GRACE),
                    EvictOutcome::BelowThreshold { consecutive } if consecutive == expected
                ),
                "响应头超时应独立计数到 {expected}"
            );
        }
        assert_eq!(
            reg.len(),
            1,
            "2 次开流 + 2 次响应头 = 4 次失败，但没有任何**一种**达到阈值"
        );

        // 第三种原因也从 1 开始，不受前两种影响
        assert!(matches!(
            reg.evict(id, EvictCause::TunnelWriteFailed, GRACE),
            EvictOutcome::BelowThreshold { consecutive: 1 }
        ));

        // 只有某一种真正连续到阈值才摘除
        assert_eq!(
            reg.evict(id, EvictCause::OpenTimeout, GRACE),
            EvictOutcome::RemovedClosed
        );
        assert_eq!(reg.len(), 0);
    }

    /// 可观测性契约：**注册条目数**与**可路由数**必须能分开看。
    ///
    /// 失联 agent 的条目要等连接真正关闭才摘除，所以 `len()` 会把它算作"在线"，
    /// 而 `try_acquire` 会把它过滤掉。两者混为一谈时，"所有请求 503"会被误读成
    /// "agent 掉了"——线上排查正是卡在这里（/metrics 显示 2 个 agent，实际全部 stale）。
    #[tokio::test]
    async fn healthy_count_separates_registered_from_routable() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let fresh = reg.register("fresh".into(), vec!["*".into()], 4, c1.clone());
        reg.register("stale".into(), vec!["*".into()], 4, c2.clone());

        let stale_after = Duration::from_millis(30);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 两条都过期
        assert_eq!(reg.len(), 2, "条目仍在注册表里（连接没关）");
        assert_eq!(reg.healthy_count(stale_after), 0, "但没有一条可路由");
        let st = reg.status(stale_after);
        assert_eq!((st.registered, st.healthy), (2, 0));
        assert!(st.oldest_last_seen_ago.unwrap() >= Duration::from_millis(50));
        assert!(matches!(
            reg.try_acquire(stale_after, "qwen2.5"),
            Err(AcquireError::NoAgent)
        ));

        // 一条心跳恢复 → 只有它可路由
        assert!(reg.heartbeat_if_same("fresh", fresh));
        assert_eq!(reg.len(), 2);
        assert_eq!(reg.healthy_count(stale_after), 1);
        assert_eq!(reg.status(stale_after).healthy, 1);
        assert!(reg.try_acquire(stale_after, "qwen2.5").is_ok());

        // 空注册表：两个数都是 0，且没有 last_seen 可报
        let empty = Registry::default();
        assert_eq!(empty.healthy_count(stale_after), 0);
        assert_eq!(empty.status(stale_after).registered, 0);
        assert!(empty.status(stale_after).oldest_last_seen_ago.is_none());
    }

    #[tokio::test]
    async fn heartbeat_refreshes_stale_entry() {
        let reg = Registry::default();
        let conn = test_connection().await;
        let h = reg.register("h".into(), vec!["*".into()], 4, conn.clone());
        // 30ms 后仍按 10ms 判定失联
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(matches!(
            reg.try_acquire(Duration::from_millis(10), "qwen2.5"),
            Err(AcquireError::NoAgent)
        ));
        // 心跳刷新 last_seen → 恢复可用
        assert!(reg.heartbeat_if_same("h", h));
        assert!(reg
            .try_acquire(Duration::from_millis(100), "qwen2.5")
            .is_ok());
        // 对不存在的 agent 心跳 → 无害
        assert!(!reg.heartbeat_if_same("ghost", 0));

        // 别的连接的 stable_id → 也不刷新（这就是本次修的那条：帧里的 id 不足以证明"你是谁"）
        assert!(!reg.heartbeat_if_same("h", h.wrapping_add(1)));
    }

    /// 规格（2026-10-07 修复）：**心跳只对"本连接注册的那条条目"生效**。
    ///
    /// 修复前 `heartbeat(agent_id)` 只按帧里自报的 id 查全表，于是任何持合法证书的 agent 都能用
    /// 别人的 id 替一条**已经死掉**的条目续命——网关会持续把请求路由到那台机器，而且日志里没有
    /// 任何痕迹（不像顶替会打 `duplicate agent connection`）。
    #[tokio::test]
    async fn a_heartbeat_only_refreshes_the_connection_that_registered_the_agent() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let victim = reg.register("victim".into(), vec!["*".into()], 4, c1.clone());
        let attacker = reg.register("attacker".into(), vec!["*".into()], 4, c2.clone());
        assert_ne!(victim, attacker, "前提：两条连接拿到不同的 stable_id");

        let stale_after = Duration::from_millis(10);
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert_eq!(reg.healthy_count(stale_after), 0, "前提：两条都已过期");

        // 攻击者用自己的连接、发 victim 的 id 的心跳 → **不得**刷新（stable_id 对不上）
        assert!(
            !reg.heartbeat_if_same("victim", attacker),
            "另一条连接的 stable_id 不该刷新 victim"
        );
        assert_eq!(reg.healthy_count(stale_after), 0, "victim 应仍是 stale");

        // victim 自己的连接发心跳 → 刷新
        assert!(
            reg.heartbeat_if_same("victim", victim),
            "本连接的 stable_id 应当刷新"
        );
        assert_eq!(reg.healthy_count(stale_after), 1, "victim 恢复可路由");
    }

    #[tokio::test]
    async fn try_acquire_spreads_load_and_capacity() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("a".into(), vec!["*".into()], 1, c1.clone());
        reg.register("b".into(), vec!["*".into()], 1, c2.clone());

        // 两个容量各 1 的 agent：连续两个请求应命中不同 agent
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_ne!(e1.stable_id, e2.stable_id);
        // 全满 → AtCapacity
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10), "qwen2.5"),
            Err(AcquireError::AtCapacity)
        ));
        drop(s1);
        drop(s2);
        // 槽位释放后恢复
        assert!(reg.try_acquire(Duration::from_secs(10), "qwen2.5").is_ok());
    }

    /// 规格：`max_concurrency == 0` = 不限（永远拿得到槽位），但**计数仍然必须真实**。
    ///
    /// `0` 只关掉"准入上限"这一件事；`inflight` 同时还是另外三处的输入：
    /// 开流超时的忙/死（[`Entry::open_timeout_is_fatal`]）、摘除时"是否还有别人在途"
    /// （[`Registry::evict`] 的 `inflight <= 1`）、以及负载排序（`try_acquire_excluding`
    /// 的 `sort_by_key`）。只减不加会让 `AtomicU32` **下溢回绕成 4294967295**：开流判据
    /// 永久失效、每次摘除都白等满宽限期、这台 agent 永远排最后、`/admin/agents` 显示天文数字
    /// （已记录：`docs/PROJECT_SCAN.md` P1-3）。
    #[tokio::test]
    async fn max_concurrency_zero_always_acquires_and_still_counts_inflight() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("z".into(), vec!["*".into()], 0, conn.clone()); // 0 = 不限

        // ① 只减不加 → 下溢：拿 5 次再**全部归还**，计数必须回到 0。
        //    在未修的实现里这里会读到 4294967295（`AtomicU32` 回绕），正是 P1-3 记录的形态。
        {
            let mut slots = Vec::new();
            for _ in 0..5 {
                let (_entry, slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
                slots.push(slot);
            }
            drop(slots);
        }
        assert_eq!(
            reg.snapshot(Duration::from_secs(10))[0].inflight,
            0,
            "拿 5 次再全部归还后必须回到 0；只减不加会下溢成 4294967295"
        );

        // ② 而且过程里必须如实累加：不限并发不等于不计数
        let mut slots = Vec::new();
        for expected in 1..=5u32 {
            let (entry, slot) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
            slots.push(slot);
            assert_eq!(
                entry.inflight.load(Ordering::Relaxed),
                expected,
                "不限并发也必须如实计数：开流判据、摘除判据、负载排序都读这个数"
            );
        }
        assert_eq!(
            reg.snapshot(Duration::from_secs(10))[0].inflight,
            5,
            "运维看到的在途数同样要真实"
        );

        drop(slots);
        assert_eq!(
            reg.snapshot(Duration::from_secs(10))[0].inflight,
            0,
            "最后一次释放后必须回到 0；下溢会变成 4294967295"
        );
    }

    #[tokio::test]
    async fn try_acquire_filters_by_model() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        let c3 = test_connection().await;
        reg.register(
            "qwen-edge".into(),
            vec!["qwen2.5".into()],
            1, // 容量 1：打满后验证回落通配
            c1.clone(),
        );
        reg.register("llama-edge".into(), vec!["llama3".into()], 4, c2.clone());
        // 通配 edge：任何模型都可路由到它
        reg.register("wildcard-edge".into(), vec!["*".into()], 4, c3.clone());

        // qwen2.5 → 精确声明的 qwen-edge 优先于仅通配的 wildcard-edge，
        // 绝不能是 llama-edge
        let (e, s) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let id = {
            let inner = reg.inner.read().unwrap();
            inner
                .iter()
                .find(|(_, v)| v.stable_id == e.stable_id)
                .map(|(id, _)| id.clone())
                .unwrap()
        };
        assert_eq!(id, "qwen-edge", "exact model match must win over wildcard");
        drop(s);

        // llama3 → 精确声明的 llama-edge 优先
        let (e, s) = reg.try_acquire(Duration::from_secs(10), "llama3").unwrap();
        let id = {
            let inner = reg.inner.read().unwrap();
            inner
                .iter()
                .find(|(_, v)| v.stable_id == e.stable_id)
                .map(|(id, _)| id.clone())
                .unwrap()
        };
        assert_eq!(id, "llama-edge", "exact model match must win over wildcard");
        drop(s);

        // 精确 edge 容量打满后，请求回落到通配 edge
        let (e1, s1) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        let (e2, s2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_ne!(
            e1.stable_id, e2.stable_id,
            "second qwen2.5 request should fall back to wildcard edge"
        );
        drop(s1);
        drop(s2);
    }

    #[tokio::test]
    async fn try_acquire_returns_no_model_when_none_match() {
        let reg = Registry::default();
        // 无通配 agent：所有健康 agent 都无法服务 mistral-7b
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register("qwen-edge".into(), vec!["qwen2.5".into()], 4, c1.clone());
        reg.register("llama-edge".into(), vec!["llama3".into()], 4, c2.clone());
        assert!(matches!(
            reg.try_acquire(Duration::from_secs(10), "mistral-7b"),
            Err(AcquireError::NoModel)
        ));
    }

    #[tokio::test]
    async fn healthy_models_aggregates_and_excludes_wildcard() {
        let reg = Registry::default();
        let c1 = test_connection().await;
        let c2 = test_connection().await;
        reg.register(
            "edge-a".into(),
            vec!["qwen2.5".into(), "llama3".into()],
            4,
            c1.clone(),
        );
        reg.register(
            "edge-b".into(),
            vec!["llama3".into(), "*".into()],
            4,
            c2.clone(),
        );
        // 去重、排序、排除 "*"
        assert_eq!(
            reg.healthy_models(Duration::from_secs(10)),
            vec!["llama3", "qwen2.5"]
        );
        // 失联 agent 的模型不聚合
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(reg.healthy_models(Duration::from_millis(10)).is_empty());
    }

    #[tokio::test]
    async fn snapshot_reports_agent_details() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register(
            "home-1".into(),
            vec!["qwen2.5".into(), "llama3".into()],
            2,
            conn.clone(),
        );
        let snap = reg.snapshot(Duration::from_secs(10));
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].agent_id, "home-1");
        assert_eq!(
            snap[0].models,
            vec!["qwen2.5".to_string(), "llama3".to_string()]
        );
        assert_eq!(snap[0].max_concurrency, 2);
        assert_eq!(snap[0].inflight, 0);
        assert!(snap[0].last_seen_secs_ago < 1, "freshly registered agent");
        assert!(
            snap[0].healthy,
            "刚注册的 agent 必须在路由窗口内（复扫 G1）"
        );

        // **结论随窗口变**，而不是某个写死的阈值——这正是复扫 G1 的实质：前端原先拿一个
        // 写死的 15s 去比 `last_seen_secs_ago`，完全无视网关配的 `agent_stale_secs`。
        //
        // 为什么不构造"心跳很旧"的条目：`now_millis()` 是**进程相对**时钟（`epoch().elapsed()`），
        // 测试进程刚起来时它约等于 0，把 `last_seen` 往回拨会被 `saturating_sub` 夹到 0、
        // 反而变成"最新"（实测踩过）。要造旧条目只能真的 sleep；而"窗口一收就不健康、一放就健康"
        // 已经把同一条性质钉住了，且不依赖时钟推进。
        assert!(
            !reg.snapshot(Duration::ZERO)[0].healthy,
            "零窗口下没有任何条目算新鲜"
        );
        assert!(
            reg.snapshot(Duration::from_secs(3600))[0].healthy,
            "同一个条目在足够大的窗口里是健康的 ⇒ 判定跟着窗口走，而不是写死的阈值"
        );

        // 按 agent_id 排序、空注册表为空
        let conn2 = test_connection().await;
        reg.register("agent-a".into(), vec![], 4, conn2.clone());
        let snap = reg.snapshot(Duration::from_secs(10));
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].agent_id, "agent-a");
        assert_eq!(snap[1].agent_id, "home-1");
        assert!(Registry::default()
            .snapshot(Duration::from_secs(10))
            .is_empty());
    }

    /// 规格：**"开流超时"不等于"连接已死"**。
    ///
    /// `open_bidirectional_stream()` 在连接级流额度排满时会排队等回收，所以超时有两种
    /// 成因：对端死了（该摘除），或对端忙、在途已经顶到承载上限（正常背压，摘除就是
    /// 把局部过载放大成全站不可用）。
    ///
    /// 云端实测的代价（2026-09-17，4 agent、768 并发）：一律摘除 → `tunnel open timed out`
    /// 9345 次、健康 agent 被关掉重连 → 单次 30s 压测 `registry-empty` +6835 → 全量 503。
    #[tokio::test]
    async fn open_timeout_is_fatal_only_when_the_connection_is_not_at_capacity() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("busy".into(), vec!["*".into()], 1, conn.clone());
        let (entry, guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();

        // 在途 1 > 0：没到这条连接的上限（max_concurrency = 1 时 1 就是满）
        entry.inflight.store(0, Ordering::Relaxed);
        assert!(
            entry.open_timeout_is_fatal(1024),
            "没有任何在途请求却开不出流 = 连接确实坏了，必须摘除"
        );

        // 在途 1 = max_concurrency：额度排满后的排队超时是背压，不是死亡
        entry.inflight.store(1, Ordering::Relaxed);
        assert!(
            !entry.open_timeout_is_fatal(1024),
            "在途已达声明的 max_concurrency → 超时是排队等额度，不能摘除健康连接"
        );
        drop(guard);

        // 声明不限并发（max_concurrency = 0）时，上限就是端点流额度
        let conn2 = test_connection().await;
        reg.register("unbounded".into(), vec!["*".into()], 0, conn2);
        let (entry2, _g2) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_eq!(entry2.agent_id, "unbounded");
        entry2.inflight.store(3, Ordering::Relaxed);
        assert!(
            entry2.open_timeout_is_fatal(4),
            "在途 3 < 额度 4 → 还有额度却开不出流 = 坏连接"
        );
        entry2.inflight.store(4, Ordering::Relaxed);
        assert!(
            !entry2.open_timeout_is_fatal(4),
            "在途 = 额度 → 超时是额度排队，不是死亡"
        );

        // 配置不一致（agent 声明 256 > 端点额度 100）：以更小的那个为准，
        // 否则"忙"会被判成"死"，又回到摘除健康 agent 的老路。
        let conn3 = test_connection().await;
        reg.register("over-declared".into(), vec!["*".into()], 256, conn3);
        let (entry3, _g3) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        assert_eq!(entry3.agent_id, "over-declared");
        entry3.inflight.store(99, Ordering::Relaxed);
        assert!(entry3.open_timeout_is_fatal(100));
        entry3.inflight.store(100, Ordering::Relaxed);
        assert!(
            !entry3.open_timeout_is_fatal(100),
            "额度先于容量耗尽时，超时同样是背压（这正是要告警的配置不一致）"
        );
    }
    /// 规格：**响应头超时要能区分"最近还在干活"与"真的没有了"**（判据第一层）。
    ///
    /// 这条判据是"链路被堵住 → 健康 agent 被摘除 → 全量 503"的唯一出口：窗口内有过成功响应头
    /// 就只是慢（不摘除），窗口内一次都没有才算死。窗口本身由 `4 × head_timeout` 派生（见 `state.rs`）。
    /// 第二层（对端还活着时的延长）在下面那条用例里。
    ///
    /// ⚠️ 时间基准 `epoch()` 是**首次使用时才创建**的，所以测试进程刚起来时 `now_millis()`
    /// 接近 0——不能用"把时间戳减去 10 秒"来伪造沉默（会被 saturating 压到 0）。这里改为
    /// 真实小睡几毫秒、再把窗口压到 1ms 来跨过边界，避免依赖时间基准的起点。
    #[tokio::test]
    async fn head_timeout_is_fatal_only_after_a_window_of_total_silence() {
        let reg = Registry::default();
        let conn = test_connection().await;
        reg.register("alive".into(), vec!["*".into()], 4, conn);
        let (entry, _guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();
        // 本用例只考第一层：`stuck_after` 给 0（对端活着也延长不了），对端也**从未心跳**。
        let only_window = |window: Duration| HeadSilence {
            window,
            peer_alive_window: Duration::from_secs(15),
            stuck_after: Duration::ZERO,
        };

        // ① 刚注册但**从未回过响应头** → 没有"只是慢"的证据 → 判死
        //    （否则注册后从不回包的坏隧道会被宽限一个窗口才摘除）
        assert!(
            entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
            "从未收到过响应头时不该被当成「只是慢」"
        );

        // ② 收到过响应头 → 仍在窗口内 → 只是慢（这条是判据最该避免的误判）
        reg.note_tunnel_op_ok(entry.stable_id());
        assert!(
            !entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
            "刚刚回过响应头的隧道被判定为死"
        );

        // ③ 沉默 50ms 之后：窗口 1ms → 判死；窗口 60s → 仍只是慢。
        //    同一次沉默、只改窗口就翻转结论，说明判据确实由"沉默时长 vs 窗口"决定。
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            entry.head_timeout_is_fatal(only_window(Duration::from_millis(1))),
            "沉默 50ms > 窗口 1ms → 必须判死（否则坏连接永远摘不掉）"
        );
        assert!(
            !entry.head_timeout_is_fatal(only_window(Duration::from_secs(60))),
            "沉默 50ms < 窗口 60s → 只是慢，不能判死"
        );

        // ④ 期间只要再成功收到一次响应头，窗口重新开始计时
        reg.note_tunnel_op_ok(entry.stable_id());
        assert!(
            !entry.head_timeout_is_fatal(only_window(Duration::from_millis(1))),
            "刚回过响应头就该立刻回到「只是慢」，否则连续计数的语义不成立"
        );
    }

    /// 规格（判据第二层，评估 §5 H2）：**对端还在说话时，窗口过了也不判死**——
    /// 均匀慢流量（所有请求都慢过 `head_timeout`）不能摘掉一条活着的 agent。
    ///
    /// 为什么必须单独钉：`last_head_ok` 的唯一刷新点就是成功响应头，所以"所有请求都慢"时
    /// 没有任何一次成功能刷新它，第一层必然走到"判死"。这一层用"收到过心跳"作为对端活着的
    /// 证据把容忍度延长到 `stuck_after`（一条请求的寿命）。
    #[tokio::test]
    async fn head_silence_is_tolerated_while_the_peer_keeps_heartbeating() {
        let reg = Registry::default();
        let conn = test_connection().await;
        let alive_id = reg.register("slow-but-alive".into(), vec!["*".into()], 4, conn);
        let (entry, _guard) = reg.try_acquire(Duration::from_secs(10), "qwen2.5").unwrap();

        // 先让它"回过一次响应头"，然后沉默 50ms（把窗口压到 1ms 来跨过边界，同上面的技巧）。
        reg.note_tunnel_op_ok(entry.stable_id());
        tokio::time::sleep(Duration::from_millis(50)).await;

        // ① 对端**从未心跳** → 只有第一层 → 判死（这就是既有 e2e 钉的"裸 agent"形态）
        assert!(
            entry.head_timeout_is_fatal(HeadSilence {
                window: Duration::from_millis(1),
                peer_alive_window: Duration::from_secs(15),
                stuck_after: Duration::from_secs(120),
            }),
            "对端从未说过话时不该获得延长"
        );

        // ② 收到心跳 → 对端还活着 → 沉默没超过 stuck_after → **不判死**（H2 要的就是这一格）
        assert!(reg.heartbeat_if_same("slow-but-alive", alive_id));
        let alive = HeadSilence {
            window: Duration::from_millis(1),
            peer_alive_window: Duration::from_secs(15),
            stuck_after: Duration::from_secs(120),
        };
        assert!(
            !entry.head_timeout_is_fatal(alive),
            "对端还在心跳、沉默也远没到一条请求的寿命，不该判死（均匀慢流量误摘）"
        );

        // ③ 但静默超过 stuck_after 就判死：心跳正常、数据面却长时间一声不响 = 卡死，
        //    不能让它永远留在路由里（否则每个请求都白等一次 head_timeout）。
        assert!(
            entry.head_timeout_is_fatal(HeadSilence {
                stuck_after: Duration::from_millis(1),
                ..alive
            }),
            "沉默超过一条请求的寿命后必须判死，否则数据面卡死的连接永远摘不掉"
        );

        // ④ 心跳也停了 → 回到"只看窗口"。
        //    用 `peer_alive_window = 0` 表示"心跳一律不算新鲜"，比"压到 1ms 再睡几毫秒"确定：
        //    刚发出的心跳在同一个毫秒里 `since == 0`，1ms 的窗口仍然算新鲜（这里踩过一次）。
        assert!(
            entry.head_timeout_is_fatal(HeadSilence {
                peer_alive_window: Duration::ZERO,
                ..alive
            }),
            "心跳过期后不该再享有延长"
        );
    }
}
