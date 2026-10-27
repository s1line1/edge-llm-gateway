//! `io` 的单元测试：从 `proto/src/io.rs` 的内联 `mod tests` 原样搬出。
//!
//! `tests` 仍是 `io` 的子模块，所以 `use super::*` 仍能直接构造 `FrameReader`、
//! 访问 `MAX_FRAME`/`BUFFER_RETAINED_CAPACITY` 等私有实现细节。

use std::time::Duration;

use super::*;
use crate::Frame;
use bytes::Bytes;

#[tokio::test]
async fn frame_reader_invalid_postcard_payload_rejected() {
    // 长度合法但字节不是合法 postcard → 反序列化错误
    let mut buf = Vec::new();
    buf.extend_from_slice(&4u32.to_be_bytes());
    buf.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    let mut reader = FrameReader::new(buf.as_slice());
    let err = reader.next().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

/// 规格（记录 R4）：**半个长度前缀不算干净关闭**。
///
/// 触发：对端只写出 1–3 字节的长度前缀就 FIN（写入中途被放弃、进程被杀、连接被掐）。
/// 当年那条读路径把前缀 `read_exact` 的任何 `UnexpectedEof` 都映射成 `Ok(None)`，于是这种
/// 截断被当成"对端有序收工"：`forward` 侧记成 `UpstreamClosed` 而不是读取错误，`quic` 侧记成
/// "注册前就关了"。只有**一个字节都没读到**才是干净关闭。
///
/// 记录 R3 之后全项目只剩 [`FrameReader`] 这一条读路径，所以这条规格现在只钉它一处。
#[tokio::test]
async fn frame_reader_a_truncated_length_prefix_is_not_a_clean_close() {
    // 0 字节 = 干净关闭（对端开了流又什么都不发就关，是合法的）
    let mut empty = FrameReader::new(&[][..]);
    assert!(empty.next().await.unwrap().is_none());

    // 1–3 字节 = 截断
    for n in 1..4usize {
        let mut prefix: &[u8] = &vec![0u8; n];
        let mut reader = FrameReader::new(&mut prefix);
        let err = reader
            .next()
            .await
            .expect_err("只给了前缀的一部分就 EOF，不该当成干净关闭");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "n={n}");
    }

    // 慢喂（每次 1 字节）下同样要认出来——不能依赖"一次 read 就能拿到整段前缀"
    let mut dribble = FrameReader::new(DribbleReader::new(vec![0u8; 3]));
    let err = dribble.next().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

/// 总是返回错误的读取器，用于触发非 EOF 的读错误分支。
struct ErrReader;

impl tokio::io::AsyncRead for ErrReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("boom")))
    }
}

#[tokio::test]
async fn frame_reader_non_eof_read_error_propagates() {
    // 非 EOF 的底层读错误应直接向上传播（区别于干净 EOF 的 None）
    let mut reader = FrameReader::new(ErrReader);
    let err = reader.next().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::Other);
    assert_eq!(err.to_string(), "boom");
}

/// 每次只吐 2 字节、且每轮之间插入一次 Pending 的读取器。
/// 效果：任何一帧都必然跨多次 poll，因此"中途被 drop"必然落在**帧内部**
/// （而不会恰好落在帧边界上），从而把"丢字节"暴露成可断言的失败。
struct DribbleReader {
    data: Vec<u8>,
    pos: usize,
    /// true = 本轮吐字节；false = 本轮返回 Pending（并自我唤醒，保证仍会推进）
    deliver: bool,
}

impl DribbleReader {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            pos: 0,
            deliver: true,
        }
    }
}

impl tokio::io::AsyncRead for DribbleReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let me = self.get_mut();
        if !me.deliver {
            me.deliver = true;
            cx.waker().wake_by_ref(); // 之后仍会被唤醒，保证继续推进（不会死等）
            return std::task::Poll::Pending;
        }
        me.deliver = false;
        let n = (me.data.len() - me.pos).min(2).min(buf.remaining());
        buf.put_slice(&me.data[me.pos..me.pos + n]);
        me.pos += n;
        std::task::Poll::Ready(Ok(()))
    }
}

/// 把若干帧序列化成一条 wire 字节流。
async fn wire_of(frames: &[Frame]) -> Vec<u8> {
    let mut buf = Vec::new();
    for f in frames {
        write_frame(&mut buf, f).await.unwrap();
    }
    buf
}

/// 规格：帧读取**必须可安全取消**——在 `select!` 中落败（future 被 drop）后
/// 不得丢失已读字节，下一次读取仍要拿到完整的帧。
///
/// 背景：旧的那条读路径内部是 `read_exact`，tokio 明确标注它 **not cancellation
/// safe**（落败时"some data may already have been read into buf"）。而 agent 的
/// `handle_stream` 直接把它当作 `select!` 分支用：落败分支一赢就丢掉半读的帧，
/// 后续按长度前缀错位解析——网关发来的 `Cancel` 被静默丢弃，取消传播失效、
/// 上游 token 继续白烧（与设计意图相反）。这条测试就是那次重写的护栏。
#[tokio::test]
async fn frame_reader_survives_cancel_mid_frame() {
    let body = Frame::ProxyResponseBody {
        request_id: 7,
        chunk: vec![1u8, 2, 3].into(),
    };
    let cancel = Frame::Cancel { request_id: 7 };
    let wire = wire_of(&[body.clone(), cancel.clone()]).await;
    let mut reader = FrameReader::new(DribbleReader::new(wire));

    // biased：先 poll 读分支（不足一帧 → Pending），再由立即就绪的分支获胜
    // → 读 future 被 drop 在**帧中间**（此时长度前缀已被消费掉一部分）。
    tokio::select! {
        biased;
        r = reader.next() => unreachable!("dribble reader 需多次 poll，读分支不应获胜: {r:?}"),
        _ = std::future::ready(()) => {}
    }

    // 落败不得丢字节：两帧都必须完整读出。
    assert_eq!(
        reader.next().await.unwrap(),
        Some(body),
        "落败的读取丢掉了已读字节（长度前缀错位）"
    );
    assert_eq!(reader.next().await.unwrap(), Some(cancel));
}

/// 帧语义护栏：这条读路径当年为了取消安全性重写了长度前缀解析，必须与旧读路径
/// **逐字节等价**。以下是那次重写的四条护栏（EOF / 截断 / 超大前缀 / 全帧型）。
#[tokio::test]
async fn frame_reader_roundtrip_all_frame_types() {
    let frames = vec![
        Frame::Register {
            agent_id: "home-1".into(),
            models: vec!["mock-llm".into()],
            max_concurrency: 4,
            version: "0.1.0".into(),
        },
        Frame::Heartbeat {
            agent_id: "home-1".into(),
            inflight: 3,
        },
        Frame::ProxyRequest {
            request_id: 42,
            method: "POST".into(),
            path: "/v1/chat/completions?stream=true".into(),
            headers: vec![("content-type".into(), "application/json".into())],
            body: Bytes::from_static(b"{\"model\":\"x\"}"),
        },
        Frame::ProxyResponseHead {
            request_id: 42,
            status: 200,
            headers: vec![("content-type".into(), "text/event-stream".into())],
        },
        Frame::ProxyResponseBody {
            request_id: 42,
            chunk: Bytes::from_static(b"data: {...}\n\n"),
        },
        Frame::ProxyResponseEnd {
            request_id: 42,
            ok: true,
        },
        Frame::Cancel { request_id: 42 },
        Frame::Error {
            request_id: Some(42),
            code: 502,
            message: "upstream error".into(),
        },
    ];
    let wire = wire_of(&frames).await;

    // 整块可读的 reader
    let mut reader = FrameReader::new(wire.as_slice());
    let mut out = Vec::new();
    while let Some(f) = reader.next().await.unwrap() {
        out.push(f);
    }
    assert_eq!(out, frames, "逐帧解码结果必须与写出去的一致");

    // 逐 2 字节慢喂的 reader：缓冲累积逻辑也必须正确（跨多次 poll 拼帧）
    let mut dribble = FrameReader::new(DribbleReader::new(wire));
    let mut out2 = Vec::new();
    while let Some(f) = dribble.next().await.unwrap() {
        out2.push(f);
    }
    assert_eq!(out2, frames, "慢速 reader 下也必须逐帧拼对");
}

#[tokio::test]
async fn frame_reader_clean_eof_returns_none() {
    let mut reader = FrameReader::new(&[][..]);
    assert!(reader.next().await.unwrap().is_none());
}

/// 大帧必须跨多次内部 read 正确拼装，且拼完后下一帧仍对齐
/// （LLM 响应体动辄几十 KiB，这是生产主路径）。
#[tokio::test]
async fn frame_reader_large_body_spans_multiple_reads() {
    let big = Frame::ProxyResponseBody {
        request_id: 7,
        chunk: vec![0xab; 64 * 1024].into(), // 远超内部 8KiB 读块
    };
    let next = Frame::ProxyResponseEnd {
        request_id: 7,
        ok: true,
    };
    let wire = wire_of(&[big.clone(), next.clone()]).await;

    let mut reader = FrameReader::new(wire.as_slice());
    assert_eq!(reader.next().await.unwrap(), Some(big.clone()));
    assert_eq!(
        reader.next().await.unwrap(),
        Some(next.clone()),
        "大帧后必须仍对齐"
    );
    assert!(reader.next().await.unwrap().is_none());

    // 慢喂（每次 2 字节）下同样要拼对
    let mut dribble = FrameReader::new(DribbleReader::new(wire));
    assert_eq!(dribble.next().await.unwrap(), Some(big));
    assert_eq!(dribble.next().await.unwrap(), Some(next));
}

#[tokio::test]
async fn frame_reader_truncated_frame_errors() {
    // 声明 10 字节只给了 3 字节：中途 EOF 应报错（区别于干净 EOF 的 None）
    let mut buf = Vec::new();
    buf.extend_from_slice(&10u32.to_be_bytes());
    buf.extend_from_slice(&[1, 2, 3]);
    let mut reader = FrameReader::new(buf.as_slice());
    let err = reader.next().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

/// 规格（记录 P2-5）：**大帧读完之后，峰值容量必须还回去**。
///
/// `Vec::drain` 不缩容，所以修复前一个读过 1MiB 帧的 reader 会带着 ≥1MiB 容量活到整条流
/// 结束（agent 侧每个请求流一个 reader ⇒ 随并发线性叠加）。这条直接断言容量，看的正是
/// "内存有没有还回去"；第二段再确认缩容没有把"同一批到达的后续帧"弄丢。
#[tokio::test]
async fn a_large_frame_does_not_leave_its_buffer_capacity_behind() {
    let big = Frame::ProxyResponseBody {
        request_id: 1,
        chunk: vec![7u8; 1024 * 1024].into(),
    };
    let small = Frame::ProxyResponseBody {
        request_id: 2,
        chunk: Bytes::from_static(b"small"),
    };
    // 两帧写在**同一条线上**：第二帧常常和第一帧的尾巴一起到达，正好是"缓冲非空 ⇒ 不缩容"
    // 的那条路径，必须照样解析正确
    let mut wire = Vec::new();
    write_frame(&mut wire, &big).await.unwrap();
    write_frame(&mut wire, &small).await.unwrap();

    let mut reader = FrameReader::new(wire.as_slice());
    assert_eq!(reader.next().await.unwrap(), Some(big));
    assert_eq!(
        reader.next().await.unwrap(),
        Some(small),
        "缩容不得弄丢同一批到达的后续帧"
    );
    assert!(reader.buf.is_empty(), "两帧都取走后缓冲应当为空");
    // **写死一个独立的上限**，不拿被测常量当阈值：`BUFFER_RETAINED_CAPACITY` 本身就是要守的
    // 规格，用它当阈值等于自指——把它抬到 1MiB，这条测试照样绿（2026-09-24 二轮审计发现；
    // 同类自指在 P3-14 的 `MAX_NON_STREAM_BUFFER` 上已订正过，这条当时漏了）。
    const EXPECTED_CAP: usize = 64 * 1024;
    assert_eq!(
        BUFFER_RETAINED_CAPACITY, EXPECTED_CAP,
        "保留容量被改动了：动它之前先确认这条规格（以及为什么是 64KiB）仍然成立"
    );
    assert!(
        reader.buf.capacity() <= EXPECTED_CAP,
        "1MiB 帧读完后容量必须还回去：实际 {} 字节（上限 {EXPECTED_CAP}）",
        reader.buf.capacity()
    );
    assert!(reader.next().await.unwrap().is_none());
}

#[tokio::test]
async fn frame_reader_oversized_len_prefix_rejected() {
    // 长度前缀超过 MAX_FRAME → 直接拒绝，不分配大块内存
    let mut buf = Vec::new();
    buf.extend_from_slice(&u32::MAX.to_be_bytes());
    let mut reader = FrameReader::new(buf.as_slice());
    let err = reader.next().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("too large"), "err: {err}");

    // 慢速 reader 下同样必须在"凑齐前缀"后立刻拒绝
    let mut dribble = FrameReader::new(DribbleReader::new(buf));
    let err = dribble.next().await.unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
}

/// 规格：帧里的 `body`/`chunk` 从 `Vec<u8>` 换成 [`bytes::Bytes`]（H6：让 postcard 走
/// `serialize_bytes` 一次写整块）**不改变线上格式**。
///
/// 为什么必须钉：隧道两端可以版本不一致（新网关 + 旧 agent，或反过来）。`Bytes` 用
/// `serialize_bytes`、`Vec<u8>` 用"元素序列"，是两条不同的 serde 路径；postcard 恰好把两者
/// 都编成 `varint 长度 + 原始字节`，这里用一个**变体顺序与字段顺序完全一致**的镜像枚举
/// 逐字节比对，把"恰好"变成判据。（镜像里变体顺序也必须一致——postcard 的枚举是"变体序号 +
/// 字段"，所以这个测试顺带钉住"变体顺序不能改"。）
#[test]
fn bytes_body_encodes_identically_to_a_plain_vec() {
    // 只构造 ProxyRequest/ProxyResponseBody；其余变体存在的意义是**对齐变体序号**
    // （postcard 的枚举编码 = 变体序号 + 字段），所以这里允许它们"未被构造"。
    #[derive(serde::Serialize)]
    #[allow(dead_code)]
    enum PlainFrame {
        Register {
            agent_id: String,
            models: Vec<String>,
            max_concurrency: u32,
            version: String,
        },
        Heartbeat {
            agent_id: String,
            inflight: u32,
        },
        ProxyRequest {
            request_id: u64,
            method: String,
            path: String,
            headers: Vec<(String, String)>,
            body: Vec<u8>,
        },
        ProxyResponseHead {
            request_id: u64,
            status: u16,
            headers: Vec<(String, String)>,
        },
        ProxyResponseBody {
            request_id: u64,
            chunk: Vec<u8>,
        },
        ProxyResponseEnd {
            request_id: u64,
            ok: bool,
        },
        Cancel {
            request_id: u64,
        },
        Error {
            request_id: Option<u64>,
            code: u16,
            message: String,
        },
    }

    // 边界：空、单字节、跨 0x80、1KiB
    for body in [
        Vec::new(),
        vec![0u8],
        vec![0x7f, 0x80, 0xff],
        vec![b'x'; 1024],
    ] {
        let headers = vec![("content-type".to_string(), "application/json".into())];
        let frame = Frame::ProxyRequest {
            request_id: 7,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers: headers.clone(),
            body: Bytes::copy_from_slice(&body),
        };
        let plain = PlainFrame::ProxyRequest {
            request_id: 7,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            headers,
            body: body.clone(),
        };
        assert_eq!(
            postcard::to_allocvec(&frame).expect("encode"),
            postcard::to_allocvec(&plain).expect("encode"),
            "body={} 字节时线上格式变了（旧 agent 会解不开）",
            body.len()
        );

        let chunk = Frame::ProxyResponseBody {
            request_id: 9,
            chunk: Bytes::copy_from_slice(&body),
        };
        let plain_chunk = PlainFrame::ProxyResponseBody {
            request_id: 9,
            chunk: body.clone(),
        };
        assert_eq!(
            postcard::to_allocvec(&chunk).expect("encode"),
            postcard::to_allocvec(&plain_chunk).expect("encode"),
            "chunk={} 字节时线上格式变了",
            body.len()
        );
    }

    // 反向：旧端（`Vec<u8>` 编码）写出的字节，新端必须解成同一个帧
    let plain_bytes = postcard::to_allocvec(&PlainFrame::ProxyResponseBody {
        request_id: 3,
        chunk: b"hello".to_vec(),
    })
    .expect("encode");
    match postcard::from_bytes::<Frame>(&plain_bytes).expect("decode") {
        Frame::ProxyResponseBody { request_id, chunk } => {
            assert_eq!(request_id, 3);
            assert_eq!(&chunk[..], b"hello");
        }
        other => panic!("应当解出 ProxyResponseBody，实际 {other:?}"),
    }
}

/// 规格（并集报告 H8 的机制那一半）：**写到一半被超时放弃的帧，只在对端留下一个严格前缀**。
///
/// `write_frame` 是**一次** `write_all`（长度前缀 + 载荷在同一缓冲里），而 `write_all` 内部
/// 是"部分写 + 循环"：超时把它 drop 掉时，剩下的字节**再也不会**写到这条流上。所以对端最多
/// 拿到真帧的一个前缀，`FrameReader` 的 `read_exact` 永远等不齐——请求不可能被执行。
///
/// 这条钉住的是那个前提。另一半（网关不会把剩余字节补写到同一条流、而是换新流重试）在
/// `proxy::routing::open_and_send` 的重试循环里，见那里的注释与 e2e
/// `write_backpressure::e2e_a_write_that_times_out_mid_frame_never_reaches_the_agent_as_a_request`。
#[tokio::test]
async fn a_timed_out_write_leaves_only_a_strict_prefix_of_the_frame() {
    /// 前 `limit` 字节照收、之后永远 `Pending`（且**不唤醒**）的 writer——模拟"对端不读"。
    struct StallingWriter {
        limit: usize,
        buf: Vec<u8>,
    }

    impl AsyncWrite for StallingWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            if self.buf.len() >= self.limit {
                return std::task::Poll::Pending; // 卡住，永不就绪
            }
            let n = buf.len().min(self.limit - self.buf.len());
            self.buf.extend_from_slice(&buf[..n]);
            std::task::Poll::Ready(Ok(n))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    let frame = Frame::ProxyRequest {
        request_id: 1,
        method: "POST".into(),
        path: "/v1/chat/completions".into(),
        headers: vec![],
        body: Bytes::from(vec![b'x'; 4096]),
    };
    // 完整帧的字节（长度前缀 + postcard 载荷）
    let payload = postcard::to_allocvec(&frame).expect("encode");
    let mut full = Vec::with_capacity(4 + payload.len());
    full.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    full.extend_from_slice(&payload);
    assert!(full.len() > 64, "前提：这一帧要比注入的前缀长");

    let mut writer = StallingWriter {
        limit: 64,
        buf: Vec::new(),
    };
    let timed_out =
        tokio::time::timeout(Duration::from_millis(50), write_frame(&mut writer, &frame)).await;
    assert!(timed_out.is_err(), "对端不读时写应当超时");
    assert_eq!(writer.buf.len(), 64, "超时前应当恰好写满注入的前缀");
    assert!(
        full.starts_with(&writer.buf),
        "对端拿到的必须是真帧的前缀（否则线上格式已变）"
    );
    assert!(
        writer.buf.len() < full.len(),
        "前缀必须**严格短于**整帧——等长的意思是对端可能已经解出完整请求"
    );
}

/// Phase 0 表征测试：**8 个 `Frame` 变体的线格式逐字节固定**。
///
/// 为什么需要它：线格式是 `[u32 BE 长度][postcard]`，而 postcard 的**枚举变体序号就是
/// 编码本身**（`frame.rs` 的声明顺序 = tag）。以前只有 `frame_reader_roundtrip_all_frame_types`
/// 做往返测试——它是拿 proto 自己的编码器验自己的解码器，重排变体时两边一起变、测试仍绿。
/// 这里的 golden 字节独立于编码器：调换 `Cancel`/`Error` 的顺序会立刻红。
///
/// 期望值来自当前实现的实测输出（`dump_frame_wire_bytes` 那一轮），不是手算的；
/// **改动线格式时必须同时改这张表**，并在 PR 里说明兼容性影响。`Frame` 的变体顺序、
/// `Bytes` 的 `serialize_bytes` 编码、`Option`/`u32` 的 varint 形式都被这张表钉住。
#[tokio::test]
async fn all_frame_variants_have_stable_wire_bytes() {
    let expected = [
        ("Register", "0000000900016101016d010176"),
        ("Heartbeat", "0000000401016100"),
        ("ProxyRequest", "0000000a02010150022f78000162"),
        ("ProxyResponseHead", "000000050301c80100"),
        ("ProxyResponseBody", "0000000404010163"),
        ("ProxyResponseEnd", "00000003050101"),
        ("Cancel", "000000020601"),
        ("Error", "000000060700f4030165"),
    ];

    for (frame, (kind, hex)) in golden_frames().iter().zip(expected) {
        assert_eq!(frame.kind(), kind, "golden 表的顺序必须与变体声明顺序一致");
        let wire = wire_of(std::slice::from_ref(frame)).await;
        let actual: String = wire.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            actual, hex,
            "{kind} 的线格式变了：这会让新旧版本不能混跑（变体顺序、字段顺序或编码方式被改动）"
        );

        // 反方向：golden 字节必须解回同一个帧（只断言编码不够——解码器也可能漂移）。
        let mut reader = FrameReader::new(wire.as_slice());
        assert_eq!(
            reader.next().await.expect("decode golden bytes"),
            Some(frame.clone()),
            "{kind} 的 golden 字节解不回原帧"
        );
    }
}

/// 每个变体给一份最小载荷：golden 断言只关心"变体序号 + 字段顺序 + 编码方式"，
/// 不关心业务值；小载荷让字节串可读、可人工核对。
fn golden_frames() -> Vec<Frame> {
    vec![
        Frame::Register {
            agent_id: "a".into(),
            models: vec!["m".into()],
            max_concurrency: 1,
            version: "v".into(),
        },
        Frame::Heartbeat {
            agent_id: "a".into(),
            inflight: 0,
        },
        Frame::ProxyRequest {
            request_id: 1,
            method: "P".into(),
            path: "/x".into(),
            headers: vec![],
            body: Bytes::from_static(b"b"),
        },
        Frame::ProxyResponseHead {
            request_id: 1,
            status: 200,
            headers: vec![],
        },
        Frame::ProxyResponseBody {
            request_id: 1,
            chunk: Bytes::from_static(b"c"),
        },
        Frame::ProxyResponseEnd {
            request_id: 1,
            ok: true,
        },
        Frame::Cancel { request_id: 1 },
        Frame::Error {
            request_id: None,
            code: 500,
            message: "e".into(),
        },
    ]
}
