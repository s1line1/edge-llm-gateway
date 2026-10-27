//! 帧的读写：长度前缀 + postcard 序列化，兼容任何 tokio AsyncRead/AsyncWrite
//! （如 quinn 的 SendStream/RecvStream）。

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Frame;

/// 单帧最大字节数（64 MiB）。
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

/// [`FrameReader`] 在"缓冲已空"之后愿意保留的容量（记录 P2-5）。
///
/// 取值够装常见帧（一次底层 `read` 是 8KiB，响应块上限是 [`crate::frame::MAX_RESPONSE_CHUNK`]
/// = 64KiB），又不至于让一次大 body 的峰值容量跟着整条流。
const BUFFER_RETAINED_CAPACITY: usize = crate::frame::MAX_RESPONSE_CHUNK;

// 长度前缀只有 u32：MAX_FRAME 必须装得下，否则下面 `as u32` 会静默截断。
const _: () = assert!(MAX_FRAME <= u32::MAX as usize);

/// 写入一帧：`[u32 大端长度][postcard 字节]`。
pub async fn write_frame<W>(w: &mut W, frame: &Frame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let bytes =
        postcard::to_allocvec(frame).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let len = bytes.len() as u32;
    let mut buf = Vec::with_capacity(4 + bytes.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&bytes);
    w.write_all(&buf).await?;

    Ok(())
}

/// 可安全取消的帧读取器：把半读状态（已收字节 + 目标长度）保存在**自身**，
/// 因此使用方在 `select!` 中落败（future 被 drop）时不会丢掉已读字节。
///
/// 为什么需要这种形状（记录 R3 的前身）：早先另有一条"直接 `read_exact` 一帧"的读路径，
/// tokio 明确标注 `read_exact` **not cancellation safe**——落败时"已读进局部缓冲的字节"
/// 随之消失，下一次读取就会按错误偏移解析长度前缀（帧错位）。本类型唯一的 await 是
/// `AsyncReadExt::read`（tokio 保证取消安全：落败时"没有读到任何数据"），
/// 且解析进度全部落在字段上，所以任何 await 点被打断都可安全重入。
///
/// **现在全项目只剩这一条读路径**（记录 R3）：`select!` 里、响应头/响应体跨阶段交接处
/// （两者共用同一个 reader）、控制流一帧即弃处，用的都是它。
pub struct FrameReader<R> {
    inner: R,
    /// 已收到、尚未组成完整帧的字节（长度前缀 + 载荷）。
    buf: Vec<u8>,
    /// 当前帧总长度（4 字节前缀 + 载荷）；None = 前缀尚未凑齐。
    want: Option<usize>,
}

impl<R> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            want: None,
        }
    }
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    /// 读下一帧。流被对端干净关闭时返回 `Ok(None)`。
    ///
    /// **可安全取消**：任何 await 点被打断都不丢字节，重入后继续拼同一帧。
    pub async fn next(&mut self) -> io::Result<Option<Frame>> {
        loop {
            // 1) 先用已有字节试着凑一帧（这段不 await，不会被从中间打断）
            if let Some(frame) = self.take_frame()? {
                return Ok(Some(frame));
            }
            // 2) 还差字节：进度都留在 self 上，故这里的 await 是取消安全的
            let mut chunk = [0u8; 8 * 1024];
            let n = self.inner.read(&mut chunk).await?;
            if n == 0 {
                // EOF：正好落在帧边界 = 干净关闭；帧中途 = 截断
                if self.buf.is_empty() && self.want.is_none() {
                    return Ok(None);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "early eof"));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// 缓冲区里若已凑齐完整一帧则取出解码（不 await，故可安全地在中途调用）。
    fn take_frame(&mut self) -> io::Result<Option<Frame>> {
        if self.want.is_none() {
            if self.buf.len() < 4 {
                return Ok(None);
            }
            let len =
                u32::from_be_bytes(self.buf[..4].try_into().expect("4 bytes checked")) as usize;
            if len > MAX_FRAME {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "frame too large",
                ));
            }
            self.want = Some(4 + len);
        }
        let total = self.want.expect("just set above");
        if self.buf.len() < total {
            return Ok(None);
        }
        // 直接从缓冲区解码（记录 P2-5）：以前先 `self.buf[4..total].to_vec()` 复制一份载荷再解，
        // 大 body 白白多一次整块拷贝。`Frame` 的字段全是拥有的（`Bytes`/`String`/`Vec`），
        // 解码不借用 `self.buf`（借用检查会拦住），所以可以"先解、后 drain"。
        let frame = postcard::from_bytes(&self.buf[4..total])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.buf.drain(..total);
        self.want = None;
        self.release_peak_buffer();
        Ok(Some(frame))
    }

    /// 缓冲已空且容量明显过大时把内存还回去（记录 P2-5）。
    ///
    /// `Vec::drain` **不缩容**：读过一次 16MiB 的 `ProxyRequest` 之后，这个 reader 会带着同量级
    /// 容量活到**整条流结束**（agent 侧每个请求流一个 reader ⇒ 随并发线性叠加）。实测比"同量级"
    /// 更大——`Vec` 按指数扩容，1MiB 的帧读完后容量是 2MiB（约 2×）。
    /// 只在"已空且超过 [`BUFFER_RETAINED_CAPACITY`]"时缩，避免每帧都 realloc；留下那一点容量
    /// 是为了"多帧连续到达"这条常见路径不重新分配。
    fn release_peak_buffer(&mut self) {
        if self.buf.is_empty() && self.buf.capacity() > BUFFER_RETAINED_CAPACITY {
            self.buf.shrink_to(BUFFER_RETAINED_CAPACITY);
        }
    }
}

#[cfg(test)]
mod tests;
