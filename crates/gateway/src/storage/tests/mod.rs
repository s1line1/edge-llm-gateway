//! storage 的单元测试：从 `storage/mod.rs` 的两个内联模块搬出，并按变更理由分文件。
//!
//! `tests` 仍是 `storage` 的子模块，所以 `use super::*` 仍能看到 `Storage` 私有字段
//! （`inner.runtime` / `inner.db`）与 `hash` 的线程局部开关。共享导入留在这里。

use super::*;
use serial_test::serial;
use tempfile::tempdir;

mod cache;
mod keys;
mod persistence;
mod poison;
mod usage;
