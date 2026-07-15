//! Copy-on-write storage abstraction for instance rootfs and
//! snapshots.
//!
//! # What this is
//!
//! mvm currently copies a template's full ext4 rootfs into each
//! instance's working directory (`vm/template/lifecycle.rs:606`,
//! `:847` — `cp -a {} {rev_dst}/rootfs.ext4`). Pause/resume captures
//! full vmstate + memory images per snapshot. Storage cost grows
//! linearly with both instance count and snapshot count — a
//! sandbox-as-a-service workload pattern (frequent agent-loop
//! checkpointing) breaks this cost model.
//!
//! The substrate adopts **dm-thin** (device-mapper thin
//! provisioning) so per-instance volumes clone from a verity-sealed
//! base in O(metadata) and snapshot chains share unchanged blocks.
//!
//! # Scope (this module)
//!
//! - Trait surface (`ThinPool` / `ThinVolume`) abstracting `dmsetup`
//!   so tests don't depend on Linux + root.
//! - Default `DmsetupPool` impl shelling out to the system tool
//!   (gated on Linux).
//! - In-memory `MockPool` impl for unit tests + macOS dev hosts.
//! - `mvmctl storage info` / `mvmctl storage gc` CLI verbs that
//!   query the pool through the trait.
//! - Audit kinds for pool operations.
//!
//! A follow-on change wires the actual instance-create path in
//! `vm/template/lifecycle.rs` to use `ThinPool::clone_from_base`
//! instead of `cp -a`. That's the behavioral change; this is the
//! tested substrate it depends on.

pub mod backend;
pub mod pool;
pub mod thin;

pub use backend::{DeviceMapperBackend, DmsetupBackend, MockBackend};
pub use pool::{PoolConfig, PoolStats, ThinPool, ThinPoolImpl};
pub use thin::{ThinVolume, VolumeId, VolumeStats};

/// Default pool name on the host. The pool device is materialized at
/// `/dev/mapper/<DEFAULT_POOL_NAME>` after `dmsetup create`.
pub const DEFAULT_POOL_NAME: &str = "mvm_pool";

/// Default pool size (sparse-file-backed) on dev hosts. Production
/// hosts pin a real LV via the `pool_path` config.
pub const DEFAULT_POOL_SIZE_BYTES: u64 = 100 * 1024 * 1024 * 1024; // 100 GiB

/// Default block size for thin-pool data. 64 KiB matches the typical
/// dm-thin tuning for general-purpose workloads.
pub const DEFAULT_BLOCK_SIZE_BYTES: u32 = 64 * 1024;

/// Errors surfaced by the storage abstraction.
#[derive(Debug)]
pub enum StorageError {
    BackendUnavailable(String),
    PoolNotInitialized(String),
    PoolFull {
        used_bytes: u64,
        capacity_bytes: u64,
    },
    BaseNotFound(String),
    VolumeExists(String),
    VolumeNotFound(String),
    DmsetupFailed {
        cmd: String,
        stderr: String,
    },
    Io(std::io::Error),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable(s) => {
                write!(f, "storage backend not available on this host: {s}")
            }
            Self::PoolNotInitialized(s) => write!(f, "pool not initialized: {s}"),
            Self::PoolFull {
                used_bytes,
                capacity_bytes,
            } => write!(f, "pool full: {used_bytes} / {capacity_bytes} bytes used"),
            Self::BaseNotFound(s) => write!(f, "base volume not found: {s}"),
            Self::VolumeExists(s) => write!(f, "volume already exists: {s}"),
            Self::VolumeNotFound(s) => write!(f, "volume not found: {s}"),
            Self::DmsetupFailed { cmd, stderr } => {
                write!(f, "dmsetup invocation failed: {cmd}: {stderr}")
            }
            Self::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, StorageError>;
