//! Storage backend trait — the seam between the high-level pool API
//! and the underlying `dmsetup` (or mock) implementation.

use super::{Result, StorageError};
use std::path::PathBuf;

/// One concrete `dmsetup`-style operation. Implementations either
/// shell out to the real binary (`DmsetupBackend`) or record the
/// invocation in memory for tests (`MockBackend`).
pub trait DeviceMapperBackend: Send + Sync {
    /// Create the thin pool device. Idempotent: returns Ok if the
    /// pool already exists.
    fn create_pool(&self, name: &str, size_bytes: u64, block_size: u32) -> Result<()>;

    /// Destroy the thin pool device and any backing storage.
    fn destroy_pool(&self, name: &str) -> Result<()>;

    /// Create a thin volume in the pool (writable). Returns the
    /// device path (e.g. `/dev/mapper/<name>`).
    fn create_thin_volume(
        &self,
        pool_name: &str,
        volume_name: &str,
        device_id: u32,
        virtual_size_bytes: u64,
    ) -> Result<PathBuf>;

    /// Snapshot an existing thin volume. The snapshot starts as a
    /// chained CoW clone — only modified blocks consume new space.
    fn snapshot_volume(
        &self,
        pool_name: &str,
        origin_volume: &str,
        snapshot_name: &str,
        device_id: u32,
    ) -> Result<PathBuf>;

    /// Remove a thin volume. Idempotent.
    fn remove_volume(&self, pool_name: &str, volume_name: &str) -> Result<()>;

    /// Query pool-wide stats.
    fn pool_stats(&self, pool_name: &str) -> Result<BackendPoolStats>;

    /// Query per-volume stats.
    fn volume_stats(&self, pool_name: &str, volume_name: &str) -> Result<BackendVolumeStats>;

    /// List every volume in the pool. Used by `mvmctl storage gc`.
    fn list_volumes(&self, pool_name: &str) -> Result<Vec<String>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendPoolStats {
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub volume_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendVolumeStats {
    pub used_bytes: u64,
    pub virtual_size_bytes: u64,
}

// ────────────────────────────────────────────────────────────────────
// DmsetupBackend — production impl. Shells `dmsetup` on Linux.
// ────────────────────────────────────────────────────────────────────

/// Production backend that shells out to `dmsetup`. On non-Linux
/// hosts (macOS dev hosts) every method returns
/// `StorageError::BackendUnavailable`. Real CoW lives in the Lima VM
/// where this backend can run with root privileges.
pub struct DmsetupBackend;

impl DmsetupBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DmsetupBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
mod dmsetup_linux {
    use super::*;

    pub fn check_available() -> Result<()> {
        match std::process::Command::new("dmsetup")
            .arg("--version")
            .output()
        {
            Ok(o) if o.status.success() => Ok(()),
            Ok(_) => Err(StorageError::BackendUnavailable(
                "dmsetup --version exited non-zero".to_string(),
            )),
            Err(e) => Err(StorageError::BackendUnavailable(format!(
                "dmsetup not on PATH: {e}"
            ))),
        }
    }
}

impl DeviceMapperBackend for DmsetupBackend {
    #[cfg(target_os = "linux")]
    fn create_pool(&self, _name: &str, _size_bytes: u64, _block_size: u32) -> Result<()> {
        dmsetup_linux::check_available()?;
        // Phase 1 deferral: the actual `dmsetup create` invocation
        // (with sparse-file backing + `thin-pool` target) lands in
        // Phase 2 alongside the instance-create migration. The
        // backend trait is what's stable here; the impl can fail
        // closed until Phase 2 ships the real invocation.
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend::create_pool is phase-2 work — use MockBackend for now".to_string(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    fn create_pool(&self, _name: &str, _size_bytes: u64, _block_size: u32) -> Result<()> {
        Err(StorageError::BackendUnavailable(
            "dmsetup requires Linux".to_string(),
        ))
    }

    fn destroy_pool(&self, _name: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        dmsetup_linux::check_available()?;
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }

    fn create_thin_volume(
        &self,
        _pool_name: &str,
        _volume_name: &str,
        _device_id: u32,
        _virtual_size_bytes: u64,
    ) -> Result<PathBuf> {
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }

    fn snapshot_volume(
        &self,
        _pool_name: &str,
        _origin_volume: &str,
        _snapshot_name: &str,
        _device_id: u32,
    ) -> Result<PathBuf> {
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }

    fn remove_volume(&self, _pool_name: &str, _volume_name: &str) -> Result<()> {
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }

    fn pool_stats(&self, _pool_name: &str) -> Result<BackendPoolStats> {
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }

    fn volume_stats(&self, _pool_name: &str, _volume_name: &str) -> Result<BackendVolumeStats> {
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }

    fn list_volumes(&self, _pool_name: &str) -> Result<Vec<String>> {
        Err(StorageError::BackendUnavailable(
            "DmsetupBackend phase-2 work".to_string(),
        ))
    }
}

// ────────────────────────────────────────────────────────────────────
// MockBackend — in-memory backend for unit tests + macOS dev hosts.
// ────────────────────────────────────────────────────────────────────

/// Pure in-memory backend. Records every operation in a
/// `Mutex<MockState>` so tests can assert on the operation log + the
/// resulting pool/volume topology.
///
/// Volumes are tracked by `(pool_name, volume_name)`; their
/// `used_bytes` start at 0 and can be set via
/// [`MockBackend::set_used_bytes`] for tests that need to drive
/// pool-full scenarios.
pub struct MockBackend {
    state: std::sync::Mutex<MockState>,
}

#[derive(Default)]
pub(crate) struct MockState {
    pub pools: std::collections::HashMap<String, MockPool>,
    pub log: Vec<String>,
}

#[derive(Default)]
pub(crate) struct MockPool {
    pub capacity_bytes: u64,
    /// Block size kept as metadata for round-trip parity with dm-thin's
    /// pool layout; not consulted by the mock arithmetic.
    #[allow(dead_code)]
    pub block_size: u32,
    pub volumes: std::collections::HashMap<String, MockVolume>,
    /// Monotonic device id counter — every new volume gets the next
    /// one. Mirrors dm-thin's metadata-id allocation.
    pub next_device_id: u32,
}

#[derive(Default, Clone, Copy)]
pub(crate) struct MockVolume {
    pub virtual_size_bytes: u64,
    pub used_bytes: u64,
    /// Device id of the volume this snapshotted from. `None` for
    /// freshly-created (non-clone) volumes. Phase 2 uses this to
    /// reconstruct snapshot chains for the supervisor's reaper.
    #[allow(dead_code)]
    pub origin: Option<u32>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(MockState::default()),
        }
    }

    pub fn log(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("MockBackend state mutex poisoned")
            .log
            .clone()
    }

    /// Set the `used_bytes` field on a volume. Tests use this to
    /// drive pool-full + per-volume scenarios.
    pub fn set_used_bytes(&self, pool_name: &str, volume_name: &str, used: u64) {
        let mut s = self.state.lock().expect("MockBackend state mutex poisoned");
        if let Some(p) = s.pools.get_mut(pool_name)
            && let Some(v) = p.volumes.get_mut(volume_name)
        {
            v.used_bytes = used;
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceMapperBackend for MockBackend {
    fn create_pool(&self, name: &str, size_bytes: u64, block_size: u32) -> Result<()> {
        let mut s = self.state.lock().expect("MockBackend state mutex poisoned");
        s.log.push(format!(
            "create_pool({name}, size={size_bytes}, block={block_size})"
        ));
        s.pools.entry(name.to_string()).or_insert(MockPool {
            capacity_bytes: size_bytes,
            block_size,
            ..MockPool::default()
        });
        Ok(())
    }

    fn destroy_pool(&self, name: &str) -> Result<()> {
        let mut s = self.state.lock().expect("MockBackend state mutex poisoned");
        s.log.push(format!("destroy_pool({name})"));
        s.pools.remove(name);
        Ok(())
    }

    fn create_thin_volume(
        &self,
        pool_name: &str,
        volume_name: &str,
        _device_id: u32,
        virtual_size_bytes: u64,
    ) -> Result<PathBuf> {
        let mut s = self.state.lock().expect("MockBackend state mutex poisoned");
        s.log.push(format!(
            "create_thin_volume({pool_name}, {volume_name}, size={virtual_size_bytes})"
        ));
        let pool = s
            .pools
            .get_mut(pool_name)
            .ok_or_else(|| StorageError::PoolNotInitialized(pool_name.to_string()))?;
        if pool.volumes.contains_key(volume_name) {
            return Err(StorageError::VolumeExists(volume_name.to_string()));
        }
        pool.next_device_id += 1;
        pool.volumes.insert(
            volume_name.to_string(),
            MockVolume {
                virtual_size_bytes,
                used_bytes: 0,
                origin: None,
            },
        );
        Ok(PathBuf::from(format!("/dev/mapper/{volume_name}")))
    }

    fn snapshot_volume(
        &self,
        pool_name: &str,
        origin_volume: &str,
        snapshot_name: &str,
        _device_id: u32,
    ) -> Result<PathBuf> {
        let mut s = self.state.lock().expect("MockBackend state mutex poisoned");
        s.log.push(format!(
            "snapshot_volume({pool_name}, origin={origin_volume}, snap={snapshot_name})"
        ));
        let pool = s
            .pools
            .get_mut(pool_name)
            .ok_or_else(|| StorageError::PoolNotInitialized(pool_name.to_string()))?;
        let origin = pool
            .volumes
            .get(origin_volume)
            .ok_or_else(|| StorageError::VolumeNotFound(origin_volume.to_string()))?;
        let virtual_size_bytes = origin.virtual_size_bytes;
        if pool.volumes.contains_key(snapshot_name) {
            return Err(StorageError::VolumeExists(snapshot_name.to_string()));
        }
        pool.next_device_id += 1;
        let id = pool.next_device_id;
        pool.volumes.insert(
            snapshot_name.to_string(),
            MockVolume {
                virtual_size_bytes,
                used_bytes: 0,
                origin: Some(id),
            },
        );
        Ok(PathBuf::from(format!("/dev/mapper/{snapshot_name}")))
    }

    fn remove_volume(&self, pool_name: &str, volume_name: &str) -> Result<()> {
        let mut s = self.state.lock().expect("MockBackend state mutex poisoned");
        s.log
            .push(format!("remove_volume({pool_name}, {volume_name})"));
        let pool = s
            .pools
            .get_mut(pool_name)
            .ok_or_else(|| StorageError::PoolNotInitialized(pool_name.to_string()))?;
        pool.volumes.remove(volume_name);
        Ok(())
    }

    fn pool_stats(&self, pool_name: &str) -> Result<BackendPoolStats> {
        let s = self.state.lock().expect("MockBackend state mutex poisoned");
        let pool = s
            .pools
            .get(pool_name)
            .ok_or_else(|| StorageError::PoolNotInitialized(pool_name.to_string()))?;
        let used: u64 = pool.volumes.values().map(|v| v.used_bytes).sum();
        Ok(BackendPoolStats {
            used_bytes: used,
            capacity_bytes: pool.capacity_bytes,
            volume_count: pool.volumes.len() as u32,
        })
    }

    fn volume_stats(&self, pool_name: &str, volume_name: &str) -> Result<BackendVolumeStats> {
        let s = self.state.lock().expect("MockBackend state mutex poisoned");
        let pool = s
            .pools
            .get(pool_name)
            .ok_or_else(|| StorageError::PoolNotInitialized(pool_name.to_string()))?;
        let v = pool
            .volumes
            .get(volume_name)
            .ok_or_else(|| StorageError::VolumeNotFound(volume_name.to_string()))?;
        Ok(BackendVolumeStats {
            used_bytes: v.used_bytes,
            virtual_size_bytes: v.virtual_size_bytes,
        })
    }

    fn list_volumes(&self, pool_name: &str) -> Result<Vec<String>> {
        let s = self.state.lock().expect("MockBackend state mutex poisoned");
        let pool = s
            .pools
            .get(pool_name)
            .ok_or_else(|| StorageError::PoolNotInitialized(pool_name.to_string()))?;
        let mut names: Vec<String> = pool.volumes.keys().cloned().collect();
        names.sort();
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_pool_round_trips() {
        let b = MockBackend::new();
        b.create_pool("p", 1_000_000, 65536).unwrap();
        let path = b.create_thin_volume("p", "vol-1", 0, 100_000).unwrap();
        assert_eq!(path, PathBuf::from("/dev/mapper/vol-1"));

        let stats = b.pool_stats("p").unwrap();
        assert_eq!(stats.capacity_bytes, 1_000_000);
        assert_eq!(stats.volume_count, 1);

        let vstats = b.volume_stats("p", "vol-1").unwrap();
        assert_eq!(vstats.virtual_size_bytes, 100_000);
        assert_eq!(vstats.used_bytes, 0);
    }

    #[test]
    fn mock_snapshot_inherits_size() {
        let b = MockBackend::new();
        b.create_pool("p", 1_000_000, 65536).unwrap();
        b.create_thin_volume("p", "base", 0, 100_000).unwrap();
        b.snapshot_volume("p", "base", "snap1", 0).unwrap();
        let vstats = b.volume_stats("p", "snap1").unwrap();
        assert_eq!(vstats.virtual_size_bytes, 100_000);
    }

    #[test]
    fn mock_volume_exists_rejects_duplicates() {
        let b = MockBackend::new();
        b.create_pool("p", 1_000_000, 65536).unwrap();
        b.create_thin_volume("p", "v", 0, 1000).unwrap();
        let err = b.create_thin_volume("p", "v", 0, 1000).unwrap_err();
        matches!(err, StorageError::VolumeExists(_));
    }

    #[test]
    fn mock_volume_not_found_on_snapshot() {
        let b = MockBackend::new();
        b.create_pool("p", 1_000_000, 65536).unwrap();
        let err = b.snapshot_volume("p", "missing", "snap", 0).unwrap_err();
        matches!(err, StorageError::VolumeNotFound(_));
    }

    #[test]
    fn mock_log_records_invocations() {
        let b = MockBackend::new();
        b.create_pool("p", 1000, 64).unwrap();
        b.create_thin_volume("p", "v", 0, 100).unwrap();
        b.remove_volume("p", "v").unwrap();
        let log = b.log();
        assert_eq!(log.len(), 3);
        assert!(log[0].starts_with("create_pool"));
        assert!(log[1].starts_with("create_thin_volume"));
        assert!(log[2].starts_with("remove_volume"));
    }

    #[test]
    fn list_volumes_returns_sorted_names() {
        let b = MockBackend::new();
        b.create_pool("p", 1_000_000, 65536).unwrap();
        b.create_thin_volume("p", "z", 0, 100).unwrap();
        b.create_thin_volume("p", "a", 0, 100).unwrap();
        b.create_thin_volume("p", "m", 0, 100).unwrap();
        assert_eq!(b.list_volumes("p").unwrap(), vec!["a", "m", "z"]);
    }

    #[test]
    fn pool_stats_sums_used_bytes() {
        let b = MockBackend::new();
        b.create_pool("p", 1_000_000, 65536).unwrap();
        b.create_thin_volume("p", "v1", 0, 1_000).unwrap();
        b.create_thin_volume("p", "v2", 0, 1_000).unwrap();
        b.set_used_bytes("p", "v1", 200);
        b.set_used_bytes("p", "v2", 300);
        assert_eq!(b.pool_stats("p").unwrap().used_bytes, 500);
    }
}
