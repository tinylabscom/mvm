//! Pool-level operations on top of a [`DeviceMapperBackend`]. The trait exposes
//! the user-facing surface: bootstrap, info, gc, capacity gating.

use super::backend::{BackendPoolStats, DeviceMapperBackend};
use super::thin::{ThinVolume, VolumeId};
use super::{
    DEFAULT_BLOCK_SIZE_BYTES, DEFAULT_POOL_NAME, DEFAULT_POOL_SIZE_BYTES, Result, StorageError,
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub name: String,
    pub size_bytes: u64,
    pub block_size: u32,
    /// Hard cap as a fraction of `size_bytes`. New volume creation
    /// rejects when used / capacity exceeds this. Default 0.95 leaves
    /// 5% headroom for in-flight writes to existing volumes.
    pub fill_cap: f32,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            name: DEFAULT_POOL_NAME.to_string(),
            size_bytes: DEFAULT_POOL_SIZE_BYTES,
            block_size: DEFAULT_BLOCK_SIZE_BYTES,
            fill_cap: 0.95,
        }
    }
}

/// Pool-wide statistics for `mvmctl storage info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PoolStats {
    pub used_bytes: u64,
    pub capacity_bytes: u64,
    pub volume_count: u32,
}

impl PoolStats {
    /// Used / capacity as a fraction in [0.0, 1.0].
    pub fn fill_fraction(&self) -> f32 {
        if self.capacity_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f64 / self.capacity_bytes as f64).min(1.0) as f32
    }
}

impl From<BackendPoolStats> for PoolStats {
    fn from(b: BackendPoolStats) -> Self {
        Self {
            used_bytes: b.used_bytes,
            capacity_bytes: b.capacity_bytes,
            volume_count: b.volume_count,
        }
    }
}

/// User-facing pool API. Hides the DeviceMapperBackend so callers don't need to
/// know whether they're talking to dmsetup or a mock.
pub trait ThinPool {
    fn config(&self) -> &PoolConfig;

    /// Bootstrap the pool. Idempotent.
    fn ensure_initialized(&self) -> Result<()>;

    /// Tear down the pool and all its volumes.
    fn destroy(&self) -> Result<()>;

    /// Clone a writable volume from a base. The base must already
    /// exist (created via [`ThinPool::register_base`]).
    fn clone_from_base(&self, base: &VolumeId, dest: &VolumeId) -> Result<ThinVolume>;

    /// Take a chained snapshot of an existing volume. The new
    /// snapshot is the new write target; the origin remains read-
    /// only behind it.
    fn snapshot(&self, origin: &VolumeId, dest: &VolumeId) -> Result<ThinVolume>;

    /// Register a base volume. Used when a new template revision is
    /// built and we need a thin-pool entry to clone from.
    fn register_base(&self, base: &VolumeId, virtual_size_bytes: u64) -> Result<ThinVolume>;

    /// Remove a volume. Idempotent.
    fn remove(&self, volume: &VolumeId) -> Result<()>;

    /// Pool-wide stats.
    fn stats(&self) -> Result<PoolStats>;

    /// Per-volume stats.
    fn volume_stats(&self, volume: &VolumeId) -> Result<super::thin::VolumeStats>;

    /// List every volume in the pool. Returns sorted names.
    fn list_volumes(&self) -> Result<Vec<String>>;

    /// Garbage-collect volumes whose names match `predicate(name) ==
    /// true`. Returns the names that were removed.
    ///
    /// Callers feed this with a set of "live" volumes from elsewhere
    /// (e.g. the instance registry); anything not in the live set
    /// can be reclaimed.
    fn gc<F>(&self, mut should_remove: F) -> Result<Vec<String>>
    where
        F: FnMut(&str) -> bool,
    {
        let mut removed = Vec::new();
        for name in self.list_volumes()? {
            if should_remove(&name) {
                self.remove(&VolumeId::new(&name))?;
                removed.push(name);
            }
        }
        Ok(removed)
    }
}

/// Default `ThinPool` implementation backed by any `DeviceMapperBackend`.
pub struct ThinPoolImpl {
    config: PoolConfig,
    backend: Arc<dyn DeviceMapperBackend>,
}

impl ThinPoolImpl {
    pub fn new(config: PoolConfig, backend: Arc<dyn DeviceMapperBackend>) -> Self {
        Self { config, backend }
    }

    fn check_capacity_or_err(&self) -> Result<()> {
        let stats = self.stats()?;
        let cap = (stats.capacity_bytes as f64 * self.config.fill_cap as f64) as u64;
        if stats.used_bytes >= cap {
            return Err(StorageError::PoolFull {
                used_bytes: stats.used_bytes,
                capacity_bytes: stats.capacity_bytes,
            });
        }
        Ok(())
    }
}

impl ThinPool for ThinPoolImpl {
    fn config(&self) -> &PoolConfig {
        &self.config
    }

    fn ensure_initialized(&self) -> Result<()> {
        self.backend.create_pool(
            &self.config.name,
            self.config.size_bytes,
            self.config.block_size,
        )
    }

    fn destroy(&self) -> Result<()> {
        self.backend.destroy_pool(&self.config.name)
    }

    fn clone_from_base(&self, base: &VolumeId, dest: &VolumeId) -> Result<ThinVolume> {
        self.check_capacity_or_err()?;
        let path =
            self.backend
                .snapshot_volume(&self.config.name, base.as_str(), dest.as_str(), 0)?;
        Ok(ThinVolume::new(dest.clone(), path))
    }

    fn snapshot(&self, origin: &VolumeId, dest: &VolumeId) -> Result<ThinVolume> {
        self.check_capacity_or_err()?;
        let path =
            self.backend
                .snapshot_volume(&self.config.name, origin.as_str(), dest.as_str(), 0)?;
        Ok(ThinVolume::new(dest.clone(), path))
    }

    fn register_base(&self, base: &VolumeId, virtual_size_bytes: u64) -> Result<ThinVolume> {
        self.check_capacity_or_err()?;
        let path = self.backend.create_thin_volume(
            &self.config.name,
            base.as_str(),
            0,
            virtual_size_bytes,
        )?;
        Ok(ThinVolume::new(base.clone(), path))
    }

    fn remove(&self, volume: &VolumeId) -> Result<()> {
        self.backend
            .remove_volume(&self.config.name, volume.as_str())
    }

    fn stats(&self) -> Result<PoolStats> {
        Ok(self.backend.pool_stats(&self.config.name)?.into())
    }

    fn volume_stats(&self, volume: &VolumeId) -> Result<super::thin::VolumeStats> {
        Ok(self
            .backend
            .volume_stats(&self.config.name, volume.as_str())?
            .into())
    }

    fn list_volumes(&self) -> Result<Vec<String>> {
        self.backend.list_volumes(&self.config.name)
    }
}

#[cfg(test)]
mod tests {
    use super::super::backend::MockBackend;
    use super::*;
    use std::sync::Arc;

    fn pool_with_size(size_bytes: u64) -> ThinPoolImpl {
        let backend = Arc::new(MockBackend::new());
        let cfg = PoolConfig {
            name: "test-pool".to_string(),
            size_bytes,
            block_size: 65536,
            fill_cap: 0.95,
        };
        let pool = ThinPoolImpl::new(cfg, backend);
        pool.ensure_initialized().unwrap();
        pool
    }

    #[test]
    fn ensure_initialized_is_idempotent() {
        let pool = pool_with_size(1_000_000);
        // Second call should not error.
        pool.ensure_initialized().unwrap();
    }

    #[test]
    fn clone_from_base_creates_new_volume() {
        let pool = pool_with_size(1_000_000);
        let base = VolumeId::new("template-abc");
        pool.register_base(&base, 100_000).unwrap();

        let instance = VolumeId::new("instance-xyz");
        let vol = pool.clone_from_base(&base, &instance).unwrap();

        assert_eq!(vol.id().as_str(), "instance-xyz");
        assert_eq!(pool.list_volumes().unwrap().len(), 2);
    }

    #[test]
    fn snapshot_creates_chained_volume() {
        let pool = pool_with_size(1_000_000);
        pool.register_base(&VolumeId::new("base"), 100_000).unwrap();
        pool.clone_from_base(&VolumeId::new("base"), &VolumeId::new("inst"))
            .unwrap();

        let snap = pool
            .snapshot(&VolumeId::new("inst"), &VolumeId::new("snap-0"))
            .unwrap();
        assert_eq!(snap.id().as_str(), "snap-0");
        assert_eq!(pool.list_volumes().unwrap().len(), 3);
    }

    #[test]
    fn pool_full_rejects_new_volumes() {
        // Build a concrete-typed mock so the test can drive used-bytes
        // (the production trait object is `dyn DeviceMapperBackend`, which can't
        // be downcast in stable Rust without `Any`).
        let backend = Arc::new(MockBackend::new());
        let cfg = PoolConfig {
            name: "p-full".to_string(),
            size_bytes: 1_000,
            block_size: 65536,
            fill_cap: 0.95,
        };
        let pool = ThinPoolImpl::new(cfg, backend.clone());
        pool.ensure_initialized().unwrap();
        pool.register_base(&VolumeId::new("base"), 1_000).unwrap();
        // Drive used past the 0.95 cap (cap = 950 bytes of 1000).
        backend.set_used_bytes("p-full", "base", 960);

        let err = pool
            .clone_from_base(&VolumeId::new("base"), &VolumeId::new("inst"))
            .unwrap_err();
        matches!(err, StorageError::PoolFull { .. });
    }

    #[test]
    fn gc_removes_matching_volumes() {
        let pool = pool_with_size(1_000_000);
        pool.register_base(&VolumeId::new("keep-1"), 100).unwrap();
        pool.register_base(&VolumeId::new("orphan-1"), 100).unwrap();
        pool.register_base(&VolumeId::new("orphan-2"), 100).unwrap();

        let removed = pool.gc(|name| name.starts_with("orphan-")).unwrap();
        assert_eq!(removed.len(), 2);
        assert_eq!(pool.list_volumes().unwrap(), vec!["keep-1"]);
    }

    #[test]
    fn fill_fraction_handles_zero_capacity() {
        let stats = PoolStats {
            used_bytes: 0,
            capacity_bytes: 0,
            volume_count: 0,
        };
        assert_eq!(stats.fill_fraction(), 0.0);
    }

    #[test]
    fn fill_fraction_clamps_to_one() {
        let stats = PoolStats {
            used_bytes: 2000,
            capacity_bytes: 1000,
            volume_count: 1,
        };
        assert_eq!(stats.fill_fraction(), 1.0);
    }
}
