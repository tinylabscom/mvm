//! `VolumeBackend` async trait — the contract every backing storage
//! implementation honours.

use std::path::Path;

use async_trait::async_trait;
use bytes::Bytes;

use mvm_core::volume::{VolumeEntry, VolumeError, VolumePath};

/// Storage backing for a volume.
///
/// Implementations: `LocalBackend` (this crate), `ObjectStoreBackend`
/// + `EncryptedBackend<B>` (mvmd-side).
///
/// All operations are scoped to the volume the backend was constructed
/// for — the trait does not take an `org_id`/`workspace_id`/`name`
/// because that scope is fixed at construction.
#[async_trait]
pub trait VolumeBackend: Send + Sync {
    /// Stable string identifier for metrics / audit / error messages.
    fn kind(&self) -> &'static str;

    /// Write `data` to `key`. Atomic per-key — partial writes are not
    /// observable. Overwrites any existing entry.
    async fn put(&self, key: &VolumePath, data: Bytes) -> Result<(), VolumeError>;

    /// Read `key` in full. Errors with [`VolumeError::NotFound`] if
    /// the key doesn't exist.
    async fn get(&self, key: &VolumePath) -> Result<Bytes, VolumeError>;

    /// List entries directly under `prefix`. Returns both files and
    /// directories. Order is unspecified.
    async fn list(&self, prefix: &VolumePath) -> Result<Vec<VolumeEntry>, VolumeError>;

    /// Remove `key`. Errors with [`VolumeError::NotFound`] if the key
    /// doesn't exist. Idempotency is the caller's responsibility.
    async fn delete(&self, key: &VolumePath) -> Result<(), VolumeError>;

    /// Look up metadata for a single entry.
    async fn stat(&self, key: &VolumePath) -> Result<VolumeEntry, VolumeError>;

    /// Move/rename `from` to `to`. Atomic for in-bucket moves where
    /// the backend supports it; for object stores this is
    /// O(copy + delete).
    async fn rename(&self, from: &VolumePath, to: &VolumePath) -> Result<(), VolumeError>;

    /// Backend-specific reachability/permissions check. Cheap to
    /// invoke; called at backend construction and on demand.
    async fn health_check(&self) -> Result<(), VolumeError>;

    /// Returns `Some(path)` iff this backend can be virtio-fs-mounted
    /// into a guest (i.e., it's a real local filesystem path that
    /// virtiofsd can export). `None` for object-store backends in v1.
    fn local_export_path(&self) -> Option<&Path>;
}
