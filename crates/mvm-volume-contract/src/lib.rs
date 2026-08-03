#![deny(unsafe_code)]
//! Minimal, dependency-light contract for mvm volume backends.
//!
//! Fleet orchestrators depend on this leaf crate without linking mvm's VMM,
//! signing, guest-agent, or provider dependency graphs. The mvm facade and
//! runtime re-export the same types and trait.

use std::future::Future;
use std::path::Path;
use std::pin::Pin;

use anyhow::{Result, bail};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "local")]
pub mod local;
#[cfg(feature = "local")]
pub use local::LocalBackend;

const MAX_VOLUME_PATH_LEN: usize = 1024;

/// Validated path within a volume namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VolumePath(String);

impl VolumePath {
    /// Validate and construct a relative volume path.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            bail!("volume path must not be empty");
        }
        if value.len() > MAX_VOLUME_PATH_LEN {
            bail!(
                "volume path must be 1-{MAX_VOLUME_PATH_LEN} bytes, got {}",
                value.len()
            );
        }
        if value.contains('\0') {
            bail!("volume path must not contain NUL");
        }
        if value.starts_with('/') {
            bail!("volume path must be relative (no leading '/'): {value:?}");
        }
        for segment in value.split('/') {
            if segment == ".." {
                bail!("volume path must not contain '..' segment: {value:?}");
            }
        }
        Ok(Self(value))
    }

    /// Return the validated relative path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for VolumePath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Filesystem-shaped metadata returned by a volume backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeEntry {
    /// Entry path relative to the volume root.
    pub path: VolumePath,
    /// Logical content length in bytes.
    pub size: u64,
    /// Whether this entry represents a direct-child prefix/directory.
    pub is_dir: bool,
    /// Provider content hash or version tag when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

/// Typed failures shared by every canonical backend implementation.
#[derive(Debug, Error)]
pub enum VolumeError {
    /// The requested entry does not exist.
    #[error("volume entry not found: {0}")]
    NotFound(VolumePath),
    /// A conditional destination already exists.
    #[error("volume entry already exists: {0}")]
    AlreadyExists(VolumePath),
    /// An explicit logical byte limit was exceeded.
    #[error("size cap exceeded ({attempted} > {limit} bytes)")]
    SizeCapExceeded { attempted: u64, limit: u64 },
    /// A mutation was attempted through a read-only backend.
    #[error("read-only volume rejects mutation")]
    ReadOnly,
    /// The selected implementation cannot provide the requested capability.
    #[error("backend kind {kind} not supported in this context: {reason}")]
    UnsupportedBackend {
        kind: &'static str,
        reason: &'static str,
    },
    /// A path failed validation at a backend boundary.
    #[error("invalid path: {0}")]
    InvalidPath(String),
    /// Local I/O failed.
    #[error("backend I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A sanitized backend failure that has no stronger portable category.
    #[error("backend error: {0}")]
    Other(String),
}

/// Boxed asynchronous operation returned by a volume backend.
pub type VolumeFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, VolumeError>> + Send + 'a>>;

/// Storage backing for one already-scoped volume.
///
/// Returning a boxed future keeps this trait object-safe without imposing an
/// async proc-macro or runtime on consumers that only need the wire types.
pub trait VolumeBackend: Send + Sync {
    /// Stable non-sensitive identifier for metrics and audit records.
    fn kind(&self) -> &'static str;
    /// Atomically write all bytes, overwriting an existing entry.
    fn put<'a>(&'a self, key: &'a VolumePath, data: Bytes) -> VolumeFuture<'a, ()>;
    /// Read an entry in full under the implementation's explicit bound.
    fn get<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, Bytes>;
    /// Return only entries directly beneath `prefix`.
    fn list<'a>(&'a self, prefix: &'a VolumePath) -> VolumeFuture<'a, Vec<VolumeEntry>>;
    /// Delete an existing entry.
    fn delete<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, ()>;
    /// Return metadata for one entry.
    fn stat<'a>(&'a self, key: &'a VolumePath) -> VolumeFuture<'a, VolumeEntry>;
    /// Rename without overwriting an existing destination.
    fn rename<'a>(&'a self, from: &'a VolumePath, to: &'a VolumePath) -> VolumeFuture<'a, ()>;
    /// Verify the permissions required by this backend.
    fn health_check(&self) -> VolumeFuture<'_, ()>;
    /// Return a validated local export root only for mountable local backends.
    fn local_export_path(&self) -> Option<&Path>;
}

/// Reusable behavioral contract tests for external implementations.
pub mod contract {
    use super::{VolumeBackend, VolumeError, VolumePath};
    use bytes::Bytes;

    fn key(value: &str) -> VolumePath {
        VolumePath::new(value).expect("valid contract-test path")
    }

    /// Exercise the portable behavior required of every backend.
    pub async fn assert_backend_contract<B: VolumeBackend + ?Sized>(backend: &B) {
        backend
            .health_check()
            .await
            .expect("contract: health check");

        let roundtrip = key("contract/put-get/file.txt");
        backend
            .put(&roundtrip, Bytes::from_static(b"hello"))
            .await
            .expect("contract: put");
        assert_eq!(
            backend.get(&roundtrip).await.expect("contract: get"),
            Bytes::from_static(b"hello")
        );
        backend
            .put(&roundtrip, Bytes::from_static(b"replacement"))
            .await
            .expect("contract: overwrite");
        assert_eq!(
            backend
                .get(&roundtrip)
                .await
                .expect("contract: get overwrite"),
            Bytes::from_static(b"replacement")
        );
        backend.delete(&roundtrip).await.expect("contract: delete");
        assert!(matches!(
            backend.get(&roundtrip).await,
            Err(VolumeError::NotFound(_))
        ));
        assert!(matches!(
            backend.delete(&roundtrip).await,
            Err(VolumeError::NotFound(_))
        ));

        let source = key("contract/rename/source");
        let destination = key("contract/rename/destination");
        backend
            .put(&source, Bytes::from_static(b"source"))
            .await
            .expect("contract: source put");
        backend
            .rename(&source, &destination)
            .await
            .expect("contract: rename");
        assert!(matches!(
            backend.get(&source).await,
            Err(VolumeError::NotFound(_))
        ));
        assert_eq!(
            backend
                .get(&destination)
                .await
                .expect("contract: destination"),
            Bytes::from_static(b"source")
        );

        backend
            .put(&source, Bytes::from_static(b"new source"))
            .await
            .expect("contract: second source");
        assert!(matches!(
            backend.rename(&source, &destination).await,
            Err(VolumeError::AlreadyExists(_))
        ));

        let metadata = backend.stat(&destination).await.expect("contract: stat");
        assert_eq!(metadata.size, 6);
        assert!(!metadata.is_dir);

        let nested = key("contract/rename/nested/file");
        backend
            .put(&nested, Bytes::from_static(b"nested"))
            .await
            .expect("contract: nested put");
        let entries = backend
            .list(&key("contract/rename"))
            .await
            .expect("contract: list");
        assert!(entries.iter().any(|entry| entry.path == source));
        assert!(entries.iter().any(|entry| entry.path == destination));
        assert!(
            entries
                .iter()
                .any(|entry| entry.path == key("contract/rename/nested") && entry.is_dir)
        );

        backend
            .delete(&source)
            .await
            .expect("contract: cleanup source");
        backend
            .delete(&destination)
            .await
            .expect("contract: cleanup destination");
        backend
            .delete(&nested)
            .await
            .expect("contract: cleanup nested");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_validation_and_serde_are_stable() {
        let path = VolumePath::new("nested/file").unwrap();
        let encoded = serde_json::to_string(&path).unwrap();
        assert_eq!(encoded, "\"nested/file\"");
        assert_eq!(serde_json::from_str::<VolumePath>(&encoded).unwrap(), path);
        assert!(VolumePath::new("").is_err());
        assert!(VolumePath::new("/absolute").is_err());
        assert!(VolumePath::new("a/../b").is_err());
        assert!(VolumePath::new("nul\0byte").is_err());
    }
}
