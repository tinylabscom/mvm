//! S3-backed `MountProvider` (feature `s3`).
//!
//! Resolves a `MountSource::External { provider: "s3", config }` by syncing
//! the configured prefix **read-only** from an object store into a local
//! cache directory, then handing that directory back as a `HostPath`
//! [`Mountable`]. Built on the lean `object_store` crate (ring TLS, not
//! aws-lc-rs); its in-memory backend makes the sync logic testable without
//! network.
//!
//! Sync-over-async: [`MountProvider::resolve`] is sync but object_store is
//! async, so the provider owns a current-thread runtime and `block_on`s the
//! transfer. Calling resolve from inside another tokio runtime would need the
//! caller to offload it (a mvm-backend integration concern — B4 follow-up).
//!
//! Only the sync-to-cache path is unit-tested here (in-memory store). The
//! real `AmazonS3` construction in [`S3MountProvider::from_s3_config`] is the
//! network leg — compile-checked under `--features s3`, exercised against a
//! live bucket in higher tiers.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use futures::StreamExt;
use mvm_core::volume::VolumeError;
use mvm_sdk::ir::MountSource;
use object_store::ObjectStore;
use object_store::path::Path as ObjPath;

use crate::mount_provider::{MountError, MountProvider, Mountable};

/// Syncs an object-store prefix into a local cache dir on resolve.
pub struct S3MountProvider {
    store: Arc<dyn ObjectStore>,
    cache_root: PathBuf,
    rt: tokio::runtime::Runtime,
}

impl S3MountProvider {
    /// Build over any `ObjectStore` — prod passes an `AmazonS3`, tests pass
    /// an `InMemory`. Owns a current-thread runtime to drive the async
    /// transfer from the sync `resolve`.
    pub fn new(
        store: Arc<dyn ObjectStore>,
        cache_root: impl Into<PathBuf>,
    ) -> Result<Self, MountError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| MountError::Volume(VolumeError::Other(e.to_string())))?;
        Ok(Self {
            store,
            cache_root: cache_root.into(),
            rt,
        })
    }

    /// Build the prod `AmazonS3` client from an `External` config's `bucket`
    /// (region/credentials come from the standard AWS env). The network path;
    /// not unit-tested here — compile-checked under `--features s3`.
    pub fn from_s3_config(
        config: &serde_json::Value,
        cache_root: impl Into<PathBuf>,
    ) -> Result<Self, MountError> {
        let bucket = config
            .get("bucket")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                MountError::Volume(VolumeError::Other(
                    "s3 mount config missing 'bucket'".into(),
                ))
            })?;
        let s3 = object_store::aws::AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(os_err)?;
        Self::new(Arc::new(s3), cache_root)
    }
}

fn os_err(e: object_store::Error) -> MountError {
    MountError::Volume(VolumeError::Other(format!("object_store: {e}")))
}

fn io_err(e: std::io::Error) -> MountError {
    MountError::Volume(VolumeError::Io(e))
}

/// Join `rel` onto `root`, rejecting any component that could escape the
/// cache root — `..` (`ParentDir`), an absolute/root component, or a
/// Windows prefix. The mount-spec `prefix` is untrusted input, and
/// object-store keys come from a potentially-untrusted remote store, so a
/// `..` would let synced bytes land outside `cache_root` (an arbitrary
/// host-path write primitive). A leading `/` is harmless — `trim_matches`
/// neutralizes it to a contained relative path — but `..` is refused
/// outright. `resolve` adds a canonicalize backstop on top of this to
/// also defend against symlinks in the cache tree.
fn contained_join(root: &Path, rel: &str) -> Result<PathBuf, MountError> {
    let trimmed = rel.trim_matches('/');
    for comp in Path::new(trimmed).components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(MountError::Volume(VolumeError::InvalidPath(format!(
                    "path escapes cache root: {rel:?}"
                ))));
            }
        }
    }
    Ok(root.join(trimmed))
}

/// Copy every object under `prefix` into `dest`, mirroring the key layout
/// (prefix-relative). Read-only — never writes back to `store`.
async fn sync_prefix(store: &dyn ObjectStore, prefix: &str, dest: &Path) -> Result<(), MountError> {
    let op = ObjPath::from(prefix);
    let mut listing = store.list(Some(&op));
    while let Some(meta) = listing.next().await {
        let meta = meta.map_err(os_err)?;
        let bytes = store
            .get(&meta.location)
            .await
            .map_err(os_err)?
            .bytes()
            .await
            .map_err(os_err)?;
        let key = meta.location.as_ref();
        let rel = key
            .strip_prefix(prefix)
            .unwrap_or(key)
            .trim_start_matches('/');
        let target = contained_join(dest, rel)?;
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(io_err)?;
        }
        tokio::fs::write(&target, &bytes).await.map_err(io_err)?;
    }
    Ok(())
}

impl MountProvider for S3MountProvider {
    fn kind(&self) -> &str {
        "s3"
    }

    fn resolve(&self, src: &MountSource) -> Result<Mountable, MountError> {
        let prefix = match src {
            MountSource::External { provider, config } if provider == "s3" => config
                .get("prefix")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            _ => {
                return Err(MountError::MismatchedSource {
                    provider: "s3",
                    got: "non-s3 source".to_string(),
                });
            }
        };
        // Per-prefix cache dir so distinct mounts don't collide. `prefix`
        // is untrusted mount-spec input; reject components that would
        // escape the cache root before creating anything on disk.
        let dest = contained_join(&self.cache_root, &prefix)?;
        std::fs::create_dir_all(&dest).map_err(io_err)?;
        // Backstop against symlinks in cache_root or an intermediate dir:
        // canonicalize both and assert the resolved dest stays under the
        // resolved cache root.
        let real_root = self.cache_root.canonicalize().map_err(io_err)?;
        let real_dest = dest.canonicalize().map_err(io_err)?;
        if !real_dest.starts_with(&real_root) {
            return Err(MountError::Volume(VolumeError::InvalidPath(format!(
                "s3 prefix {prefix:?} escapes cache root after canonicalization"
            ))));
        }
        self.rt
            .block_on(sync_prefix(self.store.as_ref(), &prefix, &dest))?;
        Ok(Mountable::HostPath(dest))
    }

    fn release(&self, _m: Mountable) -> Result<(), MountError> {
        // The cache dir's lifecycle belongs to cache_root; nothing to unmount.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use object_store::memory::InMemory;

    #[test]
    fn s3_provider_syncs_prefix_to_cache_dir() {
        let store = Arc::new(InMemory::new());
        // Seed one object under the "data/" prefix and one outside it.
        let seed_rt = tokio::runtime::Runtime::new().unwrap();
        seed_rt.block_on(async {
            store
                .put(
                    &ObjPath::from("data/hello.txt"),
                    Bytes::from_static(b"S3 OBJECT BYTES").into(),
                )
                .await
                .unwrap();
            store
                .put(
                    &ObjPath::from("other/skip.txt"),
                    Bytes::from_static(b"NOT SYNCED").into(),
                )
                .await
                .unwrap();
        });
        drop(seed_rt);

        let tmp = tempfile::tempdir().unwrap();
        let provider = S3MountProvider::new(store, tmp.path()).unwrap();
        let src = MountSource::External {
            provider: "s3".into(),
            config: serde_json::json!({ "bucket": "b", "prefix": "data/" }),
        };
        match provider.resolve(&src).unwrap() {
            Mountable::HostPath(p) => {
                assert_eq!(
                    std::fs::read(p.join("hello.txt")).unwrap(),
                    b"S3 OBJECT BYTES"
                );
                // An object outside the synced prefix must not appear.
                assert!(!p.join("skip.txt").exists());
            }
            other => panic!("expected HostPath cache dir, got {other:?}"),
        }
    }

    #[test]
    fn s3_provider_rejects_prefix_path_traversal() {
        // A `..` in the (untrusted) mount-spec prefix must not let synced
        // bytes escape the cache root. Each of these must be refused with
        // InvalidPath before any directory is created or object fetched.
        let store = Arc::new(InMemory::new());
        let tmp = tempfile::tempdir().unwrap();
        let provider = S3MountProvider::new(store, tmp.path()).unwrap();
        for evil in [
            "../escape",
            "../../etc",
            "data/../../../etc",
            "/etc/passwd/..",
        ] {
            let src = MountSource::External {
                provider: "s3".into(),
                config: serde_json::json!({ "bucket": "b", "prefix": evil }),
            };
            match provider.resolve(&src) {
                Err(MountError::Volume(VolumeError::InvalidPath(_))) => {}
                other => panic!("prefix {evil:?} must be rejected as InvalidPath, got {other:?}"),
            }
        }
        // A leading slash with no `..` is contained (neutralized to a
        // relative path under the cache root), not an escape.
        let contained = contained_join(tmp.path(), "/data/sub").unwrap();
        assert!(contained.starts_with(tmp.path()));
    }
}
