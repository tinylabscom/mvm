//! mvm-storage — `VolumeBackend` trait + `LocalBackend` impl.
//!
//! This crate ships **only** the trait and `LocalBackend`.
//! `ObjectStoreBackend` and `EncryptedBackend<B>` live
//! in mvmd — they wrap the same trait so callers don't see the
//! difference.
//!
//! ## Why the trait lives here
//!
//! Both mvm and mvmd need a uniform way to dispatch volume data-plane
//! operations. Putting the trait in this crate (re-exported through
//! the `mvmctl` facade) lets mvmd implement additional backings
//! against the same contract, with no API duplication.
//!
//! ## Generic contract test fixture
//!
//! [`contract::assert_backend_contract`] runs the full trait contract
//! (put → get round-trip, list, delete, rename, idempotent stat,
//! concurrent put/get) against any [`VolumeBackend`] impl. mvmd
//! re-uses it for `ObjectStoreBackend` and `EncryptedBackend<B>`.

pub mod backend;
pub mod content_addressed;
pub mod contract;
pub mod local;
pub mod mount_provider;
pub mod provider;
pub mod snapshot;

// At-rest-encrypted `StorageProvider` — two arms, one `encrypted::EncryptedStorage`
// type so callers never branch on platform:
// - non-Linux: per-file AES-256-GCM seal (mvm-core volume sealer).
// - Linux: block-level LUKS2 over a loop-backed image (`cryptsetup`).
#[cfg(not(target_os = "linux"))]
pub mod encrypted;
#[cfg(target_os = "linux")]
#[path = "encrypted_linux.rs"]
pub mod encrypted;

// S3 mount source — off by default; pulls object_store only under `s3`.
#[cfg(feature = "s3")]
pub mod s3;

pub use backend::VolumeBackend;
pub use content_addressed::{ContentAddressedStore, ContentDigest};
pub use local::LocalBackend;
pub use mount_provider::{
    HostPathFs, MountError, MountProvider, MountRegistry, Mountable, TmpfsFs, VolumeFs,
};
pub use provider::{AttachedVolume, LocalStorage, StorageProvider, VolumeHandle, VolumeSpec};
pub use snapshot::SnapshotUpper;

pub use encrypted::EncryptedStorage;

#[cfg(feature = "s3")]
pub use s3::S3MountProvider;

use std::sync::Arc;

use mvm_core::volume::{VolumeBackendConfig, VolumeError};

/// Construct a backend from a declarative [`VolumeBackendConfig`].
///
/// In the mvm-side build this only constructs `LocalBackend`. For
/// `VolumeBackendConfig::ObjectStore`, returns
/// [`VolumeError::UnsupportedBackend`] with a clear redirect to
/// `--remote` (which proxies through mvmd, where the object-store
/// impl lives).
///
/// mvmd has its own `make_backend_for_bucket` that handles every
/// variant.
pub async fn make_backend(
    config: &VolumeBackendConfig,
) -> Result<Arc<dyn VolumeBackend>, VolumeError> {
    match config {
        VolumeBackendConfig::Local { root } => {
            let backend = LocalBackend::new(root.clone()).await?;
            Ok(Arc::new(backend))
        }
        VolumeBackendConfig::ObjectStore(_) => Err(VolumeError::UnsupportedBackend {
            kind: "object-store",
            reason: "ObjectStore backend lives in mvmd; use `mvmctl --remote` to dispatch through mvmd",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::volume::ObjectStoreSpec;

    #[tokio::test]
    async fn make_backend_local_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = VolumeBackendConfig::Local {
            root: tmp.path().to_path_buf(),
        };
        let backend = make_backend(&cfg).await.unwrap();
        assert_eq!(backend.kind(), "local");
        assert!(backend.local_export_path().is_some());
    }

    #[tokio::test]
    async fn make_backend_object_store_returns_unsupported() {
        let cfg = VolumeBackendConfig::ObjectStore(ObjectStoreSpec {
            url: "s3://b/".into(),
            prefix: None,
            credentials_ref: None,
        });
        match make_backend(&cfg).await {
            Ok(_) => panic!("must reject ObjectStore in mvm-storage"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("object-store") && msg.contains("--remote"),
                    "error must redirect to --remote: {msg}"
                );
            }
        }
    }
}
