//! Service-owned publication and claim boundary for trusted snapshots.
//!
//! The service is deliberately separate from the ordinary filesystem snapshot
//! store. A caller receives an opaque handle after publication and can never
//! provide a filesystem path to the claim operation. The backend is responsible
//! for the immutable read-view guarantee; the service owns the publication
//! lifecycle and handle registry.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use mvm_fs::clone::CloneStrategy;
use mvm_fs::snapshot_store::SnapshotId;
use mvm_fs::trusted_snapshot::TrustedSnapshotBackend;

/// Opaque service-issued reference to one sealed snapshot publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSnapshotHandle {
    id: SnapshotId,
}

impl TrustedSnapshotHandle {
    fn new(id: SnapshotId) -> Self {
        Self { id }
    }
}

/// Resident owner of trusted snapshot publications.
pub struct TrustedSnapshotService {
    backend: Arc<dyn TrustedSnapshotBackend>,
    publications: Mutex<BTreeMap<String, TrustedSnapshotHandle>>,
}

impl TrustedSnapshotService {
    /// Create a service over a platform-backed immutable snapshot provider.
    pub fn new(backend: Arc<dyn TrustedSnapshotBackend>) -> Self {
        Self {
            backend,
            publications: Mutex::new(BTreeMap::new()),
        }
    }

    /// Open the explicitly enabled host platform backend.
    pub fn from_platform(root: impl AsRef<Path>) -> Result<Self> {
        let backend = mvm_fs::trusted_snapshot::platform_backend(root)
            .context("open platform trusted snapshot backend")?;
        Ok(Self::new(Arc::from(backend)))
    }

    /// Stage and seal a publication, then return its opaque claim handle.
    ///
    /// The handle is inserted only after sealing succeeds. A failed stage or
    /// seal therefore cannot become claimable through this service.
    pub fn publish(&self, id: SnapshotId, source: &Path) -> Result<TrustedSnapshotHandle> {
        let key = id.id().to_owned();
        {
            let publications = self
                .publications
                .lock()
                .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?;
            if publications.contains_key(&key) {
                bail!("trusted snapshot '{key}' is already published");
            }
        }

        self.backend
            .stage(&id, source)
            .with_context(|| format!("stage trusted snapshot {key}"))?;
        if let Err(error) = self.backend.seal(&id) {
            let _ = self.backend.remove(&id);
            return Err(error).with_context(|| format!("seal trusted snapshot {key}"));
        }

        let handle = TrustedSnapshotHandle::new(id);
        let mut publications = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?;
        if publications.insert(key.clone(), handle.clone()).is_some() {
            let _ = self.backend.remove(&handle.id);
            bail!("trusted snapshot '{key}' was published concurrently");
        }
        Ok(handle)
    }

    /// Materialize a previously published handle.
    ///
    /// The destination is the only path accepted at claim time. The source
    /// path remains wholly inside the backend and its immutable read view.
    pub fn materialize(
        &self,
        handle: &TrustedSnapshotHandle,
        destination: &Path,
    ) -> Result<CloneStrategy> {
        let known = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .get(handle.id.id())
            .is_some_and(|published| published == handle);
        if !known {
            bail!("trusted snapshot handle is not owned by this service");
        }
        self.backend
            .materialize(&handle.id, destination)
            .with_context(|| format!("materialize trusted snapshot {}", handle.id))
    }

    /// Remove a publication after all claims have released it.
    pub fn remove(&self, handle: TrustedSnapshotHandle) -> Result<()> {
        let removed = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .remove(handle.id.id());
        if removed.as_ref() != Some(&handle) {
            bail!("trusted snapshot handle is not owned by this service");
        }
        self.backend
            .remove(&handle.id)
            .with_context(|| format!("remove trusted snapshot {}", handle.id))
    }

    /// Number of sealed publications currently owned by the service.
    pub fn publication_count(&self) -> Result<usize> {
        Ok(self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotStore};
    use std::io;

    struct TestBackend {
        store: FsSnapshotStore,
    }

    impl TrustedSnapshotBackend for TestBackend {
        fn stage(&self, id: &SnapshotId, source: &Path) -> io::Result<()> {
            self.store.create(id, source)
        }

        fn seal(&self, _id: &SnapshotId) -> io::Result<()> {
            Ok(())
        }

        fn validate(
            &self,
            id: &SnapshotId,
            _manifest_digest: &str,
            _trusted_signer: &[u8; 32],
        ) -> io::Result<()> {
            if self.store.root().join(id.id()).join("content").is_dir() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "test snapshot publication is missing",
                ))
            }
        }

        fn materialize(&self, id: &SnapshotId, destination: &Path) -> io::Result<CloneStrategy> {
            self.store.materialize(id, destination)
        }

        fn remove(&self, id: &SnapshotId) -> io::Result<()> {
            self.store.remove(id)
        }

        fn name(&self) -> &'static str {
            "test"
        }
    }

    #[test]
    fn service_publishes_materializes_and_removes_opaque_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("rootfs.ext4"), b"immutable-test-bytes").unwrap();
        let service = TrustedSnapshotService::new(Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
        }));
        let handle = service
            .publish(SnapshotId::new("snapshot-1"), &source)
            .unwrap();
        let destination = tmp.path().join("destination");

        service.materialize(&handle, &destination).unwrap();
        assert_eq!(
            std::fs::read(destination.join("rootfs.ext4")).unwrap(),
            b"immutable-test-bytes"
        );
        assert_eq!(service.publication_count().unwrap(), 1);
        service.remove(handle).unwrap();
        assert_eq!(service.publication_count().unwrap(), 0);
    }

    #[test]
    fn service_rejects_unknown_handle_without_materializing() {
        let tmp = tempfile::tempdir().unwrap();
        let service = TrustedSnapshotService::new(Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
        }));
        let unknown = TrustedSnapshotHandle::new(SnapshotId::new("not-published"));
        let destination = tmp.path().join("destination");

        let error = service.materialize(&unknown, &destination).unwrap_err();
        assert!(error.to_string().contains("not owned by this service"));
        assert!(!destination.exists());
    }

    #[test]
    fn unsupported_backend_never_registers_a_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let service = TrustedSnapshotService::new(Arc::new(
            mvm_fs::trusted_snapshot::UnsupportedTrustedSnapshotBackend,
        ));

        let error = service
            .publish(SnapshotId::new("snapshot-unsupported"), &source)
            .unwrap_err();
        assert!(error.to_string().contains("stage trusted snapshot"));
        assert_eq!(service.publication_count().unwrap(), 0);
    }
}
