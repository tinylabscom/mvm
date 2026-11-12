//! Service-owned publication and claim boundary for trusted snapshots.
//!
//! The service is deliberately separate from the ordinary filesystem snapshot
//! store. A caller receives an opaque handle after publication and can never
//! provide a filesystem path to the claim operation. The backend is responsible
//! for the immutable read-view guarantee; the service owns the publication
//! lifecycle and handle registry.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result, anyhow, bail};
use mvm_fs::clone::CloneStrategy;
use mvm_fs::snapshot_store::SnapshotId;
use mvm_fs::trusted_snapshot::TrustedSnapshotBackend;
use uuid::Uuid;

/// Opaque service-issued reference to one sealed snapshot publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSnapshotHandle {
    id: SnapshotId,
    generation: Uuid,
}

impl TrustedSnapshotHandle {
    fn new(id: SnapshotId) -> Self {
        Self {
            id,
            generation: Uuid::new_v4(),
        }
    }
}

enum PublicationState {
    Reserved,
    Published(TrustedSnapshotHandle),
    Removing(TrustedSnapshotHandle),
}

/// Resident owner of trusted snapshot publications.
pub struct TrustedSnapshotService {
    backend: Arc<dyn TrustedSnapshotBackend>,
    // Reserved also quarantines an ID after failed staging or cleanup.
    // The per-ID lock holds claims open until materialization finishes.
    publications: Mutex<BTreeMap<String, Arc<RwLock<PublicationState>>>>,
}

impl TrustedSnapshotService {
    /// Create a service over a platform-backed immutable snapshot provider.
    pub fn new(backend: Arc<dyn TrustedSnapshotBackend>) -> Self {
        Self {
            backend,
            publications: Mutex::new(BTreeMap::new()),
        }
    }

    /// Stage and seal a publication, then return its opaque claim handle.
    ///
    /// The ID is reserved before staging; only sealed publications are claimable.
    pub fn publish(&self, id: SnapshotId, source: &Path) -> Result<TrustedSnapshotHandle> {
        let key = id.id().to_owned();
        let entry = Arc::new(RwLock::new(PublicationState::Reserved));
        let mut publications = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?;
        if publications.contains_key(&key) {
            bail!("trusted snapshot '{key}' is already published or reserved");
        }
        publications.insert(key.clone(), Arc::clone(&entry));
        drop(publications);

        // A failed stage may have left partial backend state, or encountered
        // state belonging to another owner. Without an ownership proof, do
        // not remove that state or release this ID for reuse.
        self.backend
            .stage(&id, source)
            .with_context(|| format!("stage trusted snapshot {key}"))?;
        if let Err(error) = self.backend.seal(&id) {
            // A successful stage belongs to this reservation; cleanup before
            // releasing the ID so a later publisher cannot race old bytes.
            if self.backend.remove(&id).is_ok() {
                self.publications
                    .lock()
                    .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
                    .remove(&key);
            }
            return Err(error).with_context(|| format!("seal trusted snapshot {key}"));
        }

        let handle = TrustedSnapshotHandle::new(id);
        *entry
            .write()
            .map_err(|_| anyhow!("trusted snapshot publication is poisoned"))? =
            PublicationState::Published(handle.clone());
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
        let entry = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .get(handle.id.id())
            .cloned()
            .ok_or_else(|| anyhow!("trusted snapshot handle is not owned by this service"))?;
        let published = entry
            .read()
            .map_err(|_| anyhow!("trusted snapshot publication is poisoned"))?;
        if !matches!(&*published, PublicationState::Published(current) if current == handle) {
            bail!("trusted snapshot handle is not owned by this service");
        }
        // Keep the read lease through the backend call so removal cannot
        // reclaim the sealed read view while a claim is in progress.
        self.backend
            .materialize(&handle.id, destination)
            .with_context(|| format!("materialize trusted snapshot {}", handle.id))
    }

    /// Remove a publication after all claims have released it.
    pub fn remove(&self, handle: TrustedSnapshotHandle) -> Result<()> {
        let entry = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .get(handle.id.id())
            .cloned()
            .ok_or_else(|| anyhow!("trusted snapshot handle is not owned by this service"))?;
        let mut state = entry
            .write()
            .map_err(|_| anyhow!("trusted snapshot publication is poisoned"))?;
        if !matches!(
            &*state,
            PublicationState::Published(current) | PublicationState::Removing(current)
                if current == &handle
        ) {
            bail!("trusted snapshot handle is not owned by this service");
        }
        *state = PublicationState::Removing(handle.clone());
        self.backend
            .remove(&handle.id)
            .with_context(|| format!("remove trusted snapshot {}", handle.id))?;
        self.publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .remove(handle.id.id());
        Ok(())
    }

    /// Number of sealed publications currently owned by the service.
    pub fn publication_count(&self) -> Result<usize> {
        let entries: Vec<_> = self
            .publications
            .lock()
            .map_err(|_| anyhow!("trusted snapshot registry is poisoned"))?
            .values()
            .cloned()
            .collect();
        entries.into_iter().try_fold(0, |count, entry| {
            let state = entry
                .read()
                .map_err(|_| anyhow!("trusted snapshot publication is poisoned"))?;
            Ok(count + usize::from(matches!(&*state, PublicationState::Published(_))))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotStore};
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc;

    struct TestBackend {
        store: FsSnapshotStore,
        fail_next_seal: AtomicBool,
        fail_next_remove: AtomicBool,
    }

    impl TrustedSnapshotBackend for TestBackend {
        fn stage(&self, id: &SnapshotId, source: &Path) -> io::Result<()> {
            self.store.create(id, source)
        }

        fn seal(&self, _id: &SnapshotId) -> io::Result<()> {
            if self.fail_next_seal.swap(false, Ordering::SeqCst) {
                return Err(io::Error::other("injected sealing failure"));
            }
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
            if self.fail_next_remove.swap(false, Ordering::SeqCst) {
                return Err(io::Error::other("injected removal failure"));
            }
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
            fail_next_seal: AtomicBool::new(false),
            fail_next_remove: AtomicBool::new(false),
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
    fn a_failed_seal_releases_its_reservation_only_after_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let backend = Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
            fail_next_seal: AtomicBool::new(true),
            fail_next_remove: AtomicBool::new(false),
        });
        let service = TrustedSnapshotService::new(backend);
        let id = SnapshotId::new("seal-retry");
        assert!(service.publish(id.clone(), &source).is_err());
        assert_eq!(service.publication_count().unwrap(), 0);
        let handle = service.publish(id, &source).unwrap();
        service.remove(handle).unwrap();
    }

    #[test]
    fn failed_seal_cleanup_quarantines_the_id() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let backend = Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
            fail_next_seal: AtomicBool::new(true),
            fail_next_remove: AtomicBool::new(true),
        });
        let service = TrustedSnapshotService::new(backend);
        let id = SnapshotId::new("quarantined");
        assert!(service.publish(id.clone(), &source).is_err());
        assert_eq!(service.publication_count().unwrap(), 0);
        assert!(service.publish(id, &source).is_err());
    }

    #[test]
    fn failed_removal_refuses_claims_and_can_be_retried_by_the_owner() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        let backend = Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
            fail_next_seal: AtomicBool::new(false),
            fail_next_remove: AtomicBool::new(true),
        });
        let service = TrustedSnapshotService::new(backend);
        let id = SnapshotId::new("retry-removal");
        let handle = service.publish(id.clone(), &source).unwrap();
        assert!(service.remove(handle.clone()).is_err());
        assert_eq!(service.publication_count().unwrap(), 0);
        assert!(
            service
                .materialize(&handle, &tmp.path().join("claim"))
                .is_err()
        );
        assert!(service.publish(id, &source).is_err());
        service.remove(handle).unwrap();
        assert_eq!(service.publication_count().unwrap(), 0);
    }

    #[test]
    fn a_removed_handle_cannot_claim_a_new_publication_under_the_same_id() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("rootfs.ext4"), b"first").unwrap();
        let service = TrustedSnapshotService::new(Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
            fail_next_seal: AtomicBool::new(false),
            fail_next_remove: AtomicBool::new(false),
        }));
        let id = SnapshotId::new("reused-id");
        let stale = service.publish(id.clone(), &source).unwrap();
        service.remove(stale.clone()).unwrap();
        std::fs::write(source.join("rootfs.ext4"), b"second").unwrap();
        let current = service.publish(id, &source).unwrap();
        let destination = tmp.path().join("destination");

        assert_ne!(
            stale, current,
            "a new publication must have a new generation"
        );
        assert!(service.materialize(&stale, &destination).is_err());
        assert!(!destination.exists(), "stale handle reached the backend");
        assert!(service.remove(stale).is_err());
        assert_eq!(service.publication_count().unwrap(), 1);
        service.materialize(&current, &destination).unwrap();
        assert_eq!(
            std::fs::read(destination.join("rootfs.ext4")).unwrap(),
            b"second"
        );
    }

    struct PausedPublisher {
        entered: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
        staged: AtomicUsize,
        removed: AtomicUsize,
    }

    impl TrustedSnapshotBackend for PausedPublisher {
        fn stage(&self, _id: &SnapshotId, _source: &Path) -> io::Result<()> {
            if self.staged.fetch_add(1, Ordering::SeqCst) == 0 {
                self.entered.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
            }
            Ok(())
        }

        fn seal(&self, _id: &SnapshotId) -> io::Result<()> {
            Ok(())
        }

        fn validate(
            &self,
            _id: &SnapshotId,
            _manifest_digest: &str,
            _trusted_signer: &[u8; 32],
        ) -> io::Result<()> {
            Ok(())
        }

        fn materialize(&self, _id: &SnapshotId, _dst: &Path) -> io::Result<CloneStrategy> {
            Ok(CloneStrategy::Copied)
        }

        fn remove(&self, _id: &SnapshotId) -> io::Result<()> {
            self.removed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &'static str {
            "paused-test"
        }
    }

    #[test]
    fn a_concurrent_publisher_cannot_stage_or_remove_an_owners_publication() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let backend = Arc::new(PausedPublisher {
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
            staged: AtomicUsize::new(0),
            removed: AtomicUsize::new(0),
        });
        let service = Arc::new(TrustedSnapshotService::new(backend.clone()));
        let first = {
            let service = service.clone();
            std::thread::spawn(move || service.publish(SnapshotId::new("same-id"), Path::new(".")))
        };
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("first publisher reached the backend");
        let (second_tx, second_rx) = mpsc::channel();
        let second = {
            let service = service.clone();
            std::thread::spawn(move || {
                second_tx
                    .send(service.publish(SnapshotId::new("same-id"), Path::new(".")))
                    .unwrap();
            })
        };
        let second_result = second_rx.recv_timeout(std::time::Duration::from_secs(2));
        resume_tx.send(()).unwrap();
        let first_handle = first.join().unwrap().expect("first publisher owns the ID");
        second.join().unwrap();
        assert!(
            second_result
                .expect("duplicate must refuse while first is staging")
                .is_err(),
            "a concurrent caller published the same ID"
        );
        assert_eq!(service.publication_count().unwrap(), 1);
        assert_eq!(backend.staged.load(Ordering::SeqCst), 1);
        assert_eq!(backend.removed.load(Ordering::SeqCst), 0);
        service.materialize(&first_handle, Path::new(".")).unwrap();
    }

    struct PausedClaim {
        entered: mpsc::Sender<()>,
        resume: Mutex<mpsc::Receiver<()>>,
        removed: AtomicUsize,
    }

    impl TrustedSnapshotBackend for PausedClaim {
        fn stage(&self, _id: &SnapshotId, _source: &Path) -> io::Result<()> {
            Ok(())
        }

        fn seal(&self, _id: &SnapshotId) -> io::Result<()> {
            Ok(())
        }

        fn validate(
            &self,
            _id: &SnapshotId,
            _manifest_digest: &str,
            _trusted_signer: &[u8; 32],
        ) -> io::Result<()> {
            Ok(())
        }

        fn materialize(&self, _id: &SnapshotId, _dst: &Path) -> io::Result<CloneStrategy> {
            self.entered.send(()).unwrap();
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert_eq!(self.removed.load(Ordering::SeqCst), 0);
            Ok(CloneStrategy::Copied)
        }

        fn remove(&self, _id: &SnapshotId) -> io::Result<()> {
            self.removed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &'static str {
            "paused-claim-test"
        }
    }

    #[test]
    fn removal_waits_for_an_in_flight_claim() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let backend = Arc::new(PausedClaim {
            entered: entered_tx,
            resume: Mutex::new(resume_rx),
            removed: AtomicUsize::new(0),
        });
        let service = Arc::new(TrustedSnapshotService::new(backend.clone()));
        let handle = service
            .publish(SnapshotId::new("leased"), Path::new("."))
            .unwrap();
        let claim = {
            let service = service.clone();
            let handle = handle.clone();
            std::thread::spawn(move || service.materialize(&handle, Path::new(".")))
        };
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the backend entered materialization");
        let (removed_tx, removed_rx) = mpsc::channel();
        let removal = {
            let service = service.clone();
            std::thread::spawn(move || removed_tx.send(service.remove(handle)).unwrap())
        };
        assert!(
            removed_rx
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "removal completed before the active claim"
        );
        resume_tx.send(()).unwrap();
        claim.join().unwrap().unwrap();
        removal.join().unwrap();
        removed_rx.recv().unwrap().unwrap();
        assert_eq!(backend.removed.load(Ordering::SeqCst), 1);
        assert_eq!(service.publication_count().unwrap(), 0);
    }

    #[test]
    fn service_rejects_unknown_handle_without_materializing() {
        let tmp = tempfile::tempdir().unwrap();
        let service = TrustedSnapshotService::new(Arc::new(TestBackend {
            store: FsSnapshotStore::new(tmp.path().join("snapshots")).unwrap(),
            fail_next_seal: AtomicBool::new(false),
            fail_next_remove: AtomicBool::new(false),
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
