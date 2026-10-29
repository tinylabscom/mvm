//! Original capture storage and writer-quiescence lifetime.

use super::{
    CaptureVmFullParams, CheckpointMeta, CheckpointStore, FsSnapshotStore, Result,
    TrustedSnapshotBackend, VmFullControl, capture_vm_full_inner, protection, staging,
};

/// Capture a running VM's consistent {rootfs, memory, machine-id} triple in one
/// pause window. The disk clone happens while paused so memory and disk match.
pub fn capture_vm_full(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
) -> Result<CheckpointMeta> {
    capture_vm_full_inner(store, params, control, None, None)
}

/// Capture a vm_full checkpoint and stage its immutable bytes in the supplied
/// snapshot store before writing metadata. The resulting snapshot ID is part
/// of the checkpoint's load-bearing digest, so later claims can materialize it
/// without rereading the captured memory image.
pub fn capture_vm_full_into_snapshot_store(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
    snapshot_store: &FsSnapshotStore,
) -> Result<CheckpointMeta> {
    capture_vm_full_inner(store, params, control, Some(snapshot_store), None)
}

/// Capture a vm_full checkpoint and publish its bytes through an immutable
/// trusted-snapshot backend. The backend owns the publication proof, allowing
/// a later claim to materialize without hashing the captured blobs again.
pub fn capture_vm_full_to_trusted_snapshot_backend(
    store: &CheckpointStore,
    params: CaptureVmFullParams,
    control: &dyn VmFullControl,
    backend: &dyn TrustedSnapshotBackend,
) -> Result<CheckpointMeta> {
    capture_vm_full_inner(store, params, control, None, Some(backend))
}

#[derive(Clone, Copy, PartialEq)]
pub(super) enum CaptureWriterState {
    NotStarted,
    Unconfirmed,
    Quiescent,
}

pub(super) struct CaptureGuardGroup {
    pub(super) storage: Option<Box<CaptureStorage>>,
    pub(super) writer: CaptureWriterState,
}

pub(super) struct CaptureStorage {
    pub(super) staged: Option<staging::StagedCapture>,
    pub(super) protection: protection::CaptureProtection,
}

impl Drop for CaptureGuardGroup {
    fn drop(&mut self) {
        if self.writer == CaptureWriterState::Unconfirmed
            && let Some(storage) = self.storage.take()
        {
            // This guard is armed BEFORE invoking a writer, including its
            // panic/unwind path. Retain the exact storage/protection group.
            // Abandonment is not recovery or proof that the writer stopped.
            std::mem::forget(storage);
        }
    }
}

pub(super) fn run_capture_writer<T>(
    state: &mut CaptureWriterState,
    staged: &staging::StagedCapture,
    write: impl FnOnce() -> Result<T>,
) -> Result<T> {
    // Errors AND unwinding leave the original guard armed. Only a completed
    // synchronous writer invocation permits ordinary storage cleanup.
    arm_capture_writer(state, || staged.arm_writer())?;
    let result = write()?;
    *state = CaptureWriterState::Quiescent;
    staged.writer_completed()?;
    Ok(result)
}

fn arm_capture_writer(
    state: &mut CaptureWriterState,
    arm: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let previous = *state;
    *state = CaptureWriterState::Unconfirmed;
    if let Err(error) = arm() {
        // Explicit refusal is before the delegated effect; unwind is not.
        *state = previous;
        return Err(error);
    }
    Ok(())
}

/// Owns original capture storage/protection on failure, never a reopened path.
pub struct CaptureCustodyFailure {
    pub(super) primary: Option<anyhow::Error>,
    pub(super) resume: Option<anyhow::Error>,
    pub(super) custody: std::sync::Mutex<Option<Box<CaptureGuardGroup>>>,
}

impl CaptureCustodyFailure {
    pub fn error(&self) -> &anyhow::Error {
        self.primary.as_ref().expect("capture error present")
    }
    pub fn resume_error(&self) -> Option<&anyhow::Error> {
        self.resume.as_ref()
    }

    /// Storage release after actual synchronous writer completion, or before
    /// writer invocation. This is not native VM terminal/stop evidence.
    pub fn into_released_error(mut self) -> std::result::Result<anyhow::Error, Self> {
        let slot = self
            .custody
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot
            .as_ref()
            .is_some_and(|group| group.writer == CaptureWriterState::Unconfirmed)
        {
            return Err(self);
        }
        drop(slot.take());
        let primary = self.primary.take().expect("capture error consumed once");
        match self.resume.take() {
            Some(resume) => Ok(anyhow::Error::new(CaptureReleasedFailure {
                primary,
                resume,
            })),
            None => Ok(primary),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{primary}; additionally failed to resume: {resume}")]
struct CaptureReleasedFailure {
    #[source]
    primary: anyhow::Error,
    resume: anyhow::Error,
}

impl std::fmt::Debug for CaptureCustodyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureCustodyFailure")
            .field("primary", &self.primary)
            .field("resume", &self.resume)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for CaptureCustodyFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.error(), f)
    }
}
impl std::error::Error for CaptureCustodyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error().as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::checkpoint::CheckpointId;
    use std::path::PathBuf;

    fn owned_capture_storage() -> (CaptureGuardGroup, PathBuf) {
        let store = CheckpointStore::owning_tempdir(tempfile::tempdir().unwrap());
        let root = store.root().to_path_buf();
        let staged =
            staging::StagedCapture::begin(&store, &CheckpointId::new("guard-only")).unwrap();
        let protection = protection::CaptureProtection::admit(
            &store,
            &mvm_core::checkpoint::CheckpointKeyDomain::host(),
        )
        .unwrap();
        let group = CaptureGuardGroup {
            storage: Some(Box::new(CaptureStorage {
                staged: Some(staged),
                protection,
            })),
            writer: CaptureWriterState::NotStarted,
        };
        drop(store);
        (group, root)
    }

    #[test]
    fn original_temp_storage_releases_before_writer_and_after_synchronous_completion() {
        let (group, root) = owned_capture_storage();
        assert!(root.exists());
        drop(group);
        assert!(!root.exists());

        let (mut group, root) = owned_capture_storage();
        run_capture_writer(
            &mut group.writer,
            group.storage.as_ref().unwrap().staged.as_ref().unwrap(),
            || Ok(()),
        )
        .unwrap();
        drop(group);
        assert!(!root.exists());
    }

    #[test]
    fn original_temp_storage_survives_writer_error_and_unwind_without_native_claim() {
        let (mut group, root) = owned_capture_storage();
        assert!(
            run_capture_writer(
                &mut group.writer,
                group.storage.as_ref().unwrap().staged.as_ref().unwrap(),
                || -> Result<()> { anyhow::bail!("local writer error") }
            )
            .is_err()
        );
        drop(group);
        assert!(root.exists());

        let (group, panic_root) = owned_capture_storage();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let mut original = group;
                let _: Result<()> = run_capture_writer(
                    &mut original.writer,
                    original.storage.as_ref().unwrap().staged.as_ref().unwrap(),
                    || panic!("local writer unwind"),
                );
            }))
            .is_err()
        );
        assert!(panic_root.exists());
        // These original TempDir aggregates are deliberately retained. This
        // test proves only production storage-policy behavior, not a running
        // VMM writer, terminal proof, native recovery, or safe crash cleanup.
    }

    #[test]
    fn returned_arm_failure_is_pre_effect_but_arm_unwind_retains_whole_custody() {
        let (mut local, local_root) = owned_capture_storage();
        let staged = local.storage.as_ref().unwrap().staged.as_ref().unwrap();
        let disposition = staged
            .content_dir()
            .parent()
            .unwrap()
            .join(".capture-disposition.json");
        std::fs::remove_file(&disposition).unwrap();
        std::fs::create_dir(&disposition).unwrap();
        assert!(
            run_capture_writer(&mut local.writer, staged, || -> Result<()> {
                panic!("writer must not run after returned persistence failure");
            })
            .is_err()
        );
        assert!(local.writer == CaptureWriterState::NotStarted);
        drop(local);
        assert!(
            !local_root.exists(),
            "known pre-effect failure uses normal RAII"
        );

        let (mut group, root) = owned_capture_storage();
        let staged = group.storage.as_ref().unwrap().staged.as_ref().unwrap();
        let old = staged.content_dir().parent().unwrap().to_path_buf();
        // Replacing the lease defeats the real identity check before writing.
        std::fs::rename(old.join(".capture-lease"), old.join("original-lease")).unwrap();
        std::fs::write(old.join(".capture-lease"), b"replacement").unwrap();
        let invoked = std::cell::Cell::new(false);
        assert!(
            run_capture_writer(&mut group.writer, staged, || {
                invoked.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!invoked.get());
        assert!(group.writer == CaptureWriterState::NotStarted);
        drop(group);
        assert!(
            root.exists(),
            "replacement/root custody must not be deleted"
        );

        let (group, panic_root) = owned_capture_storage();
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let mut original = group;
                let _ = arm_capture_writer(&mut original.writer, || {
                    assert!(
                        original
                            .storage
                            .as_ref()
                            .unwrap()
                            .staged
                            .as_ref()
                            .unwrap()
                            .content_dir()
                            .parent()
                            .unwrap()
                            .exists()
                    );
                    panic!("arming persistence unwind");
                });
            }))
            .is_err()
        );
        assert!(panic_root.exists());
        // The production arming seam is exercised with local guards only.
        // Retention is not a VM-exit or recovery claim.
    }
}
