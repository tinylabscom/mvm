//! Putting a VM back to running after its pause failed to capture.

use mvm_runtime::vm::instance_snapshot::SnapshotIO;

use super::backend_err;
use crate::MvmError;

/// The error for a pause whose capture failed, after putting the VM back to
/// running.
///
/// A failed capture publishes nothing and leaves the previous snapshot as it
/// was, and the machine is not marked paused, so its VMM must not be left
/// paused either: Firecracker pauses the vCPUs before it snapshots and leaves
/// them paused when the snapshot fails. Resuming them keeps the backend's
/// state and the registry's in agreement. When that resume fails too, the
/// error says so, because the machine is then running in name only.
pub(super) fn resume_after_failed_capture(
    io: &dyn SnapshotIO,
    name: &str,
    error: &anyhow::Error,
) -> MvmError {
    match io.resume() {
        Ok(()) => backend_err(format!(
            "pausing VM {name:?}: {error:#}; nothing was saved, the VM was resumed and its \
             previous snapshot is unchanged"
        )),
        Err(resume) => backend_err(format!(
            "pausing VM {name:?}: {error:#}; resuming it afterwards also failed \
             ({resume:#}), so its vCPUs may be left paused — stop the machine and start it \
             again"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_capture_resumes_the_vm_it_paused() {
        let io = mvm_runtime::vm::instance_snapshot::CannedIO::new(b"v".to_vec(), b"m".to_vec());
        let err = resume_after_failed_capture(&io, "vm", &anyhow::anyhow!("PUT /snapshot/create"));
        assert_eq!(io.calls(), vec!["resume"]);
        let text = err.to_string();
        assert!(
            text.contains("PUT /snapshot/create") && text.contains("was resumed"),
            "{text}"
        );
    }

    #[test]
    fn a_failed_resume_after_a_failed_capture_is_reported() {
        let io = mvm_runtime::vm::instance_snapshot::CannedIO::new(b"v".to_vec(), b"m".to_vec())
            .with_failing_resume();
        let err = resume_after_failed_capture(&io, "vm", &anyhow::anyhow!("capture failed"));
        let text = err.to_string();
        assert!(
            text.contains("resuming it afterwards also failed"),
            "{text}"
        );
    }
}
