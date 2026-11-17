//! Backend-specific warm and sealed resume paths.

use mvm_core::client::Result;
use mvm_core::client::dto::ResumeOutcome;
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{SnapshotCapability, VmId, VmStartConfig, WarmStartError};
use mvm_runtime::AnyBackend;
use mvm_runtime::vm::instance_snapshot::verify_and_resume;

use super::{
    LocalBackend, RESUME_ADMISSION, backend_err, mark_resumed_after_restore, post_restore_signal,
    refuse_resume, require_registry_paused, resume_sealed, warm_resume_reseed_verdict,
};

impl LocalBackend {
    /// Warm-resume through the backend's live-memory `warm_start` path: mint a
    /// fresh VMGenID, load + resume live memory, reseed. Fails closed with the
    /// typed `WarmStartError::Unsupported` recovery hint on a disk-only backend
    /// rather than silently cold-booting.
    pub(super) fn warm_resume(&self, backend: &AnyBackend, name: &str) -> Result<ResumeOutcome> {
        require_registry_paused(name)?;
        let config = VmStartConfig {
            name: name.to_string(),
            ..Default::default()
        };
        match backend.warm_start(&config, SnapshotCapability::LiveMemory) {
            Ok(outcome) => {
                let reseed = match warm_resume_reseed_verdict(outcome.reseed) {
                    Ok(summary) => summary,
                    Err(why) => {
                        return Err(refuse_resume(name, &why, || {
                            backend.stop(&VmId(name.to_string())).map(|_timing| ())
                        }));
                    }
                };
                // A warm start resumes the paused process itself, so the pause
                // marker still names it and would keep reporting it paused.
                if let Err(error) = mvm_runtime::vm::admission::clear_paused(&vm_state_dir(name)) {
                    tracing::warn!(vm = %name, error = %format!("{error:#}"), "could not clear the pause marker");
                }
                mark_resumed_after_restore(name, "")?;
                // A warm resume restores live memory, not a sealed snapshot, so it
                // carries no epoch/lengths — only the reseed summary.
                Ok(ResumeOutcome {
                    reseed: Some(reseed),
                    ..Default::default()
                })
            }
            // Name the tier mismatch + recovery hint verbatim (its `Display` is
            // the actionable message); other failures keep a locating context.
            Err(e @ WarmStartError::Unsupported { .. }) => Err(backend_err(format!("{e}"))),
            Err(e) => Err(backend_err(format!("warm-starting VM {name:?}: {e}"))),
        }
    }

    /// Plain resume: verify the sealed snapshot envelope — **refusing a replayed
    /// older-epoch snapshot** — load it back and resume vCPUs, then finish
    /// bringing the guest back with a fresh-VMGenID PostRestore (skipped for the
    /// mock, which has no guest agent).
    pub(super) fn plain_resume(&self, backend: &AnyBackend, name: &str) -> Result<ResumeOutcome> {
        require_registry_paused(name)?;
        if !Self::uses_sealed_snapshot(backend) {
            backend
                .resume(&VmId(name.to_string()))
                .map_err(|e| backend_err(format!("resuming VM {name:?}: {e:#}")))?;
            mark_resumed_after_restore(name, "")?;
            return Ok(ResumeOutcome::default());
        }

        let io = self.snapshot_io_for(backend, name)?;
        if !Self::is_mock_backend(backend) {
            let (sidecar, reseed) =
                resume_sealed(name, &*io, post_restore_signal(name), RESUME_ADMISSION)?;
            // Report the verified snapshot's epoch + artifact lengths so the
            // caller's WorkloadWake audit entry carries the same detail the
            // pause did.
            return Ok(ResumeOutcome {
                epoch: sidecar.epoch,
                vmstate_len: sidecar.vmstate_len,
                mem_len: sidecar.mem_len,
                reseed: Some(reseed),
            });
        }
        // The mock has no guest agent to reseed, so its restore is the whole
        // resume.
        let sidecar = verify_and_resume(name, &*io)
            .map_err(|e| backend_err(format!("resuming VM {name:?}: {e:#}")))?;
        let reseed = None;
        mark_resumed_after_restore(name, "")?;
        // Report the verified snapshot's epoch + artifact lengths so the caller's
        // WorkloadWake audit entry carries the same detail the pause did.
        Ok(ResumeOutcome {
            epoch: sidecar.epoch,
            vmstate_len: sidecar.vmstate_len,
            mem_len: sidecar.mem_len,
            reseed,
        })
    }
}
