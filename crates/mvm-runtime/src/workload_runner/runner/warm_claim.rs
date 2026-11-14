use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use mvm_core::config::vm_state_dir;
use mvm_core::vm_backend::{StandbyError, StartMode, VmId, VmStartConfig};

use crate::standby_pool::SupervisorStandbyPool;

/// Marker a committed resident claim writes into the child's state dir, naming
/// the standby parent the claim consumed. A resident handoff runs the child
/// out of the parent's own state dir — the child's rootfs *is* the parent's
/// rootfs and the child's control files are symlinks into the parent dir — so
/// the parent dir cannot be removed at claim time. The child's stop path reads
/// this marker after the child's confirmed exit and removes what the claim
/// left behind.
pub(super) const CONSUMED_RESIDENT_PARENT_FILE: &str = "consumed-resident-parent";

/// Record, in the child's state dir, which standby parent a committed resident
/// claim consumed. Best-effort at the call site: the child is live and admitted
/// by the time this runs, so a write failure must not fail the claim.
pub(super) fn record_consumed_resident_parent(
    child_dir: &Path,
    parent_vm_name: &str,
) -> std::io::Result<()> {
    std::fs::write(
        child_dir.join(CONSUMED_RESIDENT_PARENT_FILE),
        format!("{parent_vm_name}\n"),
    )
}

/// Remove the standby-parent state a committed resident claim consumed: the
/// parent's VM state dir and its pool record. Runs on the child's stop path,
/// only after the child's exit has been confirmed by the driver's bounded
/// exit-evidence mechanism (for HVF, the authenticated `ConfirmedExit` proof).
/// A resident handoff resumed the parent's own supervisor process under the
/// child name — the child's pid file is a symlink to the parent's — so the
/// child's confirmed exit is also the parent's bounded confirmed exit, and
/// every descriptor the parent held on its state dir is closed by then.
///
/// Deliberately best-effort and NotFound-tolerant: this is teardown hygiene,
/// so a failure is logged and never turned into a stop failure. Without a
/// marker (a cold boot or a saved-state claim) there is nothing to do.
pub(super) fn cleanup_consumed_resident_parent(child_dir: &Path, child_exit_confirmed: bool) {
    if !child_exit_confirmed {
        // The parent dir holds the child's rootfs; removing it while the child
        // may still run would tear the live machine's storage out from under
        // it. The reaper keeps owning the not-confirmed case.
        return;
    }
    let marker = child_dir.join(CONSUMED_RESIDENT_PARENT_FILE);
    let Ok(contents) = std::fs::read_to_string(&marker) else {
        return;
    };
    let parent_vm_name = contents.trim();
    if parent_vm_name.is_empty() {
        tracing::warn!(child_dir = %child_dir.display(), "consumed resident parent marker is empty; leaving parent state in place");
        return;
    }
    if let Err(error) = mvm_core::naming::validate_vm_name(parent_vm_name) {
        tracing::warn!(child_dir = %child_dir.display(), parent = %parent_vm_name, error = %error, "consumed resident parent marker failed name validation; leaving parent state in place");
        return;
    }
    let parent_dir = vm_state_dir(parent_vm_name);
    match std::fs::remove_dir_all(&parent_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(dir = %parent_dir.display(), error = %e, "removing consumed resident parent state dir after child stop")
        }
    }
    match SupervisorStandbyPool::open() {
        Ok(pool) => {
            if let Err(e) = pool.remove(parent_vm_name) {
                tracing::warn!(parent = %parent_vm_name, error = %e, "removing consumed resident parent pool record after child stop");
            }
        }
        Err(e) => {
            tracing::warn!(parent = %parent_vm_name, error = %e, "opening standby pool to remove consumed resident parent record")
        }
    }
    match std::fs::remove_file(&marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(marker = %marker.display(), error = %e, "removing consumed resident parent marker after child stop")
        }
    }
}

pub(super) fn record_phase(
    claim_started: Instant,
    claim_debug: &mut Option<std::fs::File>,
    phase: &'static str,
) {
    let elapsed_us = claim_started.elapsed().as_micros();
    tracing::debug!(
        target: "mvm_runtime::warm_claim",
        phase,
        elapsed_us,
        "warm claim phase"
    );
    if let Some(file) = claim_debug.as_mut() {
        use std::io::Write;

        let _ = writeln!(file, "[warm-claim] phase={phase} elapsed_us={elapsed_us}");
    }
}

/// Record how long into a standby spawn a step finished, beside the claim
/// phases. A refill runs as a detached process, so the same trace file the claim
/// writes (`MVM_HVF_AGENT_DEBUG`) carries these.
pub(super) fn record_standby_phase(started: Instant, scope: &'static str, phase: &'static str) {
    mvm_vmm::agent_debug::phase(
        "standby-spawn",
        started,
        format_args!("scope={scope} phase={phase}"),
    );
}

/// Write a saved-state claimed child's runtime metadata: the record a cold boot
/// writes from its start config, plus the device anchors its materialized
/// checkpoint carries, which its restored VMM keeps naming.
pub(super) fn record_claimed_child_runtime_meta(
    child: &VmId,
    child_cfg: &VmStartConfig,
    child_dir: &Path,
) -> std::result::Result<(), StandbyError> {
    let record = || -> Result<()> {
        let anchors = crate::base::runtime_meta::read_restored_device_anchors(child_dir)?;
        crate::base::runtime_meta::record_restored_from_start_config(
            &child.0,
            StartMode::Detached,
            child_cfg,
            anchors,
        )
    };
    record().map_err(|e| {
        StandbyError::ClaimFailed(format!(
            "recording claimed child '{}' runtime metadata: {e:#}",
            child.0
        ))
    })
}

/// Resolve the launch source recorded for a resident standby parent. The live
/// HVF supervisor already has this image attached; the path is used only for
/// the same host-side overlay admission gate a cold workload boot performs.
pub(super) fn resident_parent_rootfs_dir(
    parent_vm_name: &str,
) -> std::result::Result<PathBuf, StandbyError> {
    let metadata = crate::base::runtime_meta::read(parent_vm_name)
        .map_err(|e| StandbyError::ClaimFailed(format!("read resident parent metadata: {e:#}")))?
        .ok_or_else(|| {
            StandbyError::ClaimFailed(format!(
                "resident parent '{parent_vm_name}' has no runtime metadata"
            ))
        })?;
    let rootfs = metadata
        .rootfs_path
        .ok_or_else(|| StandbyError::ClaimFailed("resident parent has no rootfs path".into()))?;
    let rootfs = PathBuf::from(rootfs);
    if !rootfs.is_file() {
        return Err(StandbyError::ClaimFailed(format!(
            "resident parent rootfs {} is not a regular file",
            rootfs.display()
        )));
    }
    rootfs.parent().map(Path::to_path_buf).ok_or_else(|| {
        StandbyError::ClaimFailed(format!(
            "resident parent rootfs {} has no containing directory",
            rootfs.display()
        ))
    })
}
