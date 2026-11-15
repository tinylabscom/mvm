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

/// Marker a committed preloaded-child claim writes into the child's state dir,
/// naming the standby parent the claim consumed. The claim adopts the child the
/// pool pre-paused instead of forking a fresh one, so the parent's dir holds
/// the state that paused child was loaded from — the load opens the parent's
/// recorded drive paths — and the dir cannot be removed at claim time. The
/// child's stop path reads this marker after the child's confirmed exit and
/// removes what the claim left behind.
pub(super) const CONSUMED_PRELOADED_PARENT_FILE: &str = "consumed-preloaded-parent";

/// Record, in the child's state dir, which standby parent a committed claim
/// consumed, choosing the marker for the claim's handoff shape: a resident
/// handoff runs the child out of the parent's own state dir, and a
/// preloaded-child adoption loads the paused child from the parent dir's
/// recorded drives, so neither may remove the parent dir at claim time — only
/// the child's stop path may, once the child's exit is confirmed. A claim with
/// neither shape (a forked saved-state child) consumes nothing. Best-effort:
/// the child is live and admitted by the time this runs, so a write failure
/// must not fail the claim.
pub(super) fn record_consumed_parent(
    resident_handoff: bool,
    preloaded_child: bool,
    child_dir: &Path,
    parent_vm_name: &str,
    child_vm_name: &str,
) {
    let recorded = if resident_handoff {
        record_consumed_resident_parent(child_dir, parent_vm_name)
    } else if preloaded_child {
        record_consumed_preloaded_parent(child_dir, parent_vm_name)
    } else {
        return;
    };
    if let Err(error) = recorded {
        let shape = if resident_handoff {
            "resident"
        } else {
            "preloaded"
        };
        tracing::warn!(
            parent = %parent_vm_name,
            child = %child_vm_name,
            error = %error,
            "recording the consumed {shape} parent failed; its state dir will linger"
        );
    }
}

/// Record, in the child's state dir, which standby parent a committed resident
/// claim consumed. Best-effort at the call site: the child is live and admitted
/// by the time this runs, so a write failure must not fail the claim.
pub(super) fn record_consumed_resident_parent(
    child_dir: &Path,
    parent_vm_name: &str,
) -> std::io::Result<()> {
    write_consumed_parent_marker(child_dir, CONSUMED_RESIDENT_PARENT_FILE, parent_vm_name)
}

/// Record, in the child's state dir, which standby parent a committed
/// preloaded-child claim consumed. Best-effort at the call site for the same
/// reason as the resident marker above.
pub(super) fn record_consumed_preloaded_parent(
    child_dir: &Path,
    parent_vm_name: &str,
) -> std::io::Result<()> {
    write_consumed_parent_marker(child_dir, CONSUMED_PRELOADED_PARENT_FILE, parent_vm_name)
}

fn write_consumed_parent_marker(
    child_dir: &Path,
    marker_file: &str,
    parent_vm_name: &str,
) -> std::io::Result<()> {
    std::fs::write(child_dir.join(marker_file), format!("{parent_vm_name}\n"))
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
    cleanup_consumed_parent(
        child_dir,
        CONSUMED_RESIDENT_PARENT_FILE,
        child_exit_confirmed,
    )
}

/// Remove the standby-parent state a committed preloaded-child claim consumed:
/// the parent's VM state dir and its pool record. Runs on the adopted child's
/// stop path, only after the child's exit has been confirmed by the driver's
/// bounded exit-evidence mechanism; a preloaded child is its own VMM process,
/// so a stop that reaches its terminate has that confirmation, and any drive
/// descriptor the load opened on the parent dir's files is closed by then.
///
/// Deliberately best-effort and NotFound-tolerant, exactly like the resident
/// cleanup above.
pub(super) fn cleanup_consumed_preloaded_parent(child_dir: &Path, child_exit_confirmed: bool) {
    cleanup_consumed_parent(
        child_dir,
        CONSUMED_PRELOADED_PARENT_FILE,
        child_exit_confirmed,
    )
}

fn cleanup_consumed_parent(child_dir: &Path, marker_file: &str, child_exit_confirmed: bool) {
    if !child_exit_confirmed {
        // The parent dir backs the running child's storage (resident: the
        // child's rootfs itself; preloaded: the recorded drive paths the load
        // opened), so removing it while the child may still run would tear the
        // live machine's state out from under it. The reaper keeps owning the
        // not-confirmed case.
        return;
    }
    let marker = child_dir.join(marker_file);
    let Ok(contents) = std::fs::read_to_string(&marker) else {
        return;
    };
    let parent_vm_name = contents.trim();
    if parent_vm_name.is_empty() {
        tracing::warn!(child_dir = %child_dir.display(), "consumed standby parent marker is empty; leaving parent state in place");
        return;
    }
    if let Err(error) = mvm_core::naming::validate_vm_name(parent_vm_name) {
        tracing::warn!(child_dir = %child_dir.display(), parent = %parent_vm_name, error = %error, "consumed standby parent marker failed name validation; leaving parent state in place");
        return;
    }
    let parent_dir = vm_state_dir(parent_vm_name);
    match std::fs::remove_dir_all(&parent_dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(dir = %parent_dir.display(), error = %e, "removing consumed standby parent state dir after child stop")
        }
    }
    match SupervisorStandbyPool::open() {
        Ok(pool) => {
            if let Err(e) = pool.remove(parent_vm_name) {
                tracing::warn!(parent = %parent_vm_name, error = %e, "removing consumed standby parent pool record after child stop");
            }
        }
        Err(e) => {
            tracing::warn!(parent = %parent_vm_name, error = %e, "opening standby pool to remove consumed standby parent record")
        }
    }
    match std::fs::remove_file(&marker) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(marker = %marker.display(), error = %e, "removing consumed standby parent marker after child stop")
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
