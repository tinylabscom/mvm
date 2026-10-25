use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use mvm_core::vm_backend::{StandbyError, StartMode, VmId, VmStartConfig};

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
    let elapsed_us = started.elapsed().as_micros();
    tracing::debug!(
        target: "mvm_runtime::standby_spawn",
        scope,
        phase,
        elapsed_us,
        "standby spawn phase"
    );
    mvm_vmm::agent_debug::line(
        "standby-spawn",
        format_args!("scope={scope} phase={phase} elapsed_us={elapsed_us}"),
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
