//! The volume half of warm eligibility and of the claim: which volumes a
//! restored child can take over the parent's late-volume slots, and the
//! re-check of those volumes against the shares the claiming plan admitted.

use anyhow::{Context, Result};
use mvm_core::vm_backend::VmStartConfig;

/// Whether every volume of this launch can be attached to a claimed child
/// through the backend's late-volume slots.
pub(super) fn late_volumes_attachable(cfg: &VmStartConfig, late_volume_slots: u8) -> bool {
    cfg.volumes.len() <= usize::from(late_volume_slots)
        && cfg
            .volumes
            .iter()
            .all(|volume| volume.read_only && volume.materialized_image.is_some())
}

/// Re-check every volume a claim will attach against the shares its signed
/// plan admitted, immediately before the claim, exactly as a cold boot checks
/// them before it attaches anything: the volume must be named by the plan, and
/// a directory whose content digest the plan pinned must still hash to it.
pub(super) fn enforce_late_volume_shares(cfg: &VmStartConfig, plan_json: &str) -> Result<()> {
    if cfg.volumes.is_empty() {
        return Ok(());
    }
    let plan = mvm_core::plan::plan_from_admitted_json(plan_json)
        .context("a warm claim attaching volumes needs its admitted plan")?;
    mvm_hostd::plan_admission::enforce_admitted_shares(&cfg.volumes, &plan)
        .context("checking the volumes a warm claim attaches against its admitted shares")
}
