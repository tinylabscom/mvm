//! Firecracker snapshot controls, gated on the device-model guard below.
//!
//! `verify_and_resume` / `verify_and_resume_from_dir` in
//! `crate::vm::instance_snapshot` run the no-NIC guard strictly between
//! loading a snapshot paused and resuming it — see there for the full
//! ordering. That path backs the live `mvmctl pause`/`resume` cycle today.
//!
//! `warm_restore_instance_from_path` reuses the same load → guard → resume
//! ordering via `guarded_load_resume`, but skips the instance-snapshot HMAC
//! verify: its caller (the fork restore path) already established the
//! content's integrity upstream via the checkpoint lineage's content-address
//! and audit-chain checks, so a second verifier here would either be
//! redundant or fail closed on content it was never meant to see.
//!
//! The template restore entry point and the bare `warm_restore_instance`
//! stay refused. A template snapshot carries its own Ed25519 + HMAC sidecar
//! (a separate, stronger check) that isn't wired up yet; `warm_restore_instance`
//! has no caller. Re-enabling either needs a design that keeps its own
//! integrity check and adds the same guard ordering on top of it.

use anyhow::Result;
use tracing::instrument;

/// Refuse template snapshot restore.
///
/// Snapshots capture complete VMM device state and may contain a network
/// interface, bypassing the vsock-only egress boundary. Template snapshots
/// are sealed with their own Ed25519 + HMAC sidecar, a separate mechanism
/// from the instance-snapshot HMAC path the no-NIC guard is wired behind;
/// restoring them needs a design that keeps that signature check AND adds
/// the guard, so this stays refused until that design lands.
#[instrument(skip_all, fields(template_id, name = %config.name))]
pub fn restore_from_template_snapshot(
    template_id: &str,
    config: &super::flake_run::FlakeRunConfig,
    snapshot_dir: &str,
    _snapshot_info: &mvm_core::template::SnapshotInfo,
) -> Result<()> {
    let _ = (template_id, snapshot_dir);
    config.validate()?;
    anyhow::bail!(
        "Firecracker template snapshot restore is disabled; use the vsock workload runner"
    );
}
