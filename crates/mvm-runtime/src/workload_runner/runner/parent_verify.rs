//! What a claim must prove about its standby parent before any child is
//! restored from it, and the deferred cleanup a committed resident handoff
//! leaves behind.
//!
//! These gates share one property: each fails closed on evidence it cannot
//! verify, and a parent that cannot be verified is quarantined by removal
//! rather than returned to the claimable pool.

use anyhow::Context;
use std::path::Path;

use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::vm_backend::{StandbyError, StandbyHandle};
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotStore};

use super::refusal::{map_lineage_refusal, refuse};
use super::{ClaimContext, ClaimRefusal};
use crate::checkpoint::{CheckpointStore, verify_content_at_rest, verify_lineage};
use crate::vm::name_registry::acquire_registry_lock;
use crate::warm_snapshot::is_trusted_snapshot_id;

/// Reserve the passed parent atomically under the registry lock (the no-double-
/// claim guard), then verify its sealed content and its content-address. Saved-
/// state claims additionally verify the metadata lineage against the signed
/// audit chain; resident HVF claims use their signed snapshot manifest as the
/// O(1) publication witness. Returns the verified parent meta. Runs before any
/// clone or boot: an unclaimable or tampered parent fails closed.
///
/// A parent that fails verification (or whose sealed record is unreadable) is
/// **quarantined by removal** — a parent that cannot be verified must never be
/// reused, so it is dropped from the pool rather than returned to claimable.
/// Replenish spawns a fresh one in its place. This is the deliberate exception to
/// the release-on-failure rule the caller's `WarmClaimLease` applies to a healthy
/// reserved parent.
pub(super) fn reserve_and_verify_parent(
    ctx: &ClaimContext<'_>,
    handle: &StandbyHandle,
    resident_handoff: bool,
) -> std::result::Result<CheckpointMeta, StandbyError> {
    {
        let _lock = acquire_registry_lock(ctx.registry_path)
            .map_err(|e| StandbyError::ClaimFailed(format!("acquire registry lock: {e:#}")))?;
        let current = ctx
            .pool
            .load(&handle.id)
            .map_err(|e| StandbyError::ClaimFailed(format!("load standby {}: {e:#}", handle.id)))?;
        if !current.state.is_claimable() {
            // Not yet reserved (no `mark_claimed`), so nothing to release.
            return Err(refuse(ClaimRefusal::ParentNotClaimable));
        }
        ctx.pool.mark_claimed(&handle.id).map_err(|e| {
            StandbyError::ClaimFailed(format!("reserve standby {}: {e:#}", handle.id))
        })?;
    }

    // Quarantine (remove) the reserved parent on any verification failure — a
    // parent we cannot trust must not linger claimable OR stranded `Claimed`.
    let quarantine = |err: StandbyError| -> StandbyError {
        if let Err(e) = ctx.pool.remove(&handle.id) {
            tracing::warn!(
                parent = %handle.id,
                error = %e,
                "failed to quarantine an untrusted reserved parent; it stays claimed (unclaimable) until the pool reaper"
            );
        }
        err
    };
    let parent = ctx
        .checkpoints
        .read_meta(ctx.parent_checkpoint)
        .map_err(|e| {
            quarantine(StandbyError::ClaimFailed(format!(
                "read parent checkpoint: {e:#}"
            )))
        })?;
    if resident_handoff
        && !is_trusted_snapshot_id(parent.snapshot_id.as_deref().unwrap_or_default())
    {
        verify_resident_snapshot_manifest(ctx, &parent)
            .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    } else if let Some(snapshot_id) = parent
        .snapshot_id
        .as_deref()
        .filter(|id| is_trusted_snapshot_id(id))
    {
        let backend =
            mvm_fs::trusted_snapshot::platform_backend(ctx.snapshots.root()).map_err(|e| {
                quarantine(StandbyError::ClaimFailed(format!(
                    "open trusted snapshot backend: {e:#}"
                )))
            })?;
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().map_err(|e| {
            quarantine(StandbyError::ClaimFailed(format!(
                "load trusted snapshot signer: {e:#}"
            )))
        })?;
        let manifest_digest = mvm_core::checkpoint::content_manifest_digest(&parent.content);
        let manifest_digest_text = manifest_digest.to_string();
        let signer = identity.verifying_key().to_bytes();
        backend
            .validate(
                &mvm_fs::snapshot_store::SnapshotId::with_digest(
                    snapshot_id,
                    manifest_digest_text.clone(),
                ),
                &manifest_digest_text,
                &signer,
            )
            .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    } else {
        // Authenticated where it lies, not decrypted: a preloaded child was
        // opened from this content when its standby was prepared, and a child
        // materialized below is opened chunk by chunk as it is written. Either
        // way a parent tampered with since capture is refused here.
        verify_content_at_rest(ctx.checkpoints, &parent)
            .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    }
    if !resident_handoff {
        verify_lineage(ctx.checkpoints, ctx.parent_checkpoint, ctx.anchor)
            .map_err(|e| quarantine(refuse(map_lineage_refusal(&e))))?;
    }
    Ok(parent)
}

/// Verify the signed publication witness for a resident parent without reading
/// the bundle's large content files. The live, paused HVF parent is the machine
/// that will be transferred; the ordinary snapshot is retained as a signed,
/// user-owned publication record and remains fully verified for saved restores.
pub(super) fn verify_resident_snapshot_manifest(
    ctx: &ClaimContext<'_>,
    parent: &CheckpointMeta,
) -> anyhow::Result<()> {
    let snapshot_id = parent
        .snapshot_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("resident parent has no staged snapshot"))?;
    if snapshot_id.is_empty()
        || snapshot_id.contains('/')
        || snapshot_id.contains('\\')
        || snapshot_id.contains('\0')
    {
        anyhow::bail!("resident parent snapshot id is not a safe store entry")
    }
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()?;
    let digest = mvm_core::checkpoint::content_manifest_digest(&parent.content);
    mvm_core::crypto::snapshot_sign::verify_manifest(
        &ctx.snapshots.root().join(snapshot_id),
        &digest.to_string(),
        &[identity.verifying_key()],
    )?;
    Ok(())
}

/// Reclaim the bulky publication payload after a resident parent has become a
/// committed child. The signed manifest has already authorized the handoff,
/// and the resident parent is no longer claimable, so retaining its checkpoint
/// bytes would make every warm claim add another large saved-state artifact.
/// Saved-state claims do not use this path because their checkpoint remains the
/// restore resource and its lineage record.
pub(super) fn schedule_resident_checkpoint_reclaim(
    ctx: &ClaimContext<'_>,
    parent: &CheckpointMeta,
) {
    let checkpoints_root = ctx.checkpoints.root().to_path_buf();
    let snapshots_root = ctx.snapshots.root().to_path_buf();
    let parent_id = parent.id.clone();
    let snapshot_id = parent.snapshot_id.clone();
    let result = std::thread::Builder::new()
        .name("mvm-resident-reclaim".to_string())
        .spawn(move || {
            if let Err(error) = reclaim_consumed_resident_checkpoint_at(
                &checkpoints_root,
                &snapshots_root,
                &parent_id,
                snapshot_id.as_deref(),
            ) {
                tracing::warn!(
                    checkpoint = %parent_id,
                    error = %error,
                    "resident parent publication cleanup failed; warm handoff remains committed"
                );
            }
        });
    if let Err(error) = result {
        tracing::warn!(
            checkpoint = %parent.id,
            error = %error,
            "could not schedule resident parent publication cleanup"
        );
    }
}

pub(super) fn reclaim_consumed_resident_checkpoint_at(
    checkpoints_root: &Path,
    snapshots_root: &Path,
    parent_id: &CheckpointId,
    snapshot_id: Option<&str>,
) -> anyhow::Result<()> {
    let checkpoints = CheckpointStore::at(checkpoints_root);
    let snapshots = FsSnapshotStore::new(snapshots_root)
        .context("open resident snapshot store for deferred cleanup")?;
    let Some(snapshot_id) = snapshot_id else {
        return checkpoints
            .remove(parent_id)
            .context("remove resident checkpoint without snapshot");
    };

    if is_trusted_snapshot_id(snapshot_id) {
        // The platform snapshot provider owns trusted-snapshot reclamation;
        // ordinary filesystem snapshots are the resident publication path here.
        return Ok(());
    }

    let snapshot = mvm_fs::snapshot_store::SnapshotId::new(snapshot_id);
    match snapshots.remove(&snapshot) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove resident snapshot payload"),
    }
    checkpoints
        .remove(parent_id)
        .context("remove resident checkpoint payload")
}
