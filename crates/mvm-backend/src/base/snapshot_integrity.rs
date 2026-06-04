//! HMAC-SHA256 sealing + verification for Firecracker template
//! snapshots. ADR-007 / plan 41 W4 / M9.
//!
//! Plan-60 W8 lifted these helpers out of
//! `mvm::vm::template::lifecycle` so the snapshot **verify**
//! side (called from `mvm_backend::microvm::restore_from_template_snapshot`)
//! can reach them without `mvm-backend` taking a back-edge on
//! `mvm`. The **seal** side (called from
//! `mvm::vm::template::lifecycle::create_snapshot`) keeps its
//! original call shape via the same module.
//!
//! Failure model:
//!
//! - **Sealing**: errors propagate; the caller re-raises with extra
//!   context. Snapshot files that exist but can't be sealed are left
//!   on disk so the operator can inspect them.
//! - **Verification**: a missing sidecar is a non-fatal warning by
//!   default (preserves restorability of pre-W4 snapshots).
//!   `MVM_SNAPSHOT_HMAC_STRICT=1` flips that to a hard error.
//!   `MVM_ALLOW_STALE_SNAPSHOT=1` lets a version mismatch through —
//!   used when the operator wants to resume a snapshot sealed by an
//!   older mvmctl.

use anyhow::{Context, Result};

use crate::base::ui;

/// Seal a freshly-created snapshot with an HMAC-SHA256 sidecar.
/// ADR-007 / plan 41 W4 / M9.
///
/// Reads the host-local key (creating it on first run), computes a
/// tag over the snapshot files plus the current `mvmctl` version,
/// and writes `integrity.json` next to `vmstate.bin` / `mem.bin`.
/// Restore verifies the sidecar before handing bytes to Firecracker.
pub fn seal_snapshot_artifacts(snap_dir: &str) -> Result<()> {
    use std::path::Path;
    let snap_path = Path::new(snap_dir);
    let key_path =
        mvm_security::snapshot_hmac::default_key_path(Path::new(&mvm_core::config::mvm_data_dir()));
    let key = mvm_security::snapshot_hmac::load_or_init_key(&key_path)
        .with_context(|| format!("loading snapshot HMAC key {}", key_path.display()))?;
    let files = mvm_security::snapshot_hmac::files_in(snap_path);
    let mvmctl_version = env!("CARGO_PKG_VERSION");
    // Bump the per-resource epoch counter so a future `verify` call
    // can detect a captured-and-replayed older envelope (G5 of the
    // filesystem-volumes plan). Counter lives next to the snapshot files
    // so re-creating the dir with `mvmctl template build --force`
    // resumes from the previous high-water mark.
    let epoch_store = mvm_security::snapshot_hmac::EpochStore::new(snap_path.join(".epoch"));
    let next_epoch = epoch_store
        .next()
        .with_context(|| format!("advancing epoch counter for {snap_dir}"))?;
    let _sidecar = mvm_security::snapshot_hmac::seal(
        snap_path,
        &files,
        next_epoch,
        mvmctl_version,
        secrecy::ExposeSecret::expose_secret(&key),
    )
    .with_context(|| format!("sealing snapshot at {snap_dir}"))?;
    Ok(())
}

/// Verify the integrity sidecar for a snapshot before resume.
/// ADR-007 / plan 41 W4 / M9.
///
/// Returns `Ok(())` on a clean match. Honours `MVM_ALLOW_STALE_SNAPSHOT=1`
/// for the version-mismatch case (e.g. a snapshot sealed by an earlier
/// `mvmctl` build that the operator wants to resume anyway). The
/// `MVM_SNAPSHOT_HMAC_STRICT=1` env var flips a missing sidecar from a
/// non-fatal warning (default — preserves restorability of pre-W4
/// snapshots) into a hard error.
pub fn verify_snapshot_artifacts(snap_dir: &str) -> Result<()> {
    use mvm_security::snapshot_hmac::VerifyError;
    use std::path::Path;

    let snap_path = Path::new(snap_dir);
    let sidecar_path = snap_path.join(mvm_security::snapshot_hmac::SIDECAR_FILENAME);
    if !sidecar_path.exists() {
        if std::env::var("MVM_SNAPSHOT_HMAC_STRICT").as_deref() == Ok("1") {
            anyhow::bail!(
                "snapshot at {snap_dir} has no integrity sidecar and \
                 MVM_SNAPSHOT_HMAC_STRICT=1 forbids resume"
            );
        }
        ui::warn(&format!(
            "snapshot at {snap_dir} has no integrity sidecar \
             (created before plan 41 W4); resuming without HMAC verification. \
             Re-build the template to seal it."
        ));
        return Ok(());
    }

    let key_path =
        mvm_security::snapshot_hmac::default_key_path(Path::new(&mvm_core::config::mvm_data_dir()));
    let key = mvm_security::snapshot_hmac::load_or_init_key(&key_path)
        .with_context(|| format!("loading snapshot HMAC key {}", key_path.display()))?;
    let files = mvm_security::snapshot_hmac::files_in(snap_path);
    let mvmctl_version = env!("CARGO_PKG_VERSION");
    let allow_stale = std::env::var("MVM_ALLOW_STALE_SNAPSHOT").as_deref() == Ok("1");
    // Read the per-resource high-water mark; the verifier rejects
    // any envelope whose epoch is below it (G5 replay defence).
    let epoch_store = mvm_security::snapshot_hmac::EpochStore::new(snap_path.join(".epoch"));
    let min_epoch = epoch_store.load();

    match mvm_security::snapshot_hmac::verify(
        snap_path,
        &files,
        min_epoch,
        mvmctl_version,
        secrecy::ExposeSecret::expose_secret(&key),
        allow_stale,
    ) {
        Ok(_) => Ok(()),
        Err(VerifyError::VersionMismatch { sealed, current }) => {
            audit_snapshot_integrity_failure(
                snap_dir,
                &format!("variant=version_mismatch sealed={sealed} current={current}"),
            );
            anyhow::bail!(
                "snapshot at {snap_dir} was sealed by mvmctl '{sealed}' but \
                 current is '{current}'. Set MVM_ALLOW_STALE_SNAPSHOT=1 to override."
            )
        }
        Err(VerifyError::TagMismatch) => {
            audit_snapshot_integrity_failure(snap_dir, "variant=tag_mismatch");
            anyhow::bail!(
                "snapshot at {snap_dir} failed HMAC verification — files have been \
                 tampered or the host key changed. Refusing to resume."
            )
        }
        Err(other) => {
            audit_snapshot_integrity_failure(snap_dir, &format!("variant=other detail={other}"));
            Err(anyhow::anyhow!(
                "snapshot at {snap_dir} integrity check failed: {other}"
            ))
        }
    }
}

/// Emit a `SnapshotIntegrityFailed` local audit event.
///
/// `snap_dir` lands in `vm_name` so an operator scanning the audit log
/// can correlate the failure with the specific template snapshot
/// directory; `detail` carries the variant string distinguishing
/// tamper (`tag_mismatch`) from version drift (`version_mismatch`)
/// from lower-level I/O / encoding failures (`other`).
fn audit_snapshot_integrity_failure(snap_dir: &str, detail: &str) {
    mvm_core::audit_emit!(SnapshotIntegrityFailed, vm: snap_dir, "{detail}");
}
