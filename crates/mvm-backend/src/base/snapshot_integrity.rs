//! HMAC-SHA256 sealing + verification for Firecracker template
//! snapshots.
//!
//! These helpers live here (out of `mvm::vm::template::lifecycle`) so
//! the snapshot **verify** side (called from
//! `mvm_backend::microvm::restore_from_template_snapshot`) can reach
//! them without `mvm-backend` taking a back-edge on `mvm`. The
//! **seal** side (called from
//! `mvm::vm::template::lifecycle::create_snapshot`) keeps its
//! original call shape via the same module.
//!
//! Failure model:
//!
//! - **Sealing**: errors propagate; the caller re-raises with extra
//!   context. Snapshot files that exist but can't be sealed are left
//!   on disk so the operator can inspect them.
//! - **Verification**: a missing sidecar is a non-fatal warning by
//!   default (preserves restorability of snapshots sealed before
//!   integrity sidecars existed).
//!   `MVM_SNAPSHOT_HMAC_STRICT=1` flips that to a hard error.
//!   `MVM_ALLOW_STALE_SNAPSHOT=1` lets a version mismatch through —
//!   used when the operator wants to resume a snapshot sealed by an
//!   older mvmctl.

use anyhow::{Context, Result};

use crate::base::ui;

/// Seal a freshly-created snapshot with an HMAC-SHA256 sidecar.
///
/// Reads the host-local key (creating it on first run), computes a
/// tag over the snapshot files plus the current `mvmctl` version,
/// and writes `integrity.json` next to `vmstate.bin` / `mem.bin`.
/// Restore verifies the sidecar before handing bytes to Firecracker.
pub fn seal_snapshot_artifacts(snap_dir: &str) -> Result<()> {
    use std::path::Path;
    let snap_path = Path::new(snap_dir);
    let key_path = mvm_core::crypto::snapshot_hmac::default_key_path(Path::new(
        &mvm_core::config::mvm_data_dir(),
    ));
    let key = mvm_core::crypto::snapshot_hmac::load_or_init_key(&key_path)
        .with_context(|| format!("loading snapshot HMAC key {}", key_path.display()))?;
    let files = mvm_core::crypto::snapshot_hmac::files_in(snap_path);
    let mvmctl_version = env!("CARGO_PKG_VERSION");
    // Bump the per-resource epoch counter so a future `verify` call
    // can detect a captured-and-replayed older envelope. Counter lives
    // next to the snapshot files so re-creating the dir with
    // `mvmctl template build --force` resumes from the previous
    // high-water mark.
    let epoch_store = mvm_core::crypto::snapshot_hmac::EpochStore::new(snap_path.join(".epoch"));
    let next_epoch = epoch_store
        .next()
        .with_context(|| format!("advancing epoch counter for {snap_dir}"))?;
    let _sidecar = mvm_core::crypto::snapshot_hmac::seal(
        snap_path,
        &files,
        next_epoch,
        mvmctl_version,
        secrecy::ExposeSecret::expose_secret(&key),
    )
    .with_context(|| format!("sealing snapshot at {snap_dir}"))?;
    // Additionally content-address + Ed25519-sign the snapshot under
    // the host attestation identity. The signature (not the symmetric
    // HMAC, which anyone holding the host key could forge) is the
    // authentication gate at resume admit.
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
        .context("loading host snapshot signing identity")?;
    mvm_core::crypto::snapshot_sign::sign(snap_path, &files, next_epoch, &identity.signing)
        .with_context(|| format!("signing snapshot at {snap_dir}"))?;
    Ok(())
}

/// Verify the integrity sidecar for a snapshot before resume.
///
/// Returns `Ok(())` on a clean match. Honours `MVM_ALLOW_STALE_SNAPSHOT=1`
/// for the version-mismatch case (e.g. a snapshot sealed by an earlier
/// `mvmctl` build that the operator wants to resume anyway). The
/// `MVM_SNAPSHOT_HMAC_STRICT=1` env var flips a missing sidecar from a
/// non-fatal warning (default — preserves restorability of snapshots
/// sealed before integrity sidecars existed) into a hard error.
pub fn verify_snapshot_artifacts(snap_dir: &str) -> Result<()> {
    use mvm_core::crypto::snapshot_hmac::VerifyError;
    use std::path::Path;

    let snap_path = Path::new(snap_dir);
    let sidecar_path = snap_path.join(mvm_core::crypto::snapshot_hmac::SIDECAR_FILENAME);
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

    let key_path = mvm_core::crypto::snapshot_hmac::default_key_path(Path::new(
        &mvm_core::config::mvm_data_dir(),
    ));
    let key = mvm_core::crypto::snapshot_hmac::load_or_init_key(&key_path)
        .with_context(|| format!("loading snapshot HMAC key {}", key_path.display()))?;
    let files = mvm_core::crypto::snapshot_hmac::files_in(snap_path);
    let mvmctl_version = env!("CARGO_PKG_VERSION");
    let allow_stale = std::env::var("MVM_ALLOW_STALE_SNAPSHOT").as_deref() == Ok("1");
    // Read the per-resource high-water mark; the verifier rejects
    // any envelope whose epoch is below it (replay defence).
    let epoch_store = mvm_core::crypto::snapshot_hmac::EpochStore::new(snap_path.join(".epoch"));
    let min_epoch = epoch_store.load();

    let hmac_sidecar = match mvm_core::crypto::snapshot_hmac::verify(
        snap_path,
        &files,
        min_epoch,
        mvmctl_version,
        secrecy::ExposeSecret::expose_secret(&key),
        allow_stale,
    ) {
        Ok(sidecar) => sidecar,
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
            return Err(anyhow::anyhow!(
                "snapshot at {snap_dir} integrity check failed: {other}"
            ));
        }
    };

    // The Ed25519 signature is the authentication gate. The HMAC above
    // is cheap local integrity; this proves the host signed these
    // exact bytes at this epoch.
    verify_snapshot_signature(snap_dir, snap_path, &files, hmac_sidecar.epoch)
}

/// Verify the `snapshot.sig` Ed25519 sidecar. Missing signatures are a
/// non-fatal warning by default (preserves restorability of snapshots
/// sealed before signing existed); `MVM_SNAPSHOT_HMAC_STRICT=1` makes
/// them a hard error. A present-but-invalid signature is always fatal.
fn verify_snapshot_signature(
    snap_dir: &str,
    snap_path: &std::path::Path,
    files: &mvm_core::crypto::snapshot_hmac::SnapshotFiles,
    epoch: u64,
) -> Result<()> {
    let sig_path = snap_path.join(mvm_core::crypto::snapshot_sign::SIGNATURE_FILENAME);
    if !sig_path.exists() {
        if std::env::var("MVM_SNAPSHOT_HMAC_STRICT").as_deref() == Ok("1") {
            anyhow::bail!(
                "snapshot at {snap_dir} has no Ed25519 signature sidecar and \
                 MVM_SNAPSHOT_HMAC_STRICT=1 forbids resume"
            );
        }
        ui::warn(&format!(
            "snapshot at {snap_dir} has no Ed25519 signature sidecar \
             (sealed before plan 122 C); resuming on HMAC integrity only. \
             Re-build the template to sign it."
        ));
        return Ok(());
    }

    // Standalone host: trust our own attestation identity. (Under mvmd the
    // verifier would pin the enrolled worker identities instead — the
    // substrate already takes a trusted set.)
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
        .context("loading host snapshot signing identity for verification")?;
    match mvm_core::crypto::snapshot_sign::verify_signature(
        snap_path,
        files,
        epoch,
        &[identity.verifying_key()],
    ) {
        Ok(_) => Ok(()),
        Err(e) => {
            audit_snapshot_integrity_failure(snap_dir, &format!("variant=signature detail={e}"));
            anyhow::bail!(
                "snapshot at {snap_dir} failed Ed25519 signature verification: {e}. \
                 Refusing to resume."
            )
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
