//! Instance-snapshot store.
//!
//! `mvmctl pause <vm>` quiesces the running VM, asks Firecracker
//! for a snapshot, seals the bytes with the HMAC envelope (now
//! including a monotonic per-instance epoch), and stops the
//! VM. `mvmctl resume <vm>` verifies the envelope, asks Firecracker
//! to load the snapshot, then re-establishes vsock auth via
//! `PostRestore`. This module owns the disk layout + seal/verify
//! helpers; the actual Firecracker quiesce/load lives behind a
//! `SnapshotIO` trait so the substrate is fully unit-testable
//! without a live KVM host.
//!
//! # On-disk layout
//!
//! ```text
//! ~/.mvm/instances/<vm-name>/
//!     snapshot/
//!         vmstate.bin       (Firecracker VM state, mode 0600)
//!         mem.bin           (guest memory image, mode 0600)
//!         integrity.json    (HMAC sidecar, mode 0600)
//!         .epoch            (monotonic counter, mode 0600)
//! ```
//!
//! The directory itself is mode `0700` (consistent with the
//! existing `~/.mvm` discipline). All snapshot files are
//! mode `0600` so a co-tenant on the same host can't read another
//! sandbox's memory image even if `~/.mvm/instances/` were ever
//! made world-readable by mistake.
//!
//! # What this module does NOT do (yet)
//!
//! - AES-GCM encryption of `mem.bin`.
//!   The HMAC envelope guarantees integrity; confidentiality
//!   currently rests on the file mode + `~/.mvm` directory perms.
//!   The natural seam to add it is in `seal_instance_snapshot` /
//!   `verify_instance_snapshot` so callers don't change.
//! - Firecracker's actual `create_snapshot` / `load_snapshot` API
//!   calls. Those land in a follow-up chunk gated on a live KVM
//!   host; the `SnapshotIO` trait below is the seam.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use mvm_core::crypto::keystore;
use mvm_core::crypto::snapshot_encryption;
use mvm_core::crypto::snapshot_hmac::{
    EpochStore, IntegritySidecar, MEM_FILENAME, SIDECAR_FILENAME, SnapshotFiles, VMSTATE_FILENAME,
    VerifyError, files_in, load_or_init_key, seal, verify,
};

use secrecy::ExposeSecret;

/// Tenant id used for snapshot encryption in mvm's single-host
/// posture. Mirrors the "one guest = one workload" framing —
/// every snapshot belongs to the local tenant. mvmd's multi-tenant
/// path uses a different code path that takes a `tenant_id`
/// explicitly.
pub const SNAPSHOT_TENANT_ID: &str = "local";

/// Env var that lets operators opt out of the "encrypted snapshot
/// when a key is configured" guard on resume — for the one-time
/// v1 → v2 migration after upgrading mvmctl. Defaults to refusing
/// unencrypted snapshots when a tenant DEK is configured.
pub const ALLOW_UNENCRYPTED_ENV: &str = "MVM_ALLOW_UNENCRYPTED_SNAPSHOT";

/// Explicit env-var override for the local tenant's snapshot DEK.
/// This must win over OS-keyring auto-detection so dev/CI and
/// emergency-recovery workflows can pin the key deterministically.
pub const SNAPSHOT_TENANT_KEY_ENV: &str = "MVM_TENANT_KEY_LOCAL";

/// Filename of the persistent epoch counter inside an
/// instance-snapshot dir. Hidden by default (`.epoch`) so a casual
/// `ls` doesn't show it next to the bin files.
pub const EPOCH_FILENAME: &str = ".epoch";

/// Returns the `~/.mvm/instances/<vm-name>/` directory. Doesn't
/// create it — callers that need to write into it use
/// `prepare_instance_snapshot_dir` instead.
pub fn instance_dir(vm_name: &str) -> PathBuf {
    mvm_core::config::instance_dir(vm_name)
}

/// Returns `~/.mvm/instances/<vm-name>/snapshot/`.
pub fn snapshot_dir(vm_name: &str) -> PathBuf {
    mvm_core::config::instance_snapshot_dir(vm_name)
}

/// Create `<instance>/snapshot/` with mode 0700 if it doesn't
/// already exist. Returns the path. Idempotent.
pub fn prepare_instance_snapshot_dir(vm_name: &str) -> Result<PathBuf> {
    let dir = snapshot_dir(vm_name);
    ensure_dir_with_mode(&dir, 0o700)?;
    Ok(dir)
}

/// Convenience: build the canonical `SnapshotFiles` for a VM.
pub fn files_for(vm_name: &str) -> SnapshotFiles {
    files_in(&snapshot_dir(vm_name))
}

/// Pause + seal one VM's snapshot. Returns the sealed sidecar so
/// callers can record what they sealed.
///
/// 1. Ensure the snapshot dir exists (mode 0700).
/// 2. Ask the IO impl to write `vmstate.bin` + `mem.bin`.
/// 3. Tighten file modes to 0600.
/// 4. Bump the per-instance epoch counter.
/// 5. Seal the HMAC envelope with the new epoch.
pub fn pause_and_seal<IO: SnapshotIO + ?Sized>(vm_name: &str, io: &IO) -> Result<IntegritySidecar> {
    let dir = prepare_instance_snapshot_dir(vm_name)?;
    io.create_snapshot(&dir)
        .with_context(|| format!("Firecracker create_snapshot({})", dir.display()))?;
    tighten_snapshot_file_modes(&dir)?;

    // Encrypt vmstate + mem in place under the tenant DEK if one is
    // available. The HMAC envelope below then covers the ciphertext,
    // so any tamper attempt fails the seal check before AEAD
    // decryption is even attempted on resume.
    encrypt_artifacts_if_keyed(&dir)
        .with_context(|| format!("encrypting snapshot artifacts at {}", dir.display()))?;

    let key_path =
        mvm_core::crypto::snapshot_hmac::default_key_path(Path::new(&mvm_core::config::mvm_home()));
    let key = load_or_init_key(&key_path)
        .with_context(|| format!("loading HMAC key {}", key_path.display()))?;
    let files = files_in(&dir);
    let mvmctl_version = env!("CARGO_PKG_VERSION");

    let store = EpochStore::new(dir.join(EPOCH_FILENAME));
    let next_epoch = store
        .next()
        .with_context(|| format!("advancing epoch counter for {}", dir.display()))?;

    let sidecar = seal(
        &dir,
        &files,
        next_epoch,
        mvmctl_version,
        key.expose_secret(),
    )
    .with_context(|| format!("sealing instance snapshot at {}", dir.display()))?;
    Ok(sidecar)
}

/// Verify + load one VM's own instance snapshot (`~/.mvm/instances/<vm-name>/snapshot/`).
/// Thin wrapper around [`verify_and_resume_from_dir`] for the common case
/// where the sealed envelope lives at the canonical per-VM path; the fork and
/// template-restore paths hold their sealed envelope elsewhere and call
/// [`verify_and_resume_from_dir`] directly.
///
/// Returns the verified sidecar so the caller can audit it before
/// resuming Firecracker.
pub fn verify_and_resume<IO: SnapshotIO + ?Sized>(
    vm_name: &str,
    io: &IO,
) -> Result<IntegritySidecar> {
    let dir = snapshot_dir(vm_name);
    verify_and_resume_from_dir(&dir, io)
}

/// Verify + load a sealed snapshot at a caller-supplied `dir`, then run the
/// device-model guard before resuming vCPUs.
///
/// Honours `MVM_ALLOW_STALE_SNAPSHOT=1` for both the version-mismatch and the
/// epoch-rollback branches; refuses both by default.
///
/// Ordering is the security property this function exists to enforce:
/// verify the HMAC envelope → decrypt → load the snapshot PAUSED → read the
/// restored device model → refuse (and tear down) on any NIC → only then
/// resume vCPUs. A NIC-carrying snapshot must never execute a single guest
/// instruction, so `resume` is reachable only past the guard.
///
/// Returns the verified sidecar so the caller can audit it before
/// resuming Firecracker.
pub fn verify_and_resume_from_dir<IO: SnapshotIO + ?Sized>(
    dir: &Path,
    io: &IO,
) -> Result<IntegritySidecar> {
    if !dir.exists() {
        bail!(
            "no instance snapshot directory at {} — pause the VM first",
            dir.display()
        );
    }
    let key_path =
        mvm_core::crypto::snapshot_hmac::default_key_path(Path::new(&mvm_core::config::mvm_home()));
    let key = load_or_init_key(&key_path)
        .with_context(|| format!("loading HMAC key {}", key_path.display()))?;
    let files = files_in(dir);
    let mvmctl_version = env!("CARGO_PKG_VERSION");
    let allow_stale = std::env::var("MVM_ALLOW_STALE_SNAPSHOT").as_deref() == Ok("1");

    let store = EpochStore::new(dir.join(EPOCH_FILENAME));
    let min_epoch = store.load();

    let sidecar = match verify(
        dir,
        &files,
        min_epoch,
        mvmctl_version,
        key.expose_secret(),
        allow_stale,
    ) {
        Ok(s) => s,
        Err(e) => return Err(map_verify_error(e, dir)),
    };

    // HMAC verify passed → the artifacts on disk are the bytes that
    // were sealed. If they're AES-GCM-encrypted (MVSE magic),
    // decrypt them in place before handing to Firecracker.
    decrypt_artifacts_if_encrypted(dir)
        .with_context(|| format!("decrypting snapshot artifacts at {}", dir.display()))?;

    guarded_load_resume(io, dir)?;
    Ok(sidecar)
}

/// Load a sealed snapshot at `dir` into a fresh VMM, then run the no-NIC
/// device-model guard strictly between load and resume — resuming vCPUs only
/// if the guard passes.
///
/// Factored out of [`verify_and_resume_from_dir`] so a caller whose content
/// integrity is already established by a different mechanism (the fork
/// restore path verifies a checkpoint's content-address and audit-chain
/// lineage upstream, not the instance-snapshot HMAC envelope) can reuse the
/// load → guard → resume ordering without layering a second, wrong integrity
/// check on top. `verify_and_resume_from_dir` is the only caller that also
/// runs the HMAC verify + decrypt step first; this function does neither —
/// callers are responsible for establishing their own content integrity
/// before calling it.
///
/// Fail closed: never resume a NIC-carrying restore. Best-effort tear down
/// the paused VMM on refusal so it does not linger — the caller's `dir` stays
/// sealed on disk, so a retry (after e.g. re-sealing a clean snapshot) is
/// still possible.
// The snapshot seam (SnapshotIO, the device-model guard, and the guarded
// load paths) lives in mvm-vmm so concrete backends can implement it without
// depending on this crate. Re-exported here at its original paths.
// The Firecracker SnapshotIO moved to the backend that implements it;
// re-exported here so callers keep resolving it at its original path.
pub use mvm_backends::fc::io::FirecrackerIO;
pub use mvm_vmm::snapshot::{
    CannedIO, SnapshotIO, assert_vsock_only_device_model, guarded_fork_load_paused,
    guarded_fork_load_resume, guarded_load_resume,
};

// Post-restore signal and primed-barrier primitives live in mvm-vmm so the
// VmmDriver seam can use them without a runtime dependency cycle.
pub use mvm_vmm::post_restore::*;

/// Encrypt `vmstate.bin` and `mem.bin` in place under the tenant
/// DEK, when one is available. No-op when no DEK is configured —
/// the resulting snapshot stays unencrypted, HMAC-only.
fn encrypt_artifacts_if_keyed(dir: &Path) -> Result<()> {
    let provider = snapshot_key_provider();
    let Ok(dek) = provider.get_data_key(SNAPSHOT_TENANT_ID) else {
        // No tenant DEK configured — leave artifacts unencrypted.
        // Operators who want at-rest encryption configure a key
        // via `mvmctl secret put` or the MVM_TENANT_KEY_LOCAL env
        // var.
        return Ok(());
    };
    let key_bytes = dek.expose_secret();
    if key_bytes.len() != snapshot_encryption::KEY_SIZE {
        bail!(
            "tenant DEK is {} bytes, snapshot encryption requires {}",
            key_bytes.len(),
            snapshot_encryption::KEY_SIZE
        );
    }
    for name in [VMSTATE_FILENAME, MEM_FILENAME] {
        let p = dir.join(name);
        if !p.exists() {
            continue;
        }
        // Skip files that already begin with the MVSE magic — this
        // makes pause_and_seal idempotent on retry after a crash
        // that successfully encrypted but failed before sealing.
        if snapshot_encryption::probe(&p)?.is_some() {
            continue;
        }
        snapshot_encryption::encrypt_file_in_place(&p, key_bytes)
            .with_context(|| format!("encrypting {}", p.display()))?;
    }
    Ok(())
}

/// Decrypt `vmstate.bin` and `mem.bin` in place when they carry the
/// MVSE magic. Refuses to fall through silently when a DEK *is*
/// configured but the artifacts are unencrypted (downgrade attack
/// or v1-shape leftover); set `MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1`
/// to bypass during the one-time v1 → v2 migration.
fn decrypt_artifacts_if_encrypted(dir: &Path) -> Result<()> {
    let provider = snapshot_key_provider();
    let dek_opt = provider.get_data_key(SNAPSHOT_TENANT_ID).ok();

    for name in [VMSTATE_FILENAME, MEM_FILENAME] {
        let p = dir.join(name);
        if !p.exists() {
            continue;
        }
        let is_encrypted = snapshot_encryption::probe(&p)?.is_some();
        match (is_encrypted, &dek_opt) {
            (true, Some(dek)) => {
                snapshot_encryption::decrypt_file_in_place(&p, dek.expose_secret())
                    .with_context(|| format!("decrypting {}", p.display()))?;
            }
            (true, None) => {
                bail!(
                    "{} is AES-GCM encrypted but no tenant DEK is configured — \
                     run `mvmctl secret put` to provision a key, then `mvmctl resume`",
                    p.display()
                );
            }
            (false, Some(_)) => {
                if std::env::var(ALLOW_UNENCRYPTED_ENV).as_deref() != Ok("1") {
                    bail!(
                        "{} is not encrypted but a tenant DEK is configured — \
                         refusing to resume (set {ALLOW_UNENCRYPTED_ENV}=1 to \
                         force during v1 → v2 migration)",
                        p.display()
                    );
                }
                // No-op — operator opted in to the migration escape.
            }
            (false, None) => {
                // Unencrypted artifact, no DEK configured. Resume normally.
            }
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn snapshot_key_provider() -> Box<dyn keystore::KeyProvider> {
    keystore::default_provider()
}

#[cfg(test)]
fn snapshot_key_provider() -> Box<dyn keystore::KeyProvider> {
    Box::new(keystore::EnvKeyProvider)
}

/// Drop the on-disk snapshot files + sidecar + epoch counter for
/// one VM. The instance directory itself stays so other state
/// (e.g. forwarded-port records) isn't disturbed. Returns `true` if
/// anything was removed.
pub fn delete_instance_snapshot(vm_name: &str) -> Result<bool> {
    let dir = snapshot_dir(vm_name);
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    Ok(true)
}

/// One row of the snapshot listing. Cheap value type so callers
/// can render it however they want (table, JSON, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSnapshotEntry {
    pub vm_name: String,
    pub vmstate_size_bytes: u64,
    pub mem_size_bytes: u64,
    /// `Some(s)` when an integrity sidecar exists and parses;
    /// `None` when the snapshot is unsealed (legacy or
    /// in-progress).
    pub sidecar: Option<IntegritySidecar>,
}

/// Walk `~/.mvm/instances/*/snapshot/` and report every snapshot
/// dir we find. Errors on a single entry don't fail the whole
/// listing — a VM with a broken sidecar still surfaces with
/// `sidecar = None` so the operator can investigate.
pub fn list_instance_snapshots() -> Result<Vec<InstanceSnapshotEntry>> {
    let root = PathBuf::from(mvm_core::config::mvm_home()).join("instances");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&root).with_context(|| format!("read_dir {}", root.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let vm_name = entry.file_name().to_string_lossy().into_owned();
        let snap = entry.path().join("snapshot");
        if !snap.is_dir() {
            continue;
        }
        let vmstate_size = std::fs::metadata(snap.join(VMSTATE_FILENAME))
            .map(|m| m.len())
            .unwrap_or(0);
        let mem_size = std::fs::metadata(snap.join(MEM_FILENAME))
            .map(|m| m.len())
            .unwrap_or(0);
        let sidecar = std::fs::read(snap.join(SIDECAR_FILENAME))
            .ok()
            .and_then(|raw| serde_json::from_slice::<IntegritySidecar>(&raw).ok());
        out.push(InstanceSnapshotEntry {
            vm_name,
            vmstate_size_bytes: vmstate_size,
            mem_size_bytes: mem_size,
            sidecar,
        });
    }
    out.sort_by(|a, b| a.vm_name.cmp(&b.vm_name));
    Ok(out)
}

// ============================================================================
// Helpers
// ============================================================================

fn ensure_dir_with_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("create_dir_all {}", path.display()))?;
    }
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod {:o} {}", mode, path.display()))?;
    Ok(())
}

fn tighten_snapshot_file_modes(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    for name in [VMSTATE_FILENAME, MEM_FILENAME] {
        let p = dir.join(name);
        if !p.exists() {
            continue;
        }
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&p, perms)
            .with_context(|| format!("chmod 0600 {}", p.display()))?;
    }
    Ok(())
}

fn map_verify_error(err: VerifyError, dir: &Path) -> anyhow::Error {
    match err {
        VerifyError::SidecarMissing { .. } => anyhow::anyhow!(
            "instance snapshot at {} has no integrity sidecar — refusing to resume \
             (a fresh `mvmctl pause` would seal one)",
            dir.display()
        ),
        VerifyError::EpochRollback { got, expected } => anyhow::anyhow!(
            "instance snapshot at {} appears to be a replayed older state \
             (sealed epoch {got}, persisted high-water {expected}). Set \
             MVM_ALLOW_STALE_SNAPSHOT=1 to override.",
            dir.display()
        ),
        VerifyError::TagMismatch => anyhow::anyhow!(
            "instance snapshot at {} failed HMAC verification — files have been \
             tampered or the host key changed. Refusing to resume.",
            dir.display()
        ),
        other => anyhow::anyhow!(
            "instance snapshot at {} failed verification: {other}",
            dir.display()
        ),
    }
}

// ============================================================================
// Test-only IO impls
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_backends::fc::io::FirecrackerIO;
    use mvm_core::util::test_env::TestEnv;
    use mvm_vmm::host::shell::{run_in_vm, shell_quote};
    use std::os::unix::fs::PermissionsExt;

    /// Run a closure with `MVM_HOME` overridden to a tempdir
    /// so each test gets an isolated `~/.mvm/instances/...` tree.
    /// The override is restored on drop. Tests that touch the data
    /// dir take this guard; serialisation across tests is via
    /// `DATA_DIR_LOCK` since `set_var` is process-global.
    struct DataDirGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        env: TestEnv,
        _tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let lock = super::super::DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let mut env = TestEnv::new();
            env.set("MVM_HOME", tmp.path());
            DataDirGuard {
                _guard: lock,
                env,
                _tmp: tmp,
            }
        }
    }

    fn canned() -> CannedIO {
        CannedIO::new(b"vmstate-bytes".to_vec(), b"memory-image".to_vec())
    }

    #[test]
    fn snapshot_dir_lives_under_data_dir() {
        let _g = DataDirGuard::new();
        let dir = snapshot_dir("vm-1");
        assert!(dir.starts_with(mvm_core::config::mvm_home()));
        assert!(dir.ends_with("instances/vm-1/snapshot"));
    }

    #[test]
    fn pause_and_seal_creates_files_with_mode_0600() {
        let _g = DataDirGuard::new();
        let sidecar = pause_and_seal("vm-1", &canned()).unwrap();
        assert_eq!(sidecar.epoch, 1);
        let dir = snapshot_dir("vm-1");
        for name in [VMSTATE_FILENAME, MEM_FILENAME, SIDECAR_FILENAME] {
            let p = dir.join(name);
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{name} should be mode 0600");
        }
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "snapshot dir should be mode 0700");
    }

    #[test]
    fn pause_and_seal_advances_epoch() {
        let _g = DataDirGuard::new();
        let s1 = pause_and_seal("vm-1", &canned()).unwrap();
        let s2 = pause_and_seal("vm-1", &canned()).unwrap();
        let s3 = pause_and_seal("vm-1", &canned()).unwrap();
        assert_eq!(s1.epoch, 1);
        assert_eq!(s2.epoch, 2);
        assert_eq!(s3.epoch, 3);
    }

    #[test]
    fn verify_and_resume_accepts_freshly_sealed_snapshot() {
        let _g = DataDirGuard::new();
        let sealed = pause_and_seal("vm-1", &canned()).unwrap();
        let verified = verify_and_resume("vm-1", &canned()).unwrap();
        assert_eq!(verified, sealed);
    }

    #[test]
    fn verify_and_resume_rejects_tampered_mem() {
        let _g = DataDirGuard::new();
        pause_and_seal("vm-1", &canned()).unwrap();
        let mem_path = snapshot_dir("vm-1").join(MEM_FILENAME);
        let mut bytes = std::fs::read(&mem_path).unwrap();
        bytes[0] ^= 0xff;
        std::fs::write(&mem_path, &bytes).unwrap();
        let err = verify_and_resume("vm-1", &canned()).unwrap_err();
        assert!(
            err.to_string().contains("HMAC verification"),
            "expected HMAC mismatch, got {err}"
        );
    }

    #[test]
    fn verify_and_resume_rejects_replayed_older_envelope() {
        // Seal at epoch 1, copy the bytes aside, seal again at
        // epoch 2 (overwriting), then restore the epoch-1 files +
        // sidecar to disk and re-verify. The persistent epoch
        // counter still reads 2, so the verifier must refuse.
        let _g = DataDirGuard::new();
        let dir = snapshot_dir("vm-1");
        let _ = pause_and_seal("vm-1", &canned()).unwrap();
        let v1_vmstate = std::fs::read(dir.join(VMSTATE_FILENAME)).unwrap();
        let v1_mem = std::fs::read(dir.join(MEM_FILENAME)).unwrap();
        let v1_sidecar = std::fs::read(dir.join(SIDECAR_FILENAME)).unwrap();

        let _ = pause_and_seal("vm-1", &canned()).unwrap();
        // Roll the visible files back to the epoch-1 state, but
        // leave the persisted epoch counter at 2.
        std::fs::write(dir.join(VMSTATE_FILENAME), &v1_vmstate).unwrap();
        std::fs::write(dir.join(MEM_FILENAME), &v1_mem).unwrap();
        std::fs::write(dir.join(SIDECAR_FILENAME), &v1_sidecar).unwrap();

        let err = verify_and_resume("vm-1", &canned()).unwrap_err();
        assert!(
            err.to_string().contains("replayed"),
            "expected replay rejection, got {err}"
        );
    }

    #[test]
    fn verify_and_resume_errors_when_snapshot_dir_missing() {
        let _g = DataDirGuard::new();
        let err = verify_and_resume("nope", &canned()).unwrap_err();
        assert!(err.to_string().contains("no instance snapshot directory"));
    }

    // ──────────────────────────────────────────────────────────────
    // Device-model guard ordering (load_paused → guard → resume)
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn verify_and_resume_refuses_nic_on_restore() {
        let _g = DataDirGuard::new();
        pause_and_seal("vm-nic", &canned()).unwrap();
        let spy =
            CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec()).with_network_interfaces(1);
        let err = verify_and_resume("vm-nic", &spy).unwrap_err();
        assert!(err.to_string().contains("device-model guard"), "got: {err}");
        let calls = spy.calls();
        assert!(
            calls.contains(&"teardown_paused"),
            "a refused restore must tear down the paused VMM: {calls:?}"
        );
        assert!(
            !calls.contains(&"resume"),
            "resume must never run when the guard refuses: {calls:?}"
        );
    }

    #[test]
    fn verify_and_resume_resumes_vsock_only_restore() {
        let _g = DataDirGuard::new();
        pause_and_seal("vm-clean", &canned()).unwrap();
        let spy = CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec());
        verify_and_resume("vm-clean", &spy).expect("a no-NIC restore must resume");
        let calls = spy.calls();
        assert!(
            calls.contains(&"resume"),
            "a clean restore must resume: {calls:?}"
        );
        assert!(
            !calls.contains(&"teardown_paused"),
            "a clean restore must not tear down: {calls:?}"
        );
    }

    #[test]
    fn load_guard_resume_ordering() {
        let _g = DataDirGuard::new();
        pause_and_seal("vm-order", &canned()).unwrap();
        let spy = CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec());
        verify_and_resume("vm-order", &spy).unwrap();
        assert_eq!(
            spy.calls(),
            vec!["load_paused", "restored_device_model", "resume"],
            "the guard must run strictly between load and resume"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // `guarded_load_resume` — the fork-restore path's witness. Fork restore
    // calls this directly (no HMAC verify — its integrity is established
    // upstream by the checkpoint lineage's content-address + audit-chain
    // check), so these exercise the guard reached via that bare entry point
    // rather than only through `verify_and_resume`.
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn fork_restore_refuses_nic() {
        let spy =
            CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec()).with_network_interfaces(1);
        let dir = tempfile::tempdir().unwrap();
        let err = guarded_load_resume(&spy, dir.path()).unwrap_err();
        assert!(err.to_string().contains("device-model guard"), "got: {err}");
        let calls = spy.calls();
        assert!(
            calls.contains(&"teardown_paused"),
            "a refused restore must tear down the paused VMM: {calls:?}"
        );
        assert!(
            !calls.contains(&"resume"),
            "resume must never run when the guard refuses: {calls:?}"
        );
    }

    #[test]
    fn guarded_load_resume_resumes_when_vsock_only() {
        let spy = CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec());
        let dir = tempfile::tempdir().unwrap();
        guarded_load_resume(&spy, dir.path()).expect("a no-NIC restore must resume");
        let calls = spy.calls();
        assert_eq!(
            calls,
            vec!["load_paused", "restored_device_model", "resume"],
            "load, guard, then resume — in order"
        );
    }

    /// A fork inherits its parent's device model, so it gets the same guard.
    /// The fork load is the one that preserves the child's already-remapped
    /// vsock path, which is why it is a distinct call from `load_paused`.
    #[test]
    fn guarded_fork_load_resume_resumes_when_vsock_only() {
        let spy = CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec());
        let dir = tempfile::tempdir().unwrap();
        guarded_fork_load_resume(&spy, dir.path()).expect("a no-NIC fork must resume");
        let calls = spy.calls();
        assert_eq!(
            calls,
            vec!["load_fork_paused", "restored_device_model", "resume"],
            "fork load, guard, then resume — in order"
        );
    }

    #[test]
    fn guarded_fork_load_paused_leaves_clean_child_paused() {
        let spy = CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec());
        let dir = tempfile::tempdir().unwrap();
        guarded_fork_load_paused(&spy, dir.path()).expect("a no-NIC fork must stay paused");
        assert_eq!(
            spy.calls(),
            vec!["load_fork_paused", "restored_device_model"],
            "preload must guard the child without resuming it"
        );
    }

    /// The regression this guards: a fork that loads paused and is never
    /// checked would either sit paused forever or, once resumed, reach
    /// userspace carrying an unaudited NIC.
    #[test]
    fn guarded_fork_load_resume_refuses_nic_on_restore() {
        let spy =
            CannedIO::new(b"spy-vmstate".to_vec(), b"spy-mem".to_vec()).with_network_interfaces(1);
        let dir = tempfile::tempdir().unwrap();
        let err = guarded_fork_load_resume(&spy, dir.path()).unwrap_err();
        assert!(err.to_string().contains("device-model guard"), "got: {err}");
        let calls = spy.calls();
        assert!(
            calls.contains(&"teardown_paused"),
            "a refused fork must tear down the paused VMM: {calls:?}"
        );
        assert!(
            !calls.contains(&"resume"),
            "resume must never run when the guard refuses a fork: {calls:?}"
        );
    }

    #[test]
    fn delete_instance_snapshot_removes_files() {
        let _g = DataDirGuard::new();
        pause_and_seal("vm-1", &canned()).unwrap();
        assert!(delete_instance_snapshot("vm-1").unwrap());
        assert!(!snapshot_dir("vm-1").exists());
        // Idempotent — second delete returns false.
        assert!(!delete_instance_snapshot("vm-1").unwrap());
    }

    #[test]
    fn list_instance_snapshots_returns_each_sealed_vm() {
        let _g = DataDirGuard::new();
        pause_and_seal("alpha", &canned()).unwrap();
        pause_and_seal("beta", &canned()).unwrap();
        let entries = list_instance_snapshots().unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.vm_name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta"]);
        for entry in &entries {
            let sidecar = entry.sidecar.as_ref().expect("sealed → sidecar parses");
            assert_eq!(sidecar.epoch, 1);
            assert!(entry.vmstate_size_bytes > 0);
            assert!(entry.mem_size_bytes > 0);
        }
    }

    #[test]
    fn list_handles_unsealed_snapshot_gracefully() {
        let _g = DataDirGuard::new();
        // Manually create an unsealed snapshot (vmstate + mem but
        // no integrity.json) — the listing should report it with
        // `sidecar = None` rather than failing.
        let dir = prepare_instance_snapshot_dir("ghost").unwrap();
        std::fs::write(dir.join(VMSTATE_FILENAME), b"vmstate").unwrap();
        std::fs::write(dir.join(MEM_FILENAME), b"mem").unwrap();
        let entries = list_instance_snapshots().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vm_name, "ghost");
        assert!(entries[0].sidecar.is_none());
    }

    #[test]
    fn list_returns_empty_when_root_missing() {
        let _g = DataDirGuard::new();
        assert!(list_instance_snapshots().unwrap().is_empty());
    }

    // ──────────────────────────────────────────────────────────────
    // Encryption integration
    // ──────────────────────────────────────────────────────────────

    /// 32-byte tenant DEK, hex-encoded, suitable for the env-var
    /// provider via `MVM_TENANT_KEY_LOCAL`.
    const TEST_DEK_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn pause_and_seal_encrypts_vmstate_and_mem_when_key_is_configured() {
        let mut g = DataDirGuard::new();
        g.env.set("MVM_TENANT_KEY_LOCAL", TEST_DEK_HEX);
        let _s = pause_and_seal("vm-encrypt", &canned()).unwrap();
        let dir = snapshot_dir("vm-encrypt");
        // Both artifact files must now begin with the MVSE magic.
        for name in [VMSTATE_FILENAME, MEM_FILENAME] {
            let header = mvm_core::crypto::snapshot_encryption::probe(&dir.join(name))
                .unwrap()
                .unwrap_or_else(|| panic!("{name} should be encrypted (MVSE magic missing)"));
            assert_eq!(
                header.version,
                mvm_core::crypto::snapshot_encryption::SCHEMA_VERSION
            );
        }
        // And the on-disk vmstate must NOT contain the plaintext
        // sentinel CannedIO writes (`b"vmstate-bytes"`) — confirms
        // the file is genuinely encrypted, not just magic-tagged.
        let ct = std::fs::read(dir.join(VMSTATE_FILENAME)).unwrap();
        assert!(
            !ct.windows(13).any(|w| w == b"vmstate-bytes"),
            "plaintext leaked into ciphertext"
        );
    }

    #[test]
    fn pause_and_seal_leaves_artifacts_unencrypted_when_no_key() {
        let mut g = DataDirGuard::new();
        // Defensive: clear the env var in case a parallel test left
        // it set. The DataDirGuard's lock means we're alone for the
        // duration of this test.
        g.env.remove("MVM_TENANT_KEY_LOCAL");
        let _s = pause_and_seal("vm-plain", &canned()).unwrap();
        let dir = snapshot_dir("vm-plain");
        // No MVSE magic — vmstate is raw bytes from CannedIO.
        assert!(
            mvm_core::crypto::snapshot_encryption::probe(&dir.join(VMSTATE_FILENAME))
                .unwrap()
                .is_none()
        );
        let raw = std::fs::read(dir.join(VMSTATE_FILENAME)).unwrap();
        assert_eq!(raw, b"vmstate-bytes");
    }

    #[test]
    fn verify_and_resume_round_trips_encrypted_snapshot() {
        let mut g = DataDirGuard::new();
        g.env.set("MVM_TENANT_KEY_LOCAL", TEST_DEK_HEX);
        let sealed = pause_and_seal("vm-rt", &canned()).unwrap();
        let verified = verify_and_resume("vm-rt", &canned()).unwrap();
        assert_eq!(verified, sealed);
        // After resume, the artifacts should be decrypted in place
        // (Firecracker reads plaintext bytes).
        let dir = snapshot_dir("vm-rt");
        let pt = std::fs::read(dir.join(VMSTATE_FILENAME)).unwrap();
        assert_eq!(pt, b"vmstate-bytes");
    }

    #[test]
    fn verify_and_resume_rejects_encrypted_snapshot_with_wrong_key() {
        let mut g = DataDirGuard::new();
        g.env.set("MVM_TENANT_KEY_LOCAL", TEST_DEK_HEX);
        pause_and_seal("vm-wk", &canned()).unwrap();
        // Swap to a different DEK and try to resume. HMAC verify
        // passes (it's keyed on the host HMAC key, not the DEK), so
        // we fail at the AEAD step.
        let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        g.env.set("MVM_TENANT_KEY_LOCAL", wrong);
        let err = verify_and_resume("vm-wk", &canned()).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("decrypting") || s.contains("authentication"),
            "want AEAD failure context, got: {s}"
        );
    }

    #[test]
    fn verify_and_resume_refuses_unencrypted_snapshot_when_key_configured() {
        let mut g = DataDirGuard::new();
        // First seal WITHOUT a key — unencrypted, v1-shape.
        g.env.remove("MVM_TENANT_KEY_LOCAL");
        pause_and_seal("vm-mix", &canned()).unwrap();

        // Now configure a key and try to resume. Refuse because the
        // snapshot was sealed before the DEK was
        // provisioned (downgrade vs v1 leftover indistinguishable
        // at this layer).
        g.env.set("MVM_TENANT_KEY_LOCAL", TEST_DEK_HEX);
        let err = verify_and_resume("vm-mix", &canned()).unwrap_err();
        let chained: String = err
            .chain()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            chained.contains("not encrypted") || chained.contains("DEK is configured"),
            "want unencrypted-with-key refusal, got: {chained}"
        );
    }

    #[test]
    fn verify_and_resume_v1_unencrypted_bypass_via_env() {
        // The one-time v1 → v2 migration escape: operator opts in
        // via MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1 to resume a legacy
        // unencrypted snapshot under a key-configured tenant.
        let mut g = DataDirGuard::new();
        g.env.remove("MVM_TENANT_KEY_LOCAL");
        pause_and_seal("vm-mig", &canned()).unwrap();

        g.env.set("MVM_TENANT_KEY_LOCAL", TEST_DEK_HEX);
        g.env.set(ALLOW_UNENCRYPTED_ENV, "1");
        let result = verify_and_resume("vm-mig", &canned());
        assert!(
            result.is_ok(),
            "migration escape should let unencrypted v1 snapshot resume; got {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_and_resume_refuses_encrypted_snapshot_when_key_missing() {
        let mut g = DataDirGuard::new();
        g.env.set("MVM_TENANT_KEY_LOCAL", TEST_DEK_HEX);
        pause_and_seal("vm-lost", &canned()).unwrap();
        // Operator lost the key. Resume must refuse rather than
        // silently produce gibberish.
        g.env.remove("MVM_TENANT_KEY_LOCAL");
        let err = verify_and_resume("vm-lost", &canned()).unwrap_err();
        let chained: String = err
            .chain()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            chained.contains("encrypted") && chained.contains("tenant DEK"),
            "want missing-DEK refusal, got: {chained}"
        );
    }

    // ──────────────────────────────────────────────────────────────
    // Live warm-restore timing harness
    //
    // Boots a real Firecracker VM against a real KVM host, snapshots it, and
    // times `guarded_load_resume` — the warm-restore path this module owns —
    // so the reported number measures the actual restore code instead of a
    // full CLI boot chase. A second test proves the guard refuses a
    // NIC-carrying restore end-to-end. Both are `#[ignore]`d and gated on
    // `MVM_LIVE_KERNEL`/`MVM_LIVE_ROOTFS` + `/dev/kvm`: unset or absent, the
    // test prints a skip note and returns — a clean no-op everywhere except a
    // KVM host with the env wired up (the controller runs these, not CI).
    // ──────────────────────────────────────────────────────────────

    /// Kernel + rootfs paths for the live warm-restore tests, read from
    /// `MVM_LIVE_KERNEL`/`MVM_LIVE_ROOTFS`.
    struct LiveImages {
        kernel: PathBuf,
        rootfs: PathBuf,
    }

    /// Env gate for the live warm-restore tests: both path env vars set AND
    /// `/dev/kvm` present. Prints a skip note and returns `None` otherwise, so
    /// an accidental `--ignored` run on a non-KVM host is a clean pass rather
    /// than a failure.
    fn live_images() -> Option<LiveImages> {
        let kernel = std::env::var("MVM_LIVE_KERNEL").ok();
        let rootfs = std::env::var("MVM_LIVE_ROOTFS").ok();
        if kernel.is_none() || rootfs.is_none() || !Path::new("/dev/kvm").exists() {
            eprintln!(
                "skip: live warm-restore test needs MVM_LIVE_KERNEL + MVM_LIVE_ROOTFS + \
                 /dev/kvm — not present here"
            );
            return None;
        }
        Some(LiveImages {
            kernel: PathBuf::from(kernel.expect("checked above")),
            rootfs: PathBuf::from(rootfs.expect("checked above")),
        })
    }

    /// Boot the SOURCE Firecracker VM the live warm-restore tests snapshot:
    /// the API sequence validated live (boot-source, drive, InstanceStart),
    /// with an optional NIC inserted before InstanceStart so
    /// `warm_restore_refuses_nic_live` can snapshot a genuinely NIC-carrying
    /// VM. Sleeps ~1s after InstanceStart for the instance to come up.
    ///
    /// Deliberately no vsock device: a restored VMM must re-bind a vsock
    /// device's recorded host-side UDS path, and remapping that path is the
    /// production fork-restore path's job (a mount-namespace remap), not
    /// this timing/guard harness's — the memory-load/resume cost this test
    /// measures doesn't depend on vsock being present.
    fn boot_live_source_vm(
        images: &LiveImages,
        src_dir: &Path,
        rootfs_copy: &Path,
        tap: Option<&str>,
    ) -> Result<()> {
        let src_sock = src_dir.join("fc.socket");
        crate::microvm::start_vm_firecracker(
            &src_dir.to_string_lossy(),
            &src_sock.to_string_lossy(),
        )?;
        let sock = src_sock.to_string_lossy();

        crate::microvm::api_put_socket(
            &sock,
            "/boot-source",
            &crate::microvm::boot_source_body(
                &images.kernel.to_string_lossy(),
                "console=ttyS0 pci=off",
                None,
            ),
        )?;
        crate::microvm::api_put_socket(
            &sock,
            "/drives/rootfs",
            &crate::microvm::drive_body("rootfs", &rootfs_copy.to_string_lossy(), true, false),
        )?;
        if let Some(tap) = tap {
            crate::microvm::api_put_socket(
                &sock,
                "/network-interfaces/eth0",
                &format!(r#"{{"iface_id":"eth0","host_dev_name":"{tap}"}}"#),
            )?;
        }
        crate::microvm::api_put_socket(&sock, "/actions", r#"{"action_type":"InstanceStart"}"#)?;
        std::thread::sleep(std::time::Duration::from_secs(1));
        Ok(())
    }

    /// Best-effort: kill the Firecracker process in `vm_dir` (by its
    /// `fc.pid` file) so a live test doesn't leave a paused VMM running.
    /// Mirrors `FirecrackerIO::teardown_paused`.
    fn kill_live_vm(vm_dir: &Path) {
        let pid_file = vm_dir.join("fc.pid");
        if !pid_file.exists() {
            return;
        }
        let pid_file_str = pid_file.to_string_lossy();
        let q_pid = shell_quote(&pid_file_str);
        let _ = run_in_vm(&format!(
            "sudo kill -9 \"$(cat {q_pid})\" 2>/dev/null; sleep 1"
        ));
    }

    #[test]
    #[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS"]
    fn warm_restore_latency_live() {
        let Some(images) = live_images() else {
            return;
        };

        let base = std::env::temp_dir().join(format!("mvm-warmtest-{}", std::process::id()));
        let src_dir = base.join("src");
        let dest_dir = base.join("dest");
        let snap_dir = base.join("snap");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::create_dir_all(&dest_dir).expect("create dest dir");
        std::fs::create_dir_all(&snap_dir).expect("create snap dir");

        let rootfs_copy = src_dir.join("rootfs.ext4");
        std::fs::copy(&images.rootfs, &rootfs_copy).expect("copy rootfs into writable src dir");

        boot_live_source_vm(&images, &src_dir, &rootfs_copy, None).expect("boot source FC VM");

        let src_sock = src_dir.join("fc.socket");
        FirecrackerIO::new(src_sock)
            .create_snapshot(&snap_dir)
            .expect("create_snapshot on source VM");
        assert!(
            snap_dir.join(VMSTATE_FILENAME).exists(),
            "vmstate.bin must exist after snapshot"
        );
        assert!(
            snap_dir.join(MEM_FILENAME).exists(),
            "mem.bin must exist after snapshot"
        );

        kill_live_vm(&src_dir);

        // Time the warm restore — this is the number this test exists to produce.
        let dest_io = FirecrackerIO::new(dest_dir.join("fc.socket"));
        let t = std::time::Instant::now();
        guarded_load_resume(&dest_io, &snap_dir).expect("warm restore must resume");
        let ms = t.elapsed().as_millis();
        println!("WARM_RESTORE_MS={ms}");

        kill_live_vm(&dest_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    #[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS/TAP"]
    fn warm_restore_refuses_nic_live() {
        let Some(images) = live_images() else {
            return;
        };
        let Ok(tap) = std::env::var("MVM_LIVE_TAP") else {
            eprintln!("skip: MVM_LIVE_TAP not set — NIC-refusal live test is a no-op here");
            return;
        };

        let base = std::env::temp_dir().join(format!("mvm-warmtest-nic-{}", std::process::id()));
        let src_dir = base.join("src");
        let dest_dir = base.join("dest");
        let snap_dir = base.join("snap");
        std::fs::create_dir_all(&src_dir).expect("create src dir");
        std::fs::create_dir_all(&dest_dir).expect("create dest dir");
        std::fs::create_dir_all(&snap_dir).expect("create snap dir");

        let rootfs_copy = src_dir.join("rootfs.ext4");
        std::fs::copy(&images.rootfs, &rootfs_copy).expect("copy rootfs into writable src dir");

        boot_live_source_vm(&images, &src_dir, &rootfs_copy, Some(&tap))
            .expect("boot NIC-carrying source FC VM");

        let src_sock = src_dir.join("fc.socket");
        FirecrackerIO::new(src_sock)
            .create_snapshot(&snap_dir)
            .expect("create_snapshot on NIC-carrying source VM");

        kill_live_vm(&src_dir);

        let dest_io = FirecrackerIO::new(dest_dir.join("fc.socket"));
        let err =
            guarded_load_resume(&dest_io, &snap_dir).expect_err("NIC restore must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("device-model guard") || msg.contains("network"),
            "expected a device-model-guard refusal, got: {msg}"
        );

        kill_live_vm(&dest_dir);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Live end-to-end measurement of the Firecracker warm-pool claim path
    /// captured through `FcDriver`. That rootfs is not available on this box,
    /// so this harness instead measures the load-bearing half of the claim:
    /// fresh Firecracker + snapshot load + resume from a pre-captured snapshot
    /// staged in a child directory. That is the same restore hot path the fork
    /// path uses once the checkpoint has been staged, and it is the number that
    /// bounds how fast a pooled claim can be.
    #[test]
    #[ignore = "live: needs /dev/kvm + MVM_LIVE_KERNEL/ROOTFS"]
    fn warm_pool_claim_latency_live() {
        let Some(images) = live_images() else {
            return;
        };
        let _guard = DataDirGuard::new();

        let pid = std::process::id();
        let parent_id = format!("mvm-warmclaim-parent-{pid}");
        let child_id = format!("mvm-warmclaim-child-{pid}");
        let parent_dir: std::path::PathBuf = crate::microvm::resolve_running_vm_dir(&parent_id)
            .expect("resolve parent VM dir")
            .into();
        let child_dir: std::path::PathBuf = crate::microvm::resolve_running_vm_dir(&child_id)
            .expect("resolve child VM dir")
            .into();
        std::fs::create_dir_all(&parent_dir).expect("create parent dir");
        std::fs::create_dir_all(&child_dir).expect("create child dir");

        // Boot the parent VM with the standard helper path (no agent wait).
        let parent_sock = parent_dir.join("fc.socket");
        crate::microvm::start_vm_firecracker(
            &parent_dir.to_string_lossy(),
            &parent_sock.to_string_lossy(),
        )
        .expect("start source FC VM");
        let sock = parent_sock.to_string_lossy();
        crate::microvm::api_put_socket(
            &sock,
            "/boot-source",
            &crate::microvm::boot_source_body(
                &images.kernel.to_string_lossy(),
                "console=ttyS0 pci=off",
                None,
            ),
        )
        .expect("configure boot source");
        crate::microvm::api_put_socket(
            &sock,
            "/drives/rootfs",
            &crate::microvm::drive_body("rootfs", &images.rootfs.to_string_lossy(), true, false),
        )
        .expect("configure rootfs drive");
        crate::microvm::api_put_socket(&sock, "/actions", r#"{"action_type":"InstanceStart"}"#)
            .expect("start source VM");
        std::thread::sleep(std::time::Duration::from_secs(1));

        // Capture a full snapshot into the parent dir (the pool's asset).
        let src_io = FirecrackerIO::new(parent_sock);
        src_io
            .create_snapshot(&parent_dir)
            .expect("create snapshot on source VM");
        assert!(
            parent_dir.join(VMSTATE_FILENAME).exists(),
            "vmstate.bin must exist after snapshot"
        );
        assert!(
            parent_dir.join(MEM_FILENAME).exists(),
            "mem.bin must exist after snapshot"
        );

        // Stage the snapshot into the child dir before stopping the parent,
        // because `stop_vm` removes the parent's VM directory.
        for name in [VMSTATE_FILENAME, MEM_FILENAME] {
            let src = parent_dir.join(name);
            std::fs::copy(&src, child_dir.join(name))
                .unwrap_or_else(|e| panic!("copy {} to child dir: {}", src.display(), e));
        }
        crate::microvm::stop_vm(&parent_id).ok();

        // Time the warm-pool claim: fresh Firecracker + snapshot load + resume.
        let io = FirecrackerIO::new(child_dir.join("fc.socket"));
        let t = std::time::Instant::now();
        guarded_load_resume(&io, &child_dir).expect("warm claim restore must resume");
        let claim_ms = t.elapsed().as_millis();
        println!("WARM_POOL_CLAIM_MS={claim_ms}");

        crate::microvm::stop_vm(&child_id).ok();
        let _ = std::fs::remove_dir_all(&child_dir);
    }
}
