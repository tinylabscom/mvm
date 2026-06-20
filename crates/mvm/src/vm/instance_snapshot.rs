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
    PathBuf::from(mvm_core::config::mvm_data_dir())
        .join("instances")
        .join(vm_name)
}

/// Returns `~/.mvm/instances/<vm-name>/snapshot/`.
pub fn snapshot_dir(vm_name: &str) -> PathBuf {
    instance_dir(vm_name).join("snapshot")
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

/// Trait the pause/resume orchestrator uses to talk to Firecracker.
/// Production wires `FirecrackerIO`; tests use `MemoryIO` which
/// just writes canned bytes into the snapshot files.
pub trait SnapshotIO {
    /// Quiesce the running VM, write `vmstate.bin` + `mem.bin` into
    /// `dir`, leave the VM in a paused-and-shutdown state.
    fn create_snapshot(&self, dir: &Path) -> Result<()>;

    /// Load the bytes at `<dir>/{vmstate,mem}.bin` into a fresh VM
    /// and resume vCPUs. The agent's `PostRestore` path takes care
    /// of vsock auth re-establishment after this returns.
    fn load_snapshot(&self, dir: &Path) -> Result<()>;
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

    let key_path = mvm_core::crypto::snapshot_hmac::default_key_path(Path::new(
        &mvm_core::config::mvm_data_dir(),
    ));
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

/// Verify + load one VM's snapshot. Honours
/// `MVM_ALLOW_STALE_SNAPSHOT=1` for both the version-mismatch and
/// the epoch-rollback branches; refuses both by default.
///
/// Returns the verified sidecar so the caller can audit it before
/// resuming Firecracker.
pub fn verify_and_resume<IO: SnapshotIO + ?Sized>(
    vm_name: &str,
    io: &IO,
) -> Result<IntegritySidecar> {
    let dir = snapshot_dir(vm_name);
    if !dir.exists() {
        bail!(
            "no instance snapshot directory at {} — pause the VM first",
            dir.display()
        );
    }
    let key_path = mvm_core::crypto::snapshot_hmac::default_key_path(Path::new(
        &mvm_core::config::mvm_data_dir(),
    ));
    let key = load_or_init_key(&key_path)
        .with_context(|| format!("loading HMAC key {}", key_path.display()))?;
    let files = files_in(&dir);
    let mvmctl_version = env!("CARGO_PKG_VERSION");
    let allow_stale = std::env::var("MVM_ALLOW_STALE_SNAPSHOT").as_deref() == Ok("1");

    let store = EpochStore::new(dir.join(EPOCH_FILENAME));
    let min_epoch = store.load();

    let sidecar = match verify(
        &dir,
        &files,
        min_epoch,
        mvmctl_version,
        key.expose_secret(),
        allow_stale,
    ) {
        Ok(s) => s,
        Err(e) => return Err(map_verify_error(e, &dir)),
    };

    // HMAC verify passed → the artifacts on disk are the bytes that
    // were sealed. If they're AES-GCM-encrypted (MVSE magic),
    // decrypt them in place before handing to Firecracker.
    decrypt_artifacts_if_encrypted(&dir)
        .with_context(|| format!("decrypting snapshot artifacts at {}", dir.display()))?;

    io.load_snapshot(&dir)
        .with_context(|| format!("Firecracker load_snapshot({})", dir.display()))?;
    Ok(sidecar)
}

// ============================================================================
// Post-restore signal — the host-side sender
// ============================================================================

/// Outcome of signaling `PostRestore` to a resumed guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostRestoreOutcome {
    /// The guest agent acknowledged the post-restore signal succeeded
    /// (its `PostRestoreAck.success`). `false` means the agent answered
    /// but reported a failure (e.g. its SIGUSR1 → PID 1 kill failed).
    pub acknowledged: bool,
    /// Free-form detail from the agent's ack (e.g. "post-restore signal
    /// sent to init"), surfaced to the operator.
    pub detail: Option<String>,
    /// `true` iff the guest reseeded its CSPRNG because the delivered
    /// generation token changed (a fresh clone of the snapshot). `false` for a
    /// plain wake or a no-rotation (zero-token) restore.
    pub reseeded: bool,
}

/// Sends the `PostRestore` signal to a resumed guest so it finishes coming
/// back: the agent maps `PostRestore` to `SIGUSR1 → PID 1`, which remounts
/// the config/secrets drives and restarts services. Backend-agnostic — the
/// production impl ([`VsockPostRestoreSignal`]) routes through the same
/// `vsock_transport::for_vm` dispatcher every other host→agent RPC uses;
/// tests inject a mock. This is the missing seam: the guest has handled
/// `GuestRequest::PostRestore` all along, but nothing on the host sent it
/// after a snapshot restore.
pub trait PostRestoreSignal {
    fn post_restore(&self, vm_name: &str) -> Result<PostRestoreOutcome>;
}

/// After a snapshot restore resumes vCPUs, signal the guest to finish
/// re-establishing itself. An *unacknowledged* signal is an error: the VM is
/// running at the hypervisor level but its drives may be unmounted, so the
/// resume is not actually complete — fail closed and let the operator retry
/// (`PostRestore` is safe to re-send; SIGUSR1 just re-runs the remount).
pub fn signal_post_restore<S: PostRestoreSignal + ?Sized>(
    vm_name: &str,
    signal: &S,
) -> Result<PostRestoreOutcome> {
    let outcome = signal
        .post_restore(vm_name)
        .with_context(|| format!("signaling post-restore to {vm_name}"))?;
    if !outcome.acknowledged {
        let detail = outcome
            .detail
            .as_deref()
            .map(|d| format!(": {d}"))
            .unwrap_or_default();
        bail!(
            "VM {vm_name} resumed but the guest did not acknowledge post-restore{detail} \
             — config/secrets drives may be unmounted; re-run `mvmctl resume`"
        );
    }
    Ok(outcome)
}

/// Production [`PostRestoreSignal`] — sends `GuestRequest::PostRestore` over
/// the backend-agnostic vsock transport (Firecracker / libkrun / Apple
/// Container, selected per VM by `vsock_transport::for_vm`). Not unit-tested
/// here (needs a live guest agent); the orchestration in
/// [`signal_post_restore`] is what the tests cover, mirroring the
/// `FirecrackerIO` / `CannedIO` split on [`SnapshotIO`].
pub struct VsockPostRestoreSignal {
    /// Host-minted generation token delivered to the guest on this resume so
    /// it rotates its VMGenID. Random per resume; an all-zero token requests
    /// no rotation (template restore).
    pub token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
}

impl PostRestoreSignal for VsockPostRestoreSignal {
    fn post_restore(&self, vm_name: &str) -> Result<PostRestoreOutcome> {
        use mvm_guest::vsock::{GUEST_AGENT_PORT, GuestRequest, GuestResponse, call_unary};
        let transport = crate::vsock_transport::for_vm(vm_name)
            .with_context(|| format!("resolving vsock transport for {vm_name}"))?;
        let mut stream = transport
            .connect(GUEST_AGENT_PORT)
            .with_context(|| format!("connecting to guest agent on {vm_name}"))?;
        // `call_unary` enforces PostRestore's response contract — the agent
        // `Error` / off-contract cases surface as a typed `RpcError`, so the
        // only `Ok` variant here is the contracted `PostRestoreAck`.
        match call_unary(
            &mut stream,
            &GuestRequest::PostRestore { token: self.token },
        )? {
            GuestResponse::PostRestoreAck {
                success,
                detail,
                reseeded,
            } => Ok(PostRestoreOutcome {
                acknowledged: success,
                detail,
                reseeded,
            }),
            other => bail!("unexpected response to PostRestore: {other:?}"),
        }
    }
}

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
    let root = PathBuf::from(mvm_core::config::mvm_data_dir()).join("instances");
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

/// `SnapshotIO` impl that just writes canned bytes. Used by the
/// unit tests below and by integration tests that want to exercise
/// the seal/verify flow without a live Firecracker.
pub struct CannedIO {
    pub vmstate_bytes: Vec<u8>,
    pub mem_bytes: Vec<u8>,
}

impl SnapshotIO for CannedIO {
    fn create_snapshot(&self, dir: &Path) -> Result<()> {
        std::fs::write(dir.join(VMSTATE_FILENAME), &self.vmstate_bytes)?;
        std::fs::write(dir.join(MEM_FILENAME), &self.mem_bytes)?;
        Ok(())
    }
    fn load_snapshot(&self, _dir: &Path) -> Result<()> {
        Ok(())
    }
}

/// `SnapshotIO` impl that talks to a live Firecracker over its
/// Unix socket. Pause shells out to `curl`'s `PATCH /vm` (state =
/// Paused) followed by `PUT /snapshot/create`; resume runs `PUT
/// /snapshot/load` then `PATCH /vm` (state = Resumed).
///
/// The socket path is taken from the running-VM lookup at call
/// time so a stale `mvmctl pause` against a vanished VM fails
/// cleanly with `socket does not exist` rather than mid-API.
pub struct FirecrackerIO {
    /// Absolute path to the live Firecracker control socket.
    pub socket_path: PathBuf,
}

impl FirecrackerIO {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    fn ensure_socket(&self) -> Result<()> {
        if !self.socket_path.exists() {
            bail!(
                "Firecracker socket {} does not exist — VM is not running",
                self.socket_path.display()
            );
        }
        Ok(())
    }
}

impl SnapshotIO for FirecrackerIO {
    fn create_snapshot(&self, dir: &Path) -> Result<()> {
        self.ensure_socket()?;
        // Pause vCPUs first (Firecracker requires a paused VM
        // before /snapshot/create). PATCH /vm.
        run_curl(&self.socket_path, "PATCH", "/vm", r#"{"state":"Paused"}"#)
            .with_context(|| "PATCH /vm Paused")?;

        let payload = format!(
            r#"{{"snapshot_type":"Full","snapshot_path":"{}/{}","mem_file_path":"{}/{}"}}"#,
            dir.display(),
            VMSTATE_FILENAME,
            dir.display(),
            MEM_FILENAME,
        );
        run_curl(&self.socket_path, "PUT", "/snapshot/create", &payload)
            .with_context(|| "PUT /snapshot/create")?;
        Ok(())
    }

    fn load_snapshot(&self, dir: &Path) -> Result<()> {
        self.ensure_socket()?;
        let payload = format!(
            r#"{{"snapshot_path":"{}/{}","mem_file_path":"{}/{}","resume_vm":true}}"#,
            dir.display(),
            VMSTATE_FILENAME,
            dir.display(),
            MEM_FILENAME,
        );
        run_curl(&self.socket_path, "PUT", "/snapshot/load", &payload)
            .with_context(|| "PUT /snapshot/load")?;
        Ok(())
    }
}

fn run_curl(socket: &Path, method: &str, endpoint: &str, body: &str) -> Result<()> {
    use std::process::Command;
    let url = format!("http://localhost{endpoint}");
    let out = Command::new("curl")
        .arg("--unix-socket")
        .arg(socket)
        .arg("-fsS")
        .arg("-X")
        .arg(method)
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(body)
        .arg(&url)
        .output()
        .with_context(|| format!("invoking curl for {method} {endpoint}"))?;
    if !out.status.success() {
        bail!(
            "{method} {endpoint} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Run a closure with `MVM_DATA_DIR` overridden to a tempdir
    /// so each test gets an isolated `~/.mvm/instances/...` tree.
    /// The override is restored on drop. Tests that touch the data
    /// dir take this guard; serialisation across tests is via
    /// `DATA_DIR_LOCK` since `set_var` is process-global.
    struct DataDirGuard {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<String>,
        _tmp: tempfile::TempDir,
    }

    impl DataDirGuard {
        fn new() -> Self {
            let lock = super::super::DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let tmp = tempfile::tempdir().expect("tempdir");
            let prev = std::env::var("MVM_DATA_DIR").ok();
            // SAFETY: the lock above serialises this set/restore
            // pair across the test binary; no other threads are
            // observing MVM_DATA_DIR while the guard is held.
            unsafe {
                std::env::set_var("MVM_DATA_DIR", tmp.path());
            }
            DataDirGuard {
                _guard: lock,
                prev,
                _tmp: tmp,
            }
        }
    }

    impl Drop for DataDirGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("MVM_DATA_DIR", v),
                    None => std::env::remove_var("MVM_DATA_DIR"),
                }
            }
        }
    }

    fn canned() -> CannedIO {
        CannedIO {
            vmstate_bytes: b"vmstate-bytes".to_vec(),
            mem_bytes: b"memory-image".to_vec(),
        }
    }

    #[test]
    fn snapshot_dir_lives_under_data_dir() {
        let _g = DataDirGuard::new();
        let dir = snapshot_dir("vm-1");
        assert!(dir.starts_with(mvm_core::config::mvm_data_dir()));
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

    /// RAII guard that pins `MVM_TENANT_KEY_LOCAL` for the lifetime
    /// of the test. Combine with `DataDirGuard` (which holds the
    /// data-dir lock) — both pieces must be in scope so the
    /// env-var mutation is serialised across the test binary.
    struct TenantKeyGuard {
        prev: Option<String>,
    }

    impl TenantKeyGuard {
        fn set(hex: &str) -> Self {
            let prev = std::env::var("MVM_TENANT_KEY_LOCAL").ok();
            unsafe {
                std::env::set_var("MVM_TENANT_KEY_LOCAL", hex);
            }
            Self { prev }
        }
    }

    impl Drop for TenantKeyGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("MVM_TENANT_KEY_LOCAL", v),
                    None => std::env::remove_var("MVM_TENANT_KEY_LOCAL"),
                }
            }
        }
    }

    #[test]
    fn pause_and_seal_encrypts_vmstate_and_mem_when_key_is_configured() {
        let _g = DataDirGuard::new();
        let _k = TenantKeyGuard::set(TEST_DEK_HEX);
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
        let _g = DataDirGuard::new();
        // Defensive: clear the env var in case a parallel test left
        // it set. The DataDirGuard's lock means we're alone for the
        // duration of this test.
        unsafe { std::env::remove_var("MVM_TENANT_KEY_LOCAL") };
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
        let _g = DataDirGuard::new();
        let _k = TenantKeyGuard::set(TEST_DEK_HEX);
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
        let _g = DataDirGuard::new();
        let _k = TenantKeyGuard::set(TEST_DEK_HEX);
        pause_and_seal("vm-wk", &canned()).unwrap();
        drop(_k);
        // Swap to a different DEK and try to resume. HMAC verify
        // passes (it's keyed on the host HMAC key, not the DEK), so
        // we fail at the AEAD step.
        let wrong = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let _k2 = TenantKeyGuard::set(wrong);
        let err = verify_and_resume("vm-wk", &canned()).unwrap_err();
        let s = err.to_string();
        assert!(
            s.contains("decrypting") || s.contains("authentication"),
            "want AEAD failure context, got: {s}"
        );
    }

    #[test]
    fn verify_and_resume_refuses_unencrypted_snapshot_when_key_configured() {
        let _g = DataDirGuard::new();
        // First seal WITHOUT a key — unencrypted, v1-shape.
        unsafe { std::env::remove_var("MVM_TENANT_KEY_LOCAL") };
        pause_and_seal("vm-mix", &canned()).unwrap();

        // Now configure a key and try to resume. Refuse because the
        // snapshot was sealed before the DEK was
        // provisioned (downgrade vs v1 leftover indistinguishable
        // at this layer).
        let _k = TenantKeyGuard::set(TEST_DEK_HEX);
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
        let _g = DataDirGuard::new();
        unsafe { std::env::remove_var("MVM_TENANT_KEY_LOCAL") };
        pause_and_seal("vm-mig", &canned()).unwrap();

        let _k = TenantKeyGuard::set(TEST_DEK_HEX);
        unsafe { std::env::set_var(ALLOW_UNENCRYPTED_ENV, "1") };
        let result = verify_and_resume("vm-mig", &canned());
        unsafe { std::env::remove_var(ALLOW_UNENCRYPTED_ENV) };
        assert!(
            result.is_ok(),
            "migration escape should let unencrypted v1 snapshot resume; got {:?}",
            result.err()
        );
    }

    #[test]
    fn verify_and_resume_refuses_encrypted_snapshot_when_key_missing() {
        let _g = DataDirGuard::new();
        let _k = TenantKeyGuard::set(TEST_DEK_HEX);
        pause_and_seal("vm-lost", &canned()).unwrap();
        drop(_k);
        // Operator lost the key. Resume must refuse rather than
        // silently produce gibberish.
        unsafe { std::env::remove_var("MVM_TENANT_KEY_LOCAL") };
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
    // Post-restore signal orchestration
    // ──────────────────────────────────────────────────────────────

    /// Mock `PostRestoreSignal` returning a canned result, so the
    /// `signal_post_restore` failure policy is testable without a guest.
    struct MockSignal(Result<PostRestoreOutcome>);

    impl PostRestoreSignal for MockSignal {
        fn post_restore(&self, _vm_name: &str) -> Result<PostRestoreOutcome> {
            match &self.0 {
                Ok(o) => Ok(o.clone()),
                Err(e) => bail!("{e}"),
            }
        }
    }

    #[test]
    fn signal_post_restore_ok_when_guest_acknowledges() {
        let signal = MockSignal(Ok(PostRestoreOutcome {
            acknowledged: true,
            detail: Some("post-restore signal sent to init".into()),
            reseeded: true,
        }));
        let outcome = signal_post_restore("vm-1", &signal).unwrap();
        assert!(outcome.acknowledged);
        assert!(outcome.reseeded, "a fresh-clone resume rotates the CSPRNG");
    }

    #[test]
    fn signal_post_restore_errors_when_guest_reports_failure() {
        // The agent answered but its SIGUSR1 failed → the VM is up but
        // degraded; resume must fail closed and name the detail.
        let signal = MockSignal(Ok(PostRestoreOutcome {
            acknowledged: false,
            detail: Some("kill failed: no such process".into()),
            reseeded: false,
        }));
        let err = signal_post_restore("vm-1", &signal).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("did not acknowledge"), "got: {msg}");
        assert!(msg.contains("kill failed"), "detail must surface: {msg}");
    }

    #[test]
    fn signal_post_restore_propagates_transport_error() {
        // A transport/connect failure surfaces as Err with context, not a
        // silent success that would leave the guest unsignaled.
        let signal = MockSignal(Err(anyhow::anyhow!("connection refused")));
        let err = signal_post_restore("vm-1", &signal).unwrap_err();
        let chained: String = err
            .chain()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(" | ");
        assert!(
            chained.contains("signaling post-restore"),
            "context: {chained}"
        );
        assert!(chained.contains("connection refused"), "cause: {chained}");
    }
}
