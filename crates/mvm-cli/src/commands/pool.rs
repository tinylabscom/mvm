//! Plan 118 WS-1 1b — warm-pool launch glue + the `mvmctl pool` command.
//!
//! Owns the bits that must live above the backend: the kernel-identity hash (part of the
//! base-compat key), the per-spawn binding nonce, and the host signer identity/key path
//! the standby re-verifies the attach plan against (claim 8). Builds a backend-agnostic
//! `StandbySpec` and drives the `SupervisorStandbyPool` + `VmBackend` trait methods.
//!
//! v1 is default-shaped only: a standby is claimable by a launch whose kernel **and**
//! resources match (`StandbyCompat`) and that carries no extra volumes (1a's attach only
//! threads the rootfs). Anything else cold-boots. Multi-kernel keying + honouring an
//! explicit `--name`/volumes for warm launches are deferred follow-ups (SPRINT.md).

use std::path::Path;

use anyhow::{Context, Result};
use mvm_backend::standby_pool::SupervisorStandbyPool;
use mvm_core::vm_backend::{StandbyClaim, StandbyCompat, StandbySpec, VmBackend, VmId};
use sha2::{Digest, Sha256};

// NB: the `mvmctl pool` command (1b-ii) resolves `signer_id` via
// `super::vm::host_signer::host_signer_id()` and passes it into these helpers; the
// helpers themselves stay signer-agnostic (they take `signer_id` as a parameter).

/// Lowercase-hex sha256 of a kernel image — part of the base-compat key.
pub fn kernel_sha256_hex(kernel: &Path) -> Result<String> {
    let bytes =
        std::fs::read(kernel).with_context(|| format!("read kernel {}", kernel.display()))?;
    Ok(hex_lower(&Sha256::digest(&bytes)))
}

/// 32 random bytes as lowercase hex — the per-spawn binding nonce.
pub fn fresh_binding_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex_lower(&buf)
}

/// Build a `StandbySpec` for a standby that pre-loads `kernel` with the given resources.
/// The control UDS lives under `pool_root/<id>/control-<nonce>.sock` (nonce in the path —
/// defense in depth); the VM's runtime state dir is the normal `vms_root/<id>/` so
/// stop/status/console resolve it like any cold-booted VM.
pub fn build_standby_spec(
    pool_root: &Path,
    vms_root: &Path,
    kernel: &Path,
    vcpus: u8,
    mem_mib: u32,
    signer_id: &str,
    signing_key_path: &Path,
) -> Result<StandbySpec> {
    let nonce = fresh_binding_nonce();
    let id = format!("standby-{}", &nonce[..16]);
    Ok(StandbySpec {
        kernel_path: kernel.to_string_lossy().into_owned(),
        kernel_sha256: kernel_sha256_hex(kernel)?,
        vcpus,
        mem_mib,
        signing_key_path: signing_key_path.to_path_buf(),
        signer_id: signer_id.to_string(),
        control_socket: pool_root.join(&id).join(format!("control-{nonce}.sock")),
        vm_state_dir: vms_root.join(&id).to_string_lossy().into_owned(),
        binding_nonce: nonce,
        id,
    })
}

/// Outcome of the warm-pool claim attempt on a launch.
#[derive(Debug, PartialEq, Eq)]
pub enum LaunchDecision {
    /// A standby was claimed and is booting under this VmId.
    Claimed(VmId),
    /// No compatible warm standby (or the claim failed) — caller must cold-boot.
    ColdBoot,
}

/// Try to claim an idle standby compatible with `want`; **fail open to cold boot**. On a
/// claim error the standby is removed (it's spent/broken), never left idle, so the next
/// launch doesn't keep retrying a dead standby.
pub fn claim_or_cold(
    pool: &SupervisorStandbyPool,
    backend: &dyn VmBackend,
    want: &StandbyCompat,
    claim: &StandbyClaim,
) -> Result<LaunchDecision> {
    if !backend.supports_standby_pool() {
        return Ok(LaunchDecision::ColdBoot);
    }
    let Some(handle) = pool.select_idle_compatible(want)? else {
        return Ok(LaunchDecision::ColdBoot);
    };
    // Reserve it so a concurrent launch won't double-claim.
    pool.mark_claimed(&handle.id)?;
    match backend.claim_standby(&handle, claim) {
        Ok(vm_id) => {
            // The standby has become the VM; drop its pool entry (the control UDS is
            // one-shot). The VM now lives under its vms/<id> state dir.
            let _ = pool.remove(&handle.id);
            Ok(LaunchDecision::Claimed(vm_id))
        }
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "standby claim failed; cold-booting");
            let _ = pool.remove(&handle.id); // spent/broken — never leave it idle
            Ok(LaunchDecision::ColdBoot)
        }
    }
}

/// Parameters for [`warm_to_target`] — grouped to keep the signature small.
pub struct WarmParams<'a> {
    pub backend: &'a dyn VmBackend,
    pub kernel: &'a Path,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub signer_id: &'a str,
    pub signing_key_path: &'a Path,
    pub target: u32,
}

/// Warm the pool toward `target` idle standbys for the given kernel+resources. Best-effort:
/// spawn failures are logged, not fatal (warm pool is an optimization). Returns how many
/// were newly spawned.
pub fn warm_to_target(pool: &SupervisorStandbyPool, p: &WarmParams<'_>) -> Result<u32> {
    if p.target == 0 || !p.backend.supports_standby_pool() {
        return Ok(0);
    }
    let want = StandbyCompat {
        kernel_sha256: kernel_sha256_hex(p.kernel)?,
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
    };
    let have = pool.idle_count_compatible(&want)? as u32;
    let pool_root = mvm_core::config::mvm_pool_dir()?;
    let vms_root = mvm_core::config::mvm_data_dir_strict()?.join("vms");
    let mut spawned = 0;
    for _ in have..p.target {
        let spec = build_standby_spec(
            &pool_root,
            &vms_root,
            p.kernel,
            p.vcpus,
            p.mem_mib,
            p.signer_id,
            p.signing_key_path,
        )?;
        match p.backend.spawn_standby(&spec) {
            Ok(handle) => {
                pool.record(&handle)?;
                spawned += 1;
            }
            Err(e) => tracing::warn!(error = %e, "spawn standby failed; pool stays under target"),
        }
    }
    Ok(spawned)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::{
        StandbyError, StandbyHandle, StandbyState, StartMode, VmCapabilities, VmInfo,
        VmStartConfig, VmStatus,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    fn sha256_hex_of(bytes: &[u8]) -> String {
        hex_lower(&Sha256::digest(bytes))
    }

    #[test]
    fn kernel_sha256_hex_is_64_lowercase_hex_of_known_content() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"hello-kernel").unwrap();
        let hex = kernel_sha256_hex(&kp).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(
            hex.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_eq!(hex, sha256_hex_of(b"hello-kernel"));
    }

    #[test]
    fn fresh_binding_nonce_is_64_hex_chars_and_varies() {
        let a = fresh_binding_nonce();
        let b = fresh_binding_nonce();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
    }

    #[test]
    fn standby_spec_puts_nonce_in_socket_path_and_state_under_vms() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"k").unwrap();
        let pool_root = tmp.path().join("pool");
        let vms_root = tmp.path().join("vms");
        let spec = build_standby_spec(
            &pool_root,
            &vms_root,
            &kp,
            2,
            1024,
            "host:test",
            &tmp.path().join("key"),
        )
        .unwrap();
        assert!(
            spec.control_socket
                .to_string_lossy()
                .contains(&spec.binding_nonce)
        );
        assert!(spec.control_socket.starts_with(&pool_root));
        assert!(
            spec.vm_state_dir
                .starts_with(vms_root.to_string_lossy().as_ref())
        );
        assert_eq!(spec.kernel_sha256.len(), 64);
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.mem_mib, 1024);
    }

    // A minimal VmBackend stub that opts into the standby pool and records calls, so the
    // claim/cold decision is testable without a VM.
    struct StubBackend {
        claim_ok: bool,
        claimed: AtomicBool,
    }
    impl StubBackend {
        fn new(claim_ok: bool) -> Self {
            Self {
                claim_ok,
                claimed: AtomicBool::new(false),
            }
        }
    }
    impl VmBackend for StubBackend {
        fn name(&self) -> &str {
            "stub"
        }
        fn capabilities(&self) -> VmCapabilities {
            VmCapabilities::default()
        }
        fn supports_standby_pool(&self) -> bool {
            true
        }
        fn claim_standby(
            &self,
            handle: &StandbyHandle,
            _claim: &StandbyClaim,
        ) -> std::result::Result<VmId, StandbyError> {
            self.claimed.store(true, Ordering::SeqCst);
            if self.claim_ok {
                Ok(VmId(handle.id.clone()))
            } else {
                Err(StandbyError::ClaimFailed("stub refused".into()))
            }
        }
        fn start_with_mode(&self, _: &VmStartConfig, _: StartMode) -> anyhow::Result<VmId> {
            unreachable!("cold start is the caller's job, not claim_or_cold")
        }
        fn stop(&self, _: &VmId) -> anyhow::Result<()> {
            Ok(())
        }
        fn stop_all(&self) -> anyhow::Result<()> {
            Ok(())
        }
        fn pause(&self, _: &VmId) -> anyhow::Result<()> {
            Ok(())
        }
        fn resume(&self, _: &VmId) -> anyhow::Result<()> {
            Ok(())
        }
        fn status(&self, _: &VmId) -> anyhow::Result<VmStatus> {
            Ok(VmStatus::Stopped)
        }
        fn list(&self) -> anyhow::Result<Vec<VmInfo>> {
            Ok(vec![])
        }
        fn logs(&self, _: &VmId, _: u32, _: bool) -> anyhow::Result<String> {
            Ok(String::new())
        }
        fn is_available(&self) -> anyhow::Result<bool> {
            Ok(true)
        }
        fn install(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn idle_handle(id: &str, kernel: &str) -> StandbyHandle {
        StandbyHandle {
            id: id.into(),
            control_socket: format!("/p/{id}.sock").into(),
            pid: std::process::id(),
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            binding_nonce: "ab".repeat(32),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
        }
    }

    fn compat(kernel: &str) -> StandbyCompat {
        StandbyCompat {
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
        }
    }

    fn sample_claim() -> StandbyClaim {
        StandbyClaim {
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/g.sock".into(),
            gateway_events_socket: None,
            plan_json: "{}".into(),
            bundle_json: None,
        }
    }

    #[test]
    fn claim_or_cold_claims_when_compatible_idle_standby_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&idle_handle("s1", "aa")).unwrap();
        let backend = StubBackend::new(true);
        let decision = claim_or_cold(&pool, &backend, &compat("aa"), &sample_claim()).unwrap();
        assert_eq!(decision, LaunchDecision::Claimed(VmId("s1".into())));
        assert!(backend.claimed.load(Ordering::SeqCst));
        assert!(
            pool.load("s1").is_err(),
            "a claimed standby's pool entry is removed"
        );
    }

    #[test]
    fn claim_or_cold_cold_boots_when_no_standby() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        let backend = StubBackend::new(true);
        let decision = claim_or_cold(&pool, &backend, &compat("aa"), &sample_claim()).unwrap();
        assert_eq!(decision, LaunchDecision::ColdBoot);
        assert!(!backend.claimed.load(Ordering::SeqCst));
    }

    #[test]
    fn claim_or_cold_cold_boots_and_removes_standby_when_claim_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&idle_handle("s1", "aa")).unwrap();
        let backend = StubBackend::new(false);
        let decision = claim_or_cold(&pool, &backend, &compat("aa"), &sample_claim()).unwrap();
        assert_eq!(decision, LaunchDecision::ColdBoot);
        assert!(
            pool.load("s1").is_err(),
            "a failed standby is removed, not left idle"
        );
    }
}
