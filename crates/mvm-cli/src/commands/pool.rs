//! Warm-pool launch glue + the `mvmctl pool` command.
//!
//! Owns the bits that must live above the backend: the kernel-identity hash (part of the
//! base-compat key), the per-spawn binding nonce, and the host signer identity/key path
//! the standby re-verifies the attach plan against (claim 8). Builds a backend-agnostic
//! `StandbySpec` and drives the `SupervisorStandbyPool` + `VmBackend` trait methods.
//!
//! v1 is default-shaped only: a standby is claimable by a launch whose kernel **and**
//! resources match (`StandbyCompat`) and that carries no extra volumes (the attach only
//! threads the rootfs). Anything else cold-boots. Multi-kernel keying + honouring an
//! explicit `--name`/volumes for warm launches are deferred follow-ups.

use std::path::Path;

use anyhow::{Context, Result};
use clap::{Args as ClapArgs, Subcommand};
use mvm_backend::backend::AnyBackend;
use mvm_backend::standby_pool::SupervisorStandbyPool;
use mvm_core::user_config::MvmConfig;
use mvm_core::vm_backend::{
    StandbyClaim, StandbyCompat, StandbyHandle, StandbySpec, StandbyState, VmBackend, VmId,
    VmStartConfig,
};
use sha2::{Digest, Sha256};

use super::Cli;
use super::env::dev_vz::ensure_default_microvm_image;
use super::vm::host_signer;

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

/// The compat-key kernel identity, computed identically at claim **and** replenish time.
/// For **libkrun** a workload microVM always boots the bundled libkrunfw kernel (mkGuest
/// images ship none; the builder VM uses a custom kernel but never the warm pool), so the
/// identity is a constant — crucially the same whether the workload's `kernel_path` is
/// absent (claim, pre-boot) or present (replenish, after libkrun materialized the bundled
/// kernel). That's what makes the libkrun warm claim *fire* instead of fail-open to cold
/// because the absent path can't be hashed. Other backends boot a real on-disk kernel → sha.
const LIBKRUN_BUNDLED_KERNEL_ID: &str = "libkrun-bundled-kernel";

pub fn kernel_identity(backend: &dyn VmBackend, kernel_path: Option<&str>) -> Result<String> {
    if backend.name() == "libkrun" {
        return Ok(LIBKRUN_BUNDLED_KERNEL_ID.to_string());
    }
    let kernel = kernel_path.context("launch config has no kernel path for the compat key")?;
    kernel_sha256_hex(Path::new(kernel))
}

/// The compat-key image identity. `None` for libkrun (image-agnostic standbys). For Vz
/// the sha256 of the source rootfs image ties a saved-standby to the exact image it was
/// captured from — only launches with the same image may claim it.
pub fn image_identity(backend: &dyn VmBackend, rootfs_path: &str) -> Result<Option<String>> {
    if backend.name() == "libkrun" {
        return Ok(None);
    }
    if backend.name() == "vz" || backend.name() == "virtualization" {
        let sha = kernel_sha256_hex(Path::new(rootfs_path))
            .with_context(|| format!("hashing rootfs for image identity: {rootfs_path}"))?;
        return Ok(Some(sha));
    }
    // Other backends (firecracker, qemu, …) have no pool today; return None so
    // compat_for_launch compiles without gating those paths.
    Ok(None)
}

/// Inputs to [`build_standby_spec`] (grouped to avoid a long positional signature).
pub struct StandbySpecParams<'a> {
    /// `~/.mvm/pool/` root — holds the control UDS.
    pub pool_root: &'a Path,
    /// `~/.mvm/vms/` root — the standby's runtime state dir lives at `vms_root/<id>/`.
    pub vms_root: &'a Path,
    /// Kernel image the standby pre-loads (the path; for libkrun mkGuest the bundled kernel
    /// is materialized here at boot).
    pub kernel: &'a Path,
    /// Compat-key identity (see [`kernel_identity`]) — not necessarily a hash of `kernel`
    /// (for libkrun it's the bundled-kernel constant).
    pub kernel_sha256: &'a str,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub signer_id: &'a str,
    pub signing_key_path: &'a Path,
    /// Source rootfs image for Vz saved-standbys. `None` for libkrun.
    pub image_path: Option<&'a Path>,
    /// Sha256 hex of the image for the compat key. `None` for libkrun.
    pub image_sha256: Option<&'a str>,
}

/// Build a `StandbySpec` from [`StandbySpecParams`]. The control UDS lives under
/// `pool_root/<id>/control-<nonce>.sock` (nonce in the path — defense in depth); the VM's
/// runtime state dir is the normal `vms_root/<id>/` so stop/status/console resolve it like
/// any cold-booted VM.
pub fn build_standby_spec(p: &StandbySpecParams<'_>) -> Result<StandbySpec> {
    let nonce = fresh_binding_nonce();
    // `standby-<16 hex>` — nonce-derived (defense-in-depth obfuscation within the 0700
    // dir). The socket filename is kept SHORT and fixed: a Unix domain socket path must fit
    // `SUN_LEN` (~104 bytes on macOS), so the full 64-char nonce can't live in the path —
    // the binding security is the *echoed full nonce verified in the attach*, not the path.
    let id = format!("standby-{}", &nonce[..16]);
    Ok(StandbySpec {
        kernel_path: p.kernel.to_string_lossy().into_owned(),
        kernel_sha256: p.kernel_sha256.to_string(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        signing_key_path: p.signing_key_path.to_path_buf(),
        signer_id: p.signer_id.to_string(),
        control_socket: p.pool_root.join(&id).join("control.sock"),
        vm_state_dir: p.vms_root.join(&id).to_string_lossy().into_owned(),
        binding_nonce: nonce,
        image_path: p.image_path.map(|p| p.to_string_lossy().into_owned()),
        image_sha256: p.image_sha256.map(str::to_string),
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
///
/// `make_claim` builds the [`StandbyClaim`] **for the selected standby's id** — the audit
/// substrate (`gateway-<vm>.sock`) is name-keyed, and a claimed VM runs under its
/// standby-id, so the caller must compute those paths against `handle.id`. A `make_claim`
/// error also fails open to cold boot (and reaps the reserved standby).
pub fn claim_or_cold<F>(
    pool: &SupervisorStandbyPool,
    backend: &dyn VmBackend,
    want: &StandbyCompat,
    make_claim: F,
) -> Result<LaunchDecision>
where
    F: FnOnce(&StandbyHandle) -> Result<StandbyClaim>,
{
    if !backend.supports_standby_pool() {
        return Ok(LaunchDecision::ColdBoot);
    }
    let Some(handle) = pool.select_idle_compatible(want)? else {
        return Ok(LaunchDecision::ColdBoot);
    };
    // Reserve it so a concurrent launch won't double-claim.
    pool.mark_claimed(&handle.id)?;
    let claim = match make_claim(&handle) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(standby = %handle.id, error = %e, "build claim failed; cold-booting");
            let _ = pool.remove(&handle.id);
            return Ok(LaunchDecision::ColdBoot);
        }
    };
    match backend.claim_standby(&handle, &claim) {
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
    /// Source rootfs image for Vz saved-standbys. `None` for libkrun.
    pub image: Option<&'a Path>,
}

/// Warm the pool toward `target` idle standbys for the given kernel+resources. Best-effort:
/// spawn failures are logged, not fatal (warm pool is an optimization). Returns how many
/// were newly spawned.
pub fn warm_to_target(pool: &SupervisorStandbyPool, p: &WarmParams<'_>) -> Result<u32> {
    if p.target == 0 || !p.backend.supports_standby_pool() {
        return Ok(0);
    }
    // The compat identity computed identically here and at claim time (a constant for
    // libkrun's bundled kernel) so a warmed standby is actually claimable.
    let kernel_sha256 = kernel_identity(p.backend, p.kernel.to_str())?;
    let image_sha256 = match p.image {
        Some(img) => Some(
            kernel_sha256_hex(img)
                .with_context(|| format!("hashing image for pool compat key: {}", img.display()))?,
        ),
        None => None,
    };
    let want = StandbyCompat {
        kernel_sha256: kernel_sha256.clone(),
        vcpus: p.vcpus,
        mem_mib: p.mem_mib,
        image_sha256: image_sha256.clone(),
    };
    let have = pool.idle_count_compatible(&want)? as u32;
    let pool_root = mvm_core::config::mvm_pool_dir()?;
    let vms_root = mvm_core::config::mvm_data_dir_strict()?.join("vms");
    let mut spawned = 0;
    for _ in have..p.target {
        let spec = build_standby_spec(&StandbySpecParams {
            pool_root: &pool_root,
            vms_root: &vms_root,
            kernel: p.kernel,
            kernel_sha256: &kernel_sha256,
            vcpus: p.vcpus,
            mem_mib: p.mem_mib,
            signer_id: p.signer_id,
            signing_key_path: p.signing_key_path,
            image_path: p.image,
            image_sha256: image_sha256.as_deref(),
        })?;
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

/// The base-compat key a launch needs (kernel identity + fixed vcpus/mem + image sha for
/// Vz). The kernel component is [`kernel_identity`] — for libkrun the bundled-kernel
/// constant, so it's computable pre-boot even without an on-disk kernel.
fn compat_for_launch(backend: &dyn VmBackend, cfg: &VmStartConfig) -> Result<StandbyCompat> {
    let image_sha256 = image_identity(backend, cfg.rootfs_path.as_str())?;
    Ok(StandbyCompat {
        kernel_sha256: kernel_identity(backend, cfg.kernel_path.as_deref())?,
        vcpus: u8::try_from(cfg.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX),
        mem_mib: cfg.memory_mib,
        image_sha256,
    })
}

/// Attempt a warm-pool claim for this launch. Returns the claimed `VmId` (the standby-id
/// the VM now runs under) or `None` to cold-boot. **Fail-open**: anything not default-
/// shaped, not bridge-admitted, or any error → `None` (the caller cold-boots as normal).
///
/// Eligibility (all required): `warm_pool_size > 0`, the launch is auto-named (no explicit
/// `--name` — a claimed VM is named by its standby-id), no extra volumes (the attach
/// threads only the rootfs), the backend supports the pool, and the **admitted plan +
/// tenant** are threaded into the config — which only the gateway-bridge path
/// (`MVM_GATEWAY_BRIDGE=1`) does, and which a claimed standby's `run_with_bridge` requires.
pub fn try_warm_claim(
    backend: &AnyBackend,
    cfg: &VmStartConfig,
    user_named: bool,
) -> Result<Option<VmId>> {
    if cfg.warm_pool_size == 0
        || user_named
        || !cfg.volumes.is_empty()
        || !backend.supports_standby_pool()
    {
        return Ok(None);
    }
    let (Some(plan_json), Some(tenant)) = (cfg.plan_json.clone(), cfg.tenant_id.clone()) else {
        // No admitted plan threaded in → not the bridge path → cold-boot.
        return Ok(None);
    };
    let want = compat_for_launch(backend.as_vm_backend(), cfg)?;
    let rootfs = cfg.rootfs_path.clone();
    let bundle_json = cfg.bundle_json.clone();
    let pool = SupervisorStandbyPool::open()?;
    let decision = claim_or_cold(&pool, backend.as_vm_backend(), &want, |handle| {
        // The audit substrate (`gateway-<vm>.sock`) is name-keyed; the claimed VM runs
        // under the standby-id, so compute it for `handle.id`.
        let sub = mvm_backend::audit_substrate::compute_audit_substrate(&handle.id, Some(&tenant))?;
        Ok(StandbyClaim {
            rootfs_path: rootfs.clone(),
            tenant_id: tenant.clone(),
            audit_dir: sub.audit_dir.context("audit substrate missing audit_dir")?,
            gateway_audit_socket: sub
                .gateway_audit_socket
                .context("audit substrate missing gateway_audit_socket")?,
            gateway_events_socket: sub.gateway_events_socket,
            plan_json: plan_json.clone(),
            bundle_json: bundle_json.clone(),
        })
    })?;
    Ok(match decision {
        LaunchDecision::Claimed(id) => Some(id),
        LaunchDecision::ColdBoot => None,
    })
}

/// Top the pool back up toward `cfg.warm_pool_size` after a launch (the no-daemon
/// replenish-on-use maintainer). Best-effort — failures are logged, never propagated.
///
/// For libkrun standbys this path fires automatically after each claimed launch.
/// For Vz saved-standbys the replenish path requires a boot + capture cycle that is
/// expensive and may require the builder VM to resolve the kernel. Automatic replenish
/// is skipped for Vz (pool warm is manual); `supports_standby_pool()` stays true so
/// `try_warm_claim` still fires.
pub fn replenish_after_launch(backend: &AnyBackend, cfg: &VmStartConfig) -> Result<u32> {
    if cfg.warm_pool_size == 0 || !backend.supports_standby_pool() {
        return Ok(0);
    }
    // Vz replenish requires booting a seed VM + capture: too expensive for the
    // post-claim fast path. Replenish is manual (`mvmctl pool warm`) for Vz.
    if backend.as_vm_backend().name() == "vz" {
        return Ok(0);
    }
    let Some(kernel) = cfg.kernel_path.as_ref() else {
        return Ok(0);
    };
    let signer = host_signer::load_or_init()?;
    let pool = SupervisorStandbyPool::open()?;
    warm_to_target(
        &pool,
        &WarmParams {
            backend: backend.as_vm_backend(),
            kernel: Path::new(kernel),
            vcpus: u8::try_from(cfg.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX),
            mem_mib: cfg.memory_mib,
            signer_id: &host_signer::host_signer_id(),
            signing_key_path: &signer.secret_path,
            target: cfg.warm_pool_size,
            image: None, // libkrun only: image-agnostic standbys
        },
    )
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
    fn standby_spec_socket_is_short_and_nonce_derived_state_under_vms() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"k").unwrap();
        let pool_root = tmp.path().join("pool");
        let vms_root = tmp.path().join("vms");
        let spec = build_standby_spec(&StandbySpecParams {
            pool_root: &pool_root,
            vms_root: &vms_root,
            kernel: &kp,
            kernel_sha256: &kernel_sha256_hex(&kp).unwrap(),
            vcpus: 2,
            mem_mib: 1024,
            signer_id: "host:test",
            signing_key_path: &tmp.path().join("key"),
            image_path: None,
            image_sha256: None,
        })
        .unwrap();
        // The socket lives under the nonce-derived `standby-<16hex>` dir; the filename is
        // short + fixed so the path fits SUN_LEN (the full 64-char nonce would overflow it).
        assert!(spec.id.starts_with("standby-"));
        assert!(spec.binding_nonce.starts_with(&spec.id["standby-".len()..]));
        assert!(spec.control_socket.starts_with(pool_root.join(&spec.id)));
        assert_eq!(spec.control_socket.file_name().unwrap(), "control.sock");
        // Keep the realistic ~/.mvm path well under the macOS SUN_LEN (~104 bytes).
        assert!(
            std::path::Path::new("/Users/someuser/.mvm/pool")
                .join(&spec.id)
                .join("control.sock")
                .as_os_str()
                .len()
                < 104
        );
        assert!(
            spec.vm_state_dir
                .starts_with(vms_root.to_string_lossy().as_ref())
        );
        assert_eq!(spec.kernel_sha256.len(), 64);
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.mem_mib, 1024);
    }

    #[test]
    fn kernel_identity_is_constant_for_libkrun_and_sha_elsewhere() {
        let tmp = tempfile::tempdir().unwrap();
        let kp = tmp.path().join("vmlinux");
        std::fs::write(&kp, b"real-kernel").unwrap();
        let kps = kp.to_string_lossy();

        // libkrun: the bundled-kernel constant, computable even when the workload kernel is
        // absent (the mkGuest claim/replenish symmetry fix).
        let libkrun = AnyBackend::from_hypervisor("libkrun");
        assert_eq!(
            kernel_identity(libkrun.as_vm_backend(), None).unwrap(),
            LIBKRUN_BUNDLED_KERNEL_ID
        );
        assert_eq!(
            kernel_identity(libkrun.as_vm_backend(), Some("/nonexistent/vmlinux")).unwrap(),
            LIBKRUN_BUNDLED_KERNEL_ID
        );

        // firecracker: the real on-disk kernel's sha.
        let fc = AnyBackend::from_hypervisor("firecracker");
        assert_eq!(
            kernel_identity(fc.as_vm_backend(), Some(&kps)).unwrap(),
            sha256_hex_of(b"real-kernel")
        );
        // …and it errors if a real-kernel backend has no path.
        assert!(kernel_identity(fc.as_vm_backend(), None).is_err());
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
            image_sha256: None,
        }
    }

    fn compat(kernel: &str) -> StandbyCompat {
        StandbyCompat {
            kernel_sha256: kernel.into(),
            vcpus: 2,
            mem_mib: 1024,
            image_sha256: None,
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
        let decision =
            claim_or_cold(&pool, &backend, &compat("aa"), |_h| Ok(sample_claim())).unwrap();
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
        let decision =
            claim_or_cold(&pool, &backend, &compat("aa"), |_h| Ok(sample_claim())).unwrap();
        assert_eq!(decision, LaunchDecision::ColdBoot);
        assert!(!backend.claimed.load(Ordering::SeqCst));
    }

    #[test]
    fn claim_or_cold_cold_boots_and_removes_standby_when_claim_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(tmp.path());
        pool.record(&idle_handle("s1", "aa")).unwrap();
        let backend = StubBackend::new(false);
        let decision =
            claim_or_cold(&pool, &backend, &compat("aa"), |_h| Ok(sample_claim())).unwrap();
        assert_eq!(decision, LaunchDecision::ColdBoot);
        assert!(
            pool.load("s1").is_err(),
            "a failed standby is removed, not left idle"
        );
    }

    // try_warm_claim eligibility gates — each must cold-boot (return None) before touching
    // the pool. A real libkrun AnyBackend (supports the pool, no I/O at construction) so the
    // tested gate is the deciding one.
    fn eligible_cfg() -> VmStartConfig {
        VmStartConfig {
            warm_pool_size: 2,
            kernel_path: Some("/k/vmlinux".into()),
            rootfs_path: "/vol/rootfs.ext4".into(),
            cpus: 2,
            memory_mib: 1024,
            tenant_id: Some("tenant-a".into()),
            plan_json: Some("{}".into()),
            ..Default::default()
        }
    }

    #[test]
    fn try_warm_claim_cold_when_pool_size_zero() {
        let b = AnyBackend::from_hypervisor("libkrun");
        let mut c = eligible_cfg();
        c.warm_pool_size = 0;
        assert_eq!(try_warm_claim(&b, &c, false).unwrap(), None);
    }

    #[test]
    fn try_warm_claim_cold_when_user_named() {
        let b = AnyBackend::from_hypervisor("libkrun");
        assert_eq!(try_warm_claim(&b, &eligible_cfg(), true).unwrap(), None);
    }

    #[test]
    fn try_warm_claim_cold_with_extra_volumes() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let b = AnyBackend::from_hypervisor("libkrun");
        let mut c = eligible_cfg();
        c.volumes = vec![VmVolume {
            host: "/h".into(),
            guest: "/g".into(),
            size: String::new(),
            read_only: false,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        }];
        assert_eq!(try_warm_claim(&b, &c, false).unwrap(), None);
    }

    #[test]
    fn try_warm_claim_cold_without_admitted_plan() {
        let b = AnyBackend::from_hypervisor("libkrun");
        let mut c = eligible_cfg();
        c.plan_json = None; // not the gateway-bridge/admitted path → cold-boot
        assert_eq!(try_warm_claim(&b, &c, false).unwrap(), None);
    }
}

// ── `mvmctl pool` command ───────────────────────────────────────────────────────────

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: PoolAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum PoolAction {
    /// Pre-spawn idle supervisor standbys for the default-microVM launch shape so a later
    /// `up` is fast. Default count 1.
    ///
    /// For the Vz backend a saved-standby capture requires an image rootfs. Provide
    /// `--rootfs <path>` or set `MVM_POOL_ROOTFS`; if absent, the command falls back to
    /// the cached default-microVM image (same one `up` uses without `--flake`).
    Warm {
        /// How many idle standbys to warm the pool toward (default 1).
        count: Option<u32>,
        /// Source rootfs for Vz saved-standbys (absolute path to an ext4 image).
        /// Ignored for libkrun. Defaults to the cached default-microVM rootfs.
        #[arg(long)]
        rootfs: Option<String>,
    },
    /// Show the standby pool — recorded standbys and their idle/claimed state.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// The default launch shape the warm pool targets: default-microVM kernel + the config's
/// default cpus/mem + the effective hypervisor. Both `pool warm` and the `up` auto-claim
/// resolve through the same pieces so a warmed standby is claimable by a default `up`.
struct WarmShape {
    backend: AnyBackend,
    backend_name: String,
    kernel: std::path::PathBuf,
    /// Source rootfs for Vz saved-standbys. `None` for libkrun (image-agnostic).
    image: Option<std::path::PathBuf>,
    vcpus: u8,
    mem_mib: u32,
}

fn resolve_warm_shape(cfg: &MvmConfig, rootfs_override: Option<&str>) -> Result<WarmShape> {
    let backend_name = super::shared::resolve_effective_hypervisor("firecracker");
    let backend = AnyBackend::from_hypervisor(&backend_name);
    let (kernel, default_rootfs) =
        ensure_default_microvm_image(mvm_build::pipeline::BuildMode::Prod)
            .context("resolve default-microvm kernel for the warm pool")?;
    let vcpus = u8::try_from(cfg.default_cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX);
    // Vz needs an image; libkrun does not. Resolve: explicit --rootfs > env var > default.
    let image = if backend_name == "vz" || backend_name == "virtualization" {
        let path = rootfs_override
            .map(str::to_string)
            .or_else(|| std::env::var("MVM_POOL_ROOTFS").ok())
            .unwrap_or(default_rootfs);
        Some(std::path::PathBuf::from(path))
    } else {
        None
    };
    Ok(WarmShape {
        backend,
        backend_name,
        kernel: std::path::PathBuf::from(kernel),
        image,
        vcpus,
        mem_mib: cfg.default_memory_mib,
    })
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, cfg: &MvmConfig) -> Result<()> {
    let pool = SupervisorStandbyPool::open()?;
    match args.action {
        PoolAction::Status { json } => run_status(&pool, json),
        PoolAction::Warm { count, rootfs } => {
            run_warm(&pool, cfg, count.unwrap_or(1), rootfs.as_deref())
        }
    }
}

fn run_warm(
    pool: &SupervisorStandbyPool,
    cfg: &MvmConfig,
    target: u32,
    rootfs_override: Option<&str>,
) -> Result<()> {
    let shape = resolve_warm_shape(cfg, rootfs_override)?;
    if !shape.backend.supports_standby_pool() {
        crate::ui::warn(&format!(
            "backend '{}' has no supervisor standby pool; nothing warmed.",
            shape.backend_name
        ));
        return Ok(());
    }
    // Ensure the host signer exists — the standby re-verifies the attach plan against it.
    let signer = host_signer::load_or_init()?;
    let spawned = warm_to_target(
        pool,
        &WarmParams {
            backend: shape.backend.as_vm_backend(),
            kernel: &shape.kernel,
            vcpus: shape.vcpus,
            mem_mib: shape.mem_mib,
            signer_id: &host_signer::host_signer_id(),
            signing_key_path: &signer.secret_path,
            target,
            image: shape.image.as_deref(),
        },
    )?;
    // A state-changing verb emits one audit record per attempt.
    mvm_core::audit_emit!(PoolWarm, "spawned={spawned} target={target}");
    if spawned == 0 {
        crate::ui::info(&format!("Pool already at or above target {target}."));
    } else {
        crate::ui::success(&format!(
            "Warmed {spawned} standby(s) toward target {target}."
        ));
    }
    crate::ui::info(
        "Note: a warm `up` claim boots through the gateway-bridge supervisor path \
         (MVM_GATEWAY_BRIDGE=1); the default `up` cold-boots.",
    );
    Ok(())
}

/// Machine-readable `pool status --json` shape.
#[derive(serde::Serialize)]
struct PoolStatus {
    idle: usize,
    claimed: usize,
    standbys: Vec<PoolStatusEntry>,
}

#[derive(serde::Serialize)]
struct PoolStatusEntry {
    id: String,
    state: &'static str,
    pid: u32,
    kernel_sha256: String,
    vcpus: u8,
    mem_mib: u32,
    /// Present for Vz saved-standbys; absent (null) for libkrun.
    image_sha256: Option<String>,
}

fn run_status(pool: &SupervisorStandbyPool, json: bool) -> Result<()> {
    let standbys = pool.list()?;
    let idle = standbys
        .iter()
        .filter(|h| h.state == StandbyState::Idle)
        .count();
    let claimed = standbys.len() - idle;
    let report = PoolStatus {
        idle,
        claimed,
        standbys: standbys
            .iter()
            .map(|h| PoolStatusEntry {
                id: h.id.clone(),
                state: match h.state {
                    StandbyState::Idle => "idle",
                    StandbyState::Claimed => "claimed",
                },
                pid: h.pid,
                kernel_sha256: h.kernel_sha256.clone(),
                vcpus: h.vcpus,
                mem_mib: h.mem_mib,
                image_sha256: h.image_sha256.clone(),
            })
            .collect(),
    };
    if json {
        crate::json_out::emit_json(&report)?;
        return Ok(());
    }
    println!("Supervisor standby pool: {idle} idle, {claimed} claimed");
    for e in &report.standbys {
        let image_tag = e
            .image_sha256
            .as_deref()
            .map(|s| format!(" · image {}", &s[..s.len().min(12)]))
            .unwrap_or_default();
        println!(
            "  {} · {} · {} · {} vcpu / {} MiB · kernel {}{}",
            e.id,
            e.state,
            if e.pid == 0 {
                "saved-state".to_string()
            } else {
                format!("pid {}", e.pid)
            },
            e.vcpus,
            e.mem_mib,
            &e.kernel_sha256[..e.kernel_sha256.len().min(12)],
            image_tag,
        );
    }
    Ok(())
}
