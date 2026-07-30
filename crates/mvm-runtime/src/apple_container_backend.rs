//! Apple Containerization-framework backend — shim-wired boot path.
//!
//! `AppleContainerBackend` runs mvm workloads inside Apple's
//! Containerization-framework VMs: lightweight, hardware-isolated Linux
//! VMs whose kernel boot and guest PID 1 (`vminitd`, serving gRPC on vsock
//! port 1024) are owned by Apple's Swift-only framework. Because the
//! framework owns the boot path, the mvm initramfs does not apply verbatim
//! here — activation rides `vminitd`'s API instead, while the guest agent
//! binary, the mount logic, the uid-901 privilege drop, the `NotActivated`
//! RPC gate, and the operational RPC surface stay shared verbatim with
//! every other backend.
//!
//! This stage wires the real boot machinery through the container shim
//! (`swift/mvm-container-shim`, one detached process per VM, mirroring the
//! other per-VM supervisors): artifact resolution with typed
//! `ArtifactMissing` errors, spec mapping, shim spawn, and guest file
//! injection (the static musl guest agent and the serialized
//! `ActivateEnvironment` every other backend builds). What is still
//! fail-closed is the agent bring-up itself: the guest agent has no
//! activation-file entry point yet, so `start_with_mode` injects
//! everything and then returns a typed [`AppleContainerError`] naming the
//! milestone — after tearing the VM down, so a half-boot never lingers.
//!
//! Honest reporting, unchanged from the skeleton: `capabilities()` and
//! `security_profile()` still report no snapshot, no standby pool, and
//! every numbered claim as `DoesNotHold` until a workload actually boots
//! and can enforce them; the backend stays opt-in only —
//! `AnyBackend::auto_select` never returns this kind.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::config::{mvm_cache_dir, vm_state_dir, vms_dir};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, StartMode,
    VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};
use thiserror::Error;

use crate::apple_container::shim_client::{ShimClient, spawn_shim};
use crate::apple_container::spec::{
    AppleContainerSpec, SpecInputs, build_apple_container_spec, reject_unsupported_start_config,
};

/// Per-VM shim state-file names under `vm_state_dir(name)`.
const SHIM_PID_FILE: &str = "ac-shim.pid";
const SHIM_SPEC_FILE: &str = "ac-shim-spec.json";
const SHIM_CONTROL_SOCKET: &str = "ac-shim.sock";
const SHIM_BOOT_LOG_DIR: &str = "bootlog";

/// Guest paths the injection writes.
const GUEST_RUN_DIR: &str = "/run/mvm";
const GUEST_AGENT_PATH: &str = "/run/mvm/mvm-guest-agent";
const GUEST_ACTIVATION_PATH: &str = "/run/mvm/activation.json";

/// Typed, fail-closed errors for requests this backend cannot satisfy.
/// Every error names the operation refused and the missing piece, rather
/// than silently falling back to another backend or panicking — see the
/// module docs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AppleContainerError {
    /// The operation is part of the backend's design but has no
    /// implementation yet; `milestone` names the work that provides it.
    #[error("apple-container backend cannot {operation} yet — {milestone}")]
    NotImplemented {
        operation: &'static str,
        milestone: &'static str,
    },

    /// A boot artifact is absent from the cache; `hint` names the exact
    /// fetch/build step that provides it.
    #[error("apple-container artifact missing: {what} at {path} — {hint}")]
    ArtifactMissing {
        what: &'static str,
        path: String,
        hint: &'static str,
    },

    #[error(
        "apple-container backend cannot attach block volume '{host}' — the framework \
         attaches block devices only; use a directory-share volume instead"
    )]
    DiskVolumeNotSupported { host: String },

    #[error(
        "apple-container backend has no virtiofs-root boot — the framework boots a block \
         rootfs or shares host directories; select a microVM backend for virtiofs-root"
    )]
    VirtiofsRootNotSupported,

    /// The shim failed or could not be reached for `op`.
    #[error("apple-container shim {op} failed: {reason}")]
    Shim { op: &'static str, reason: String },
}

/// Apple Containerization-framework backend. See the module docs for what
/// is wired and what still fails closed.
#[derive(Debug, Default, Clone)]
pub struct AppleContainerBackend;

impl AppleContainerBackend {
    /// Construct the backend. Side-effect free — no Containerization
    /// symbol is touched and no VM state is read.
    pub fn new() -> Self {
        Self
    }
}

/// The shim cache root: `<mvm_cache_dir>/apple-container`.
fn apple_container_cache_dir() -> PathBuf {
    PathBuf::from(mvm_cache_dir()).join("apple-container")
}

/// Resolve the shim binary, failing closed with the exact build step.
fn resolve_shim_binary() -> std::result::Result<PathBuf, AppleContainerError> {
    let path = apple_container_cache_dir().join("bin/mvm-container-shim");
    if path.is_file() {
        return Ok(path);
    }
    Err(AppleContainerError::ArtifactMissing {
        what: "the container shim",
        path: path.display().to_string(),
        hint: "run `just apple-container-shim` to build and codesign it",
    })
}

/// Resolve the framework kernel: the launch's explicit kernel when given
/// (the CLI-resolved workload kernel), else the cached artifact.
fn resolve_kernel(config: &VmStartConfig) -> std::result::Result<PathBuf, AppleContainerError> {
    if let Some(k) = config.kernel_path.as_deref() {
        let path = PathBuf::from(k);
        if path.is_file() {
            return Ok(path);
        }
    }
    let path = apple_container_cache_dir().join("vmlinux");
    if path.is_file() {
        return Ok(path);
    }
    Err(AppleContainerError::ArtifactMissing {
        what: "the framework kernel",
        path: path.display().to_string(),
        hint: "run `mvmctl kernel build --which workload` and copy the artifact here",
    })
}

/// Resolve the framework initfs (carrying `/sbin/vminitd` + `/sbin/vmexec`).
fn resolve_initfs() -> std::result::Result<PathBuf, AppleContainerError> {
    let path = apple_container_cache_dir().join("initfs.ext4");
    if path.is_file() {
        return Ok(path);
    }
    Err(AppleContainerError::ArtifactMissing {
        what: "the framework initfs",
        path: path.display().to_string(),
        hint: "build it with `make init` in apple/containerization (needs the Swift static Linux SDK) and copy it here",
    })
}

/// Resolve the static musl guest-agent binary through the shared
/// resolve-or-build helper (never a forked copy).
fn resolve_guest_agent_binary() -> Result<PathBuf> {
    let cache_root = PathBuf::from(mvm_cache_dir());
    let binaries = mvm_build::run_image::resolve_guest_binaries(&cache_root, None)
        .context("resolve the mvm-guest-agent binary for the container")?;
    Ok(binaries.agent)
}

/// The per-VM shim paths, derived from the state dir in one place so the
/// spawn path, the lifecycle ops, and tests cannot drift.
#[derive(Debug, Clone)]
struct ShimPaths {
    state_dir: PathBuf,
    pid_file: PathBuf,
    spec_file: PathBuf,
    control_socket: PathBuf,
    boot_log_dir: PathBuf,
}

impl ShimPaths {
    fn for_vm(name: &str) -> Self {
        let state_dir = vm_state_dir(name);
        Self {
            pid_file: state_dir.join(SHIM_PID_FILE),
            spec_file: state_dir.join(SHIM_SPEC_FILE),
            control_socket: state_dir.join(SHIM_CONTROL_SOCKET),
            boot_log_dir: state_dir.join(SHIM_BOOT_LOG_DIR),
            state_dir,
        }
    }
}

/// Connect to a running VM's shim, if its pid file says one exists. `None`
/// when nothing was started (a trivially-honest answer follows).
fn connect_shim(paths: &ShimPaths) -> Option<ShimClient> {
    if !paths.pid_file.is_file() {
        return None;
    }
    ShimClient::connect(&paths.control_socket, std::time::Duration::from_secs(2)).ok()
}

/// Write the spec JSON, spawn the shim, and prove it answers.
fn boot_shim(paths: &ShimPaths, spec: &AppleContainerSpec) -> Result<ShimClient> {
    let shim_bin = resolve_shim_binary()?;
    let json = serde_json::to_string_pretty(spec).context("serialize container spec")?;
    std::fs::write(&paths.spec_file, json)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", paths.spec_file.display()))?;
    let mut client = spawn_shim(
        &shim_bin,
        &paths.spec_file,
        &paths.control_socket,
        &paths.pid_file,
    )?;
    client.ping()?;
    Ok(client)
}

/// Inject everything the guest needs: the run dir, the static guest-agent
/// binary (executable), and the serialized activation message every other
/// backend builds. The shim streams each file whole over the container's
/// copy channel, so no chunking is needed even for the ~1 MiB agent.
fn inject_guest_files(
    client: &mut ShimClient,
    agent_binary: &Path,
    activation_json: &[u8],
) -> Result<(), AppleContainerError> {
    client.mkdir(GUEST_RUN_DIR, true, 0o700)?;
    let agent_bytes = std::fs::read(agent_binary).map_err(|e| AppleContainerError::Shim {
        op: "read guest agent",
        reason: format!("read {}: {e}", agent_binary.display()),
    })?;
    client.write_file(GUEST_AGENT_PATH, &agent_bytes, 0o755)?;
    client.write_file(GUEST_ACTIVATION_PATH, activation_json, 0o644)?;
    Ok(())
}

/// Tear down a just-booted VM when a later step fails closed: ask the shim
/// to stop its container (which also makes the shim exit), then drop the
/// shim's pid/spec sidecars so a retry re-boots cleanly.
fn teardown_shim(client: ShimClient, paths: &ShimPaths) {
    let mut client = client;
    let _ = client.stop();
    let _ = std::fs::remove_file(&paths.pid_file);
    let _ = std::fs::remove_file(&paths.spec_file);
}

impl VmBackend for AppleContainerBackend {
    fn name(&self) -> &str {
        "apple-container"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::AppleContainer
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // Framework VMs route egress through the same host-mediated
            // endpoint seam every other backend uses — no routable guest
            // NIC (the shim attaches no network interface).
            no_routable_guest_nic: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        reject_unsupported_start_config(config)?;
        let kernel = resolve_kernel(config)?;
        let initfs = resolve_initfs()?;
        let agent_binary = resolve_guest_agent_binary()?;

        let paths = ShimPaths::for_vm(&config.name);
        std::fs::create_dir_all(&paths.state_dir)
            .map_err(|e| anyhow::anyhow!("create state dir {}: {e}", paths.state_dir.display()))?;
        std::fs::create_dir_all(&paths.boot_log_dir).map_err(|e| {
            anyhow::anyhow!("create boot log dir {}: {e}", paths.boot_log_dir.display())
        })?;

        let spec = build_apple_container_spec(
            config,
            &SpecInputs {
                kernel_path: &kernel,
                initfs_path: &initfs,
                control_socket: &paths.control_socket,
                boot_log_dir: &paths.boot_log_dir,
                agent_port: crate::vm::vminitd_client::GUEST_AGENT_VSOCK_PORT,
            },
        );
        let activation = crate::microvm::build_activation_environment(config)?;
        let activation_json =
            serde_json::to_vec_pretty(&activation).context("serialize activation environment")?;

        let mut client = match boot_shim(&paths, &spec) {
            Ok(client) => client,
            Err(e) => {
                teardown_shim_files_only(&paths);
                return Err(e);
            }
        };
        if let Err(e) = inject_guest_files(&mut client, &agent_binary, &activation_json) {
            teardown_shim(client, &paths);
            return Err(e.into());
        }

        // Everything the guest needs is in place; what the guest agent
        // cannot yet do is consume it — it has no activation-file entry
        // point. Tear the VM down so a half-boot never lingers silently,
        // then fail closed naming the milestone.
        teardown_shim(client, &paths);
        Err(AppleContainerError::NotImplemented {
            operation: "launch the guest agent inside the container VM",
            milestone: "the guest-agent activation-file entry point (stage 4)",
        }
        .into())
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        let paths = ShimPaths::for_vm(&id.0);
        match connect_shim(&paths) {
            Some(mut client) => {
                let code = client.wait()?;
                Ok(VmExitStatus {
                    code: i32::try_from(code).ok(),
                    success: code == 0,
                })
            }
            // Nothing was ever started for this VM.
            None => Ok(VmExitStatus::UNKNOWN),
        }
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "pause a container VM",
            milestone: "a Containerization pause/resume surface (none exists yet)",
        }
        .into())
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "resume a container VM",
            milestone: "a Containerization pause/resume surface (none exists yet)",
        }
        .into())
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let paths = ShimPaths::for_vm(&id.0);
        if let Some(mut client) = connect_shim(&paths) {
            // Graceful stop first; escalate to a kill if the shim's own
            // teardown path fails (the container must not outlive the op).
            if client.stop().is_err() {
                let _ = client.kill();
            }
        } else if let Some(pid) = crate::qemu::read_pid(&paths.pid_file) {
            // The control socket is gone but the shim may still be up:
            // signal it; the shim stops its VM on exit.
            crate::qemu::send_signal(pid, libc::SIGTERM);
        }
        let _ = std::fs::remove_file(&paths.pid_file);
        let _ = std::fs::remove_file(&paths.spec_file);
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let mut last_err = None;
        for name in shim_vm_names() {
            if let Err(e) = self.stop(&VmId(name.clone())) {
                tracing::warn!(name, error = %e, "apple-container stop_all: stop failed");
                last_err = Some(e);
            }
        }
        last_err.map_or(Ok(()), Err)
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let paths = ShimPaths::for_vm(&id.0);
        Ok(match crate::qemu::read_pid(&paths.pid_file) {
            Some(pid) if crate::qemu::pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let mut vms = Vec::new();
        for name in shim_vm_names() {
            let paths = ShimPaths::for_vm(&name);
            let status = match crate::qemu::read_pid(&paths.pid_file) {
                Some(pid) if crate::qemu::pid_alive(pid) => VmStatus::Running,
                _ => VmStatus::Stopped,
            };
            vms.push(VmInfo {
                id: VmId(name.clone()),
                name,
                status,
                guest_ip: None,
                cpus: 0,
                memory_mib: 0,
                profile: None,
                revision: None,
                flake_ref: None,
                ports: Vec::new(),
            });
        }
        Ok(vms)
    }

    fn logs(&self, id: &VmId, lines: u32, _hypervisor: bool) -> Result<String> {
        // One boot stream (the framework's serial log), whether the caller
        // asked for the "hypervisor" log or not.
        let log = vm_state_dir(&id.0).join(SHIM_BOOT_LOG_DIR).join("boot.log");
        let body = std::fs::read_to_string(&log).unwrap_or_default();
        Ok(tail(&body, lines as usize))
    }

    fn is_available(&self) -> Result<bool> {
        Ok(cfg!(target_os = "macos") && resolve_shim_binary().is_ok())
    }

    fn install(&self) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "install the Apple Containerization runtime",
            milestone: "run `just apple-container-shim` plus the kernel/initfs artifact fetches (see the ArtifactMissing hints)",
        }
        .into())
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Every numbered claim still reports `DoesNotHold`: the boot
        // machinery is wired through vminitd injection, but no workload has
        // ever booted to activation, so nothing here may be claimed. The
        // tier string keeps saying so honestly.
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 2 (Apple Containerization framework; boot path wired, no agent bring-up yet)",
            notes: &[
                "Apple Containerization-framework VMs are hardware-isolated lightweight \
                 Linux VMs; the framework owns the kernel boot and `vminitd` as guest PID 1.",
                "The container shim boots the framework VM and injects the static guest \
                 agent plus the serialized activation message through vminitd's API (vsock \
                 port 1024); the agent's own activation entry point is the remaining gap.",
                "Every claim reports DoesNotHold until a workload boots to activation — \
                 nothing here may carry an untrusted workload yet.",
                "Opt-in only; never selected by auto-detect.",
            ],
        }
    }
}

/// Names of VMs with a shim pid file under `vms_dir()`. Directory scan
/// keyed on the pid file, mirroring the QEMU backend's list convention.
fn shim_vm_names() -> Vec<String> {
    let root = vms_dir();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() || !path.join(SHIM_PID_FILE).exists() {
            continue;
        }
        if let Ok(name) = entry.file_name().into_string() {
            names.push(name);
        }
    }
    names.sort();
    names
}

/// Roll back only the on-disk sidecars when the shim never came up (nothing
/// to stop through the control socket).
fn teardown_shim_files_only(paths: &ShimPaths) {
    let _ = std::fs::remove_file(&paths.pid_file);
    let _ = std::fs::remove_file(&paths.spec_file);
}

fn tail(s: &str, n: usize) -> String {
    if n == 0 {
        return String::new();
    }
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AnyBackend;

    fn cfg(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Extract the typed error from the `anyhow` wrapper the trait returns,
    /// so tests assert the exact variant, not a substring.
    fn typed(err: &anyhow::Error) -> &AppleContainerError {
        err.downcast_ref::<AppleContainerError>()
            .expect("apple-container failures must be the typed error")
    }

    #[test]
    fn kind_and_name_are_apple_container() {
        let b = AppleContainerBackend::new();
        assert_eq!(b.name(), "apple-container");
        assert_eq!(b.kind(), BackendKind::AppleContainer);
    }

    #[test]
    fn selector_and_alias_resolve_through_any_backend() {
        for sel in ["apple-container", "container"] {
            let backend = AnyBackend::from_hypervisor(sel);
            assert!(
                matches!(backend, AnyBackend::AppleContainer(_)),
                "selector {sel} must resolve to the apple-container backend"
            );
            assert_eq!(backend.name(), "apple-container");
            assert_eq!(backend.kind(), BackendKind::AppleContainer);
        }
    }

    #[test]
    fn auto_select_never_returns_apple_container() {
        assert_ne!(
            AnyBackend::auto_select().kind(),
            BackendKind::AppleContainer,
            "auto_select must never fall through to the apple-container tier"
        );
    }

    #[test]
    fn capabilities_are_honest() {
        let caps = AppleContainerBackend::new().capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert_eq!(caps.snapshot_capability, SnapshotCapability::Unsupported);
        assert!(!caps.standby_pool);
        assert!(!caps.tap_networking);
        assert!(!caps.balloon);
        assert!(!caps.pty_exec);
        assert!(!caps.production_ssh);
        assert!(caps.no_routable_guest_nic);
    }

    #[test]
    fn security_profile_still_carries_zero_numbered_claims() {
        let profile = AppleContainerBackend::new().security_profile();
        assert!(
            profile
                .claims
                .iter()
                .all(|c| matches!(c, ClaimStatus::DoesNotHold)),
            "nothing may be claimed before a workload boots to activation"
        );
        assert_eq!(profile.dropped_claims(), vec![1, 2, 3, 4, 5, 6, 7]);
        assert!(profile.tier.starts_with("Tier 2"), "tier: {}", profile.tier);
    }

    #[test]
    fn snapshot_and_standby_and_pause_resume_fail_closed() {
        use mvm_core::vm_backend::WarmStartError;
        let b = AppleContainerBackend::new();
        assert_eq!(b.snapshot_capability(), SnapshotCapability::Unsupported);
        match b.warm_start(&VmStartConfig::default(), SnapshotCapability::DiskOnly) {
            Err(WarmStartError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert!(!b.supports_standby_pool());
        let id = VmId("x".to_string());
        assert!(matches!(
            typed(&b.pause(&id).unwrap_err()),
            AppleContainerError::NotImplemented { .. }
        ));
        assert!(matches!(
            typed(&b.resume(&id).unwrap_err()),
            AppleContainerError::NotImplemented { .. }
        ));
    }

    #[test]
    fn start_fails_closed_with_typed_error_after_injection_wiring() {
        let b = AppleContainerBackend::new();
        let err = b.start(&cfg("start-fail-closed-test")).unwrap_err();
        assert!(
            matches!(
                typed(&err),
                AppleContainerError::ArtifactMissing { .. }
                    | AppleContainerError::Shim { .. }
                    | AppleContainerError::NotImplemented { .. }
            ),
            "start must fail closed with a typed error (artifact, shim, or milestone): {err}"
        );
    }

    #[test]
    fn stop_status_list_wait_are_honest_for_a_never_started_vm() {
        let b = AppleContainerBackend::new();
        let id = VmId("ac-never-started-test-vm".to_string());
        assert!(b.stop(&id).is_ok());
        assert_eq!(b.status(&id).unwrap(), VmStatus::Stopped);
        assert_eq!(b.wait(&id).unwrap(), VmExitStatus::UNKNOWN);
        assert!(!b.list().unwrap().iter().any(|v| v.name == id.0));
    }

    #[test]
    fn shim_paths_are_derived_from_the_state_dir() {
        let paths = ShimPaths::for_vm("paths-test");
        let state = vm_state_dir("paths-test");
        assert_eq!(paths.pid_file, state.join(SHIM_PID_FILE));
        assert_eq!(paths.control_socket, state.join(SHIM_CONTROL_SOCKET));
        assert_eq!(paths.boot_log_dir, state.join(SHIM_BOOT_LOG_DIR));
    }

    #[test]
    fn logs_tails_the_boot_log() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let log_dir = vm_state_dir("logs-test").join(SHIM_BOOT_LOG_DIR);
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(log_dir.join("boot.log"), "a\nb\nc\nd\n").unwrap();
        let b = AppleContainerBackend::new();
        assert_eq!(b.logs(&VmId("logs-test".into()), 2, false).unwrap(), "c\nd");
    }

    #[test]
    fn shim_vm_names_finds_only_dirs_with_a_shim_pid_file() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let with_pid = vm_state_dir("ac-vm-with-pid");
        std::fs::create_dir_all(&with_pid).unwrap();
        std::fs::write(with_pid.join(SHIM_PID_FILE), "123").unwrap();
        std::fs::create_dir_all(vm_state_dir("ac-vm-without-pid")).unwrap();
        assert_eq!(shim_vm_names(), vec!["ac-vm-with-pid".to_string()]);
    }

    #[test]
    fn connect_shim_is_none_without_a_pid_file() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_HOME", dir.path());
        let paths = ShimPaths::for_vm("connect-none-test");
        assert!(connect_shim(&paths).is_none());
    }

    /// macOS-only, gated live smoke: requires the shim binary, a framework
    /// kernel, and an initfs under the cache (see `ArtifactMissing` hints).
    /// Run with `MVM_AC_E2E=1 cargo test -p mvm-runtime --features
    /// apple-container ac_e2e -- --ignored`.
    #[cfg(all(target_os = "macos", feature = "apple-container"))]
    #[test]
    #[ignore = "requires shim + kernel + initfs artifacts (MVM_AC_E2E=1 to run)"]
    fn ac_e2e_boots_a_framework_vm_and_injects_files() {
        if std::env::var("MVM_AC_E2E").is_err() {
            return;
        }
        // The artifact precondition is the whole gate: without them the
        // backend fails closed long before this point.
        let kernel = resolve_kernel(&cfg("ac-e2e")).expect("framework kernel");
        let initfs = resolve_initfs().expect("framework initfs");
        let paths = ShimPaths::for_vm("ac-e2e");
        std::fs::create_dir_all(&paths.state_dir).unwrap();
        std::fs::create_dir_all(&paths.boot_log_dir).unwrap();
        let mut config = cfg("ac-e2e");
        config.rootfs_path = "<an ext4 rootfs>".into();
        let spec = build_apple_container_spec(
            &config,
            &SpecInputs {
                kernel_path: &kernel,
                initfs_path: &initfs,
                control_socket: &paths.control_socket,
                boot_log_dir: &paths.boot_log_dir,
                agent_port: crate::vm::vminitd_client::GUEST_AGENT_VSOCK_PORT,
            },
        );
        let mut client = boot_shim(&paths, &spec).expect("shim boots and answers ping");
        client
            .mkdir("/run/mvm", true, 0o700)
            .expect("mkdir via vminitd");
        client
            .write_file("/run/mvm/hello", b"hi", 0o644)
            .expect("file injection via the copy channel");
        let _ = client.stop();
    }
}
