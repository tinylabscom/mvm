//! Apple Container backend: Apple's guest stack booted on the in-house HVF VMM.
//!
//! `AppleContainerBackend` runs mvm workloads inside an Apple Container VM:
//! a lightweight, hardware-isolated Linux VM whose guest PID 1 is Apple's
//! `vminitd` (serving gRPC on vsock port 1024). The kernel boot is owned by
//! mvm's own HVF supervisor — the container kernel and the `initfs.ext4`
//! that carries `/sbin/vminitd` are resolved from the local artifact cache
//! ([`crate::apple_container::artifacts`]) and booted as described in
//! [`crate::apple_container::boot_spec`]. No Virtualization.framework, no
//! Swift shim: the only Apple-owned code in the picture is the guest-side
//! kernel + vminitd, running unmodified inside mvm's VMM.
//!
//! Because vminitd owns PID 1, the mvm initramfs does not apply verbatim
//! here — activation rides vminitd's gRPC API instead
//! ([`crate::apple_container::vminitd`]): the host injects the guest-agent
//! binary and the activation environment JSON, then asks vminitd to run the
//! agent. The agent binary, the mount logic, the uid-901 privilege drop,
//! the `NotActivated` RPC gate, and the operational RPC surface stay shared
//! verbatim with every other backend.
//!
//! What is wired today, and what is fail-closed: the full bring-up is real
//! — resolve artifacts, assemble the supervisor config, boot the HVF
//! supervisor, connect to vminitd, inject the agent + activation
//! environment + host-signer trust anchor, `CreateProcess`/`StartProcess`
//! the agent, and wait for it to self-apply the activation file in
//! container mode (private mount namespace + chroot, uid-901 drop) and
//! answer an authenticated control Ping. `start` returns with the VM
//! running; `stop` (agent SIGTERM via vminitd, then supervisor), `status`,
//! `list` (marker-file inventory), `wait` (vminitd `WaitProcess` on the
//! agent), and `logs` (console capture) are real; `pause` and `resume`
//! stay fail-closed. Every failure rolls the VM back.
//!
//! Honest reporting, not silent degradation: `capabilities()` advertises no
//! snapshot, no standby pool, and no warm start; `security_profile()`
//! reports every numbered claim as `DoesNotHold` until the bring-up has
//! been validated end-to-end with the real artifacts; and the backend is
//! opt-in only — `AnyBackend::auto_select` never returns this kind.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, StartMode,
    VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};
use thiserror::Error;

use crate::apple_container::vminitd::VminitdClient;
use crate::apple_container::{artifacts, boot_spec};
use crate::hvf_backend::{
    PID_FILE_NAME, PID_FILE_TIMEOUT, read_pid, resolve_supervisor_path, terminate_pid,
};

/// How long `start` waits for vminitd to answer on its vsock port after the
/// supervisor confirms the boot. The guest has to boot the kernel, mount
/// the initfs, and start the gRPC server, so this is far longer than the
/// supervisor's own pid-file confirmation.
const VMINITD_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How long `start` waits for the injected agent to self-apply the
/// activation file (mounts, chroot, privilege drop) and answer an
/// authenticated control Ping.
const AGENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(120);

/// vminitd process id for the guest agent (vminitd-scoped, not a PID).
const AGENT_PROCESS_ID: &str = "mvm-guest-agent";

/// Marker file dropped into the VM state dir on a successful bring-up, so
/// `list`/`stop_all` can tell this backend's VMs apart from the HVF
/// driver's (which shares the state-dir and pid-file convention).
const STATE_MARKER_FILE: &str = "apple-container.marker";

/// Typed, fail-closed errors for requests this backend cannot satisfy.
/// Every error names what was refused and why, rather than silently falling
/// back to another backend or panicking — see the module docs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AppleContainerError {
    /// The operation is part of the backend's design but has no
    /// implementation yet; `milestone` names the work that provides it.
    #[error("apple-container backend cannot {operation} yet — {milestone}")]
    NotImplemented {
        operation: &'static str,
        milestone: &'static str,
    },
    /// A required boot artifact (kernel or initfs) is not in the cache;
    /// `hint` names the build command that produces it.
    #[error("apple-container artifact missing: {what} at {path} — {hint}")]
    ArtifactMissing {
        what: &'static str,
        path: String,
        hint: &'static str,
    },
    /// The workload config asks for a shape this boot path does not
    /// support; `reason` says why.
    #[error("apple-container backend does not support {feature}: {reason}")]
    UnsupportedConfig {
        feature: &'static str,
        reason: &'static str,
    },
}

/// Apple Container backend. See the module docs for what is wired, what is
/// fail-closed, and the opt-in/honest-reporting rules.
#[derive(Debug, Default, Clone)]
pub struct AppleContainerBackend;

impl AppleContainerBackend {
    /// Construct the backend. Side-effect free — no artifact is probed and
    /// no VM state is read at construction.
    pub fn new() -> Self {
        Self
    }

    /// Boot the supervisor for an already-assembled config, connect to
    /// vminitd, run the injection sequence, and wait for the agent to
    /// finish its container-mode activation and answer Ping. On success
    /// the VM stays running; the caller owns the VmId answer.
    fn boot_and_activate(
        &self,
        config: &VmStartConfig,
        artifacts: &artifacts::AppleContainerArtifacts,
        state_dir: &Path,
    ) -> Result<()> {
        let spec = boot_spec::build_supervisor_config(&boot_spec::BootSpecInput {
            config,
            artifacts,
            state_dir,
            timeout_secs: 0,
        })?;
        let _supervisor = spawn_supervisor(state_dir, &spec)?;

        let mut client =
            connect_vminitd(state_dir).context("connect to vminitd inside the container VM")?;

        let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let binaries = mvm_build::run_image::resolve_guest_binaries(&cache_root, None)
            .context("resolve the mvm-guest-agent binary for injection")?;
        let agent_bytes = std::fs::read(&binaries.agent)
            .with_context(|| format!("read guest agent binary {}", binaries.agent.display()))?;
        let environment = crate::microvm::build_activation_environment(config)
            .context("build the activation environment for the container VM")?;
        let activation_json =
            serde_json::to_vec(&environment).context("serialize the activation environment")?;
        // The agent pins the host-signer trust anchor from
        // `/run/mvm/host-signer.pub` and rejects control connections
        // without it — inject the host's pubkey when one exists. (When
        // none does, the wait below times out and the boot rolls back,
        // which is the same fail-closed posture as every other backend.)
        let host_signer_pub = mvm_core::config::mvm_keys_dir().join("host-signer.pub");
        let host_signer_bytes = std::fs::read(&host_signer_pub).ok();

        inject_agent(
            &mut client,
            &agent_bytes,
            &activation_json,
            host_signer_bytes.as_deref(),
        )
        .context("vminitd injection sequence")?;

        wait_for_agent(state_dir).context("guest agent did not come up")?;
        Ok(())
    }
}

/// Spawn `mvm-hvf-supervisor` with `spec` on its stdin and wait for the pid
/// file that confirms the boot, mirroring the HVF driver's launch pattern.
/// The returned child may be dropped — the supervisor daemonizes its
/// lifecycle behind the pid file, which is how `stop`/`status` find it.
fn spawn_supervisor(
    state_dir: &Path,
    spec: &mvm_build::hvf_supervisor::HvfSupervisorConfig,
) -> Result<Child> {
    // Clear any prior run's exit file so a later `wait` reads only this
    // launch's result.
    let _ = std::fs::remove_file(state_dir.join("workload.exit"));
    let json = serde_json::to_string(spec).context("serialize HvfSupervisorConfig")?;

    let supervisor = resolve_supervisor_path()?;
    let mut child = Command::new(&supervisor)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
        .write_all(json.as_bytes())
        .map_err(|e| anyhow!("pipe HvfSupervisorConfig to supervisor stdin: {e}"))?;

    let pid_file = state_dir.join(PID_FILE_NAME);
    let deadline = Instant::now() + PID_FILE_TIMEOUT;
    loop {
        if pid_file.exists() {
            return Ok(child);
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("poll supervisor: {e}"))?
        {
            bail!(
                "hvf supervisor exited before writing its PID file (status: {status}); see {}",
                state_dir.join("console.log").display()
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "hvf supervisor did not confirm boot within {PID_FILE_TIMEOUT:?}; see {}",
                state_dir.join("console.log").display()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Connect to vminitd through the supervisor's host UDS, retrying until the
/// guest has booted far enough to answer (or the deadline passes).
fn connect_vminitd(state_dir: &Path) -> Result<VminitdClient> {
    let sock = boot_spec::vminitd_host_socket(state_dir);
    let deadline = Instant::now() + VMINITD_CONNECT_TIMEOUT;
    loop {
        match VminitdClient::connect(&sock) {
            Ok(client) => return Ok(client),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e).context(format!(
                        "vminitd did not answer within {VMINITD_CONNECT_TIMEOUT:?}"
                    ));
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

/// The injection sequence against a live vminitd: stage the agent binary,
/// the activation environment, and (when the host has one) the host-signer
/// trust anchor under `/run/mvm`, then register and start the agent
/// process.
fn inject_agent(
    client: &mut VminitdClient,
    agent_bytes: &[u8],
    activation_json: &[u8],
    host_signer_pub: Option<&[u8]>,
) -> Result<(), crate::apple_container::vminitd::VminitdError> {
    client.mkdir(boot_spec::INJECTION_GUEST_DIR, true, 0o700)?;
    client.write_file(boot_spec::AGENT_GUEST_PATH, agent_bytes, 0o755)?;
    client.write_file(boot_spec::ACTIVATION_GUEST_PATH, activation_json, 0o644)?;
    if let Some(pubkey) = host_signer_pub {
        client.write_file(boot_spec::HOST_SIGNER_PUB_GUEST_PATH, pubkey, 0o644)?;
    }
    client.create_process(AGENT_PROCESS_ID, boot_spec::agent_process_config())?;
    let pid = client.start_process(AGENT_PROCESS_ID)?;
    if pid <= 0 {
        return Err(crate::apple_container::vminitd::VminitdError::Transport(
            format!("vminitd reported a non-positive pid ({pid}) for the guest agent"),
        ));
    }
    Ok(())
}

/// Poll the agent's host-bridged vsock socket until it answers an
/// authenticated Ping — proof the agent self-applied the activation file
/// (mounts, chroot, uid-901 drop) and is serving operational RPCs. The
/// Ping rides the standard authenticated session handshake every backend's
/// host side uses.
fn wait_for_agent(state_dir: &Path) -> Result<()> {
    let sock = mvm_core::config::vm_hvf_agent_socket_at(state_dir);
    let sock = sock.to_string_lossy().into_owned();
    let deadline = Instant::now() + AGENT_CONNECT_TIMEOUT;
    loop {
        let attempt = mvm_agentd::vsock::ping_at(&sock);
        if matches!(attempt, Ok(true)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let detail = match attempt {
                Ok(true) => return Ok(()),
                Ok(false) => "agent answered Ping with a non-Pong response".to_string(),
                Err(e) => e.to_string(),
            };
            bail!(
                "guest agent did not answer an authenticated Ping within {AGENT_CONNECT_TIMEOUT:?} \
                 (last error: {detail}); see {}",
                state_dir.join("console.log").display()
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Stop the VM owned by `state_dir`, if its supervisor is running. Errors
/// are swallowed deliberately: teardown is best-effort cleanup on an error
/// path whose original error is the one that matters.
fn teardown(state_dir: &Path) {
    let pid_file = state_dir.join(PID_FILE_NAME);
    if let Some(pid) = read_pid(&pid_file) {
        terminate_pid(pid);
    }
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
            // The container VM routes egress through the same host-mediated
            // vsock endpoint seam every other backend uses — no routable
            // guest NIC.
            no_routable_guest_nic: true,
            // vminitd's control channel and the guest agent both ride vsock.
            vsock: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        // Validation failures are typed and cheap; artifact resolution
        // comes first so a missing cache reports before anything is
        // created on disk.
        let artifacts = artifacts::resolve()?;
        let state_dir = mvm_core::config::vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
        let _ = crate::libkrun::open_console_capture(&state_dir.join("console.log"));

        // Rollback on any failure: a half-brought-up VM is torn down before
        // the error propagates, so nothing unreachable is left running.
        if let Err(e) = self.boot_and_activate(config, &artifacts, &state_dir) {
            teardown(&state_dir);
            return Err(e);
        }
        // Mark the state dir as this backend's so `list`/`stop_all` can
        // distinguish it from the HVF driver's VMs (shared convention).
        std::fs::write(state_dir.join(STATE_MARKER_FILE), b"")
            .map_err(|e| anyhow!("write state marker in {}: {e}", state_dir.display()))?;
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        let state_dir = mvm_core::config::vm_state_dir(&id.0);
        if read_pid(&state_dir.join(PID_FILE_NAME)).is_none() {
            bail!("container VM {} is not running", id.0);
        }
        let mut client = connect_vminitd(&state_dir).context("connect to vminitd for wait")?;
        let code = client
            .wait_process(AGENT_PROCESS_ID)
            .context("vminitd WaitProcess for the guest agent")?;
        Ok(VmExitStatus {
            code: Some(code),
            success: code == 0,
        })
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "pause a container VM",
            milestone: "pause/resume support for the HVF supervisor boot path",
        }
        .into())
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "resume a container VM",
            milestone: "pause/resume support for the HVF supervisor boot path",
        }
        .into())
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let state_dir = mvm_core::config::vm_state_dir(&id.0);
        // Graceful first: signal the agent through vminitd so it can drain,
        // then terminate the supervisor (which ends the VM and every guest
        // process with it). The signal is best-effort — a single-shot
        // connect fails fast when the VM is already gone.
        if let Ok(mut client) = VminitdClient::connect(&boot_spec::vminitd_host_socket(&state_dir))
        {
            let _ = client.signal_process(AGENT_PROCESS_ID, libc::SIGTERM);
        }
        if let Some(pid) = read_pid(&state_dir.join(PID_FILE_NAME)) {
            terminate_pid(pid);
        }
        let _ = std::fs::remove_file(state_dir.join(STATE_MARKER_FILE));
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        for info in self.list()? {
            if matches!(info.status, VmStatus::Running) {
                self.stop(&info.id)?;
            }
        }
        Ok(())
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let pid_file = mvm_core::config::vm_state_dir(&id.0).join(PID_FILE_NAME);
        let running = pid_file.exists() && read_pid(&pid_file).is_some();
        Ok(if running {
            VmStatus::Running
        } else {
            VmStatus::Stopped
        })
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        // The state-dir convention is shared with the HVF driver, so the
        // marker file written at bring-up is the only honest discriminator.
        let root = mvm_core::config::vms_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.join(STATE_MARKER_FILE).exists() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let alive =
                read_pid(&dir.join(PID_FILE_NAME)).is_some_and(crate::hvf_backend::pid_alive);
            vms.push(VmInfo {
                id: VmId(name.clone()),
                name,
                status: if alive {
                    VmStatus::Running
                } else {
                    VmStatus::Stopped
                },
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
        let console = mvm_core::config::vm_state_dir(&id.0).join("console.log");
        let text = std::fs::read_to_string(&console).with_context(|| {
            format!(
                "read the container VM console log at {} (has the VM been started?)",
                console.display()
            )
        })?;
        let all: Vec<&str> = text.lines().collect();
        let start = all.len().saturating_sub(lines as usize);
        Ok(all[start..].join("\n"))
    }

    fn is_available(&self) -> Result<bool> {
        // The boot path is HVF-only (macOS) and needs both artifacts in the
        // cache; reporting `true` without them would let a probe conclude a
        // workload could start here.
        Ok(cfg!(target_os = "macos") && artifacts::resolve().is_ok())
    }

    fn install(&self) -> Result<()> {
        Err(AppleContainerError::NotImplemented {
            operation: "install the Apple Container boot artifacts",
            milestone: "an artifact-fetch command (build the kernel and initfs from \
                        Apple's containerization package and copy them into the cache)",
        }
        .into())
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Every numbered claim reports `DoesNotHold` until the bring-up has
        // been validated end-to-end with the real artifacts: the path is
        // fully wired, but nothing here may carry an untrusted workload on
        // the strength of unit tests alone. Apple's container VMs are
        // hardware-isolated lightweight Linux VMs, which is the Tier 2
        // shape this backend is being built toward; the tier string says so
        // honestly rather than rounding the posture up.
        BackendSecurityProfile {
            claims: [ClaimStatus::DoesNotHold; 7],
            layer_coverage: LayerCoverage::default(),
            tier: "Tier 2 (Apple Container guest stack on the in-house HVF VMM; pending e2e validation)",
            notes: &[
                "Apple Container VMs are hardware-isolated lightweight Linux VMs; the guest \
                 kernel and `vminitd` (PID 1, gRPC on vsock port 1024) come from Apple's \
                 containerization package, booted unmodified by mvm's own HVF supervisor.",
                "Activation rides vminitd's gRPC API (vsock port 1024) instead of an mvm \
                 initramfs; the agent self-applies the injected activation file in container \
                 mode (private mount namespace + chroot, uid-901 drop) and then serves the \
                 same operational RPC surface on vsock port 5252 as every other backend.",
                "Every claim reports DoesNotHold until the bring-up is validated end-to-end \
                 with the real artifacts — nothing here may carry an untrusted workload yet.",
                "Opt-in only; never selected by auto-detect.",
            ],
        }
    }
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
        // Opt-in only, same discipline as the wasm tier: `auto_select`'s
        // ladder constructs Firecracker/Hvf/Libkrun and nothing else, so this
        // holds on every platform the ladder can resolve to.
        assert_ne!(
            AnyBackend::auto_select().kind(),
            BackendKind::AppleContainer,
            "auto_select must never fall through to the apple-container backend"
        );
    }

    #[test]
    fn capabilities_are_honest_about_the_partial_boot_path() {
        let caps = AppleContainerBackend::new().capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert_eq!(caps.snapshot_capability, SnapshotCapability::Unsupported);
        assert!(!caps.standby_pool);
        assert!(caps.vsock, "vminitd and the agent both ride vsock");
        assert!(!caps.tap_networking);
        assert!(!caps.balloon);
        assert!(!caps.fs_quick_checkpoint);
        assert!(!caps.host_vsock_proxy);
        assert!(!caps.pty_exec);
        assert!(!caps.production_ssh);
        assert!(caps.no_routable_guest_nic);
    }

    #[test]
    fn security_profile_carries_zero_numbered_claims() {
        let profile = AppleContainerBackend::new().security_profile();
        assert!(
            profile
                .claims
                .iter()
                .all(|c| matches!(c, ClaimStatus::DoesNotHold)),
            "the backend must not claim any numbered security guarantee"
        );
        assert_eq!(profile.dropped_claims(), vec![1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(profile.layer_coverage, LayerCoverage::default());
        assert!(
            profile.tier.starts_with("Tier 2"),
            "the tier string must agree with the catalog's Tier 2 classification: {}",
            profile.tier
        );
    }

    #[test]
    fn snapshot_capability_defaults_to_unsupported() {
        assert_eq!(
            AppleContainerBackend::new().snapshot_capability(),
            SnapshotCapability::Unsupported
        );
    }

    #[test]
    fn warm_start_fails_closed() {
        use mvm_core::vm_backend::{SnapshotCapability, WarmStartError};
        let b = AppleContainerBackend::new();
        match b.warm_start(&VmStartConfig::default(), SnapshotCapability::DiskOnly) {
            Err(WarmStartError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn standby_pool_fails_closed() {
        assert!(!AppleContainerBackend::new().supports_standby_pool());
    }

    #[test]
    fn start_fails_closed_with_a_typed_error() {
        // With no artifacts in the cache, start fails at resolution with
        // the typed ArtifactMissing (which also carries the build hint). If
        // the cache *does* have artifacts, start instead fails closed at
        // the final agent-bring-up step — either way it is a typed
        // AppleContainerError and never a panic or a silent fallback.
        let b = AppleContainerBackend::new();
        let err = b.start(&cfg("x")).unwrap_err();
        assert!(
            matches!(
                typed(&err),
                AppleContainerError::ArtifactMissing { .. }
                    | AppleContainerError::UnsupportedConfig { .. }
                    | AppleContainerError::NotImplemented { .. }
            ),
            "expected a typed apple-container error, got: {err}"
        );
    }

    #[test]
    fn start_reports_missing_artifacts_before_touching_disk() {
        // Point MVM_HOME (and HOME) at an empty tempdir so resolution
        // deterministically finds no artifacts, then assert the typed error
        // names the kernel.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        let err = b.start(&cfg("x")).unwrap_err();
        assert!(
            matches!(
                typed(&err),
                AppleContainerError::ArtifactMissing { what, .. } if what.contains("kernel")
            ),
            "expected the kernel ArtifactMissing, got: {err}"
        );
    }

    #[test]
    fn pause_resume_fail_closed_with_typed_errors() {
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        for err in [b.pause(&id).unwrap_err(), b.resume(&id).unwrap_err()] {
            assert!(
                matches!(typed(&err), AppleContainerError::NotImplemented { .. }),
                "expected a typed NotImplemented, got: {err}"
            );
        }
    }

    #[test]
    fn wait_errors_honestly_when_the_vm_is_not_running() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        let err = b.wait(&VmId("ac-wait-test".to_string())).unwrap_err();
        assert!(
            err.to_string().contains("is not running"),
            "wait on a stopped VM must say so, got: {err}"
        );
    }

    #[test]
    fn logs_reads_the_console_tail_and_errors_without_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        let id = VmId("ac-logs-test".to_string());
        assert!(b.logs(&id, 10, false).is_err(), "no console log yet");

        let state_dir = mvm_core::config::vm_state_dir(&id.0);
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(state_dir.join("console.log"), "one\ntwo\nthree\n").expect("console");
        assert_eq!(b.logs(&id, 2, false).unwrap(), "two\nthree");
        assert_eq!(b.logs(&id, 10, false).unwrap(), "one\ntwo\nthree");
    }

    #[test]
    fn list_and_stop_all_key_on_the_marker_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        assert!(b.list().unwrap().is_empty());

        // A marker without a live pid lists as Stopped; stop_all ignores it
        // (nothing to terminate) and stop clears the marker.
        let id = VmId("ac-marker-test".to_string());
        let state_dir = mvm_core::config::vm_state_dir(&id.0);
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(state_dir.join(STATE_MARKER_FILE), b"").expect("marker");
        let listed = b.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, id.0);
        assert_eq!(listed[0].status, VmStatus::Stopped);
        assert!(b.stop_all().is_ok());
        assert!(
            state_dir.join(STATE_MARKER_FILE).exists(),
            "stop_all skips stopped VMs, so the marker stays"
        );
        assert!(b.stop(&id).is_ok());
        assert!(
            !state_dir.join(STATE_MARKER_FILE).exists(),
            "stop clears the marker"
        );
        assert!(b.list().unwrap().is_empty());
    }

    #[test]
    fn stop_and_status_are_real_pid_file_answers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(dir.path());
        let b = AppleContainerBackend::new();
        let id = VmId("ac-status-test".to_string());
        // No pid file: stopped, and stop is a no-op success.
        assert_eq!(b.status(&id).unwrap(), VmStatus::Stopped);
        assert!(b.stop(&id).is_ok());
        // A pid file with a live pid (this test process) reads as running.
        let state_dir = mvm_core::config::vm_state_dir(&id.0);
        std::fs::create_dir_all(&state_dir).expect("state dir");
        std::fs::write(
            state_dir.join(PID_FILE_NAME),
            std::process::id().to_string(),
        )
        .expect("pid file");
        assert_eq!(b.status(&id).unwrap(), VmStatus::Running);
        // Do NOT call stop here — it would terminate this test process.
        assert!(b.list().unwrap().is_empty());
        assert!(b.stop_all().is_ok());
    }

    #[test]
    fn availability_tracks_artifact_presence() {
        let b = AppleContainerBackend::new();
        let expect = cfg!(target_os = "macos") && artifacts::resolve().is_ok();
        assert_eq!(b.is_available().unwrap(), expect);
        assert!(matches!(
            typed(&b.install().unwrap_err()),
            AppleContainerError::NotImplemented { .. }
        ));
    }

    #[test]
    fn network_info_and_guest_channel_info_fail_closed_by_default() {
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        assert!(b.network_info(&id).is_err());
        assert!(b.guest_channel_info(&id).is_err());
    }

    #[test]
    fn balloon_ops_fail_closed_by_default() {
        let b = AppleContainerBackend::new();
        let id = VmId("x".to_string());
        assert!(b.balloon_set_target(&id, 64).is_err());
        assert!(b.balloon_state(&id).is_err());
    }

    #[test]
    #[ignore = "requires the apple-container artifacts in the cache and HVF (MVM_AC_E2E=1)"]
    fn start_brings_the_agent_up_and_stop_tears_the_vm_down() {
        // End-to-end: boots the real container VM on the in-house HVF VMM,
        // runs the full vminitd injection sequence, waits for the agent to
        // self-apply the activation file and answer Ping, then stops the VM
        // cleanly. Gated: needs both artifacts in the cache, macOS HVF, a
        // codesigned mvm-hvf-supervisor, and a plain ext4 workload rootfs
        // named by MVM_AC_E2E_ROOTFS.
        if std::env::var("MVM_AC_E2E").ok().as_deref() != Some("1") {
            return;
        }
        let rootfs = std::env::var("MVM_AC_E2E_ROOTFS")
            .expect("MVM_AC_E2E_ROOTFS must name a plain ext4 workload rootfs");
        let b = AppleContainerBackend::new();
        let config = VmStartConfig {
            name: format!("ac-e2e-{}", std::process::id()),
            rootfs_path: rootfs,
            memory_mib: 1024,
            ..Default::default()
        };
        let id = b.start(&config).expect("bring-up must succeed");
        assert_eq!(b.status(&id).unwrap(), VmStatus::Running);
        assert!(
            b.list().unwrap().iter().any(|v| v.name == id.0),
            "the running VM must appear in the inventory"
        );
        assert!(b.logs(&id, 5, false).is_ok());
        b.stop(&id).expect("stop");
        assert_eq!(b.status(&id).unwrap(), VmStatus::Stopped);
    }

    #[test]
    fn inject_agent_rejects_a_non_positive_pid() {
        // A zero/negative pid from vminitd's StartProcess is a server-side
        // bug; surface it as a transport error rather than reporting
        // success for an agent that does not exist.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let (client_stream, server_stream) = tokio::io::duplex(1 << 20);
        runtime.spawn(async move {
            let mut connection = h2::server::handshake(server_stream)
                .await
                .expect("server handshake");
            while let Some(accepted) = connection.accept().await {
                let (request, mut respond) = accepted.expect("accept");
                // Drain the request body, then answer every call with an
                // empty ok — except StartProcess, which answers pid 0.
                let mut body = request.into_body();
                while let Some(chunk) = body.data().await {
                    chunk.expect("body");
                }
                let response = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .body(())
                    .expect("response");
                let mut send = respond.send_response(response, false).expect("respond");
                send.send_data(bytes::Bytes::from_static(&[0, 0, 0, 0, 0]), false)
                    .expect("data");
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().expect("status"));
                send.send_trailers(trailers).expect("trailers");
            }
        });
        let (send_request, connection) = runtime
            .block_on(h2::client::handshake(client_stream))
            .expect("client handshake");
        runtime.spawn(async move {
            let _ = connection.await;
        });
        let mut client = VminitdClient::new_for_test(runtime, send_request);
        let err = inject_agent(&mut client, b"agent", b"{}", None).unwrap_err();
        assert!(
            err.to_string().contains("non-positive pid"),
            "expected the pid guard to fire, got: {err}"
        );
    }
}
