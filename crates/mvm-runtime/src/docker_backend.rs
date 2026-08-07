//! Docker **shared-kernel container** dev tier.
//!
//! `DockerBackend` runs a workload in a Docker container with the same
//! guest-visible contract as the microVM backends: the identical static
//! `mvm-guest-agent` binary is the container's PID 1 (bind-mounted
//! read-only as `/init`), the host delivers the identical
//! `ActivateEnvironment` after start — over a Unix socket on a
//! host-owned 0700 directory bind-mounted into the container, because a
//! container has no vsock — and the agent applies the identical uid-901
//! privilege drop, keeps the identical `NotActivated` gate, and serves the
//! identical operational RPC surface. The runtime overlay and declared
//! volumes are host bind mounts (read-only honored), and the container
//! runs `--network none`: egress, when the launch policy allows it, rides
//! the same per-VM substitution endpoint over a bind-mounted socket.
//!
//! Honesty rules, mirroring the claim-free wasm tier's discipline:
//!
//! - **Opt-in only, never auto-selected.** `AnyBackend::auto_select` and
//!   capability-driven selection never return this kind; a caller must
//!   name `--hypervisor docker` explicitly.
//! - **Refused by production admission.** The backend does not implement
//!   the workload-backend surface (`AnyBackend::as_workload_backend` is
//!   `None` for it, the same carve-out as QEMU and Wasm), and its catalog
//!   descriptor marks it non-workload Tier 3.
//! - **Capabilities and claims say what it is.** A shared kernel means no
//!   hardware isolation boundary, no guest kernel, no dm-verity block
//!   boot, and no mvm hash verification of the image reference — the
//!   security profile reports exactly that, and keeps reporting the
//!   substrate-independent claims that still hold (no `do_exec` in the
//!   production agent, fuzzed framing, audited dependencies).
//! - **Fail closed, never silently degrade.** Anything this tier cannot
//!   do — kernel/initrd boot, dm-verity, block volumes, snapshots,
//!   pause/resume, warm start, standby pool — fails with a typed
//!   [`DockerBackendError`] naming the limitation and the supported
//!   alternative.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_core::config::{mvm_cache_dir, vm_state_dir};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    SnapshotCapability, StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo,
    VmStartConfig, VmStatus, VmVolumeKind,
};
use thiserror::Error;

/// Container path the host-built static agent binary is mounted at. It is
/// the container's `--entrypoint`, so the agent is PID 1 of the container's
/// PID namespace — the same role it plays as `/init` in the initramfs.
const AGENT_CONTAINER_PATH: &str = "/init";
/// Container path the per-VM run directory (agent socket, agent config,
/// substitution-endpoint socket) is bind-mounted at.
const RUN_DIR_CONTAINER_PATH: &str = "/run/mvm";
/// Container path of the agent's AF_UNIX control socket (the agent's unix
/// transport default; kept in sync with `MVM_AGENT_UNIX_SOCK`).
const AGENT_SOCK_CONTAINER_PATH: &str = "/run/mvm/agent.sock";
/// File name (inside the run directory) of the substitution-endpoint socket.
const ENDPOINT_SOCK_NAME: &str = "substitution-endpoint.sock";
/// Container path the runtime-overlay guest binaries are bind-mounted at
/// read-only — the same location the dm-verity overlay occupies on microVM
/// backends.
const RUNTIME_OVERLAY_CONTAINER_PATH: &str = "/mvm/runtime";
/// How long `start` waits for the guest agent to bind its Unix socket
/// before declaring the boot failed.
const AGENT_SOCKET_TIMEOUT: Duration = Duration::from_secs(30);
/// Grace `docker stop` gives the agent before docker escalates to SIGKILL.
const STOP_GRACE_SECS: u32 = 3;

/// Typed, fail-closed errors for requests this tier cannot satisfy. Every
/// variant names the limitation and the supported alternative rather than
/// silently dropping the request — see the module docs.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DockerBackendError {
    /// The `docker` CLI is not on `$PATH`.
    #[error(
        "docker backend requires the `docker` CLI on $PATH — install Docker, or select a \
         microVM backend (firecracker, libkrun, hvf, qemu)"
    )]
    NotAvailable,

    /// `VmStartConfig::rootfs_path` — reused here to name the OCI image
    /// reference, since this tier has no root filesystem — is empty.
    #[error(
        "docker backend has no image to run — set VmStartConfig::rootfs_path to the OCI \
         image reference (e.g. alpine:3.20); this tier has no root filesystem"
    )]
    ImageRefMissing,

    #[error(
        "docker backend has no kernel/initrd boot path — a container shares the host kernel; \
         drop --kernel/--initrd or select a microVM backend"
    )]
    KernelBootNotSupported,

    #[error(
        "docker backend has no dm-verity verified boot — a container shares the host kernel; \
         select a microVM backend (firecracker, libkrun, hvf) for a verified rootfs"
    )]
    VerifiedBootNotSupported,

    #[error(
        "docker backend cannot attach block volume '{host}' — a container has no virtio-blk; \
         use a directory-share volume instead"
    )]
    DiskVolumeNotSupported { host: String },

    #[error(
        "docker backend does not support pause/resume — docker's cgroup freezer is not \
         wired into the backend; stop and start the workload instead"
    )]
    PauseResumeNotSupported,

    #[error(
        "docker backend cannot resolve the runtime-overlay guest binaries: {reason}. They \
         cross-compile from a source checkout (or a warm cache) — run one `mvmctl build` / \
         OCI `machine run` to populate the cache, or select a microVM backend"
    )]
    RuntimeOverlayUnavailable { reason: String },
}

/// Reject every launch request this tier cannot honestly satisfy before
/// touching the docker CLI. Each check names the supported alternative.
fn reject_unsupported_start_config(
    config: &VmStartConfig,
) -> std::result::Result<(), DockerBackendError> {
    if config.kernel_path.is_some() || config.initrd_path.is_some() {
        return Err(DockerBackendError::KernelBootNotSupported);
    }
    if config.verity_path.is_some() || config.roothash.is_some() {
        return Err(DockerBackendError::VerifiedBootNotSupported);
    }
    if let Some(volume) = config
        .volumes
        .iter()
        .find(|v| matches!(v.kind, VmVolumeKind::Disk))
    {
        return Err(DockerBackendError::DiskVolumeNotSupported {
            host: volume.host.clone(),
        });
    }
    if config.rootfs_path.trim().is_empty() {
        return Err(DockerBackendError::ImageRefMissing);
    }
    Ok(())
}

/// `docker` on `$PATH`, or the typed not-available error.
fn locate_docker() -> std::result::Result<String, DockerBackendError> {
    which::which("docker")
        .map(|_| "docker".to_string())
        .map_err(|_| DockerBackendError::NotAvailable)
}

/// Owned inputs for one container's `docker run` argv, decided once so the
/// argv mapping stays a pure, unit-testable function.
#[derive(Debug, Clone)]
struct DockerRunPlan {
    name: String,
    image: String,
    agent_binary: PathBuf,
    run_dir: PathBuf,
    overlay_bins_dir: Option<PathBuf>,
    /// Host path of the spawned substitution endpoint's socket (empty when
    /// the launch has nothing to mediate — see the endpoint skip rule).
    egress_endpoint_sock: Option<PathBuf>,
    /// Directory-share volumes, validated as the only volume kind.
    dir_shares: Vec<mvm_core::vm_backend::VmVolume>,
    cpus: u32,
    memory_mib: u32,
}

/// Assemble the `docker run` argv for a container (everything after
/// `docker`). Pure so the whole plan→argv mapping is unit-testable with no
/// docker daemon. The container runs with no NIC (`--network none`): the
/// only path off it is the bind-mounted substitution-endpoint socket.
fn docker_run_argv(plan: &DockerRunPlan) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--name".into(),
        plan.name.clone(),
        "--network".into(),
        "none".into(),
        // The agent is PID 1. `--entrypoint` plus an explicit `--config`
        // argument below also replaces the image's own entrypoint+cmd.
        "--entrypoint".into(),
        AGENT_CONTAINER_PATH.into(),
        // Hardening baseline: the workload (uid 901) must not regain
        // privilege through setuid binaries or file capabilities.
        "--security-opt".into(),
        "no-new-privileges".into(),
        "-v".into(),
        format!("{}:{AGENT_CONTAINER_PATH}:ro", plan.agent_binary.display()),
        "-v".into(),
        format!("{}:{RUN_DIR_CONTAINER_PATH}", plan.run_dir.display()),
    ];
    if let Some(dir) = &plan.overlay_bins_dir {
        args.push("-v".into());
        args.push(format!(
            "{}:{RUNTIME_OVERLAY_CONTAINER_PATH}:ro",
            dir.display()
        ));
    }
    for volume in &plan.dir_shares {
        let mut spec = format!("{}:{}", volume.host, volume.guest);
        if volume.read_only {
            spec.push_str(":ro");
        }
        args.push("-v".into());
        args.push(spec);
    }
    if plan.memory_mib > 0 {
        args.push("--memory".into());
        args.push(format!("{}m", plan.memory_mib));
    }
    if plan.cpus > 0 {
        args.push("--cpus".into());
        args.push(plan.cpus.to_string());
    }
    args.push("-e".into());
    args.push("MVM_AGENT_TRANSPORT=unix".into());
    args.push("-e".into());
    args.push(format!("MVM_AGENT_UNIX_SOCK={AGENT_SOCK_CONTAINER_PATH}"));
    if plan.egress_endpoint_sock.is_some() {
        args.push("-e".into());
        args.push(format!(
            "MVM_AGENT_EGRESS_ENDPOINT_SOCK={RUN_DIR_CONTAINER_PATH}/{ENDPOINT_SOCK_NAME}"
        ));
    }
    args.push(plan.image.clone());
    // Explicit command: overrides the image's CMD and points the agent at
    // its (defaults-only) config file in the run dir.
    args.push("--config".into());
    args.push(format!("{RUN_DIR_CONTAINER_PATH}/agent.json"));
    args
}

/// Record of a container this backend started. Docker itself is the source
/// of truth for liveness (queried via `docker inspect`); the map exists so
/// `list`/`stop_all`/`wait` know which containers this process started.
#[derive(Debug, Clone)]
struct DockerRun {
    container_id: String,
}

/// Docker shared-kernel container backend. See the module docs for the
/// tier's scope and the opt-in/prod-refused/fail-closed contract.
#[derive(Debug, Default, Clone)]
pub struct DockerBackend {
    runs: Arc<Mutex<HashMap<String, DockerRun>>>,
}

impl DockerBackend {
    /// Construct an empty backend. Side-effect free — no docker CLI is
    /// probed and no daemon is contacted until a container actually runs.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_runs(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, DockerRun>>> {
        self.runs
            .lock()
            .map_err(|_| anyhow!("docker backend state mutex poisoned"))
    }

    /// The docker identifier to operate on for `id`: the container id when
    /// this process started the container, else the VM name (which is also
    /// the container name, so a later CLI invocation still resolves it).
    fn docker_target(&self, id: &VmId) -> String {
        self.runs
            .lock()
            .ok()
            .and_then(|runs| runs.get(&id.0).map(|run| run.container_id.clone()))
            .unwrap_or_else(|| id.0.clone())
    }
}

/// Owned inputs for a docker run's per-VM substitution-endpoint spawn,
/// decided once by [`docker_endpoint_plan`] so the skip/spawn branch is
/// unit-testable without touching a subprocess. Mirrors the wasm tier's
/// plan exactly, except the socket lives inside the bind-mounted run
/// directory so the in-container forward proxy can reach it.
struct DockerEndpointPlan {
    vm_name: String,
    state_dir: PathBuf,
    tenant: String,
    secrets: Vec<mvm_core::plan::SecretBinding>,
    redaction: mvm_core::policy::RedactionPolicy,
    socket_path: PathBuf,
}

/// Decide whether a docker run needs the per-VM substitution endpoint, and
/// if so, the owned inputs the spawn needs. Mirrors the runner's and the
/// wasm tier's skip logic exactly: nothing to mediate — no bound secrets
/// and the resolved policy denies egress — is a no-op, returning `None`.
/// `start` then sets no endpoint env var, so every proxied request in the
/// container fails closed (and `--network none` leaves no other path).
fn docker_endpoint_plan(
    config: &VmStartConfig,
    state_dir: &Path,
    run_dir: &Path,
) -> Result<Option<DockerEndpointPlan>> {
    let default_redaction = mvm_core::policy::RedactionPolicy::default();
    let decoded = mvm_vmm::host::egress_shared::decode_plan_secrets_from_state(state_dir)?;
    let (secrets, redaction, tenant) = match decoded {
        Some((secrets, redaction, tenant)) => (secrets, redaction, tenant),
        None => (
            Vec::new(),
            default_redaction,
            match config.tenant_id.as_deref() {
                Some(t) if !t.is_empty() => t.to_string(),
                _ => "local".to_string(),
            },
        ),
    };
    if secrets.is_empty() && !config.network_policy.allows_egress() {
        return Ok(None);
    }
    Ok(Some(DockerEndpointPlan {
        vm_name: config.name.clone(),
        state_dir: state_dir.to_path_buf(),
        tenant,
        secrets,
        redaction,
        socket_path: run_dir.join(ENDPOINT_SOCK_NAME),
    }))
}

/// Build the [`crate::substitution_spawn::SubstitutionSpawnParams`] a docker
/// run's endpoint spawn needs from a decided [`DockerEndpointPlan`]. Pure
/// (no I/O) so the docker-specific literal fields are unit-testable: always
/// `Uds` inside the bind-mounted run dir (the in-container forward proxy
/// connects to it directly), no terminator (no NIC to redirect), no TLS
/// intermediate, and `raw_egress` unconditionally `false` — the agent's
/// forward proxy always speaks the `WireRequest` wire protocol, never a
/// raw byte relay.
fn docker_substitution_spawn_params<'a>(
    plan: &'a DockerEndpointPlan,
    network_policy: &'a mvm_core::network_policy::NetworkPolicy,
) -> crate::substitution_spawn::SubstitutionSpawnParams<'a> {
    crate::substitution_spawn::SubstitutionSpawnParams {
        vm_name: &plan.vm_name,
        state_dir: &plan.state_dir,
        tenant: &plan.tenant,
        secrets: &plan.secrets,
        redaction: &plan.redaction,
        transport: crate::substitution_spawn::EndpointTransport::Uds {
            path: plan.socket_path.clone(),
        },
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: Some(network_policy),
        raw_egress: false,
    }
}

/// Spawn the per-VM substitution endpoint for a docker run and return the
/// socket path to wire into the container's `MVM_AGENT_EGRESS_ENDPOINT_SOCK`
/// env. `None` when [`docker_endpoint_plan`] finds nothing to mediate; the
/// container then boots with no endpoint socket and every proxied request
/// fails closed.
fn spawn_docker_egress_endpoint_if_needed(
    config: &VmStartConfig,
    state_dir: &Path,
    run_dir: &Path,
) -> Result<Option<PathBuf>> {
    let Some(plan) = docker_endpoint_plan(config, state_dir, run_dir)? else {
        return Ok(None);
    };
    let params = docker_substitution_spawn_params(&plan, &config.network_policy);
    crate::substitution_spawn::spawn_substitution_endpoint(params)?;
    Ok(Some(plan.socket_path))
}

/// Resolve the runtime-overlay guest binaries as a host directory to
/// bind-mount read-only at `/mvm/runtime`. Fails closed with a typed error
/// when the set can't be resolved (no source checkout and a cold cache) —
/// booting without it would silently hand the workload a lesser
/// environment than the launch contract promises.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerRuntimeArtifacts {
    agent_binary: PathBuf,
    overlay_bins_dir: PathBuf,
}

fn docker_runtime_artifacts(
    binaries: mvm_build::guest_agent_build::RuntimeOverlayGuestBinaries,
) -> std::result::Result<DockerRuntimeArtifacts, DockerBackendError> {
    // Every binary in the set lives in the layout's own cache dir.
    let overlay_bins_dir = binaries
        .agent
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DockerBackendError::RuntimeOverlayUnavailable {
            reason: "resolved agent path has no parent directory".to_string(),
        })?;
    Ok(DockerRuntimeArtifacts {
        agent_binary: binaries.agent,
        overlay_bins_dir,
    })
}

fn resolve_docker_runtime(
    cache_root: &Path,
) -> std::result::Result<DockerRuntimeArtifacts, DockerBackendError> {
    let arch = mvm_core::arch::GuestArch::host();
    let Some(workspace) = mvm_build::guest_agent_build::detect_source_workspace() else {
        return Err(DockerBackendError::RuntimeOverlayUnavailable {
            reason: "no source checkout detected to build the guest binaries from".to_string(),
        });
    };
    let binaries = mvm_build::guest_agent_build::resolve_or_build_runtime_overlay_guest_binaries(
        cache_root,
        env!("CARGO_PKG_VERSION"),
        arch,
        &workspace,
    )
    .map_err(|e| DockerBackendError::RuntimeOverlayUnavailable {
        reason: e.to_string(),
    })?;
    docker_runtime_artifacts(binaries)
}

/// Create the per-VM run directory with owner-only permissions: it holds
/// the agent's control socket, so its permissions ARE the peer
/// authorization boundary on this tier (there is no vsock peer CID).
fn create_run_dir(state_dir: &Path) -> Result<PathBuf> {
    let run_dir = state_dir.join("docker-run");
    std::fs::create_dir_all(&run_dir)
        .map_err(|e| anyhow!("create docker run dir {}: {e}", run_dir.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| anyhow!("chmod 0700 docker run dir {}: {e}", run_dir.display()))?;
    }
    Ok(run_dir)
}

/// Connect the agent's bind-mounted Unix socket (retrying while the
/// container boots, failing fast if the container died) and deliver the
/// activation message, requiring the ACK.
fn activate_container(run_dir: &Path, config: &VmStartConfig, docker: &str) -> Result<()> {
    let env = crate::microvm::build_container_activation_environment(config)?;
    let sock = run_dir.join("agent.sock");
    let deadline = Instant::now() + AGENT_SOCKET_TIMEOUT;
    loop {
        match std::os::unix::net::UnixStream::connect(&sock) {
            Ok(mut stream) => {
                return crate::microvm::activate_over_stream(&mut stream, &env)
                    .context("activate container workload");
            }
            Err(connect_err) => {
                if Instant::now() >= deadline {
                    bail!(
                        "docker guest agent did not bind {} within {AGENT_SOCKET_TIMEOUT:?}: {connect_err}",
                        sock.display()
                    );
                }
                if !container_running(docker, &config.name)? {
                    bail!(
                        "docker container '{}' exited before its guest agent came up; \
                         see `docker logs {}`",
                        config.name,
                        config.name
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// `docker inspect` liveness probe: true when the named container exists
/// and is running. A missing container reports `false` (not an error) so
/// `status`/`activate` read it as Stopped/died.
fn container_running(docker: &str, name: &str) -> Result<bool> {
    let out = Command::new(docker)
        .args(["inspect", "-f", "{{.State.Running}}", name])
        .output()
        .map_err(|e| anyhow!("spawn docker inspect for '{name}': {e}"))?;
    if !out.status.success() {
        // inspect fails when the container does not exist.
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim() == "true")
}

impl VmBackend for DockerBackend {
    fn name(&self) -> &str {
        "docker"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Docker
    }

    fn capabilities(&self) -> VmCapabilities {
        VmCapabilities {
            // `--network none`: nothing in the container can reach the
            // network by IP. Egress, when the policy allows it, rides the
            // substitution endpoint over the bind-mounted socket dir — a
            // host-mediated channel, but over a Unix socket rather than
            // vsock, so `host_vsock_proxy` honestly stays false.
            no_routable_guest_nic: true,
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            ..VmCapabilities::default()
        }
    }

    fn start_with_mode(&self, config: &VmStartConfig, _mode: StartMode) -> Result<VmId> {
        reject_unsupported_start_config(config)?;
        let docker = locate_docker()?;

        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;
        // Record per-VM runtime metadata (the sidecar accessibility bit +
        // boot contract) so the `mvmctl console` accessible/sealed gate
        // holds on docker-launched containers too, matching the other
        // backends' start paths.
        crate::base::runtime_meta::record_from_start_config(
            &config.name,
            StartMode::Detached,
            config,
        )?;

        let run_dir = create_run_dir(&state_dir)?;
        // A defaults-only agent config: the run dir is bind-mounted, so the
        // explicit `--config` that overrides the image's CMD parses this.
        std::fs::write(run_dir.join("agent.json"), "{}")
            .map_err(|e| anyhow!("write agent config in {}: {e}", run_dir.display()))?;

        let cache_root = PathBuf::from(mvm_cache_dir());
        let runtime = resolve_docker_runtime(&cache_root)?;
        let egress_endpoint_sock =
            spawn_docker_egress_endpoint_if_needed(config, &state_dir, &run_dir)?;

        let plan = DockerRunPlan {
            name: config.name.clone(),
            image: config.rootfs_path.trim().to_string(),
            agent_binary: runtime.agent_binary,
            run_dir: run_dir.clone(),
            overlay_bins_dir: Some(runtime.overlay_bins_dir),
            egress_endpoint_sock,
            dir_shares: config.volumes.clone(),
            cpus: config.cpus,
            memory_mib: config.memory_mib,
        };
        let argv = docker_run_argv(&plan);
        let out = Command::new(&docker)
            .args(&argv)
            .output()
            .map_err(|e| anyhow!("spawn docker run for '{}': {e}", config.name))?;
        if !out.status.success() {
            // Roll back a half-spawned endpoint so a failed start leaves no
            // decrypted-secret process behind.
            crate::substitution_spawn::reap_substitution_endpoint(&state_dir, &config.name);
            bail!(
                "docker run failed for workload '{}': {}",
                config.name,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let container_id = String::from_utf8_lossy(&out.stdout).trim().to_string();

        // Deliver activation; on failure tear the container and endpoint
        // down so a failed start leaves nothing running.
        if let Err(e) = activate_container(&run_dir, config, &docker) {
            let _ = Command::new(&docker)
                .args(["rm", "-f", &config.name])
                .output();
            crate::substitution_spawn::reap_substitution_endpoint(&state_dir, &config.name);
            return Err(e);
        }

        self.lock_runs()?
            .insert(config.name.clone(), DockerRun { container_id });
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        let docker = locate_docker()?;
        let target = self.docker_target(id);
        let out = Command::new(&docker)
            .args(["wait", &target])
            .output()
            .map_err(|e| anyhow!("spawn docker wait for '{}': {e}", id.0))?;
        if !out.status.success() {
            bail!(
                "docker wait failed for '{}': {}",
                id.0,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let first_line = String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string();
        let code: i32 = first_line.parse().map_err(|_| {
            anyhow!(
                "docker wait for '{}' returned unparseable exit status {first_line:?}",
                id.0
            )
        })?;
        Ok(VmExitStatus {
            code: Some(code),
            success: code == 0,
        })
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        Err(DockerBackendError::PauseResumeNotSupported.into())
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        Err(DockerBackendError::PauseResumeNotSupported.into())
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        // Reap the per-VM substitution endpoint first, so a crashed
        // container's decrypted-secret process can't outlive it. Idempotent
        // + a no-op when the run spawned none.
        crate::substitution_spawn::reap_substitution_endpoint(&vm_state_dir(&id.0), &id.0);
        let docker = locate_docker()?;
        let target = self.docker_target(id);
        // Graceful stop, then remove the container so the name can be
        // reused. Both are best-effort: an already-gone container is the
        // desired end state.
        let _ = Command::new(&docker)
            .args(["stop", "-t", &STOP_GRACE_SECS.to_string(), &target])
            .output();
        let out = Command::new(&docker)
            .args(["rm", "-f", &target])
            .output()
            .map_err(|e| anyhow!("spawn docker rm for '{}': {e}", id.0))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            // "No such container" is the desired end state, not an error.
            if !stderr.contains("No such container") {
                bail!("docker rm failed for '{}': {stderr}", id.0);
            }
        }
        self.lock_runs()?.remove(&id.0);
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let names: Vec<String> = self.lock_runs()?.keys().cloned().collect();
        let mut last_err = None;
        for name in names {
            if let Err(e) = self.stop(&VmId(name.clone())) {
                tracing::warn!(name, error = %e, "docker stop_all: stop failed");
                last_err = Some(e);
            }
        }
        last_err.map_or(Ok(()), Err)
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let docker = locate_docker()?;
        Ok(match container_running(&docker, &self.docker_target(id))? {
            true => VmStatus::Running,
            false => VmStatus::Stopped,
        })
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let docker = locate_docker()?;
        let names: Vec<String> = self.lock_runs()?.keys().cloned().collect();
        let mut vms = Vec::with_capacity(names.len());
        for name in names {
            let status = match container_running(&docker, &name) {
                Ok(true) => VmStatus::Running,
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
        // One log stream: the container's stdout/stderr (the agent's
        // console), whether the caller asked for the "hypervisor" log or not.
        let docker = locate_docker()?;
        let out = Command::new(&docker)
            .args([
                "logs",
                "--tail",
                &lines.to_string(),
                &self.docker_target(id),
            ])
            .output()
            .map_err(|e| anyhow!("spawn docker logs for '{}': {e}", id.0))?;
        if !out.status.success() {
            bail!(
                "docker logs failed for '{}': {}",
                id.0,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let mut body = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.stderr.is_empty() {
            body.push_str(&String::from_utf8_lossy(&out.stderr));
        }
        Ok(body)
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        // The agent's control socket on the host side of the bind-mounted
        // run directory — the AF_UNIX analog of the vsock agent channel the
        // microVM backends report.
        Ok(GuestChannelInfo::UnixSocket {
            path: vm_state_dir(&id.0)
                .join("docker-run")
                .join("agent.sock")
                .to_string_lossy()
                .into_owned(),
        })
    }

    fn is_available(&self) -> Result<bool> {
        Ok(locate_docker().is_ok())
    }

    fn install(&self) -> Result<()> {
        crate::base::ui::info(
            "Docker must be installed via the host package manager or Docker Desktop \
             (`apt install docker.io` / https://docs.docker.com/get-docker/).",
        );
        Ok(())
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Shared kernel ⇒ the hardware-isolation claims do not hold:
        // namespaces are not a security boundary against the host (1),
        // uid-0-in-container is host-kernel-mediated (2), and there is no
        // dm-verity block boot (3) nor mvm hash verification of the image
        // reference (6). The substrate-independent claims still hold: the
        // production agent carries no `do_exec` (4), the RPC framing is the
        // same fuzzed wire (5), and the agent is the same audited build (7).
        BackendSecurityProfile {
            claims: [
                ClaimStatus::DoesNotHold, // 1 — shared kernel: host-fs isolation is namespace-only
                ClaimStatus::DoesNotHold, // 2 — shared kernel: no hardware boundary on uid 0
                ClaimStatus::DoesNotHold, // 3 — no dm-verity block boot
                ClaimStatus::Holds,       // 4 — same agent binary, no do_exec in prod builds
                ClaimStatus::Holds,       // 5 — same fuzzed RPC framing
                ClaimStatus::DoesNotHold, // 6 — image refs are tag-based, not mvm hash-verified
                ClaimStatus::Holds,       // 7 — same audited dependency tree
            ],
            layer_coverage: LayerCoverage {
                // The guest-agent (uid 901 drop, no_new_privs) and workload
                // confinement layers are real and unchanged; the hypervisor,
                // VMM, and guest-kernel layers collapse into the shared host
                // kernel.
                l4_guest_agent: true,
                l5_workload: true,
                ..LayerCoverage::default()
            },
            tier: "Tier 3 (shared-kernel container, dev tier — opt-in, prod-refused)",
            notes: &[
                "Runs the workload in a Docker container with mvm-guest-agent as PID 1; the \
                 guest shares the host kernel — namespaces are not a hardware boundary.",
                "Opt-in only; never selected by auto-detect. Refused by production admission \
                 (no workload-backend surface), the same carve-out as QEMU and Wasm.",
                "Activation rides a host bind-mounted Unix socket (no vsock in a container); \
                 the socket directory's 0700 permissions are the peer boundary, a deliberately \
                 weaker check than the vsock host-CID gate.",
                "Runs --network none; egress, when the policy allows it, rides the per-VM \
                 substitution endpoint over the bind-mounted socket dir.",
                "For development, demo, and CI-sandbox use only — never an isolation tier.",
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AnyBackend;

    fn cfg(name: &str, image: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            rootfs_path: image.to_string(),
            ..Default::default()
        }
    }

    fn sample_plan() -> DockerRunPlan {
        DockerRunPlan {
            name: "web".into(),
            image: "alpine:3.20".into(),
            agent_binary: PathBuf::from("/cache/guest-agent/mvm-guest-agent"),
            run_dir: PathBuf::from("/state/web/docker-run"),
            overlay_bins_dir: Some(PathBuf::from("/cache/runtime-overlay-bins")),
            egress_endpoint_sock: Some(PathBuf::from(
                "/state/web/docker-run/substitution-endpoint.sock",
            )),
            dir_shares: vec![
                mvm_core::vm_backend::VmVolume {
                    host: "/host/share".into(),
                    guest: "/mnt/share".into(),
                    size: String::new(),
                    read_only: true,
                    kind: VmVolumeKind::DirShare,
                    encrypted: false,
                },
                mvm_core::vm_backend::VmVolume {
                    host: "/host/data".into(),
                    guest: "/mnt/data".into(),
                    size: String::new(),
                    read_only: false,
                    kind: VmVolumeKind::DirShare,
                    encrypted: false,
                },
            ],
            cpus: 2,
            memory_mib: 512,
        }
    }

    #[test]
    fn kind_and_name_are_docker() {
        let b = DockerBackend::new();
        assert_eq!(b.name(), "docker");
        assert_eq!(b.kind(), BackendKind::Docker);
    }

    #[test]
    fn selector_resolves_and_auto_select_never_returns_docker() {
        let backend = AnyBackend::from_hypervisor("docker");
        assert!(matches!(backend, AnyBackend::Docker(_)));
        assert_eq!(backend.name(), "docker");
        assert_eq!(backend.kind(), BackendKind::Docker);
        // Opt-in only, same discipline as the wasm tier: auto_select's
        // ladder constructs Firecracker/Hvf/Libkrun and nothing else.
        assert_ne!(
            AnyBackend::auto_select().kind(),
            BackendKind::Docker,
            "auto_select must never fall through to the docker dev tier"
        );
    }

    #[test]
    fn prod_funnel_excludes_the_docker_tier() {
        let backend = AnyBackend::from_hypervisor("docker");
        assert!(
            backend.as_workload_backend().is_none(),
            "docker must be barred from the admitted workload funnel"
        );
    }

    #[test]
    fn capabilities_are_honest_about_the_shared_kernel() {
        let caps = DockerBackend::new().capabilities();
        assert!(!caps.pause_resume);
        assert!(!caps.snapshots);
        assert_eq!(caps.snapshot_capability, SnapshotCapability::Unsupported);
        assert!(!caps.standby_pool);
        assert!(!caps.vsock);
        assert!(!caps.tap_networking);
        assert!(!caps.balloon);
        assert!(!caps.host_vsock_proxy);
        assert!(!caps.pty_exec);
        assert!(!caps.production_ssh);
        assert!(caps.no_routable_guest_nic);
    }

    #[test]
    fn security_profile_drops_only_the_isolation_claims() {
        let profile = DockerBackend::new().security_profile();
        assert_eq!(profile.dropped_claims(), vec![1, 2, 3, 6]);
        assert!(
            !profile.layer_coverage.is_microvm(),
            "a shared-kernel container must not report microVM layers"
        );
        // The agent/workload confinement layers are real and unchanged.
        assert!(profile.layer_coverage.l4_guest_agent);
        assert!(profile.layer_coverage.l5_workload);
        assert!(
            profile.tier.starts_with("Tier 3"),
            "the tier string must agree with the catalog's Tier 3 classification: {}",
            profile.tier
        );
        assert!(profile.tier.contains("shared-kernel"));
    }

    #[test]
    fn snapshot_and_standby_fail_closed() {
        use mvm_core::vm_backend::WarmStartError;
        let b = DockerBackend::new();
        assert_eq!(b.snapshot_capability(), SnapshotCapability::Unsupported);
        match b.warm_start(&VmStartConfig::default(), SnapshotCapability::DiskOnly) {
            Err(WarmStartError::Unsupported { .. }) => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert!(!b.supports_standby_pool());
    }

    #[test]
    fn pause_resume_fail_closed_with_typed_error() {
        let b = DockerBackend::new();
        let id = VmId("x".into());
        let err = b.pause(&id).unwrap_err();
        assert_eq!(
            err.downcast_ref::<DockerBackendError>(),
            Some(&DockerBackendError::PauseResumeNotSupported)
        );
        let err = b.resume(&id).unwrap_err();
        assert_eq!(
            err.downcast_ref::<DockerBackendError>(),
            Some(&DockerBackendError::PauseResumeNotSupported)
        );
    }

    #[test]
    fn missing_image_ref_fails_closed() {
        let err = reject_unsupported_start_config(&cfg("x", "   ")).unwrap_err();
        assert_eq!(err, DockerBackendError::ImageRefMissing);
    }

    #[test]
    fn kernel_request_fails_closed() {
        let mut config = cfg("x", "alpine:3.20");
        config.kernel_path = Some("/some/vmlinux".into());
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(DockerBackendError::KernelBootNotSupported)
        );
        config.kernel_path = None;
        config.initrd_path = Some("/some/initrd".into());
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(DockerBackendError::KernelBootNotSupported)
        );
    }

    #[test]
    fn verified_boot_request_fails_closed() {
        let mut config = cfg("x", "alpine:3.20");
        config.roothash = Some("a".repeat(64));
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(DockerBackendError::VerifiedBootNotSupported)
        );
        config.roothash = None;
        config.verity_path = Some("/img/rootfs.verity".into());
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(DockerBackendError::VerifiedBootNotSupported)
        );
    }

    #[test]
    fn disk_volume_fails_closed_dir_share_passes() {
        let mut config = cfg("x", "alpine:3.20");
        config.volumes = vec![mvm_core::vm_backend::VmVolume {
            host: "/host/disk.img".into(),
            guest: "/mnt/disk".into(),
            size: "1G".into(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            encrypted: false,
        }];
        assert_eq!(
            reject_unsupported_start_config(&config),
            Err(DockerBackendError::DiskVolumeNotSupported {
                host: "/host/disk.img".into()
            })
        );

        config.volumes[0].kind = VmVolumeKind::DirShare;
        assert!(reject_unsupported_start_config(&config).is_ok());
    }

    #[test]
    fn argv_maps_the_full_plan_verbatim() {
        let argv = docker_run_argv(&sample_plan());
        let joined = argv.join(" ");

        // Detached, named, no NIC, agent as entrypoint, hardened.
        assert!(joined.contains("run -d --name web"));
        assert!(joined.contains("--network none"));
        assert!(joined.contains("--entrypoint /init"));
        assert!(joined.contains("--security-opt no-new-privileges"));
        // Bind mounts: agent RO, run dir RW, overlay RO, volumes with ro honored.
        assert!(joined.contains("-v /cache/guest-agent/mvm-guest-agent:/init:ro"));
        assert!(joined.contains("-v /state/web/docker-run:/run/mvm"));
        assert!(joined.contains("-v /cache/runtime-overlay-bins:/mvm/runtime:ro"));
        assert!(joined.contains("-v /host/share:/mnt/share:ro"));
        assert!(joined.contains("-v /host/data:/mnt/data"));
        // Resource limits.
        assert!(joined.contains("--memory 512m"));
        assert!(joined.contains("--cpus 2"));
        // Transport env + the egress endpoint socket.
        assert!(joined.contains("-e MVM_AGENT_TRANSPORT=unix"));
        assert!(joined.contains("-e MVM_AGENT_UNIX_SOCK=/run/mvm/agent.sock"));
        assert!(
            joined
                .contains("-e MVM_AGENT_EGRESS_ENDPOINT_SOCK=/run/mvm/substitution-endpoint.sock")
        );
        // Image, then the explicit agent config override — and never a NIC,
        // never privileged.
        assert!(joined.ends_with("alpine:3.20 --config /run/mvm/agent.json"));
        assert!(!joined.contains("--privileged"));
        assert!(!joined.contains("--net="));
    }

    #[test]
    fn docker_runtime_uses_the_universal_agent_from_the_overlay_artifact() {
        let root = PathBuf::from("/cache/runtime-overlay-bins");
        let artifacts =
            docker_runtime_artifacts(mvm_build::guest_agent_build::RuntimeOverlayGuestBinaries {
                agent: root.join("agent"),
                netinit: root.join("netinit"),
                ping: root.join("ping"),
                seccomp_apply: root.join("seccomp-apply"),
                verity_init: root.join("verity-init"),
                runner: root.join("runner"),
                egress_client: root.join("egress-client"),
                addon_dns: root.join("addon-dns"),
                exit_report: root.join("exit-report"),
            })
            .expect("map runtime overlay binaries");

        assert_eq!(artifacts.agent_binary, root.join("agent"));
        assert_eq!(artifacts.overlay_bins_dir, root);
    }

    #[test]
    fn argv_minimal_plan_carries_no_overlay_no_endpoint_no_volumes() {
        let plan = DockerRunPlan {
            overlay_bins_dir: None,
            egress_endpoint_sock: None,
            dir_shares: Vec::new(),
            cpus: 0,
            memory_mib: 0,
            ..sample_plan()
        };
        let argv = docker_run_argv(&plan);
        let joined = argv.join(" ");
        assert!(!joined.contains("/mvm/runtime"));
        assert!(!joined.contains("MVM_AGENT_EGRESS_ENDPOINT_SOCK"));
        assert!(!joined.contains("--memory"));
        assert!(!joined.contains("--cpus"));
        assert!(joined.ends_with("alpine:3.20 --config /run/mvm/agent.json"));
    }

    // ── endpoint plan / spawn params (mirrors the wasm tier's tests) ──

    #[test]
    fn endpoint_plan_is_none_when_no_secrets_and_no_egress() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("docker-run");
        let config = VmStartConfig {
            name: "no-secrets-docker-vm".to_string(),
            ..Default::default()
        };
        let plan = docker_endpoint_plan(&config, dir.path(), &run_dir).unwrap();
        assert!(
            plan.is_none(),
            "deny-all policy with no bound secrets must skip the endpoint spawn"
        );
    }

    #[test]
    fn endpoint_plan_sockets_inside_the_bind_mounted_run_dir() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("docker-run");
        let config = VmStartConfig {
            name: "policy-allow-docker-vm".to_string(),
            network_policy: mvm_core::network_policy::NetworkPolicy::preset(
                mvm_core::network_policy::NetworkPreset::Dev,
            ),
            ..Default::default()
        };
        let plan = docker_endpoint_plan(&config, dir.path(), &run_dir)
            .unwrap()
            .expect("a policy allowing egress must produce a spawn plan");
        assert!(plan.secrets.is_empty());
        assert_eq!(plan.tenant, "local");
        assert_eq!(
            plan.socket_path,
            run_dir.join("substitution-endpoint.sock"),
            "the endpoint socket must live inside the bind-mounted run dir"
        );

        let params = docker_substitution_spawn_params(&plan, &config.network_policy);
        assert_eq!(
            params.transport,
            crate::substitution_spawn::EndpointTransport::Uds {
                path: plan.socket_path.clone(),
            }
        );
        assert!(params.terminator_listen.is_none(), "no NIC to redirect");
        assert!(params.tls_intermediate.is_none());
        assert!(params.network_policy.is_some());
        assert!(
            !params.raw_egress,
            "the forward proxy always speaks WireRequest wire mode"
        );
    }

    #[test]
    fn run_dir_is_created_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = create_run_dir(dir.path()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the socket dir IS the peer boundary");
    }

    #[test]
    fn guest_channel_info_reports_the_run_dir_agent_socket() {
        let b = DockerBackend::new();
        let info = b.guest_channel_info(&VmId("chan-vm".into())).unwrap();
        let expected = vm_state_dir("chan-vm")
            .join("docker-run")
            .join("agent.sock")
            .to_string_lossy()
            .into_owned();
        match info {
            GuestChannelInfo::UnixSocket { path } => assert_eq!(path, expected),
            other => panic!("expected a unix socket channel, got {other:?}"),
        }
    }

    #[test]
    fn is_available_tracks_the_docker_cli() {
        // Tautological-looking, but pins the contract: `is_available` must
        // track whether the docker CLI resolves, never a hardcoded bool.
        assert_eq!(
            DockerBackend::new().is_available().unwrap(),
            locate_docker().is_ok()
        );
    }
}
