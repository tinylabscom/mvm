//! `HvfBackend` — the `VmBackend` impl for the raw-HVF macOS path.
//!
//! Lifecycle mirrors the other detached-supervisor backends (legacy_macos/libkrun): `start`
//! builds an [`HvfSupervisorConfig`] from the `VmStartConfig`, spawns
//! `mvm-hvf-supervisor` with the JSON on stdin, and waits for it to write its PID
//! file (boot confirmed). `stop` signals that PID; `status` probes it with
//! `kill(pid, 0)`; `list` walks `~/.mvm/vms/*/hvf.pid`; `logs` reads the captured
//! `console.log`. The guest boots through `boot_kernel` → the unified `vmm::run`
//! loop inside the supervisor.
//!
//! Transient by default (VM life = workload life): the guest runs its entrypoint
//! and reports its exit code over the workload-exit vsock port, which ends the run;
//! `wait` returns that code. A persistent (`-d`) VM instead runs until `stop`. With
//! vsock + optional virtio-blk. Not yet: pause/resume/snapshot, and vsock-mediated
//! networking/egress.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use mvm_build::hvf_supervisor::{ConsoleDataSocket, HvfDisk, HvfSupervisorConfig};
use mvm_core::config::{mvm_data_dir, vm_state_dir};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, LayerCoverage, VmBackend, VmCapabilities, VmExitStatus,
    VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::base::ui;

/// PID file the supervisor writes inside `vm_state_dir`. Distinct from the other
/// backends' markers so HVF VMs coexist under the same `~/.mvm/vms/` root.
pub(crate) const PID_FILE_NAME: &str = "hvf.pid";
/// How long `start` waits for the supervisor to confirm boot (PID file). Shared
/// with the hvf driver, which spawns the same supervisor binary.
pub(crate) const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);

/// Raw HVF (`Hypervisor.framework`) backend. macOS / Apple-silicon only.
pub struct HvfBackend;

fn hvf_console_data_sockets(state_dir: &Path, dev_console: bool) -> Vec<ConsoleDataSocket> {
    crate::workload_runner::spec_map::console_data_sockets(state_dir, dev_console)
        .into_iter()
        .map(|(guest_port, host_socket)| ConsoleDataSocket {
            guest_port,
            host_socket,
        })
        .collect()
}

pub(crate) fn read_pid(path: &Path) -> Option<libc::pid_t> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub(crate) fn pid_alive(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 probes existence/permission without delivering a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn reap_child_if_exited(pid: libc::pid_t) -> bool {
    let mut status = 0;
    // SAFETY: `waitpid` with WNOHANG only reaps this process's child if it has
    // exited; for non-child PIDs it returns ECHILD and leaves the liveness check
    // to `kill(pid, 0)`.
    unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == pid }
}

fn wait_for_pid_exit(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if reap_child_if_exited(pid) || !pid_alive(pid) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// SIGTERM a recorded pid, then SIGKILL if it lingers past a short grace. When
/// the supervisor is still this process's child, reap it with `waitpid` so an
/// already-exited zombie does not look alive for the full grace window.
/// Shared by the `VmBackend` stop path and the hvf driver's `kill`.
pub(crate) fn terminate_pid(pid: libc::pid_t) {
    // SAFETY: signalling a pid we recorded from our own supervisor.
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    if wait_for_pid_exit(pid, Duration::from_secs(5)) {
        return;
    }
    if pid_alive(pid) {
        // SAFETY: same pid.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        let _ = wait_for_pid_exit(pid, Duration::from_millis(500));
    }
}

/// Locate the per-VM supervisor binary, rebuilding it on a source checkout if
/// its source inputs are newer. See [`crate::aux_bin`].
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    crate::aux_bin::resolve_or_build(&crate::aux_bin::AuxBin {
        bin: "mvm-hvf-supervisor",
        package: "mvm-vm-host",
        env_var: "MVM_HVF_SUPERVISOR_PATH",
        features: &[],
        input_roots: &[
            "Cargo.toml",
            "Cargo.lock",
            "crates/mvm-vm-host/Cargo.toml",
            "crates/mvm-vm-host/src",
            "crates/mvm-backend/Cargo.toml",
            "crates/mvm-backend/src",
            "crates/mvm-build/Cargo.toml",
            "crates/mvm-build/src",
            "crates/mvm-core/Cargo.toml",
            "crates/mvm-core/src",
            "crates/mvm-guest/Cargo.toml",
            "crates/mvm-guest/src",
            "crates/mvm-hostd/Cargo.toml",
            "crates/mvm-hostd/src",
        ],
    })
}

fn vms_root() -> PathBuf {
    PathBuf::from(mvm_data_dir()).join("vms")
}

/// Always spawn the per-VM gating endpoint carrying the resolved `NetworkPolicy`,
/// returning an armed `EndpointGuard` and the endpoint socket to hand the
/// supervisor as its `egress_relay_socket`. Unlike the legacy helper, a secret-free
/// workload still gets an endpoint here — it is the sole egress gate now, so it must
/// run for every VM. When the plan carries no secrets, the endpoint runs raw (no
/// substitution) but still enforces the policy.
fn spawn_hvf_gating_endpoint(
    vm_name: &str,
    state_dir: &Path,
    network_policy: &mvm_core::policy::network_policy::NetworkPolicy,
    config_tenant: &str,
) -> Result<(crate::substitution_spawn::EndpointGuard, PathBuf)> {
    use crate::substitution_spawn::{
        EndpointGuard, EndpointTransport, SubstitutionSpawnParams, spawn_substitution_endpoint,
    };
    use mvm_core::policy::RedactionPolicy;

    // Owned defaults + the decoded plan outlive the params below so the borrows
    // stay valid across both branches.
    let default_redaction = RedactionPolicy::default();
    let decoded = crate::egress_shared::decode_plan_secrets_from_state(state_dir)?;
    let (secrets, redaction, tenant): (&[_], &RedactionPolicy, &str) = match &decoded {
        Some((s, r, t)) => (s.as_slice(), r, t.as_str()),
        None => (
            &[],
            &default_redaction,
            if config_tenant.is_empty() {
                "local"
            } else {
                config_tenant
            },
        ),
    };
    let socket = mvm_core::config::vm_substitution_endpoint_socket(vm_name);
    spawn_substitution_endpoint(SubstitutionSpawnParams {
        vm_name,
        state_dir,
        tenant,
        secrets,
        redaction,
        transport: EndpointTransport::Uds {
            path: socket.clone(),
        },
        // The hvf VMM has no transparent :80/:443 terminator — all egress is
        // the proxy-aware WireRequest path, so no terminator + no per-VM TLS.
        terminator_listen: None,
        tls_intermediate: None,
        network_policy: Some(network_policy),
        raw_egress: secrets.is_empty(),
    })?;
    Ok((EndpointGuard::new(vm_name), socket))
}

fn configure_hvf_supervisor_command(cmd: &mut Command) {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // Detach into its own session so a persistent HVF machine survives the
    // short-lived `mvmctl machine run -d` process that launched it.
    //
    // SAFETY: `pre_exec` runs after fork and before exec. The closure only
    // calls async-signal-safe `setsid` and returns an OS error if it fails.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn hvf_cmdline_extra(config: &VmStartConfig) -> Option<String> {
    let mut tokens = Vec::new();
    if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes) {
        tokens.push(uvols);
    }
    if let Some(token) = crate::microvm::verb_grant_cmdline_token(&config.name) {
        tokens.push(token);
    }
    if let Some(token) = crate::microvm::require_grant_cmdline_token(&config.name) {
        tokens.push(token);
    }
    (!tokens.is_empty()).then(|| tokens.join(" "))
}

impl VmBackend for HvfBackend {
    fn name(&self) -> &str {
        "hvf"
    }

    fn capabilities(&self) -> VmCapabilities {
        // vsock is live-proven through the unified run loop; the rest land as
        // pause/snapshot/networking are wired onto the primitive.
        VmCapabilities {
            vsock: true,
            // The hvf VMM is vsock-only by design: no guest NIC, and egress
            // rides the host vsock proxy (the gating endpoint), not a guest NIC.
            no_guest_nic: true,
            host_vsock_proxy: true,
            // The hvf VMM can serve the unpacked OCI tree as a read-only
            // virtiofs root (dev tier); the run-path tier gate selects it only for
            // non-prod, non-sealed workloads.
            virtiofs_root: true,
            // pause/snapshot/cow/remap land as they are wired onto the primitive.
            ..Default::default()
        }
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Same Hypervisor.framework microVM tier as LegacyMacos (Tier 2), but the in-house
        // VMM owns the surface and the data plane is vsock-only (no guest NIC;
        // egress rides the host gating endpoint). Claims 1-2/4-7 hold as on FC;
        // claim 3 (verified boot) does not hold on the default path — the
        // virtiofs-root serves a host directory that cannot be dm-verity-sealed.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1 — host-fs isolation via the VMM + admitted shares
                ClaimStatus::Holds,       // 2 — uid-0 protections, guest-side (same as FC)
                ClaimStatus::DoesNotHold, // 3 — virtiofs-root has no dm-verity; block+ext4 (FC/Option B) only
                ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds,       // 5 — vsock framing fuzzed
                ClaimStatus::Holds,       // 6 — dev image hash verified
                ClaimStatus::Holds,       // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "In-house Hypervisor.framework VMM on macOS 26+ Apple silicon (the default tier).",
                "vsock-only data plane: no guest NIC; egress rides the host gating endpoint (auditable).",
                "Claim 3 (verified boot) does not hold on the virtiofs-root path — dm-verity targets the block+ext4 backends (Firecracker + Option B).",
                "Pause/resume + snapshot land as they are wired onto the primitive.",
            ],
        }
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        // No parent-entitlement gate here: the detached supervisor self-signs the
        // hypervisor entitlement and does the HVF work. The parent (CLI) only
        // spawns it, so it needn't be entitled. (`is_available` still probes for
        // selection/doctor.)
        let kernel = config
            .kernel_path
            .clone()
            .ok_or_else(|| anyhow!("hvf backend requires an arm64 kernel Image (kernel_path)"))?;

        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        let pid_file = state_dir.join(PID_FILE_NAME);
        let console_log = state_dir.join("console.log");
        // Create/truncate the console capture file up front.
        let _ = crate::libkrun::open_console_capture(&console_log);

        // Clear any prior run's exit code so `wait` reads only this launch's.
        let workload_exit = state_dir.join("workload.exit");
        let _ = std::fs::remove_file(&workload_exit);

        // Always spawn the per-VM gating endpoint carrying the resolved policy and
        // route egress to it via `egress_relay_socket` — the endpoint is the sole
        // claim-10 gate (and secret substituter); the run loop only relays. The
        // guard reaps the endpoint on any early return below (a decrypted-secret
        // process can't outlive a failed launch) and is defused once boot is
        // confirmed (the stop path then owns teardown).
        let (mut endpoint_guard, egress_relay_socket) = {
            let (g, uds) = spawn_hvf_gating_endpoint(
                &config.name,
                &state_dir,
                &config.network_policy,
                config.tenant_id.as_deref().unwrap_or(""),
            )?;
            (g, Some(uds))
        };
        // Productionized per-VM agent RPC socket threaded through the supervisor
        // config; the `MVM_HVF_AGENT_SOCKET` dev hook still wins for live drivers.
        let agent_socket = std::env::var_os("MVM_HVF_AGENT_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| mvm_core::config::vm_hvf_agent_socket(&config.name));

        // virtiofs-root dev boot (Plan-223 tier gate): serve the unpacked+injected
        // tree read-only over virtio-fs; no block rootfs is attached.
        let virtiofs_root = config.virtiofs_root.clone().map(PathBuf::from);
        // Single workload rootfs → one ephemeral (RAM-backed) writable disk: the
        // guest mounts it `rw` but its writes must not persist to the base image.
        // Skipped entirely on the virtiofs-root path.
        let disks = if virtiofs_root.is_some() {
            Vec::new()
        } else {
            Some(config.rootfs_path.clone())
                .filter(|p| !p.is_empty())
                .map(|p| {
                    vec![HvfDisk {
                        path: PathBuf::from(p),
                        read_only: false,
                        ephemeral: true,
                    }]
                })
                .unwrap_or_default()
        };
        // A transient workload ends the VM by reporting its exit code over the
        // vsock exit port (the default — VM life = workload life); a persistent
        // (`-d`) VM ends on `stop`. MVM_HVF_TIMEOUT is only a backstop cap
        // (0 = none) against a guest that never reports + is never stopped.
        let timeout_secs = std::env::var("MVM_HVF_TIMEOUT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Interactive PTY runs (`machine run -it`) pre-open the console data
        // ports so the host can attach a shell; the supervisor binds them under
        // `<state_dir>/vsock/`. Create the dir up front so the bind can't miss.
        let console_data_sockets = hvf_console_data_sockets(&state_dir, config.dev_console);
        if !console_data_sockets.is_empty() {
            let vsock_dir = state_dir.join("vsock");
            std::fs::create_dir_all(&vsock_dir)
                .with_context(|| format!("create console vsock dir {}", vsock_dir.display()))?;
        }

        // Per-VM host-services broker UDS: the same path the host-agent daemon binds
        // below when it registers this VM. Threading it into the supervisor wires the
        // guest-side `BROKER_PORT` relay so a guest `host.audit.v1` call reaches the
        // broker, matching the other backends. Computed once, reused for the register
        // call below.
        let broker_listen_socket = mvm_core::config::vm_hvf_broker_socket(&config.name);

        let cfg = HvfSupervisorConfig {
            kernel: PathBuf::from(kernel),
            // Workload path: the supervisor's default cmdline (`init=/init`) is the
            // mkGuest contract, so leave it unset.
            cmdline: None,
            cmdline_extra: hvf_cmdline_extra(config),
            memory_mib: config.memory_mib,
            initramfs: config.initrd_path.clone().map(PathBuf::from),
            disks,
            virtiofs_root,
            vsock: true,
            console_log: console_log.clone(),
            pid_file: pid_file.clone(),
            workload_exit,
            timeout_secs,
            agent_socket: Some(agent_socket),
            substitution_socket: None,
            egress_relay_socket,
            broker_socket: Some(broker_listen_socket.clone()),
            console_data_sockets,
        };
        let json = serde_json::to_string(&cfg)
            .map_err(|e| anyhow!("serialize HvfSupervisorConfig: {e}"))?;

        let supervisor = resolve_supervisor_path()?;
        ui::info(&format!(
            "Starting HVF VM '{}' via {}...",
            config.name,
            supervisor.display()
        ));

        let mut cmd = Command::new(&supervisor);
        configure_hvf_supervisor_command(&mut cmd);
        let mut child = cmd
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe HvfSupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file (boot confirmed). If the supervisor exits first,
        // surface that — its stderr (inherited) carries the actionable detail.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        loop {
            if pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor: {e}"))?
            {
                bail!(
                    "hvf supervisor exited before writing its PID file (status: {status}); \
                     see {}",
                    console_log.display()
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "hvf supervisor did not confirm boot within {PID_FILE_TIMEOUT:?}; see {}",
                    console_log.display()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Boot confirmed: the supervisor's device is wired to the endpoint, so it
        // must outlive this launch. Defuse the guard (its Drop becomes a no-op);
        // the stop path now owns reaping the endpoint.
        endpoint_guard.defuse();

        // Register an admitted workload with the per-tenant host-agent daemon,
        // same as libkrun/legacy_macos: the daemon starts tracking this VM and binds its
        // BROKER_PORT socket. The guest-side BROKER_PORT bridge is wired on this
        // backend too — the supervisor config carries `broker_socket`
        // (`broker_listen_socket` above) and the vsock dispatcher relays
        // BROKER_PORT to it — so a guest `host.audit.v1` call reaches the broker
        // here just as it does on libkrun/legacy_macos (host->guest agent RPC over
        // GUEST_AGENT_PORT is a separate path). Registration keeps daemon-side
        // tracking + lifecycle parity with the other backends. Unlike libkrun/legacy_macos
        // there is no per-VM broker-fork fallback here, so MVM_HOST_AGENT_DAEMON=0
        // selects nothing — this backend is daemon-only. Best-effort: a
        // registration failure is logged, never a launch rollback (the workload
        // still runs). The guard reaps the registration if a later start step
        // fails; defused once the VM is confirmed up (the stop path then owns
        // teardown).
        let mut host_agent_guard =
            match crate::host_agent_spawn::register_host_agent_services_if_admitted(
                crate::host_agent_spawn::HostAgentServicesParams {
                    workload_id: &config.name,
                    tenant_id: config.tenant_id.as_deref(),
                    vm_name: &config.name,
                    state_dir: &state_dir,
                    broker_listen_socket: &broker_listen_socket,
                },
            ) {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(vm = %config.name, error = %e, "host-agent registration failed for this VM");
                    crate::host_agent_spawn::HostAgentServicesGuard::defused()
                }
            };

        // Detach: dropping the `Child` does not kill the process, so the
        // supervisor outlives this CLI invocation (reaped via its PID file).
        drop(child);
        host_agent_guard.defuse();
        ui::success(&format!(
            "HVF VM '{}' started (pid file: {}, console: {}).",
            config.name,
            pid_file.display(),
            console_log.display()
        ));
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        // Transient run-to-exit: block until the supervisor persists the guest's
        // workload exit code to `<state>/workload.exit` (shared helper, same file
        // every backend writes).
        Ok(crate::workload_wait::wait_for_workload_exit(&vm_state_dir(
            &id.0,
        )))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        let state_dir = vm_state_dir(&id.0);
        // Reap the per-VM substitution endpoint first (before the not-running
        // check), so a crashed VM's decrypted-secret process can't outlive the
        // guest. Idempotent + no-op when the VM spawned none (no secrets).
        crate::substitution_spawn::reap_substitution_endpoint(&state_dir, &id.0);
        // Deregister from the per-tenant host-agent daemon (no-op if this VM
        // never registered — an unadmitted dev VM, or a failed registration
        // that was already logged). The daemon itself stays warm.
        crate::host_agent_spawn::reap_host_agent_services_from_state(&state_dir, &id.0);
        let pid_path = state_dir.join(PID_FILE_NAME);
        if let Some(pid) = read_pid(&pid_path) {
            terminate_pid(pid);
        }
        let _ = std::fs::remove_file(&pid_path);
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        for vm in self.list()? {
            let _ = self.stop(&vm.id);
        }
        Ok(())
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        bail!("hvf pause/resume is not yet implemented (no snapshot/pause support)")
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        bail!("hvf pause/resume is not yet implemented (no snapshot/pause support)")
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let pid_path = vm_state_dir(&id.0).join(PID_FILE_NAME);
        Ok(match read_pid(&pid_path) {
            Some(pid) if pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = vms_root();
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries.flatten() {
            let pid_path = entry.path().join(PID_FILE_NAME);
            if !pid_path.exists() {
                continue; // not an HVF-managed VM
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let alive = read_pid(&pid_path).is_some_and(pid_alive);
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

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        // Capture-only console; one log (no separate hypervisor stream).
        let log = vm_state_dir(&id.0).join("console.log");
        std::fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))
    }

    fn is_available(&self) -> Result<bool> {
        Ok(hvf_probe())
    }

    fn install(&self) -> Result<()> {
        ui::info("Hypervisor.framework is built into macOS; no host install needed.");
        if !hvf_probe() {
            ui::info(
                "HVF unavailable — needs macOS / Apple silicon (and the binary \
                 codesigned with com.apple.security.hypervisor).",
            );
        }
        Ok(())
    }
}

/// Probe whether HVF can actually run here. The backend's lifecycle is
/// platform-agnostic (spawns a binary + tracks PID files), so it compiles
/// everywhere; only this probe is macOS/Apple-silicon-specific.
fn hvf_probe() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        crate::hvf::probe_available()
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_as_hvf() {
        assert_eq!(HvfBackend.name(), "hvf");
    }

    #[test]
    fn security_profile_is_tier_2_with_claim_3_partial() {
        // The macOS-26 default backend must report a real tier — doctor's
        // security posture derives from this, and the trait default is "Unknown".
        let profile = HvfBackend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        assert!(profile.layer_coverage.is_microvm());
        assert_eq!(profile.dropped_claims(), vec![3]);
    }

    #[test]
    fn vsock_is_capable_pause_snapshot_are_not() {
        let c = HvfBackend.capabilities();
        assert!(c.vsock, "vsock is live-proven");
        assert!(!c.pause_resume);
        assert!(!c.snapshots);
        assert!(!c.tap_networking);
    }

    #[test]
    fn console_data_sockets_empty_when_dev_console_disabled() {
        let sockets = hvf_console_data_sockets(Path::new("/state/hvf"), false);
        assert!(sockets.is_empty());
    }

    #[test]
    fn console_data_sockets_populated_when_dev_console_enabled() {
        let sockets = hvf_console_data_sockets(Path::new("/state/hvf"), true);
        assert_eq!(
            sockets.len(),
            mvm_guest::vsock::DEV_CONSOLE_DATA_PORT_COUNT as usize
        );
        let first = sockets.first().expect("first console socket");
        assert_eq!(first.guest_port, mvm_guest::vsock::CONSOLE_PORT_BASE + 1);
        assert_eq!(
            first.host_socket,
            PathBuf::from("/state/hvf/vsock/vsock-20001.sock")
        );
    }

    #[test]
    fn pause_resume_report_unimplemented() {
        let id = VmId("x".into());
        assert!(HvfBackend.pause(&id).is_err());
        assert!(HvfBackend.resume(&id).is_err());
    }

    #[test]
    fn unknown_vm_is_stopped_and_stop_is_idempotent() {
        let id = VmId("hvf-nonexistent-test-vm".into());
        assert_eq!(HvfBackend.status(&id).unwrap(), VmStatus::Stopped);
        assert!(HvfBackend.stop(&id).is_ok());
    }

    /// `start()` registers an admitted VM with the per-tenant host-agent
    /// daemon (mirrors libkrun/legacy_macos); `stop()` must reap that registration.
    /// This exercises the `stop()` half of the wiring without spawning a real
    /// supervisor: it plants the tenant-ref marker `register_host_agent_
    /// services_if_admitted` would have written, then asserts `stop()`
    /// removes it via `reap_host_agent_services_from_state` — the same call
    /// libkrun/legacy_macos make. The daemon connect itself is best-effort (no daemon
    /// is running for this fake tenant), so this only verifies the reap path
    /// is wired, not the network round-trip (covered by `host_agent_spawn`'s
    /// own tests).
    #[test]
    fn stop_reaps_host_agent_tenant_ref_marker() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::set_var("MVM_DATA_DIR", tmp.path());
        }

        let name = "hvf-host-agent-reap-test-vm";
        let state_dir = vm_state_dir(name);
        std::fs::create_dir_all(&state_dir).unwrap();
        let tenant_ref = state_dir.join("host-agent.tenant");
        std::fs::write(&tenant_ref, "local").unwrap();

        let id = VmId(name.to_string());
        assert!(HvfBackend.stop(&id).is_ok());
        assert!(
            !tenant_ref.exists(),
            "stop() must reap the host-agent tenant-ref marker"
        );

        // SAFETY: serialized by HOME_TEST_LOCK.
        unsafe {
            std::env::remove_var("MVM_DATA_DIR");
        }
    }

    #[test]
    fn hvf_cmdline_extra_threads_volume_and_verb_grant_tokens() {
        use mvm_core::plan::{Nonce, VerbGrant, VerbId};
        use mvm_core::protocol::vm_backend::{VerbGrantEnvelope, VmVolume, VmVolumeKind};

        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.set("MVM_DATA_DIR", tmp.path());

        let vm_name = "hvf-verb-grant-token-test";
        let state_dir = vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        let nonce = Nonce::from_bytes([7u8; 16]);
        let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "aa".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            grant: VerbGrant {
                session_id: vm_name.to_string(),
                plan_nonce: nonce,
                not_after,
                verbs: vec![VerbId::new("ping").unwrap()],
                sig: vec![0u8; 64],
            },
        };
        std::fs::write(
            state_dir.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();

        let config = VmStartConfig {
            name: vm_name.to_string(),
            volumes: vec![VmVolume {
                host: "/host/share".to_string(),
                guest: "/guest/share".to_string(),
                size: String::new(),
                read_only: true,
                kind: VmVolumeKind::DirShare,
                encrypted: false,
            }],
            ..Default::default()
        };
        let extra = hvf_cmdline_extra(&config).expect("cmdline extra");

        assert!(extra.contains("mvm.uvols="));
        assert!(extra.contains("mvm.verb_grant="));
        assert!(extra.contains("mvm.require_grant=1"));
    }

    #[test]
    fn hvf_supervisor_command_starts_a_new_session() {
        let tmp = tempfile::tempdir().unwrap();
        let pid_file = tmp.path().join("pid");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("printf '%s\n' \"$$\" > \"$1\"; sleep 30")
            .arg("sh")
            .arg(&pid_file);
        configure_hvf_supervisor_command(&mut cmd);

        let mut child = cmd.spawn().expect("spawn test helper");
        let deadline = Instant::now() + Duration::from_secs(2);
        let pid = loop {
            if let Some(pid) = read_pid(&pid_file) {
                break pid;
            }
            assert!(
                Instant::now() < deadline,
                "test helper did not write its pid"
            );
            std::thread::sleep(Duration::from_millis(10));
        };

        let sid = unsafe { libc::getsid(pid) };
        terminate_pid(pid);
        let _ = child.wait();

        assert_ne!(sid, -1, "getsid failed");
        assert_eq!(
            sid, pid,
            "detached HVF supervisor helper must become its own session leader"
        );
    }

    #[test]
    fn terminate_pid_reaps_child_without_grace_timeout() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;

        let started = Instant::now();
        terminate_pid(pid);
        let elapsed = started.elapsed();

        let _ = child.wait();
        assert!(
            elapsed < Duration::from_secs(2),
            "terminate_pid took {elapsed:?}, expected it to reap the child before the grace timeout"
        );
        assert!(!pid_alive(pid));
    }

    #[test]
    fn supervisor_path_env_must_point_at_a_file() {
        // SAFETY: single-threaded test mutation of a process env var.
        unsafe { std::env::set_var("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor") };
        let r = resolve_supervisor_path();
        unsafe { std::env::remove_var("MVM_HVF_SUPERVISOR_PATH") };
        assert!(r.is_err());
    }

    #[test]
    fn hvf_console_data_sockets_empty_for_sealed_boot() {
        // A sealed prod boot (dev_console = false) opens no console listeners.
        assert!(hvf_console_data_sockets(Path::new("/tmp/state"), false).is_empty());
    }

    #[test]
    fn hvf_console_data_sockets_match_dev_console_transport_paths() {
        let state = Path::new("/tmp/state");
        let socks = hvf_console_data_sockets(state, true);
        assert!(
            !socks.is_empty(),
            "an interactive run pre-opens console ports"
        );
        // The guest ports are exactly the dev console data range.
        let got: Vec<u32> = socks.iter().map(|s| s.guest_port).collect();
        let want: Vec<u32> = mvm_guest::vsock::dev_console_data_ports().collect();
        assert_eq!(got, want);
        // Each host UDS is `<state_dir>/vsock/vsock-<port>.sock`, the exact path
        // `DevConsoleTransport` dials — a drift here silently breaks PTY attach.
        for s in &socks {
            assert_eq!(
                s.host_socket,
                state
                    .join("vsock")
                    .join(mvm_core::config::vsock_socket_filename(s.guest_port)),
            );
        }
    }
}
