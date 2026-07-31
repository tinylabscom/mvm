//! `HvfBackend` — the `VmBackend` impl for the raw-HVF macOS path.
//!
//! Lifecycle mirrors the other detached-supervisor backend (libkrun): `start`
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
use mvm_core::config::{vm_state_dir, vms_dir};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, LayerCoverage, SnapshotCapability, VmBackend,
    VmCapabilities, VmExitStatus, VmId, VmInfo, VmStartConfig, VmStatus,
};

use crate::base::ui;
use crate::workload_runner::cmdline;

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

/// Locate the per-VM HVF supervisor binary. Compiled by mvmctl's build script;
/// see [`crate::aux_bin`] for the search order.
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    crate::aux_bin::resolve(&crate::aux_bin::AuxBin {
        bin: "mvm-hvf-supervisor",
        env_var: "MVM_HVF_SUPERVISOR_PATH",
    })
}

fn vms_root() -> PathBuf {
    vms_dir()
}

/// The per-VM gating endpoint is the sole egress gate on hvf (claim-10
/// default-deny plus optional secret substitution). It only needs to run for a
/// workload that can actually reach the network: an admitted egress policy, or a
/// bound-secret authority whose credentials are substituted on the egress path.
/// A deny-all run carrying no secrets has no reachable egress, so the endpoint is
/// skipped and `EGRESS_PORT` is left unwired — any guest dial then fails closed,
/// mirroring libkrun's no-secrets no-op.
fn hvf_endpoint_needed(
    network_policy: &mvm_core::policy::network_policy::NetworkPolicy,
    state_dir: &Path,
) -> bool {
    network_policy.allows_egress()
        || crate::egress_shared::state_has_bound_secrets(state_dir).unwrap_or(false)
}

/// Spawn the per-VM gating endpoint carrying the resolved `NetworkPolicy` when the
/// run can reach the network ([`hvf_endpoint_needed`]), returning an armed
/// `EndpointGuard` and the endpoint socket to hand the supervisor as its
/// `egress_relay_socket`. When neither egress is admitted nor a secret is bound,
/// no endpoint is spawned: a defused (no-op) guard and `None` socket are returned
/// so the guest's egress path stays unwired and fails closed. When a plan carries
/// no secrets but egress is admitted, the endpoint runs raw (no substitution) but
/// still enforces the policy.
fn spawn_hvf_gating_endpoint_if_needed(
    vm_name: &str,
    state_dir: &Path,
    network_policy: &mvm_core::policy::network_policy::NetworkPolicy,
    config_tenant: &str,
) -> Result<(crate::substitution_spawn::EndpointGuard, Option<PathBuf>)> {
    use crate::substitution_spawn::{
        EndpointGuard, EndpointTransport, SubstitutionSpawnParams, spawn_substitution_endpoint,
    };
    use mvm_core::policy::RedactionPolicy;

    if !hvf_endpoint_needed(network_policy, state_dir) {
        return Ok((EndpointGuard::defused(), None));
    }

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
    Ok((EndpointGuard::new(vm_name), Some(socket)))
}

fn hvf_workload_disks(config: &VmStartConfig) -> Vec<HvfDisk> {
    if config.virtiofs_root.is_some() {
        return Vec::new();
    }

    if cmdline::verity_enabled(config) {
        let mut disks = vec![
            HvfDisk {
                path: PathBuf::from(&config.rootfs_path),
                read_only: true,
                ephemeral: false,
            },
            HvfDisk {
                path: PathBuf::from(
                    config
                        .verity_path
                        .as_deref()
                        .expect("verity-enabled boot must carry a verity sidecar"),
                ),
                read_only: true,
                ephemeral: false,
            },
        ];
        if let Some((overlay_path, overlay_verity_path, _)) = cmdline::runtime_overlay(config) {
            disks.push(HvfDisk {
                path: PathBuf::from(overlay_path),
                read_only: true,
                ephemeral: false,
            });
            disks.push(HvfDisk {
                path: PathBuf::from(overlay_verity_path),
                read_only: true,
                ephemeral: false,
            });
        }
        return disks;
    }

    let mut disks = Some(config.rootfs_path.clone())
        .filter(|p| !p.is_empty())
        .map(|p| {
            vec![HvfDisk {
                path: PathBuf::from(p),
                read_only: false,
                ephemeral: true,
            }]
        })
        .unwrap_or_default();
    // A non-verity dev boot has no initramfs to mount the runtime overlay, so
    // attach it as a plain read-only virtio-blk device immediately after the
    // rootfs (=> /dev/vdb). The guest `/init` mounts it from the matching
    // `mvm.runtime_data=` cmdline token. Only when the rootfs disk is present,
    // so the overlay never slides down to /dev/vda.
    if !disks.is_empty()
        && let Some(overlay) = crate::microvm::non_verity_overlay_ext4(config)
    {
        disks.push(HvfDisk {
            path: PathBuf::from(overlay),
            read_only: true,
            ephemeral: false,
        });
    }
    disks
}

fn ensure_hvf_runtime_source_supported(config: &VmStartConfig) -> Result<()> {
    if config.runtime_source_policy != mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay {
        return Ok(());
    }
    if config.virtiofs_root.is_some() {
        bail!("required-overlay hvf boots do not support virtiofs-root");
    }
    // Two supported required-overlay shapes, keyed on whether the rootfs asks to
    // be sealed. A sealed boot (verity metadata present) must be fully verity
    // capable — a missing initrd fails closed rather than silently downgrading to
    // an unverified root — and carries the dm-verity overlay triple its initramfs
    // (mvm-verity-init) mounts. A non-verity dev boot instead mounts a plain
    // read-only overlay from `/dev/vdb` in its guest `/init`.
    let verity_intended = config.roothash.is_some() || config.verity_path.is_some();
    if verity_intended {
        if !cmdline::verity_enabled(config) {
            bail!(
                "required-overlay hvf boot requires verity metadata plus an initrd \
                 (`--initrd` or sibling rootfs.initrd)"
            );
        }
        if cmdline::runtime_overlay(config).is_none() {
            bail!("required-overlay hvf boot requires the runtime overlay artifact triple");
        }
    } else if crate::microvm::non_verity_overlay_ext4(config).is_none() {
        bail!(
            "required-overlay hvf boot requires the runtime overlay artifact triple \
             (a non-verity boot mounts it as a plain read-only /dev/vdb)"
        );
    }
    Ok(())
}

fn workspace_root_from_manifest_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent()?.parent().map(Path::to_path_buf)
}

fn hvf_supervisor_launch_support_available() -> bool {
    if let Some(path) = std::env::var_os("MVM_HVF_SUPERVISOR_PATH").map(PathBuf::from) {
        return path.is_file();
    }

    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        && dir.join("mvm-hvf-supervisor").is_file()
    {
        return true;
    }

    let Some(workspace_root) = workspace_root_from_manifest_dir() else {
        return false;
    };

    for variant in ["release", "debug"] {
        if workspace_root
            .join("target")
            .join(variant)
            .join("mvm-hvf-supervisor")
            .is_file()
        {
            return true;
        }
    }

    workspace_root.join("Cargo.toml").is_file()
}

fn hvf_workload_support_available() -> bool {
    hvf_platform_supported() && hvf_supervisor_launch_support_available()
}

impl VmBackend for HvfBackend {
    fn name(&self) -> &str {
        "hvf"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Hvf
    }

    fn capabilities(&self) -> VmCapabilities {
        let proxy_path_ready = hvf_workload_support_available();
        // vsock is live-proven through the unified run loop; the rest land as
        // pause/snapshot/networking are wired onto the primitive.
        VmCapabilities {
            snapshot_capability: SnapshotCapability::Unsupported,
            standby_pool: false,
            vsock: true,
            // The hvf VMM is vsock-only by design: no guest NIC, and egress rides
            // the host vsock proxy (the per-VM gating endpoint), not a guest NIC.
            // Both are unconditional so the backend fails closed: a degraded host
            // (the detached supervisor can't launch) loses egress entirely — it
            // never falls back to a routable guest NIC. HVF never advertises a NIC
            // and always routes egress through the per-VM endpoint over vsock.
            no_routable_guest_nic: true,
            host_vsock_proxy: true,
            // The hvf VMM can serve the unpacked OCI tree as a read-only
            // virtiofs root (dev tier); the run-path tier gate selects it only for
            // non-prod, non-sealed workloads. This stays gated on the launchable
            // supervisor path — it is a dev-tier boot capability, not egress.
            virtiofs_root: proxy_path_ready,
            // pause/snapshot/cow/remap land as they are wired onto the primitive.
            ..Default::default()
        }
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Hypervisor.framework microVM tier (Tier 2): the in-house VMM owns the
        // surface and the data plane is vsock-only (no guest NIC; egress rides
        // the host gating endpoint). Claims 1-2/4-7 hold as on FC; claim 3
        // (verified boot) does not hold on the default path — the virtiofs-root
        // serves a host directory that cannot be dm-verity-sealed.
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
        ensure_hvf_runtime_source_supported(config)?;

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

        // Spawn the per-VM gating endpoint only for a run that can reach the
        // network (admitted egress or a bound-secret authority) and route egress
        // to it via `egress_relay_socket` — the endpoint is the sole claim-10 gate
        // (and secret substituter); the run loop only relays. A deny-all run with
        // no secrets gets no endpoint and no relay socket, so the guest's egress
        // path stays unwired and fails closed. The guard reaps the endpoint on any
        // early return below (a decrypted-secret process can't outlive a failed
        // launch) and is defused once boot is confirmed (the stop path then owns
        // teardown); a skipped endpoint yields a defused no-op guard.
        let (mut endpoint_guard, egress_relay_socket) = spawn_hvf_gating_endpoint_if_needed(
            &config.name,
            &state_dir,
            &config.network_policy,
            config.tenant_id.as_deref().unwrap_or(""),
        )?;
        // Productionized per-VM agent RPC socket threaded through the supervisor
        // config; the `MVM_HVF_AGENT_SOCKET` dev hook still wins for live drivers.
        let agent_socket = std::env::var_os("MVM_HVF_AGENT_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| mvm_core::config::vm_hvf_agent_socket(&config.name));

        // virtiofs-root dev boot (Plan-223 tier gate): serve the unpacked+injected
        // tree read-only over virtio-fs; no block rootfs is attached.
        let virtiofs_root = config.virtiofs_root.clone().map(PathBuf::from);
        let disks = hvf_workload_disks(config);
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
        // the shared HVF-style console socket dir. Create that dir up front so
        // the bind can't miss.
        let console_data_sockets = hvf_console_data_sockets(&state_dir, config.dev_console);
        if !console_data_sockets.is_empty() {
            let vsock_dir = console_data_sockets[0]
                .host_socket
                .parent()
                .map(Path::to_path_buf)
                .ok_or_else(|| anyhow!("console data socket missing parent directory"))?;
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
            // Thread a full cmdline only when we need extra workload tokens;
            // otherwise keep the supervisor default (`init=/init`).
            cmdline: cmdline::workload_cmdline(
                config,
                &state_dir,
                crate::hvf_bootargs::workload_bootargs,
            ),
            memory_mib: config.memory_mib,
            initramfs: cmdline::effective_initrd(config),
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
        // the stop path now owns reaping the endpoint for the VM's lifetime.
        endpoint_guard.defuse();

        // Register an admitted workload with the per-tenant host-agent daemon,
        // same as on libkrun: the daemon starts tracking this VM and binds its
        // BROKER_PORT socket. The guest-side BROKER_PORT bridge is wired on this
        // backend too — the supervisor config carries `broker_socket`
        // (`broker_listen_socket` above) and the vsock dispatcher relays
        // BROKER_PORT to it — so a guest `host.audit.v1` call reaches the broker
        // here just as it does on libkrun (host->guest agent RPC over
        // GUEST_AGENT_PORT is a separate path). Registration keeps daemon-side
        // tracking + lifecycle parity with the other backends. Unlike libkrun,
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
        Ok(hvf_workload_support_available())
    }

    fn install(&self) -> Result<()> {
        ui::info("Hypervisor.framework is built into macOS; no host install needed.");
        if !hvf_workload_support_available() {
            ui::info(
                "HVF workload launch unavailable — needs macOS / Apple silicon and a \
                 launchable mvm-hvf-supervisor helper.",
            );
        }
        Ok(())
    }
}

/// Probe whether HVF can actually run here. The backend's lifecycle is
/// platform-agnostic (spawns a binary + tracks PID files), so it compiles
/// everywhere; only this probe is macOS/Apple-silicon-specific.
fn hvf_platform_supported() -> bool {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        true
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

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
    fn supervisor_launch_support_respects_override_path() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("mvm-hvf-supervisor");
        std::fs::write(&good, b"stub").expect("stub supervisor");

        env.set("MVM_HVF_SUPERVISOR_PATH", &good);
        assert!(hvf_supervisor_launch_support_available());

        env.set("MVM_HVF_SUPERVISOR_PATH", dir.path().join("missing"));
        assert!(!hvf_supervisor_launch_support_available());
    }

    #[test]
    fn degraded_host_still_advertises_failclosed_egress_caps() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor");
        let caps = HvfBackend.capabilities();
        // SAFETY: test-only env mutation.
        unsafe {
            std::env::remove_var("MVM_HVF_SUPERVISOR_PATH");
        }
        // Fail-closed: even a degraded host (unlaunchable supervisor) advertises
        // no routable NIC and the host vsock proxy, so egress can only ride the
        // per-VM endpoint — it never falls back to a guest NIC. Only the dev-tier
        // virtiofs-root boot capability drops when the supervisor path is dead.
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
        assert!(!caps.virtiofs_root);
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    #[test]
    fn launchable_supervisor_enables_virtiofs_root_dev_boot() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("mvm-hvf-supervisor");
        std::fs::write(&good, b"stub").expect("stub supervisor");

        env.set("MVM_HVF_SUPERVISOR_PATH", &good);
        let caps = HvfBackend.capabilities();
        let available = HvfBackend.is_available().expect("availability probe");
        assert!(available);
        // The egress caps are unconditional (fail-closed); a launchable
        // supervisor additionally enables the dev-tier virtiofs-root boot.
        assert!(caps.no_routable_guest_nic);
        assert!(caps.host_vsock_proxy);
        assert!(caps.virtiofs_root);
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
            mvm_agentd::vsock::DEV_CONSOLE_DATA_PORT_COUNT as usize
        );
        let first = sockets.first().expect("first console socket");
        assert_eq!(first.guest_port, mvm_agentd::vsock::CONSOLE_PORT_BASE + 1);
        assert_eq!(
            first.host_socket,
            PathBuf::from("/state/hvf/vsock/vsock-20001.sock")
        );
    }

    #[test]
    fn endpoint_not_needed_for_deny_all_without_secrets() {
        // Fail-closed default: a deny-all workload carrying no bound secrets has
        // no reachable egress path, so no gating endpoint is spawned and the
        // supervisor gets no relay socket. Mirrors libkrun's no-secrets no-op.
        let dir = tempfile::tempdir().unwrap();
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        assert!(!hvf_endpoint_needed(&deny_all, dir.path()));
    }

    #[test]
    fn endpoint_needed_when_egress_admitted() {
        // Any admitted egress authority means the endpoint is the sole gate and
        // must run (claim-10 default-deny + optional substitution).
        let dir = tempfile::tempdir().unwrap();
        let allow_egress = mvm_core::network_policy::NetworkPolicy::preset(
            mvm_core::network_policy::NetworkPreset::Dev,
        );
        assert!(allow_egress.allows_egress());
        assert!(hvf_endpoint_needed(&allow_egress, dir.path()));
    }

    #[test]
    fn endpoint_needed_when_bound_secrets_present_even_under_deny_all() {
        // A bound-secret authority routes outbound through the substitution
        // endpoint even when the policy itself denies raw egress, so the
        // endpoint must run. Plant a bare admitted plan carrying one secret.
        let dir = tempfile::tempdir().unwrap();
        write_plan_with_secret(dir.path());
        let deny_all = mvm_core::network_policy::NetworkPolicy::deny_all();
        assert!(!deny_all.allows_egress());
        assert!(
            crate::egress_shared::state_has_bound_secrets(dir.path()).unwrap(),
            "planted plan must decode a bound secret"
        );
        assert!(hvf_endpoint_needed(&deny_all, dir.path()));
    }

    /// Write a bare `ExecutionPlan` carrying one static secret to
    /// `<state_dir>/plan.json`, the shape `decode_plan_secrets_from_state` reads.
    fn write_plan_with_secret(state_dir: &Path) {
        use mvm_core::plan::{
            PlanSeccompTier, SecretBinding, SecretReleasePolicy, SecretSource, SynthesisInput,
            synthesize_plan,
        };
        use mvm_core::policy::RedactionPolicy;

        let input = SynthesisInput {
            vm_name: "hvf-secret-vm",
            tenant: None,
            backend_name: "hvf",
            image_name: "img",
            image_sha256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            image_cosign_bundle: None,
            intent: None,
            seccomp_tier: PlanSeccompTier::Standard,
            network_policy_ref: None,
            fs_policy_ref: None,
            egress_policy_ref: None,
            tool_policy_ref: None,
            secret_release: SecretReleasePolicy::PlanBound,
            secrets: vec![SecretBinding {
                name: "API_KEY".into(),
                source: SecretSource::Keystore {
                    address: "test-key".into(),
                },
            }],
            audit_event_prefix: None,
            cpus: 2,
            mem_mib: 512,
            disk_mib: 0,
            boot_timeout_secs: 60,
            exec_timeout_secs: 0,
            destroy_on_exit: false,
            bundle_pin: None,
            deps_volume: None,
            shares: Vec::new(),
            redaction: RedactionPolicy::default(),
            reversible_replacement: mvm_core::policy::ReversibleReplacementPolicy::default(),
            audit_labels: Default::default(),
            agent_verbs: None,
            services: Vec::new(),
        };
        let plan = synthesize_plan(&input).expect("synthesize plan with secret");
        let json = serde_json::to_string(&plan).expect("serialize plan");
        std::fs::write(state_dir.join("plan.json"), json).expect("write plan.json");
    }

    #[test]
    fn hvf_workload_disks_use_read_only_verity_layout_with_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };
        let disks = hvf_workload_disks(&config);
        assert_eq!(disks.len(), 4);
        assert!(disks.iter().all(|disk| disk.read_only));
        assert!(disks.iter().all(|disk| !disk.ephemeral));
        assert_eq!(disks[0].path, rootfs);
        assert_eq!(disks[1].path, verity);
        assert_eq!(disks[2].path, PathBuf::from("/tmp/runtime.ext4"));
        assert_eq!(disks[3].path, PathBuf::from("/tmp/runtime.verity"));
    }

    #[test]
    fn hvf_non_verity_boot_attaches_runtime_overlay_as_vdb() {
        // A plain dev rootfs (no verity) with a resolved overlay triple: the
        // rootfs stays the ephemeral read-write /dev/vda, and the overlay is a
        // read-only /dev/vdb the guest `/init` mounts from the cmdline token.
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            ..Default::default()
        };
        let disks = hvf_workload_disks(&config);
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].path, PathBuf::from("/tmp/rootfs.ext4"));
        assert!(!disks[0].read_only);
        assert!(disks[0].ephemeral);
        assert_eq!(disks[1].path, PathBuf::from("/tmp/runtime.ext4"));
        assert!(disks[1].read_only);
        assert!(!disks[1].ephemeral);

        let dir = tempfile::tempdir().unwrap();
        let assembled =
            cmdline::workload_cmdline(&config, dir.path(), crate::hvf_bootargs::workload_bootargs)
                .expect("cmdline");
        assert!(
            assembled.contains("mvm.runtime_data=/dev/vdb"),
            "got: {assembled}"
        );
        assert!(!assembled.contains("mvm.runtime_hash="), "got: {assembled}");
    }

    #[test]
    fn hvf_non_verity_boot_without_overlay_attaches_only_rootfs() {
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::PreferOverlay,
            ..Default::default()
        };
        assert_eq!(hvf_workload_disks(&config).len(), 1);
    }

    #[test]
    fn required_overlay_hvf_support_rejects_missing_overlay_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        let initrd = dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let err = ensure_hvf_runtime_source_supported(&config).unwrap_err();
        assert!(err.to_string().contains("runtime overlay artifact triple"));
    }

    #[test]
    fn required_overlay_hvf_support_rejects_missing_initrd() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let verity = dir.path().join("rootfs.verity");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();

        let config = VmStartConfig {
            rootfs_path: rootfs.display().to_string(),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let err = ensure_hvf_runtime_source_supported(&config).unwrap_err();
        assert!(err.to_string().contains("rootfs.initrd"));
    }

    #[test]
    fn required_overlay_hvf_support_accepts_non_verity_block_overlay() {
        // A non-verity dev boot carrying the resolved overlay triple is served by
        // the plain read-only /dev/vdb mount — no verity metadata or initrd.
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_overlay_path: Some("/tmp/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/tmp/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        assert!(ensure_hvf_runtime_source_supported(&config).is_ok());
    }

    #[test]
    fn required_overlay_hvf_support_rejects_non_verity_without_overlay() {
        let config = VmStartConfig {
            rootfs_path: "/tmp/rootfs.ext4".into(),
            runtime_source_policy: mvm_core::vm_backend::RuntimeSourcePolicy::RequiredOverlay,
            ..Default::default()
        };
        let err = ensure_hvf_runtime_source_supported(&config).unwrap_err();
        assert!(err.to_string().contains("/dev/vdb"));
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
    /// daemon (mirrors libkrun); `stop()` must reap that registration.
    /// This exercises the `stop()` half of the wiring without spawning a real
    /// supervisor: it plants the tenant-ref marker `register_host_agent_
    /// services_if_admitted` would have written, then asserts `stop()`
    /// removes it via `reap_host_agent_services_from_state` — the same call
    /// libkrun makes. The daemon connect itself is best-effort (no daemon
    /// is running for this fake tenant), so this only verifies the reap path
    /// is wired, not the network round-trip (covered by `host_agent_spawn`'s
    /// own tests).
    #[test]
    fn stop_reaps_host_agent_tenant_ref_marker() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path());

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
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut env = TestEnv::new();
        env.set("MVM_HVF_SUPERVISOR_PATH", "/no/such/mvm-hvf-supervisor");
        let r = resolve_supervisor_path();
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
        let want: Vec<u32> = mvm_agentd::vsock::dev_console_data_ports().collect();
        assert_eq!(got, want);
        // Each host UDS is `<state_dir>/vsock/vsock-<port>.sock`, the exact path
        // `DevConsoleTransport` dials — a drift here silently breaks PTY attach.
        for s in &socks {
            assert_eq!(
                s.host_socket,
                mvm_core::config::vm_hvf_vsock_port_socket_at(state, s.guest_port),
            );
        }
    }
}
