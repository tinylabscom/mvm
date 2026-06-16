//! libkrun backend for mvm.
//!
//! Tier 2 microVM backend that runs on
//! Linux KVM and macOS Apple Silicon. The lifecycle
//! delegates to a per-VM `mvm-libkrun-supervisor` subprocess
//! rather than calling libkrun in-process: `krun_start_enter` calls
//! `exit()` on the host process when the guest powers off, so any
//! in-process registry would tear down sibling guests. One process per
//! VM scopes the `exit()` to that supervisor and lets the parent
//! `mvmctl` survive a guest shutdown.
//!
//! ## Lifecycle
//!
//! - `start` writes `~/.mvm/vms/<name>/{rootfs.ref,kernel.ref}` runtime
//!   metadata (so `mvmctl console` can find the artifacts), serializes a
//!   [`SupervisorConfig`], spawns `mvm-libkrun-supervisor` with the JSON
//!   on stdin, and waits up to `PID_FILE_TIMEOUT` for the supervisor
//!   to write its PID file. Returns once the supervisor is running or
//!   exits with an error if the spawn fails or PID file never appears.
//! - `stop` reads `<vm_state_dir>/libkrun.pid`, sends `SIGTERM`, polls
//!   for the process to exit, and falls back to `SIGKILL` if it doesn't
//!   die within `STOP_TIMEOUT`.
//! - `status` reads the PID file and probes with `kill(pid, 0)`.
//! - `list` walks `~/.mvm/vms/*/libkrun.pid`.

use anyhow::{Result, anyhow, bail};
use mvm_core::vm_backend::{
    BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage, SnapshotCapability,
    StandbyClaim, StandbyError, StandbyHandle, StandbySpec, StandbyState, StartMode, VmBackend,
    VmCapabilities, VmId, VmInfo, VmStartConfig, VmStatus, WarmStartError,
};
use mvm_storage::snapshot::SnapshotUpper;

use crate::base::ui;
use libkrun_sys::{
    BridgeRestartPolicy, KrunContext, SupervisorAttachConfig, SupervisorBaseConfig,
    SupervisorConfig,
};
use mvm_core::config::{mvm_data_dir, vm_console_log, vm_libkrun_pid, vm_state_dir};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// libkrun backend (Linux KVM / macOS Hypervisor.framework).
pub struct LibkrunBackend;

use crate::substitution_spawn::EndpointGuard;

/// Spawn the per-VM substitution endpoint when the admitted plan carries egress
/// secrets, returning an armed [`EndpointGuard`]; a secret-free plan (or no
/// `plan.json`) yields a defused no-op guard. The libkrun guest reaches the
/// endpoint by dialing `connect_host_vsock(SUBSTITUTION_PORT)`; libkrun proxies
/// that to the per-VM UDS the endpoint binds, so the transport is `Uds`. No
/// transparent terminator on this path (`terminator_listen: None`), hence no
/// per-VM TLS intermediate.
fn spawn_libkrun_egress_endpoint_if_needed(
    vm_name: &str,
    state_dir: &Path,
) -> Result<EndpointGuard> {
    use crate::substitution_spawn::{
        EndpointTransport, SubstitutionSpawnParams, spawn_substitution_endpoint,
    };
    let Some((secrets, redaction, tenant)) =
        crate::egress_shared::decode_plan_secrets_from_state(state_dir)?
    else {
        return Ok(EndpointGuard::defused());
    };
    spawn_substitution_endpoint(SubstitutionSpawnParams {
        vm_name,
        state_dir,
        tenant: &tenant,
        secrets: &secrets,
        redaction: &redaction,
        transport: EndpointTransport::Uds {
            path: mvm_core::config::vm_vsock_port_socket(
                vm_name,
                mvm_guest::vsock::SUBSTITUTION_PORT,
            ),
        },
        terminator_listen: None,
        tls_intermediate: None,
    })?;
    Ok(EndpointGuard::new(vm_name))
}

/// How long [`LibkrunBackend::start`] waits for the supervisor to
/// write its PID file before giving up and killing the child.
const PID_FILE_TIMEOUT: Duration = Duration::from_secs(5);
/// After the PID file appears the supervisor still has to bind the
/// per-port vsock listener socket; callers (the console attach,
/// `shell_exec` via `connect_with_auto_start`) race that window and
/// wrongly see the VM as "not running". `start` waits for the
/// agent socket before returning so "ready" actually means reachable.
const VSOCK_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// How long [`LibkrunBackend::stop`] waits after `SIGTERM` before
/// escalating to `SIGKILL`. Tight because libkrun's signal handling
/// under `krun_start_enter` is empirically unreliable — when the
/// supervisor is spawned via `std::process::Command` (the production
/// `mvmctl up` path), SIGTERM often doesn't reach the in-supervisor
/// `sigaction` handler before we escalate. The in-supervisor handler
/// (see `libkrun_sys::install_shutdown_handler`) still helps the
/// shell-stop case where SIGTERM is delivered cleanly (~200 ms); in
/// the always-escalate cargo-spawn / launchd path a shorter timeout
/// means `mvmctl stop` returns in 2 s instead of 5 s.
const STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Upper bound for `wait()` (the `up --wait` path): how long to wait
/// for the guest's one-shot workload to finish and report its exit code via
/// `<vm_state_dir>/workload.exit`. A workload that exceeds this (or crashes
/// without reporting) fails closed to `VmExitStatus::UNKNOWN`.
const WORKLOAD_WAIT_TIMEOUT: Duration = Duration::from_secs(300);

/// Open the per-VM guest-console capture sink. OUTPUT-ONLY by
/// construction (write-only, create+truncate): the guest console
/// streams here and NO host-readable fd is ever attached as console
/// input. The sole interactive path into a guest is the dev-shell-gated
/// agent vsock console (claim 15 — no interactive access to a sealed prod
/// microVM), absent from sealed prod agents. Centralized so the write-only
/// invariant lives in one place.
pub(crate) fn open_console_capture(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

/// Default kernel cmdline for libkrun-launched guests.
/// `console=hvc0` matches libkrun's virtio-console wiring;
/// `root=/dev/vda rw init=/init` matches Apple Container's
/// boot for the same Nix-built rootfs layout.
const DEFAULT_CMDLINE: &str = "console=hvc0 root=/dev/vda rw init=/init";

/// Build the supervisor config for one VM, lifting
/// the audit-substrate resolution into the shared `audit_substrate`
/// module so libkrun and Vz share one source of truth (and the future
/// `NetworkProvider` trait extraction is mechanical).
///
/// **Do not log** `config.plan_json` or `config.bundle_json` — they
/// may carry secret bindings, env vars, or policy refs that resolve
/// to credentials. They're opaque transport bytes; the supervisor
/// re-verifies the signed envelope before trusting any decoded field.
/// Workload-**independent** KrunContext: kernel + resources + cmdline + vsock wiring +
/// the configured virtio-net gateway. **No rootfs** (the cold path sets the workload
/// rootfs; a prelaunched standby leaves it `None` until claim) and **no user volumes**.
/// Shared verbatim by `build_supervisor_config` (cold) and `standby_base_config` (warm)
/// so the two launch paths can't drift.
fn krun_context_base(
    name: &str,
    kernel: &str,
    vcpus: u8,
    mem_mib: u32,
    cmdline: &str,
    state_dir: &Path,
) -> KrunContext {
    // KrunContext::new requires a rootfs arg; we null it immediately — the caller owns
    // the rootfs decision (Some for cold boot, None for a standby).
    let mut krun = KrunContext::new(name, kernel, "")
        .with_resources(vcpus, mem_mib)
        .with_cmdline(cmdline)
        .with_vsock_socket_dir(state_dir.to_string_lossy().into_owned())
        .add_vsock_port(mvm_guest::vsock::GUEST_AGENT_PORT)
        // Workload exit-code capture (listen=false → host binds).
        .add_host_listen_port(mvm_guest::vsock::WORKLOAD_EXIT_PORT)
        // Egress substitution channel (listen=false → host binds). Registered
        // unconditionally; fail-closed: when the plan carries no secrets nothing
        // binds the UDS, so a stray guest dial gets ECONNREFUSED.
        .add_host_listen_port(mvm_guest::vsock::SUBSTITUTION_PORT)
        // Host-services broker channel (listen=false → host binds). Registered
        // unconditionally so libkrun proxies the guest's connect; fail-closed:
        // nothing binds the UDS until the per-VM broker subprocess is spawned,
        // so a stray guest dial gets ECONNREFUSED.
        .add_host_listen_port(mvm_guest::vsock::BROKER_PORT);
    krun.rootfs_path = None;
    // Select the gateway through the same
    // `resolve_networking_mode` the builder VM + cold path use (TSI is rejected by the
    // claim-10 no-bypass bridge). Workload-independent, so it belongs in the base.
    let scratch = state_dir.to_string_lossy().into_owned();
    match mvm_build::libkrun_builder::resolve_networking_mode() {
        mvm_build::libkrun_builder::NetworkingPreference::Gvproxy => {
            krun.with_gvproxy(libkrun_sys::gvproxy::DEFAULT_GUEST_MAC, scratch)
        }
        mvm_build::libkrun_builder::NetworkingPreference::Passt => {
            krun.with_passt(libkrun_sys::passt::DEFAULT_GUEST_MAC, scratch)
        }
        // Native reuses the gvproxy vfkit backend; the binary swap happens
        // in gvproxy::locate_gvproxy via MVM_GATEWAY_BIN.
        mvm_build::libkrun_builder::NetworkingPreference::Native => {
            krun.with_gvproxy(libkrun_sys::gvproxy::DEFAULT_GUEST_MAC, scratch)
        }
    }
}

/// Translate a backend-agnostic [`StandbySpec`] into the `SupervisorBaseConfig`
/// (workload-independent) the prelaunched supervisor reads on stdin. `rootfs_path` stays
/// `None` — the workload rootfs arrives in the attach at claim.
fn standby_base_config(spec: &StandbySpec) -> SupervisorBaseConfig {
    let krun = krun_context_base(
        &spec.id,
        &spec.kernel_path,
        spec.vcpus,
        spec.mem_mib,
        DEFAULT_CMDLINE,
        Path::new(&spec.vm_state_dir),
    );
    SupervisorBaseConfig {
        krun,
        vm_state_dir: spec.vm_state_dir.clone(),
        pid_file_name: None,
        signing_key_path: spec.signing_key_path.clone(),
        signer_id: spec.signer_id.clone(),
        binding_nonce: spec.binding_nonce.clone(),
        control_socket_path: spec.control_socket.clone(),
        bridge_restart_policy: BridgeRestartPolicy::HardFail,
    }
}

/// Translate a [`StandbyClaim`] into the `SupervisorAttachConfig`, echoing the
/// standby's binding nonce. `plan_json`/`bundle_json` decode to `serde_json::Value`
/// carriers (the same shape `SupervisorConfig.plan` uses).
fn standby_attach_config(
    claim: &StandbyClaim,
    binding_nonce: String,
) -> std::result::Result<SupervisorAttachConfig, StandbyError> {
    let plan: serde_json::Value = serde_json::from_str(&claim.plan_json)
        .map_err(|e| StandbyError::ClaimFailed(format!("decode plan_json: {e}")))?;
    let bundle = match &claim.bundle_json {
        Some(b) => Some(
            serde_json::from_str(b)
                .map_err(|e| StandbyError::ClaimFailed(format!("decode bundle_json: {e}")))?,
        ),
        None => None,
    };
    Ok(SupervisorAttachConfig {
        binding_nonce,
        rootfs_path: claim.rootfs_path.clone(),
        tenant_id: claim.tenant_id.clone(),
        audit_dir: claim.audit_dir.clone(),
        gateway_audit_socket: claim.gateway_audit_socket.clone(),
        gateway_events_socket: claim.gateway_events_socket.clone(),
        plan,
        bundle,
    })
}

/// Seconds since the Unix epoch (best-effort; clamps a pre-epoch clock to 0).
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_supervisor_config(config: &VmStartConfig, state_dir: &Path) -> Result<SupervisorConfig> {
    let kernel = config
        .kernel_path
        .as_deref()
        .ok_or_else(|| anyhow!("libkrun backend requires a kernel path"))?;
    let vcpus = u8::try_from(config.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX);
    // Append the `mvm.uvols=` param so the dev VM's `mvm-host-vm-init`
    // mounts user volumes at their guest paths (no-op when there are
    // none; harmless for workload guests whose `/init` ignores it).
    let mut cmdline = DEFAULT_CMDLINE.to_string();
    if let Some(uvols) = mvm_core::vm_backend::encode_user_volumes_cmdline(&config.volumes) {
        cmdline.push(' ');
        cmdline.push_str(&uvols);
    }
    // Workload-independent KrunContext (kernel + resources + vsock + gateway), shared
    // verbatim with the standby spawn so the two paths can't drift. The cold path
    // then sets the workload rootfs + user volumes below.
    let mut krun = krun_context_base(
        &config.name,
        kernel,
        vcpus,
        config.memory_mib,
        &cmdline,
        state_dir,
    );
    krun.rootfs_path = Some(config.rootfs_path.clone());

    // User-supplied volumes (--volume / MVM_VOLUMES). A directory share
    // is a virtio-fs device; a disk image is an extra virtio-blk device.
    // Tag/id `uvol{idx}` is the coordination key the guest mount manifest
    // uses to mount each at its requested guest path. Disk images are
    // sparse-created by the CLI orchestrator before start; a RO disk image
    // is RO at the hypervisor (krun_add_disk takes read_only).
    //
    // libkrun's `krun_add_virtiofs` has NO host-side read-only
    // toggle, so a "read-only" virtio-fs share would only be ro by the
    // guest's own mount flag — a compromised guest could remount it rw.
    // Rather than make a false ro promise, refuse it and point at the
    // hypervisor-enforced alternatives. (Vz/Firecracker enforce ro shares
    // natively; this restriction is libkrun-specific.)
    for (idx, vol) in config.volumes.iter().enumerate() {
        let tag = format!("uvol{idx}");
        krun = match vol.kind {
            mvm_core::vm_backend::VmVolumeKind::DirShare => {
                if vol.read_only {
                    bail!(
                        "libkrun cannot enforce a read-only virtio-fs share ('{}' -> '{}'): \
                         krun_add_virtiofs has no host-side read-only toggle, so a compromised \
                         guest could remount it read-write. Use a read-only disk image \
                         (host:/guest:SIZE) for hypervisor-enforced read-only, share it ':rw' if \
                         writes are intended, or run on the Vz backend.",
                        vol.host,
                        vol.guest
                    );
                }
                krun.add_virtio_fs(tag, vol.host.clone())
            }
            mvm_core::vm_backend::VmVolumeKind::Disk => {
                krun.add_disk(tag, vol.host.clone(), vol.read_only)
            }
        };
    }

    // Resolve the audit substrate (paths + tenant
    // validation). When the producer threaded an AdmittedPlan in
    // (`tenant_id` Some), the AuditSubstrate carries the five resolved
    // paths; otherwise it's all-None and the supervisor takes the
    // legacy `run_supervisor` path.
    let substrate =
        crate::audit_substrate::compute_audit_substrate(&config.name, config.tenant_id.as_deref())?;

    // Parse the signed-plan + bundle envelopes from VmStartConfig.
    // libkrun_sys::SupervisorConfig carries them as Option<serde_json::Value>
    // so the supervisor can re-verify the envelope without typed coupling
    // to `mvm_core::plan` at the parse boundary.
    let plan = match config.plan_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| anyhow!("parse VmStartConfig.plan_json as JSON: {e}"))?,
        ),
        None => None,
    };
    let bundle = match config.bundle_json.as_deref() {
        Some(s) => Some(
            serde_json::from_str(s)
                .map_err(|e| anyhow!("parse VmStartConfig.bundle_json as JSON: {e}"))?,
        ),
        None => None,
    };

    Ok(SupervisorConfig {
        krun,
        vm_state_dir: state_dir.to_string_lossy().into_owned(),
        pid_file_name: None,
        tenant_id: substrate.tenant_id,
        audit_dir: substrate.audit_dir,
        gateway_audit_socket: substrate.gateway_audit_socket,
        gateway_events_socket: substrate.gateway_events_socket,
        signing_key_path: substrate.signing_key_path,
        plan,
        bundle,
        // Only `HardFail` is
        // implemented today. Defaulting here keeps the producer site
        // explicit while a future change can introduce policy-driven
        // selection.
        bridge_restart_policy: libkrun_sys::BridgeRestartPolicy::HardFail,
    })
}

impl VmBackend for LibkrunBackend {
    fn name(&self) -> &str {
        "libkrun"
    }

    fn capabilities(&self) -> VmCapabilities {
        // libkrun does not support memory snapshots (same trade as
        // Apple Container) — vsock and TAP are available; pause/resume
        // is theoretically possible but not exposed by libkrun's public
        // C API today.
        VmCapabilities {
            pause_resume: false,
            snapshots: false,
            vsock: true,
            tap_networking: false,
            // libkrun's C API doesn't expose virtio-balloon control
            // today; the upstream crate carries no `.balloon(...)`
            // builder. Declared `false` until wiring lands.
            balloon: false,
            // libkrun runs on macOS but the rootfs lives in a regular
            // file, not an APFS clone-eligible volume mount; no
            // clonefile shortcut here.
            fs_quick_checkpoint: false,
        }
    }

    fn snapshot_capability(&self) -> SnapshotCapability {
        // libkrun has no memory snapshot — warm-start is a fast reboot from
        // the overlay/rootfs disk snapshot. A live-memory
        // request is refused with a typed error, not silently degraded.
        SnapshotCapability::DiskOnly
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        if !libkrun_sys::is_available() {
            bail!(
                "libkrun is not installed on this host.\n  {}",
                libkrun_sys::install_hint()
            );
        }

        // Early kernel-path check. `build_supervisor_config`
        // re-checks too, but this keeps the existing test contract
        // (`libkrun_start_errors_when_kernel_path_missing`) firing before
        // `admit_overlay_aware`'s sidecar check would mask it.
        let _ = config
            .kernel_path
            .as_deref()
            .ok_or_else(|| anyhow!("libkrun backend requires a kernel path"))?;
        let supervisor_path = resolve_supervisor_path()?;
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .map_err(|e| anyhow!("create per-VM state dir {}: {e}", state_dir.display()))?;

        // Thread the build-time sidecar into per-VM runtime
        // metadata so `mvmctl console` enforces the accessible/sealed
        // gate on libkrun-launched VMs the same way as on the
        // libkrun/Firecracker paths.
        let rootfs = Path::new(&config.rootfs_path);
        // Admission gate — refuse a rootfs that lacks the
        // `/mvm/runtime` mount point. Fires before the supervisor
        // spawn so a refusal leaves no PID file or krun handle behind.
        let rootfs_dir = rootfs.parent().unwrap_or_else(|| Path::new("."));
        mvm_build::builder_vm::admit_overlay_aware(rootfs_dir)?;
        crate::base::runtime_meta::record_from_rootfs(&config.name, StartMode::Detached, rootfs)?;

        let vcpus = u8::try_from(config.cpus.clamp(1, u32::from(u8::MAX))).unwrap_or(u8::MAX);
        let cfg = build_supervisor_config(config, &state_dir)?;
        let pid_file = cfg.pid_file();
        // Remove any stale PID file from a previous crashed supervisor
        // so the wait-loop below can detect the new one unambiguously.
        let _ = std::fs::remove_file(&pid_file);

        let json =
            serde_json::to_string(&cfg).map_err(|e| anyhow!("serialize SupervisorConfig: {e}"))?;

        ui::info(&format!(
            "Starting libkrun VM '{}' (cpus={vcpus}, mem={}MiB) via {}...",
            config.name,
            config.memory_mib,
            supervisor_path.display(),
        ));

        // Capture the guest console (hvc0 → supervisor stdout) to a
        // per-VM log so a boot failure / kernel panic is diagnosable
        // (mirrors firecracker.log). Best-effort: fall back to null if
        // the file can't be created.
        let console_log = open_console_capture(&vm_console_log(&config.name))
            .map(Stdio::from)
            .unwrap_or_else(|_| Stdio::null());
        let mut child = Command::new(&supervisor_path)
            .stdin(Stdio::piped())
            .stdout(console_log)
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow!("spawn {}: {e}", supervisor_path.display()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
            .write_all(json.as_bytes())
            .map_err(|e| anyhow!("pipe SupervisorConfig to supervisor stdin: {e}"))?;

        // Poll for the PID file to appear; if the supervisor exits
        // first, surface its status instead of waiting the full
        // timeout.
        let deadline = Instant::now() + PID_FILE_TIMEOUT;
        loop {
            if pid_file.exists() {
                break;
            }
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor child: {e}"))?
            {
                bail!(
                    "supervisor exited before writing PID file (status: {status}). \
                     Check stderr above for libkrun errors."
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                bail!(
                    "supervisor did not write {} within {:?}; killed",
                    pid_file.display(),
                    PID_FILE_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // The PID file means the supervisor process is up, but it binds the
        // per-port vsock listener a beat later. Wait for the agent socket so
        // the console attach / shell_exec that immediately follow don't race
        // a not-yet-bound socket and report the VM "not running".
        let agent_sock = mvm_core::config::vm_vsock_port_socket(
            &config.name,
            mvm_guest::vsock::GUEST_AGENT_PORT,
        );
        let sock_deadline = Instant::now() + VSOCK_SOCKET_TIMEOUT;
        while !agent_sock.exists() {
            if let Some(status) = child
                .try_wait()
                .map_err(|e| anyhow!("poll supervisor child: {e}"))?
            {
                bail!(
                    "supervisor exited before binding vsock socket {} (status: {status})",
                    agent_sock.display()
                );
            }
            if Instant::now() >= sock_deadline {
                let _ = child.kill();
                bail!(
                    "supervisor did not bind vsock socket {} within {:?}; killed",
                    agent_sock.display(),
                    VSOCK_SOCKET_TIMEOUT
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // The supervisor is up and its vsock listeners are bound. Spawn the
        // egress substitution endpoint if the admitted plan carries secrets so
        // the guest's egress can resolve placeholders host-side (the guest never
        // holds the real secret). Armed via the guard until the VM is fully up;
        // a spawn failure rolls the launch back (fail closed). When the plan has
        // no secrets this is a defused no-op.
        let mut endpoint_guard = spawn_libkrun_egress_endpoint_if_needed(&config.name, &state_dir)?;

        // Spawn the per-VM host-services broker (+ its audit-signer) for an
        // admitted workload so the guest can reach `host.audit.v1` over
        // BROKER_PORT. Best-effort: an absent broker only disables that one
        // service — the guest's emit fails, but the workload still runs and the
        // system audit chain (written host-side, not via the broker) is intact.
        // So a spawn failure is logged, never a launch rollback. On success the
        // guard reaps both subprocesses if a later start step fails; it's
        // defused once the VM is up and the `stop` path owns teardown.
        let mut broker_guard = match crate::broker_services_spawn::spawn_broker_services_if_admitted(
            crate::broker_services_spawn::BrokerServicesSpawnParams {
                workload_id: &config.name,
                tenant_id: config.tenant_id.as_deref(),
                vm_name: &config.name,
                state_dir: &state_dir,
                // libkrun proxies the guest's BROKER_PORT dial straight to this
                // per-VM socket.
                broker_listen_socket: &mvm_core::config::vm_vsock_port_socket(
                    &config.name,
                    mvm_guest::vsock::BROKER_PORT,
                ),
            },
        ) {
            Ok(guard) => guard,
            Err(e) => {
                tracing::warn!(vm = %config.name, error = %e, "host-services broker spawn failed; host.audit.v1 unavailable for this VM");
                crate::broker_services_spawn::BrokerServicesGuard::defused()
            }
        };

        ui::success(&format!(
            "libkrun VM '{}' started (pid file: {}).",
            config.name,
            pid_file.display()
        ));
        endpoint_guard.defuse();
        broker_guard.defuse();
        Ok(VmId(config.name.clone()))
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        // Reap the per-VM substitution endpoint first (no-op when none was
        // spawned) so a crashed VM's decrypted-secret process can't outlive the
        // guest. Mirrors the FC `stop_vm` ordering — safe because reap is a
        // no-op when nothing exists, even before the not-running early return.
        crate::substitution_spawn::reap_substitution_endpoint(&vm_state_dir(&id.0), &id.0);
        // Reap the per-VM broker + audit-signer too (no-op when none spawned),
        // so they can't outlive the guest.
        crate::broker_services_spawn::reap_broker_services(&vm_state_dir(&id.0));

        let pid_path = vm_libkrun_pid(&id.0);
        let pid = match read_pid(&pid_path) {
            Some(p) => p,
            None => {
                // No PID file: nothing to do, but tell the user so it's
                // not silent. Matches `mvmctl stop` on a never-started
                // VM.
                ui::info(&format!(
                    "libkrun VM '{}' has no PID file at {}; nothing to stop.",
                    id.0,
                    pid_path.display()
                ));
                return Ok(());
            }
        };

        if !pid_alive(pid) {
            ui::info(&format!(
                "libkrun VM '{}' PID {pid} is not running; cleaning up state.",
                id.0
            ));
            let _ = std::fs::remove_file(&pid_path);
            return Ok(());
        }

        // SIGTERM first — gives libkrun a chance to clean up
        // virtio-blk file descriptors. Then SIGKILL if it ignores us.
        send_signal(pid, libc::SIGTERM);
        let deadline = Instant::now() + STOP_TIMEOUT;
        while Instant::now() < deadline {
            if !pid_alive(pid) {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if pid_alive(pid) {
            ui::info(&format!(
                "libkrun VM '{}' PID {pid} did not exit after SIGTERM within {STOP_TIMEOUT:?}; sending SIGKILL.",
                id.0
            ));
            send_signal(pid, libc::SIGKILL);
        }

        let _ = std::fs::remove_file(&pid_path);
        ui::success(&format!("libkrun VM '{}' stopped.", id.0));
        Ok(())
    }

    fn stop_all(&self) -> Result<()> {
        let vms = self.list()?;
        let mut last_err = None;
        for vm in vms {
            if let Err(e) = self.stop(&VmId(vm.name.clone())) {
                tracing::warn!(name = vm.name, error = %e, "stop_all: stop failed");
                last_err = Some(e);
            }
        }
        if let Some(e) = last_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    fn pause(&self, _id: &VmId) -> Result<()> {
        bail!(
            "pause is not supported by the libkrun backend (upstream C API does not expose vCPU pause)"
        )
    }

    fn resume(&self, _id: &VmId) -> Result<()> {
        bail!(
            "resume is not supported by the libkrun backend (upstream C API does not expose vCPU pause)"
        )
    }

    fn warm_start(
        &self,
        config: &VmStartConfig,
        requested: SnapshotCapability,
    ) -> std::result::Result<VmId, WarmStartError> {
        // libkrun has no memory snapshot; a live-memory (or save/restore)
        // request fails closed with a recovery action rather than silently
        // cold-booting.
        let available = SnapshotCapability::DiskOnly;
        if !available.satisfies(requested) {
            return Err(WarmStartError::Unsupported {
                requested,
                available,
                hint: "libkrun has no live-memory snapshot — use the Firecracker (Linux) or \
                       Vz (macOS 26+) backend for a live-memory resume, or `mvmctl up` for a \
                       cold boot"
                    .to_string(),
            });
        }

        // Disk-only warm-start = fast reboot from a copy-on-write disk
        // snapshot: boot a private writable clone of the golden rootfs so the
        // base image stays immutable across resumes (via `SnapshotUpper`).
        let base = Path::new(&config.rootfs_path);
        let base_dir = base.parent().ok_or_else(|| {
            WarmStartError::Failed(format!("rootfs has no parent: {}", base.display()))
        })?;
        let base_name = base.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            WarmStartError::Failed(format!("rootfs has no file name: {}", base.display()))
        })?;
        let upper = vm_state_dir(&config.name).join("warm-upper");
        let snap = SnapshotUpper::new(base_dir, &upper)
            .map_err(|e| WarmStartError::Failed(format!("open disk snapshot: {e}")))?;
        let warm_rootfs = snap
            .materialize_image(base_name)
            .map_err(|e| WarmStartError::Failed(format!("materialize warm rootfs: {e}")))?;

        let mut warm = config.clone();
        warm.rootfs_path = warm_rootfs.to_string_lossy().into_owned();
        self.start(&warm)
            .map_err(|e| WarmStartError::Failed(e.to_string()))
    }

    fn supports_standby_pool(&self) -> bool {
        true
    }

    fn spawn_standby(
        &self,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let base = standby_base_config(spec);
        // Pre-create the control-UDS parent dir 0700 (the supervisor re-binds the socket
        // itself; this only ensures the dir exists with the right mode).
        if let Some(parent) = spec.control_socket.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| StandbyError::SpawnFailed(format!("create control dir: {e}")))?;
            let _ = std::fs::set_permissions(
                parent,
                std::os::unix::fs::PermissionsExt::from_mode(0o700),
            );
        }
        // The bin dispatches the prelaunch arm on the `prelaunch_base` wrapper key;
        // legacy callers send a bare SupervisorConfig and are unaffected.
        let envelope = serde_json::to_vec(&serde_json::json!({ "prelaunch_base": base }))
            .map_err(|e| StandbyError::SpawnFailed(format!("encode base config: {e}")))?;

        let bin =
            resolve_supervisor_path().map_err(|e| StandbyError::SpawnFailed(e.to_string()))?;
        // Capture the standby supervisor's stderr next to its control socket so a standby
        // that dies before it's claimed leaves a diagnosable trail (it's detached, so there
        // is no parent to inherit into).
        let stderr = spec
            .control_socket
            .parent()
            .map(|d| d.join("standby.stderr.log"))
            .and_then(|p| std::fs::File::create(p).ok())
            .map(Stdio::from)
            .unwrap_or_else(Stdio::null);
        let mut child = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(stderr)
            .spawn()
            .map_err(|e| StandbyError::SpawnFailed(format!("spawn supervisor: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| StandbyError::SpawnFailed("supervisor stdin unavailable".into()))?
            .write_all(&envelope)
            .map_err(|e| StandbyError::SpawnFailed(format!("write base config: {e}")))?;
        // Detached: do NOT wait — the bin blocks on the control UDS until claimed (or
        // reaped). The dropped `Child` leaves the process running (no kill-on-drop).
        let pid = child.id();

        Ok(StandbyHandle {
            id: spec.id.clone(),
            control_socket: spec.control_socket.clone(),
            pid,
            kernel_sha256: spec.kernel_sha256.clone(),
            vcpus: spec.vcpus,
            mem_mib: spec.mem_mib,
            binding_nonce: spec.binding_nonce.clone(),
            spawned_unix_secs: now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: None, // libkrun standbys are image-agnostic
        })
    }

    fn claim_standby(
        &self,
        handle: &StandbyHandle,
        claim: &StandbyClaim,
    ) -> std::result::Result<VmId, StandbyError> {
        let attach = standby_attach_config(claim, handle.binding_nonce.clone())?;
        let mut stream = UnixStream::connect(&handle.control_socket).map_err(|e| {
            StandbyError::ClaimFailed(format!(
                "connect control UDS {}: {e}",
                handle.control_socket.display()
            ))
        })?;
        libkrun_sys::framing::write_json_frame_sync(&mut stream, &attach)
            .map_err(|e| StandbyError::ClaimFailed(format!("send attach: {e}")))?;
        // The supervisor re-verifies the attach then start_enters, writing its pid
        // into vm_state_dir. The VM is identified by the standby id (its state lives under
        // vms/<id>/, so stop/status/console resolve it like any cold-booted VM).
        Ok(VmId(handle.id.clone()))
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        let pid_path = vm_libkrun_pid(&id.0);
        match read_pid(&pid_path) {
            Some(pid) if pid_alive(pid) => Ok(VmStatus::Running),
            _ => Ok(VmStatus::Stopped),
        }
    }

    fn wait(&self, id: &VmId) -> Result<mvm_core::vm_backend::VmExitStatus> {
        // Poll for the captured exit code to appear. The guest writes
        // `workload.exit` (and the supervisor persists it) BEFORE the guest
        // powers off — the ack handshake guarantees the
        // ordering — so its presence is the reliable "workload finished"
        // signal. We deliberately do NOT poll supervisor PID liveness: on a
        // busy host the dead supervisor's PID can be reused by another
        // process, making a liveness check spin forever. Bounded so a guest
        // that crashes without reporting fails closed to UNKNOWN.
        let state_dir = vm_state_dir(&id.0);
        let deadline = Instant::now() + WORKLOAD_WAIT_TIMEOUT;
        loop {
            let status = read_exit_status_from(&state_dir);
            if status != mvm_core::vm_backend::VmExitStatus::UNKNOWN {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Ok(mvm_core::vm_backend::VmExitStatus::UNKNOWN);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = PathBuf::from(mvm_data_dir()).join("vms");
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let pid_path = path.join("libkrun.pid");
            if !pid_path.exists() {
                // Not a libkrun-managed VM (e.g. Apple Container under
                // the same ~/.mvm/vms/ root).
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(s) => s,
                Err(_) => continue, // skip non-UTF-8 dir names
            };
            let alive = read_pid(&pid_path).is_some_and(pid_alive);
            // The supervisor doesn't surface cpus/memory/ports back to
            // the parent today; a future status RPC over vsock will read
            // these out of the live VM.
            // Until then, `list` reports the name + running state and
            // leaves the discoverable-from-runtime fields empty.
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
        bail!("libkrun logs not yet implemented for VM '{}'", id.0)
    }

    fn is_available(&self) -> Result<bool> {
        Ok(libkrun_sys::is_available())
    }

    fn install(&self) -> Result<()> {
        ui::info(&format!(
            "libkrun must be installed via the host's package manager.\n  {}",
            libkrun_sys::install_hint()
        ));
        // Also surface where we look for the supervisor binary so
        // operators can pre-flight the install before hitting a
        // mid-`mvmctl up` failure.
        match resolve_supervisor_path() {
            Ok(path) => ui::info(&format!("Supervisor binary: {}", path.display())),
            Err(e) => ui::info(&format!("Supervisor binary: NOT FOUND ({e})")),
        }
        Ok(())
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // libkrun exposes vsock as a host-side abstract socket; the
        // guest agent listens on the shared `GUEST_AGENT_PORT` port,
        // identical to Firecracker and Apple Container, so callers can
        // share the same vsock client implementation across backends.
        Ok(GuestChannelInfo::Vsock {
            cid: 3, // standard guest CID
            port: mvm_guest::vsock::GUEST_AGENT_PORT,
        })
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        // Tier 2: hardware isolation via KVM (Linux) or Hypervisor.framework
        // (macOS). Comparable VMM TCB to Firecracker — libkrun is rust-vmm
        // based, ~80K LOC, no Firecracker-excluded features (so it passes
        // the "fork test"). Claim 3 (verified boot) is partial
        // because the dm-verity pipeline currently targets Firecracker;
        // libkrun support is a follow-up.
        BackendSecurityProfile {
            claims: [
                ClaimStatus::Holds,       // 1 — host-fs isolation via KVM/HVF
                ClaimStatus::Holds,       // 2 — uid-0 protections same as FC
                ClaimStatus::DoesNotHold, // 3 — verified boot for libkrun rootfs not yet wired
                ClaimStatus::Holds,       // 4 — guest agent has no do_exec in prod
                ClaimStatus::Holds,       // 5 — vsock framing is fuzzed
                ClaimStatus::Holds,       // 6 — image hash verification
                ClaimStatus::Holds,       // 7 — cargo deps audited
            ],
            layer_coverage: LayerCoverage::all_layers(),
            tier: "Tier 2",
            notes: &[
                "Hardware isolation via KVM (Linux) or Hypervisor.framework (macOS).",
                "Comparable VMM TCB to Firecracker; passes plan 53 §\"fork test\".",
                "Claim 3 (verified boot) is partial — dm-verity pipeline targets Firecracker today.",
                "Supported on Linux KVM and macOS Apple Silicon; macOS Intel is not a supported local host.",
            ],
        }
    }
}

// ─── helpers ───────────────────────────────────────────────────────

/// Resolve the absolute path to the `mvm-libkrun-supervisor` binary,
/// checking three sources in order:
///
/// 1. `MVM_LIBKRUN_SUPERVISOR_PATH` — explicit override, used by tests
///    and `cargo run` workflows.
/// 2. A binary named `mvm-libkrun-supervisor` adjacent to the current
///    executable — the layout produced by `cargo install mvm-libkrun`
///    or by a Homebrew bottle that ships `mvmctl` and
///    `mvm-libkrun-supervisor` side-by-side.
/// 3. `PATH` lookup.
///
/// Returns an actionable error if all three fail.
pub(crate) fn resolve_supervisor_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("MVM_LIBKRUN_SUPERVISOR_PATH") {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        bail!(
            "MVM_LIBKRUN_SUPERVISOR_PATH points at {} which is not a file",
            path.display()
        );
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let candidate = dir.join("mvm-libkrun-supervisor");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Ok(path) = which::which("mvm-libkrun-supervisor") {
        return Ok(path);
    }
    bail!(
        "mvm-libkrun-supervisor binary not found. Looked for: \
         $MVM_LIBKRUN_SUPERVISOR_PATH, alongside the current exe, and on $PATH. \
         Install it via `cargo install --path crates/mvm-libkrun --features libkrun-sys` \
         or set MVM_LIBKRUN_SUPERVISOR_PATH=/abs/path/to/the/binary."
    )
}

fn read_pid(path: &Path) -> Option<libc::pid_t> {
    let s = std::fs::read_to_string(path).ok()?;
    s.trim().parse::<libc::pid_t>().ok()
}

fn pid_alive(pid: libc::pid_t) -> bool {
    // `kill(pid, 0)` returns 0 if the process exists (and the caller
    // has permission to signal it), -1 with errno=ESRCH if not.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn send_signal(pid: libc::pid_t, sig: libc::c_int) {
    unsafe { libc::kill(pid, sig) };
}

/// Read the workload exit status written by the supervisor into
/// `<state_dir>/workload.exit`. Returns UNKNOWN when the file is absent
/// (guest was killed / backend doesn't support capture).
fn read_exit_status_from(state_dir: &std::path::Path) -> mvm_core::vm_backend::VmExitStatus {
    match mvm_core::exit_capture::read_captured(state_dir) {
        Some(code) => mvm_core::vm_backend::VmExitStatus {
            code: Some(code),
            success: code == 0,
        },
        None => mvm_core::vm_backend::VmExitStatus::UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_standby_spec() -> StandbySpec {
        StandbySpec {
            id: "standby-x".into(),
            kernel_path: "/k/vmlinux".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 1024,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "ab".repeat(32),
            control_socket: "/p/standby-x/control-ab.sock".into(),
            vm_state_dir: "/vms/standby-x".into(),
            image_path: None,
            image_sha256: None,
        }
    }

    fn sample_standby_claim() -> StandbyClaim {
        StandbyClaim {
            rootfs_path: "/vol/rootfs.ext4".into(),
            tenant_id: "tenant-a".into(),
            audit_dir: "/audit".into(),
            gateway_audit_socket: "/audit/g.sock".into(),
            gateway_events_socket: None,
            plan_json: r#"{"signed":"envelope"}"#.into(),
            bundle_json: None,
        }
    }

    #[test]
    fn standby_spec_translates_to_base_config_with_no_rootfs() {
        let spec = sample_standby_spec();
        let base = standby_base_config(&spec);
        // A standby carries NO workload rootfs — it arrives in the attach.
        assert!(base.krun.rootfs_path.is_none());
        assert_eq!(base.binding_nonce, spec.binding_nonce);
        assert_eq!(base.signer_id, spec.signer_id);
        assert_eq!(base.control_socket_path, spec.control_socket);
        assert_eq!(base.krun.vcpus, 2);
        assert_eq!(base.krun.ram_mib, 1024);
        // The bin dispatches the prelaunch arm on the `prelaunch_base` wrapper key.
        let env = serde_json::json!({ "prelaunch_base": base });
        assert!(env.get("prelaunch_base").is_some());
    }

    #[test]
    fn standby_claim_translates_to_attach_config_echoing_nonce() {
        let attach = standby_attach_config(&sample_standby_claim(), "ab".repeat(32)).unwrap();
        assert_eq!(attach.binding_nonce, "ab".repeat(32));
        assert_eq!(attach.rootfs_path, "/vol/rootfs.ext4");
        assert_eq!(attach.tenant_id, "tenant-a");
        assert_eq!(attach.plan, serde_json::json!({"signed": "envelope"}));
        assert!(attach.bundle.is_none());
    }

    #[test]
    fn standby_claim_rejects_malformed_plan_json() {
        let mut claim = sample_standby_claim();
        claim.plan_json = "not json".into();
        match standby_attach_config(&claim, "ab".repeat(32)) {
            Err(StandbyError::ClaimFailed(_)) => {}
            other => panic!("expected ClaimFailed, got {other:?}"),
        }
    }

    #[test]
    fn prod_console_attachment_has_no_input() {
        // claim 15: the backend captures the guest console
        // to a WRITE-ONLY sink — there is no host fd from which the guest
        // could read console input. The only interactive path is the
        // dev-shell-gated agent vsock console, which a sealed prod agent
        // does not link.
        use std::io::{Read, Write};
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("console.log");
        let mut f = open_console_capture(&p).expect("open sink");
        f.write_all(b"boot log line\n")
            .expect("console capture must accept output");
        let mut buf = String::new();
        assert!(
            f.read_to_string(&mut buf).is_err(),
            "console capture sink must be write-only — no guest console input path"
        );
    }

    #[test]
    fn libkrun_backend_name() {
        assert_eq!(LibkrunBackend.name(), "libkrun");
    }

    #[test]
    fn libkrun_capabilities() {
        let caps = LibkrunBackend.capabilities();
        assert!(caps.vsock);
        assert!(!caps.snapshots);
        assert!(!caps.pause_resume);
        assert!(!caps.tap_networking);
    }

    #[test]
    fn libkrun_security_profile_is_tier_2_with_partial_claim_3() {
        let profile = LibkrunBackend.security_profile();
        assert_eq!(profile.tier, "Tier 2");
        assert!(profile.layer_coverage.is_microvm());
        // Claim 3 (verified boot) is the only partial claim; everything
        // else holds because libkrun matches Firecracker's L2 properties.
        assert_eq!(profile.dropped_claims(), vec![3]);
        assert!(profile.na_claims().is_empty());
    }

    #[test]
    fn build_supervisor_config_maps_substrate_into_supervisor_config() {
        // When the producer threaded an admitted plan,
        // build_supervisor_config maps the resolved AuditSubstrate fields
        // into SupervisorConfig + parses plan_json/bundle_json as JSON.
        let config = VmStartConfig {
            name: "test-vm".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            tenant_id: Some("acme".into()),
            plan_json: Some("{\"k\":\"v\"}".into()),
            bundle_json: None,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert_eq!(cfg.tenant_id.as_deref(), Some("acme"));
        assert!(cfg.audit_dir.is_some());
        assert!(cfg.gateway_audit_socket.is_some());
        assert!(cfg.gateway_events_socket.is_some());
        assert!(cfg.signing_key_path.is_some());
        assert!(cfg.plan.is_some());
        assert!(cfg.bundle.is_none());
    }

    /// claim 1 (host-fs isolation): libkrun can't enforce a read-only virtio-fs
    /// share at the hypervisor, so it refuses one rather than make a
    /// false ro promise (a compromised guest could remount it rw). A
    /// read-write share, or a read-only disk image, is fine.
    #[test]
    fn libkrun_refuses_read_only_virtiofs_share() {
        use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
        let tmp = tempfile::tempdir().unwrap();
        let base = VmStartConfig {
            name: "ro-fs".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };

        // read-only dir share → refused.
        let mut ro = base.clone();
        ro.volumes = vec![VmVolume {
            host: "/h/src".into(),
            guest: "/data".into(),
            read_only: true,
            kind: VmVolumeKind::DirShare,
            ..Default::default()
        }];
        let err = build_supervisor_config(&ro, tmp.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("read-only virtio-fs"), "got: {err}");

        // read-write dir share → allowed.
        let mut rw = base.clone();
        rw.volumes = vec![VmVolume {
            host: "/h/src".into(),
            guest: "/data".into(),
            read_only: false,
            kind: VmVolumeKind::DirShare,
            ..Default::default()
        }];
        assert!(build_supervisor_config(&rw, tmp.path()).is_ok());

        // read-only DISK image → allowed (hypervisor-enforced ro).
        let mut ro_disk = base;
        ro_disk.volumes = vec![VmVolume {
            host: "/h/data.img".into(),
            guest: "/data".into(),
            size: "1G".into(),
            read_only: true,
            kind: VmVolumeKind::Disk,
            ..Default::default()
        }];
        assert!(build_supervisor_config(&ro_disk, tmp.path()).is_ok());
    }

    #[test]
    fn build_supervisor_config_no_tenant_keeps_substrate_none() {
        // No admission ⇒ all five substrate fields
        // None ⇒ supervisor takes the legacy `run_supervisor` path.
        let config = VmStartConfig {
            name: "dev-vm".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert!(cfg.tenant_id.is_none());
        assert!(cfg.audit_dir.is_none());
        assert!(cfg.gateway_audit_socket.is_none());
        assert!(cfg.gateway_events_socket.is_none());
        assert!(cfg.signing_key_path.is_none());
        assert!(cfg.plan.is_none());
        assert!(cfg.bundle.is_none());
    }

    #[test]
    fn build_supervisor_config_refuses_unsafe_tenant() {
        // Defense-in-depth: tenant_id passes through
        // the DNS-label allowlist in audit_substrate; build_supervisor_config
        // propagates the error.
        let config = VmStartConfig {
            name: "evil-vm".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            tenant_id: Some("../escape".into()),
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        assert!(build_supervisor_config(&config, tmp.path()).is_err());
    }

    #[test]
    fn libkrun_install_message_is_actionable() {
        LibkrunBackend.install().expect("install hint never errors");
        let hint = libkrun_sys::install_hint();
        assert!(!hint.is_empty());
    }

    #[test]
    fn libkrun_start_errors_when_kernel_path_missing() {
        let config = VmStartConfig {
            name: "libkrun-test".to_string(),
            rootfs_path: "/tmp/rootfs.ext4".to_string(),
            ..Default::default()
        };
        // No kernel_path set → start should fail with a precise message
        // before attempting to spawn the supervisor.
        let err = LibkrunBackend
            .start(&config)
            .expect_err("expected failure without kernel_path");
        let msg = err.to_string();
        assert!(
            msg.contains("kernel path") || msg.contains("not installed"),
            "unexpected error message: {msg}"
        );
    }

    /// A VM with no PID file is `Stopped`. Mirrors what `mvmctl status
    /// <name>` reports for a never-started VM.
    #[test]
    fn libkrun_status_is_stopped_when_no_pid_file() {
        let status = LibkrunBackend
            .status(&VmId("never-started-vm".to_string()))
            .expect("status should not error");
        assert_eq!(status, VmStatus::Stopped);
    }

    /// Serialise env-var mutations across tests in this module —
    /// cargo runs tests in parallel by default, and `std::env::set_var`
    /// is process-global. Without this, a sibling test can flip
    /// `HOME` (or `MVM_LIBKRUN_SUPERVISOR_PATH`) mid-call and corrupt
    /// our assertions.
    fn with_env<F: FnOnce()>(body: F) {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        // Poisoned guard is fine — earlier panic doesn't taint env
        // for us; we restore explicitly below.
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        body();
    }

    /// `list` skips directories under `~/.mvm/vms/` that don't carry a
    /// `libkrun.pid` (e.g. Apple-Container-managed VMs sharing the
    /// same root). Returns an empty list when the root doesn't exist.
    #[test]
    fn libkrun_list_returns_empty_when_no_vms_dir() {
        with_env(|| {
            // Point HOME at a fresh temp dir so we get a known-empty
            // ~/.mvm/vms/ layout.
            let temp = tempfile::tempdir().expect("tempdir");
            let saved = std::env::var_os("HOME");
            // SAFETY: serialised by ENV_LOCK.
            unsafe { std::env::set_var("HOME", temp.path()) };
            let result = LibkrunBackend.list();
            unsafe {
                match saved {
                    Some(v) => std::env::set_var("HOME", v),
                    None => std::env::remove_var("HOME"),
                }
            }
            let vms = result.expect("list should not error on missing root");
            assert!(vms.is_empty(), "expected empty list, got {vms:?}");
        });
    }

    #[test]
    fn resolve_supervisor_path_honors_env_override() {
        with_env(|| {
            let temp = tempfile::NamedTempFile::new().expect("tempfile");
            // SAFETY: serialised by ENV_LOCK.
            unsafe { std::env::set_var("MVM_LIBKRUN_SUPERVISOR_PATH", temp.path()) };
            let result = resolve_supervisor_path();
            unsafe { std::env::remove_var("MVM_LIBKRUN_SUPERVISOR_PATH") };
            let path = result.expect("env override resolves");
            assert_eq!(path, temp.path());
        });
    }

    #[test]
    fn resolve_supervisor_path_rejects_missing_env_target() {
        with_env(|| {
            // SAFETY: serialised by ENV_LOCK.
            unsafe {
                std::env::set_var(
                    "MVM_LIBKRUN_SUPERVISOR_PATH",
                    "/definitely/does/not/exist/mvm-libkrun-supervisor",
                )
            };
            let result = resolve_supervisor_path();
            unsafe { std::env::remove_var("MVM_LIBKRUN_SUPERVISOR_PATH") };
            let err = result.expect_err("expected missing-file error");
            assert!(err.to_string().contains("not a file"));
        });
    }

    // read_exit_status_from / wait() tests.

    #[test]
    fn wait_reads_workload_exit_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(mvm_core::exit_capture::exit_file_path(dir.path()), "3").unwrap();
        let status = read_exit_status_from(dir.path());
        assert_eq!(status.code, Some(3));
        assert!(!status.success);
    }

    #[test]
    fn read_exit_status_zero_is_success() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(mvm_core::exit_capture::exit_file_path(dir.path()), "0").unwrap();
        let status = read_exit_status_from(dir.path());
        assert_eq!(status.code, Some(0));
        assert!(status.success);
    }

    #[test]
    fn read_exit_status_absent_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let status = read_exit_status_from(dir.path());
        assert_eq!(status, mvm_core::vm_backend::VmExitStatus::UNKNOWN);
    }

    #[test]
    fn build_supervisor_config_registers_control_port() {
        // The workload exit-code control port must appear in
        // host_listen_ports (not vsock_ports) so the supervisor owns the
        // listener socket and the guest connects as a client.
        let config = VmStartConfig {
            name: "ctrl-port-test".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert!(
            cfg.krun
                .host_listen_ports
                .contains(&mvm_guest::vsock::WORKLOAD_EXIT_PORT),
            "WORKLOAD_EXIT_PORT must be in host_listen_ports"
        );
        // Must not be double-registered as a guest-facing vsock port.
        assert!(
            !cfg.krun
                .vsock_ports
                .contains(&mvm_guest::vsock::WORKLOAD_EXIT_PORT),
            "WORKLOAD_EXIT_PORT must not appear in vsock_ports"
        );
    }

    #[test]
    fn build_supervisor_config_registers_substitution_port() {
        // The egress substitution port is a host-listen port (the endpoint
        // binds the UDS, the guest dials it) — registered unconditionally so
        // libkrun proxies the guest's connect. Fail-closed: nothing binds the
        // UDS unless the plan carries secrets.
        let config = VmStartConfig {
            name: "subst-port-test".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert!(
            cfg.krun
                .host_listen_ports
                .contains(&mvm_guest::vsock::SUBSTITUTION_PORT),
            "SUBSTITUTION_PORT must be in host_listen_ports"
        );
        assert!(
            !cfg.krun
                .vsock_ports
                .contains(&mvm_guest::vsock::SUBSTITUTION_PORT),
            "SUBSTITUTION_PORT must not appear in vsock_ports"
        );
    }

    #[test]
    fn build_supervisor_config_registers_broker_port() {
        // The host-services broker port is a host-listen port (the broker
        // subprocess binds the UDS, the guest dials it) — registered
        // unconditionally so libkrun proxies the guest's connect. Fail-closed:
        // nothing binds the UDS until the per-VM broker subprocess is spawned,
        // so a stray guest dial gets ECONNREFUSED.
        let config = VmStartConfig {
            name: "broker-port-test".into(),
            rootfs_path: "/tmp/rootfs.ext4".into(),
            kernel_path: Some("/tmp/vmlinux".into()),
            cpus: 1,
            memory_mib: 256,
            ..Default::default()
        };
        let tmp = tempfile::tempdir().unwrap();
        let cfg = build_supervisor_config(&config, tmp.path()).expect("build");
        assert!(
            cfg.krun
                .host_listen_ports
                .contains(&mvm_guest::vsock::BROKER_PORT),
            "BROKER_PORT must be in host_listen_ports"
        );
        assert!(
            !cfg.krun
                .vsock_ports
                .contains(&mvm_guest::vsock::BROKER_PORT),
            "BROKER_PORT must not appear in vsock_ports"
        );
    }

    /// No `plan.json` (or a secret-free plan) ⇒ no endpoint is spawned and the
    /// returned guard is defused (its Drop is a no-op, so an early return can't
    /// reap a process that was never started).
    #[test]
    fn libkrun_substitution_not_spawned_when_no_secrets() {
        let tmp = tempfile::tempdir().unwrap();
        // Empty state dir: no plan.json at all.
        let guard = spawn_libkrun_egress_endpoint_if_needed("no-secrets-vm", tmp.path())
            .expect("no-secrets path must succeed");
        assert!(
            guard.vm_name.is_none(),
            "a secret-free plan must yield a defused (no-op) guard"
        );
        // No pidfile was written (nothing spawned).
        assert!(
            !tmp.path()
                .join(crate::substitution_spawn::SUBST_PID_FILE)
                .exists()
        );
    }
}
