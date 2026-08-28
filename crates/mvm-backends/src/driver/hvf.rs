//! `HvfDriver` — the `VmmDriver` for the first-party VMM (HVF on macOS, KVM
//! on Linux via the shared `vmm` device model). `boot` maps a policy-free
//! `VmmSpec` to a relay supervisor config, spawns `mvm-hvf-supervisor`, and
//! returns a live handle. The claim-10 egress gate and secret substitution live in the
//! host-side endpoint the caller binds to the spec's `EGRESS_PORT` socket; the
//! driver only wires that socket through as the supervisor's egress relay — it
//! carries no policy and never sees a `NetworkPolicy`.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::Signer;
use mvm_agentd::vsock::{CONSOLE_PORT_BASE, GUEST_AGENT_PORT, dev_console_data_ports};
use mvm_core::config::{vm_hvf_vsock_port_socket_at, vm_state_dir, vms_dir};
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, ClaimStatus, GuestChannelInfo, LayerCoverage,
    ResourceControls, StandbyError, StandbyHandle, StandbyState, VmCapabilities, VmExitStatus,
    VmId, VmStatus,
};
use mvm_net::channel::GuestService;
use mvm_vmm::host::hvf_supervisor::{
    HostDialSocket, HvfDisk, HvfSupervisorConfig, HvfVirtioFsShare,
};
use mvm_vmm::hvf_handoff::HvfHandoffRequest;

use crate::driver::hvf_process::{
    self as hvf_backend, PID_FILE_NAME, PID_FILE_TIMEOUT, resolve_supervisor_path,
};
use mvm_contract::grants::CpuGrant;
use mvm_core::checkpoint::{DeviceAnchors, HVF_FRAME_BLOB};
use mvm_vmm::checkpoint::VmFullControl;
use mvm_vmm::driver::spec::{BlockDev, KernelImage, VmmSpec};
use mvm_vmm::driver::traits::{
    ChildForkRequest, DuplexStream, RunningVm, RunningVmStopTiming, StandbyParentSpawn, VmmDriver,
};

/// How long a capture waits for the paused supervisor to publish both halves of
/// its snapshot. Generous: the write is proportional to guest RAM.
const SNAPSHOT_PUBLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The first-party VMM driver: pure VMM mechanics, no policy and no admission.
/// It boots what a `VmmSpec` describes and relays the guest's egress port to the
/// host-side bridge; the claim-10 gate and substitution live in that bridge, not
/// here.
pub struct HvfDriver;

impl HvfDriver {
    pub fn new() -> Self {
        Self
    }

    /// Boot a VM whose supervisor must hold the exclusive lock at `lock_path`
    /// for as long as it runs.
    ///
    /// For the persistent builder, and deliberately not part of [`VmmDriver`]:
    /// the caller that starts such a VM exits immediately afterwards, so the
    /// lock cannot live with it. Every other boot leaves the lock with its
    /// caller, which outlives the VM and is already correct.
    ///
    /// An inherent method rather than a `VmmSpec` field because exactly one
    /// call site sets this, and threading it through the spec would touch
    /// every `VmmSpec` literal in the workspace for a property none of them
    /// have.
    pub fn boot_holding_image_lock(
        &self,
        spec: &VmmSpec,
        lock_path: &Path,
    ) -> Result<Box<dyn RunningVm>> {
        boot_with_handoff(spec, None, Some(lock_path))
    }
}

impl Default for HvfDriver {
    fn default() -> Self {
        Self::new()
    }
}

/// The per-VM host paths the supervisor writes and reads, resolved from the VM's
/// state dir. Grouped so the pure config mapping takes one struct rather than a
/// fistful of positional paths.
struct SupervisorPaths {
    state_dir: PathBuf,
    pid_file: PathBuf,
    console_log: PathBuf,
    workload_exit: PathBuf,
    timeout_secs: u64,
}

struct HandoffConfig {
    socket: PathBuf,
    root: PathBuf,
    verify_key: String,
}

impl SupervisorPaths {
    /// Resolve the standard per-VM paths under the VM's state dir. `timeout_secs`
    /// is a backstop cap (0 = none) against a guest that never reports its exit.
    fn resolve(state_dir: PathBuf, timeout_secs: u64) -> Self {
        let pid_file = state_dir.join(PID_FILE_NAME);
        let console_log = state_dir.join("console.log");
        let workload_exit = state_dir.join("workload.exit");
        Self {
            state_dir,
            pid_file,
            console_log,
            workload_exit,
            timeout_secs,
        }
    }
}

/// Map a policy-free `VmmSpec` to a relay `HvfSupervisorConfig`: the supervisor
/// wires the guest's `EGRESS_PORT` straight to the host-side endpoint bound at
/// `egress_relay_socket`, which owns the claim-10 gate and substitution. The
/// spec MUST carry that egress socket — an hvf workload has no other path
/// off the box, so a spec without it fails closed rather than booting ungated.
#[cfg(test)]
fn relay_supervisor_config(spec: &VmmSpec, paths: &SupervisorPaths) -> Result<HvfSupervisorConfig> {
    relay_supervisor_config_with_handoff(spec, paths, None, None)
}

fn relay_supervisor_config_with_handoff(
    spec: &VmmSpec,
    paths: &SupervisorPaths,
    handoff: Option<&HandoffConfig>,
    exclusive_image_lock: Option<&Path>,
) -> Result<HvfSupervisorConfig> {
    let kernel = match &spec.kernel {
        KernelImage::Path(p) => p.clone(),
        KernelImage::Bundled => {
            bail!("the hvf VMM requires an explicit kernel Image; VmmSpec.kernel is Bundled")
        }
    };

    // Every block in slot order becomes a virtio-blk device (`/dev/vda`…). Each
    // block carries its own read-only + ephemeral policy: a read-only block is
    // file-served with hypervisor-enforced RO; an ephemeral block is RAM-backed
    // (writes dropped on exit); a writable non-ephemeral block persists to the
    // host file (the builder's nix-store / output disks).
    let mut ordered: Vec<&BlockDev> = spec.blocks.iter().collect();
    ordered.sort_by_key(|b| b.slot);
    let disks = ordered
        .iter()
        .map(|b| HvfDisk {
            path: b.source.clone(),
            read_only: b.read_only,
            ephemeral: b.ephemeral,
        })
        .collect();

    // Guests that need host egress carry an explicit EGRESS_PORT relay socket in
    // the spec. Workloads must provide one; trusted builders now provide the same
    // vsock relay so every backend uses one egress path. A channel-less factory
    // parent is the one intentional exception: it has no guest-facing host
    // channel at all, so there is no egress path to wire or authorize.
    let egress_relay_socket = match spec.host_socket_for_service(GuestService::NetworkFlow) {
        Some(socket) => Some(socket),
        None if spec.vsock.is_empty() => None,
        // A sealed workload with no EGRESS_PORT has an explicit deny-all,
        // secret-free posture. There is no host listener to wire because the
        // guest has no admitted egress capability; its attempted dial fails
        // closed in the vsock device.
        None if !spec
            .vsock
            .iter()
            .any(|port| port.service == GuestService::NetworkFlow) =>
        {
            None
        }
        None if spec.trusted_builder => None,
        None => {
            return Err(anyhow!(
                "hvf workload spec is missing the EGRESS_PORT vsock relay socket"
            ));
        }
    };

    // An empty spec cmdline means "use the supervisor's workload default"
    // (`init=/init`); a non-empty one (e.g. the builder rootfs's
    // `init=/sbin/mvm-host-vm-init`) is threaded through verbatim.
    let cmdline = {
        let c = spec.cmdline.trim();
        (!c.is_empty()).then(|| c.to_string())
    };

    // Collect explicitly host-dialable dev console channels.
    let console_data_sockets = spec
        .vsock
        .iter()
        .filter(|p| {
            matches!(p.service, GuestService::ConsoleData { port } if dev_console_data_ports().any(|cp| cp == port))
        })
        .map(|p| HostDialSocket {
            guest_port: p.port(),
            host_socket: p.host_uds.clone(),
        })
        .collect();

    // Builder-tier control ports, by the same rule: present only when the spec
    // names them, which only a persistent builder VM's spec does. A workload
    // spec carries none, so this is empty for every tenant guest.
    let builder_control_sockets = spec
        .vsock
        .iter()
        .filter(|p| p.service.is_builder_tier())
        .map(|p| HostDialSocket {
            guest_port: p.port(),
            host_socket: p.host_uds.clone(),
        })
        .collect();

    let (cpu_millicores, quota_record) = match spec.cpu_grant {
        Some(CpuGrant::Share { millicores }) => (
            Some(millicores),
            Some(paths.state_dir.join("vcpu_quota.json")),
        ),
        Some(CpuGrant::Fuel { .. }) | None => (None, None),
    };

    Ok(HvfSupervisorConfig {
        kernel,
        cmdline,
        memory_mib: spec.memory_mib,
        vcpus: spec.vcpus,
        initramfs: spec.initramfs.clone(),
        disks,
        virtiofs_root: spec
            .shares
            .iter()
            .find(|share| share.tag == "mvmroot")
            .map(|share| share.host_path.clone()),
        virtiofs_shares: spec
            .shares
            .iter()
            .filter(|share| share.tag != "mvmroot")
            .map(|share| HvfVirtioFsShare {
                path: share.host_path.clone(),
                tag: share.tag.clone(),
            })
            .collect(),
        vsock: true,
        trusted_builder_egress: spec.trusted_builder,
        console_log: paths.console_log.clone(),
        pid_file: paths.pid_file.clone(),
        workload_exit: paths.workload_exit.clone(),
        pause_state: Some(paths.state_dir.join("pause.state")),
        snapshot_request: Some(paths.state_dir.join("snapshot.request")),
        snapshot_ram: Some(paths.state_dir.join("snapshot.ram")),
        snapshot_frame: Some(paths.state_dir.join("snapshot.frame")),
        restore_ram: None,
        restore_frame: None,
        timeout_secs: paths.timeout_secs,
        // The plan's wall-clock bound and the paths its kill is audited under.
        // The supervisor owns the guest for its whole life, so it holds the
        // only timer that can still fire once `mvmctl` is gone.
        plan: spec.plan_binding.as_ref().map(|b| b.plan_json.clone()),
        audit_dir: spec.plan_binding.as_ref().map(|b| b.audit_dir.clone()),
        signing_key_path: spec
            .plan_binding
            .as_ref()
            .map(|b| b.signing_key_path.clone()),
        // Re-derive the agent bridge from the state dir rather than trusting the
        // spec's backend-neutral agent hint (`agent.sock`): the detached
        // supervisor binds this exact path, and the host resolver probes the same
        // `hvf-agent.sock`, so binder and resolver can't drift.
        agent_socket: Some(hvf_agent_socket(&paths.state_dir)),
        substitution_socket: None,
        egress_relay_socket,
        // An admitted workload carries a BROKER_PORT relay socket; the supervisor
        // splices the guest's BROKER_PORT dial to it so host.audit.v1 /
        // host.secrets.v1 reach the per-VM broker (or the per-tenant host-agent
        // daemon). Absent for a builder/dev VM, which runs no admitted workload.
        broker_socket: spec.host_socket_for_service(GuestService::Broker),
        console_data_sockets,
        builder_control_sockets,
        exclusive_image_lock: exclusive_image_lock.map(Path::to_path_buf),
        handoff_socket: handoff.map(|value| value.socket.clone()),
        handoff_root: handoff.map(|value| value.root.clone()),
        handoff_verify_key: handoff.map(|value| value.verify_key.clone()),
        cpu_millicores,
        quota_record,
    })
}

fn handoff_config(parent_vm_name: &str) -> Result<HandoffConfig> {
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
        .context("load host identity for HVF handoff")?;
    let state_dir = vm_state_dir(parent_vm_name);
    Ok(HandoffConfig {
        socket: state_dir.join("hvf-handoff.sock"),
        root: vms_dir(),
        verify_key: hex::encode(identity.verifying.to_bytes()),
    })
}

/// The supervisor launch, bounded by whatever CPU share this VM was admitted
/// under.
///
/// The HVF VMM runs inside this supervisor process, so the supervisor is the
/// process to bound. Wired uniformly with the other drivers rather than skipped
/// for the host it happens to run on today: the bind degrades to an unwrapped
/// spawn wherever the mechanism is absent, which is the honest answer on macOS
/// and needs no second code path to express.
fn bounded_supervisor_command(supervisor: &Path, spec: &VmmSpec, state_dir: &Path) -> Command {
    mvm_core::cpu_scope::bind_cpu_grant(
        Command::new(supervisor),
        &spec.name,
        state_dir,
        spec.cpu_grant.as_ref(),
    )
}

fn boot_with_handoff(
    spec: &VmmSpec,
    handoff: Option<&HandoffConfig>,
    exclusive_image_lock: Option<&Path>,
) -> Result<Box<dyn RunningVm>> {
    let state_dir = vm_state_dir(&spec.name);
    std::fs::create_dir_all(&state_dir)
        .map_err(|e| anyhow!("create state dir {}: {e}", state_dir.display()))?;
    let _ = mvm_vmm::host::console_capture::open_console_capture(&state_dir.join("console.log"));
    let timeout_secs = std::env::var("MVM_HVF_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let paths = SupervisorPaths::resolve(state_dir, timeout_secs);
    let _ = std::fs::remove_file(&paths.workload_exit);
    let cfg = relay_supervisor_config_with_handoff(spec, &paths, handoff, exclusive_image_lock)?;
    let config_path = paths.state_dir.join("supervisor.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&cfg).map_err(|e| anyhow!("serialize supervisor config: {e}"))?,
    )
    .map_err(|e| anyhow!("write supervisor config {}: {e}", config_path.display()))?;
    let json =
        serde_json::to_string(&cfg).map_err(|e| anyhow!("serialize HvfSupervisorConfig: {e}"))?;
    let supervisor = resolve_supervisor_path()?;
    let mut child = bounded_supervisor_command(&supervisor, spec, &paths.state_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(mvm_vmm::host::console_capture::supervisor_stderr(
            &paths.state_dir,
        ))
        .spawn()
        .map_err(|e| anyhow!("spawn {}: {e}", supervisor.display()))?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("supervisor stdin was not piped"))?
        .write_all(json.as_bytes())
        .map_err(|e| anyhow!("pipe HvfSupervisorConfig to supervisor stdin: {e}"))?;
    let deadline = Instant::now() + PID_FILE_TIMEOUT;
    let mut attempt = 0u32;
    loop {
        if paths.pid_file.exists() {
            break;
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|e| anyhow!("poll supervisor: {e}"))?
        {
            bail!(
                "hvf supervisor exited before writing its PID file (status: {status}); see {}",
                paths.console_log.display()
            );
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            bail!(
                "hvf supervisor did not confirm boot within {PID_FILE_TIMEOUT:?}; see {}",
                paths.console_log.display()
            );
        }
        std::thread::sleep(mvm_core::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
    drop(child);
    let agent_socket = hvf_agent_socket(&paths.state_dir);
    Ok(Box::new(HvfRunningVm {
        id: VmId(spec.name.clone()),
        state_dir: paths.state_dir,
        pid_file: paths.pid_file,
        agent_socket,
    }))
}

impl VmmDriver for HvfDriver {
    fn name(&self) -> &str {
        "hvf"
    }

    fn kind(&self) -> BackendKind {
        BackendKind::Hvf
    }

    fn is_available(&self) -> Result<bool> {
        // Selection/doctor probe: the detached supervisor must exist and the
        // host must report a runnable HVF path.
        Ok(resolve_supervisor_path().is_ok() && hvf_backend::hvf_workload_support_available())
    }

    fn capabilities(&self) -> VmCapabilities {
        let proxy_path_ready = hvf_backend::hvf_workload_support_available();
        // vsock is live-proven through the unified run loop; the rest land as
        // pause/snapshot/networking are wired onto the primitive.
        VmCapabilities {
            // Asked of the host, not assumed. This was a hardcoded `Some(4)`
            // for a while: 5, 6 and 8 vCPU guests really did fail to reach the
            // agent, and the number recorded that. The cause turned out to be a
            // race in this backend's own vCPU creation rather than any limit —
            // HVF hands out GIC redistributor frames in `hv_vcpu_create` order,
            // and the creation threads were unordered, so two CPUs swapped
            // frames and the guest could not match either to its
            // redistributor. The suspicion written beside that constant — that
            // a plausible-looking derivation would hide a threading bug — was
            // right, and it was the constant that was hiding it.
            //
            // With creation ordered, 1, 2, 4, 5, 6, 8, 16 and 32 all boot and
            // report their full count. So the ceiling comes from
            // `hv_vm_get_max_vcpu_count` now, which answers 64 here and answers
            // for itself on a different host.
            max_vcpus: hvf_backend::hvf_max_vcpus(),
            pause_resume: true,
            // The supervisor serializes guest RAM plus vCPU and deterministic
            // device state under an acknowledged pause, and reloads both into a
            // fresh VMM. That is coarse save/restore of machine state, not the
            // incremental live-memory tier: a capture copies the whole mapping.
            snapshot_capability: mvm_core::vm_backend::SnapshotCapability::SaveRestore,
            // The native resident handoff is the warm-launch implementation;
            // admission still requires the backend's ordinary availability and
            // security gates before a parent can be created or claimed.
            standby_pool: true,
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
            // The same fact `supports_directory_shares` states to the runner,
            // restated where a caller holding an `AnyBackend` can read it. The
            // two are asserted to agree by
            // `advertised_directory_shares_match_the_driver`, because a matrix
            // that disagreed with the driver would refuse a `--mount` the
            // backend can serve, or accept one it cannot.
            directory_shares: true,
            // Named explicitly rather than left to `..Default::default()`:
            // the honest HVF answer (no cgroup, but a supervisor wall-clock
            // timer) differs from the all-`None` default.
            resource_controls: ResourceControls::for_backend(BackendKind::Hvf),
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

    fn supports_directory_shares(&self) -> bool {
        true
    }

    fn supports_resident_handoff(&self) -> bool {
        self.capabilities().standby_pool
    }

    #[tracing::instrument(
        name = "hvf.boot",
        skip_all,
        fields(vm = %spec.name, vcpus = spec.vcpus, memory_mib = spec.memory_mib)
    )]
    fn boot(&self, spec: &VmmSpec) -> Result<Box<dyn RunningVm>> {
        boot_with_handoff(spec, None, None)
    }

    fn spawn_standby_parent(
        &self,
        req: &StandbyParentSpawn<'_>,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let handoff = handoff_config(&req.spec.id)
            .map_err(|e| StandbyError::SpawnFailed(format!("prepare HVF handoff: {e}")))?;
        let vm = boot_with_handoff(req.boot, Some(&handoff), None)
            .map_err(|e| StandbyError::SpawnFailed(format!("boot HVF standby: {e}")))?;
        let state_dir = vm_state_dir(&req.spec.id);
        let pid = hvf_backend::read_pid(&state_dir.join(PID_FILE_NAME)).ok_or_else(|| {
            let _ = vm.kill();
            StandbyError::SpawnFailed(format!(
                "HVF standby '{}' did not publish a pid",
                req.spec.id
            ))
        })?;
        let pid_u32 = u32::try_from(pid).map_err(|_| {
            StandbyError::SpawnFailed(format!("HVF standby '{}' pid is negative", req.spec.id))
        })?;
        wait_for_guest_agent(&state_dir).map_err(|e| {
            let _ = vm.kill();
            StandbyError::SpawnFailed(format!(
                "HVF standby '{}' guest agent did not become ready: {e}",
                req.spec.id
            ))
        })?;
        drop(vm);
        Ok(StandbyHandle {
            id: req.spec.id.clone(),
            template_id: req.spec.template_id.clone(),
            control_socket: state_dir
                .join("hvf-control.sock")
                .to_string_lossy()
                .into_owned(),
            pid: pid_u32,
            kernel_sha256: req.spec.kernel_sha256.clone(),
            vcpus: req.spec.vcpus,
            mem_mib: req.spec.mem_mib,
            binding_nonce: req.spec.binding_nonce.clone(),
            spawned_unix_secs: mvm_core::time::now_unix_secs(),
            state: StandbyState::Idle,
            image_sha256: req.spec.image_sha256.clone(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: req.spec.vsock_egress,
        })
    }

    fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn VmFullControl>> {
        Some(Box::new(HvfVmFullControl::new(vm_name)))
    }

    fn fork_standby_child(
        &self,
        req: &ChildForkRequest<'_>,
    ) -> std::result::Result<(), StandbyError> {
        let parent_name = req.parent_vm_name.ok_or_else(|| {
            StandbyError::ClaimFailed(
                "HVF live standby claim requires a resident paused parent".into(),
            )
        })?;
        if !req.child_dir.is_dir() {
            return Err(StandbyError::ClaimFailed(format!(
                "HVF child '{}' state dir {} is missing",
                req.child_vm_name,
                req.child_dir.display()
            )));
        }
        let child_dir = req.child_dir;
        let expected_child_dir = vm_state_dir(req.child_vm_name);
        if child_dir != expected_child_dir {
            return Err(StandbyError::ClaimFailed(format!(
                "HVF child state dir {} is not the canonical dir {}",
                child_dir.display(),
                expected_child_dir.display()
            )));
        }

        let parent_dir = vm_state_dir(parent_name);
        let parent_pid_path = parent_dir.join(PID_FILE_NAME);
        let parent_pid = hvf_backend::read_pid(&parent_pid_path).ok_or_else(|| {
            StandbyError::ClaimFailed(format!(
                "HVF standby parent '{}' is no longer live",
                parent_name
            ))
        })?;
        let parent_pid = u32::try_from(parent_pid).map_err(|_| {
            StandbyError::ClaimFailed("HVF standby parent pid does not fit u32".into())
        })?;
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()
            .map_err(|e| StandbyError::ClaimFailed(format!("load host handoff identity: {e}")))?;
        let channel_mask = req.channels.iter().fold(0_u8, |mask, channel| {
            if channel.service == GuestService::MachineControl {
                mask | 1
            } else if channel.service == GuestService::NetworkFlow {
                mask | 2
            } else if channel.service == GuestService::Broker {
                mask | 4
            } else if matches!(
                channel.service,
                GuestService::ConsoleData { port }
                    if dev_console_data_ports().any(|candidate| candidate == port)
            ) {
                mask | 8
            } else {
                mask
            }
        });
        let request = HvfHandoffRequest {
            child_vm_name: req.child_vm_name.to_string(),
            parent_pid,
            channel_mask,
            signature: hex::encode(
                identity
                    .signing
                    .sign(&HvfHandoffRequest::signing_message(
                        parent_pid,
                        req.child_vm_name,
                        channel_mask,
                    ))
                    .to_bytes(),
            ),
        };
        let socket = parent_dir.join("hvf-handoff.sock");
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).map_err(|e| {
            StandbyError::ClaimFailed(format!(
                "connect to HVF parent handoff socket {}: {e}",
                socket.display()
            ))
        })?;
        let mut payload = serde_json::to_vec(&request).map_err(|e| {
            StandbyError::ClaimFailed(format!("serialize HVF handoff request: {e}"))
        })?;
        payload.push(b'\n');
        stream
            .write_all(&payload)
            .map_err(|e| StandbyError::ClaimFailed(format!("send HVF handoff request: {e}")))?;
        let response = read_handoff_response(&mut stream)
            .map_err(|e| StandbyError::ClaimFailed(format!("read HVF handoff response: {e}")))?;
        if &response != b"OK\n" {
            return Err(StandbyError::ClaimFailed(format!(
                "HVF parent rejected live handoff: {}",
                String::from_utf8_lossy(&response).trim()
            )));
        }

        link_child_state(child_dir, &parent_dir)
            .map_err(|e| StandbyError::ClaimFailed(format!("link live HVF child state: {e}")))?;
        hvf_backend::signal_vm(&parent_pid_path, libc::SIGUSR2, "resume live HVF child")
            .map_err(|e| StandbyError::ClaimFailed(format!("resume live HVF child: {e}")))?;
        // The post-restore identity RPC is the readiness barrier for the child.
        // Waiting here for the supervisor's marker adds the full pause-ack
        // timeout on HVF even after SIGUSR2 has resumed the vCPU; the RPC will
        // naturally wait until the resumed guest can answer.
        Ok(())
    }

    fn attach(&self, id: &VmId) -> Result<Box<dyn RunningVm>> {
        // The handle is entirely disk-backed (the supervisor's pid file + the
        // persisted workload-exit code under the VM's state dir), so reattaching is
        // just re-deriving those paths — no live boot state to recover.
        let state_dir = vm_state_dir(&id.0);
        Ok(Box::new(HvfRunningVm {
            pid_file: state_dir.join(PID_FILE_NAME),
            agent_socket: hvf_agent_socket(&state_dir),
            state_dir,
            id: id.clone(),
        }))
    }

    fn guest_channel_info(&self, _id: &VmId) -> Result<GuestChannelInfo> {
        // The HVF driver does not expose a queryable per-VM guest channel:
        // the agent bridge is a fixed vsock port wired by the runner, not a
        // channel the driver answers on demand.
        bail!("hvf does not provide guest channel info")
    }

    fn workload_base_bootargs(&self, virtiofs_root: bool, has_disk: bool) -> String {
        crate::driver::hvf_bootargs::workload_bootargs(virtiofs_root, has_disk)
    }
}

fn read_handoff_response(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<[u8; 3]> {
    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    let mut response = [0_u8; 3];
    let mut received = 0;
    while received < response.len() {
        match stream.read(&mut response[received..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "HVF handoff peer closed before its response was complete",
                ));
            }
            Ok(count) => received += count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "HVF handoff response timed out",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(response)
}

fn link_child_state(child_dir: &Path, parent_dir: &Path) -> std::io::Result<()> {
    for name in [PID_FILE_NAME, "console.log", "workload.exit", "pause.state"] {
        let child_path = child_dir.join(name);
        let parent_path = parent_dir.join(name);
        if let Ok(metadata) = std::fs::symlink_metadata(&child_path) {
            if metadata.file_type().is_dir() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("child state path {} is a directory", child_path.display()),
                ));
            }
            std::fs::remove_file(&child_path)?;
        }
        std::os::unix::fs::symlink(&parent_path, &child_path)?;
    }
    Ok(())
}

/// The per-VM agent-RPC socket the detached `mvm-hvf-supervisor` binds
/// (host→guest agent bridge). The driver re-derives this from the state dir
/// rather than trusting the spec's generic agent hint — the same way the FC and
/// libkrun drivers ignore the spec's agent host_uds — so the value it hands the
/// supervisor is exactly the one the host resolver (`DevConsoleTransport` /
/// `for_vm` → `vm_hvf_agent_socket`) probes. A drift here silently makes the
/// guest agent unreachable and every RPC time out.
fn hvf_agent_socket(state_dir: &std::path::Path) -> PathBuf {
    mvm_core::config::vm_hvf_agent_socket_at(state_dir)
}

/// Do not capture a factory parent until its guest agent has completed init.
/// The child resumes from the captured CPU/device state rather than rebooting,
/// so a parent captured before the agent listener is serving would make every
/// later post-restore identity handshake impossible.
fn wait_for_guest_agent(state_dir: &Path) -> Result<()> {
    let socket = hvf_agent_socket(state_dir);
    let deadline = Instant::now() + std::time::Duration::from_secs(10);
    let mut attempt = 0u32;
    while Instant::now() < deadline {
        if socket.exists() {
            // The HVF agent socket is the bridge's direct stream endpoint. It
            // is not a Firecracker-style CONNECT multiplexer, so sending the
            // `CONNECT <port>` preamble would be interpreted by the guest as
            // the first four bytes of an RPC frame. Probe the authenticated
            // RPC stream directly; this waits for a real guest response rather
            // than treating the host-side listener as readiness.
            if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&socket) {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(1)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(1)));
                if mvm_agentd::vsock::probe_agent_ready(&mut stream).is_ok() {
                    return Ok(());
                }
            }
        }
        std::thread::sleep(mvm_core::poll_backoff::poll_delay(attempt));
        attempt = attempt.saturating_add(1);
    }
    anyhow::bail!(
        "guest agent socket {} was not responsive within 10s",
        socket.display()
    )
}

/// Resolve the host UDS for a console data port via the shared HVF-style socket
/// helper. Returns `None` when the port is outside `dev_console_data_ports()`.
fn console_socket_for_port(state_dir: &std::path::Path, guest_port: u32) -> Option<PathBuf> {
    if dev_console_data_ports().any(|p| p == guest_port) {
        Some(vm_hvf_vsock_port_socket_at(state_dir, guest_port))
    } else {
        None
    }
}

/// A live hvf VM: the detached `mvm-hvf-supervisor` tracked by its PID file,
/// with the workload's exit code persisted under its state dir.
struct HvfRunningVm {
    id: VmId,
    state_dir: PathBuf,
    pid_file: PathBuf,
    /// Host→guest agent RPC socket the supervisor bound for this VM.
    agent_socket: PathBuf,
}

/// Host control for a running HVF standby parent. The supervisor owns the
/// actual vCPU/device objects; this control uses the acknowledged pause marker
/// plus fixed state-directory files for the capture rendezvous.
struct HvfVmFullControl {
    vm_name: String,
    state_dir: PathBuf,
}

impl HvfVmFullControl {
    fn new(vm_name: &str) -> Self {
        Self {
            vm_name: vm_name.to_string(),
            state_dir: vm_state_dir(vm_name),
        }
    }

    fn fixed_snapshot_paths(&self) -> (PathBuf, PathBuf, PathBuf) {
        (
            self.state_dir.join("snapshot.request"),
            self.state_dir.join("snapshot.ram"),
            self.state_dir.join("snapshot.frame"),
        )
    }

    /// Refuse to capture a VM whose guest can write to a block device.
    ///
    /// A snapshot carries guest RAM plus the devices' control plane, never a
    /// device's backing bytes. That is sound for a read-only, file-served disk:
    /// the restore rebinds the same unchanged image. It is not sound for a
    /// writable one — a RAM-backed ephemeral rootfs loses every guest write
    /// when the VMM exits, and a write-through image keeps changing after the
    /// capture — so a restore would resume a guest whose page cache disagrees
    /// with its disk. Fail closed at capture rather than mint a checkpoint that
    /// silently reverts data.
    fn ensure_every_disk_is_restorable(&self) -> Result<()> {
        let Some(path) = self.supervisor_config_path()? else {
            return Ok(());
        };
        let cfg: HvfSupervisorConfig = serde_json::from_slice(
            &std::fs::read(&path)
                .with_context(|| format!("reading HVF launch config {}", path.display()))?,
        )
        .with_context(|| format!("parsing HVF launch config {}", path.display()))?;
        if let Some(writable) = cfg.disks.iter().find(|disk| !disk.read_only) {
            bail!(
                "cannot capture a full-VM checkpoint of HVF VM '{}': its disk {} is \
                 writable, and a snapshot does not carry device backing bytes. \
                 Capture an fs_quick checkpoint of the paused VM instead.",
                self.vm_name,
                writable.path.display()
            );
        }
        Ok(())
    }
}

impl VmFullControl for HvfVmFullControl {
    fn pause(&self) -> Result<()> {
        hvf_backend::signal_vm(
            &self.state_dir.join(PID_FILE_NAME),
            libc::SIGUSR1,
            "pause standby parent",
        )?;
        hvf_backend::wait_for_pause_state(&self.state_dir.join("pause.state"), true)
    }

    fn save_memory(&self, memory_path: &Path) -> Result<()> {
        anyhow::ensure!(
            memory_path.is_absolute(),
            "save_memory requires an absolute path, got {}",
            memory_path.display()
        );
        self.ensure_every_disk_is_restorable()?;
        let parent = memory_path
            .parent()
            .ok_or_else(|| anyhow!("memory path has no parent directory"))?;
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create snapshot output {}", parent.display()))?;
        let (request, ram, frame) = self.fixed_snapshot_paths();
        let _ = std::fs::remove_file(&ram);
        let _ = std::fs::remove_file(&frame);
        std::fs::write(&request, b"capture\n")
            .with_context(|| format!("request HVF snapshot at {}", request.display()))?;
        let deadline = Instant::now() + SNAPSHOT_PUBLISH_TIMEOUT;
        let mut wait = std::time::Duration::from_micros(200);
        while (!ram.exists() || !frame.exists()) && Instant::now() < deadline {
            std::thread::sleep(wait);
            wait = (wait * 2).min(std::time::Duration::from_millis(5));
        }
        anyhow::ensure!(
            ram.exists() && frame.exists(),
            "HVF supervisor did not publish its paused snapshot within {SNAPSHOT_PUBLISH_TIMEOUT:?}"
        );
        std::fs::copy(&ram, memory_path).with_context(|| {
            format!(
                "copying captured HVF RAM {} -> {}",
                ram.display(),
                memory_path.display()
            )
        })?;
        let frame_dst = parent.join(format!(
            "{}.hvf-frame",
            memory_path
                .file_name()
                .ok_or_else(|| anyhow!("memory path has no file name"))?
                .to_string_lossy()
        ));
        std::fs::copy(&frame, &frame_dst).with_context(|| {
            format!(
                "copying captured HVF frame {} -> {}",
                frame.display(),
                frame_dst.display()
            )
        })?;
        Ok(())
    }

    fn resume(&self) -> Result<()> {
        hvf_backend::signal_vm(
            &self.state_dir.join(PID_FILE_NAME),
            libc::SIGUSR2,
            "resume standby parent",
        )?;
        hvf_backend::wait_for_pause_state(&self.state_dir.join("pause.state"), false)
    }

    fn retain_paused_after_capture(&self) -> bool {
        true
    }

    fn rootfs_path(&self) -> Result<PathBuf> {
        let meta = mvm_vmm::host::runtime_meta::read(&self.vm_name)?
            .ok_or_else(|| anyhow!("no runtime metadata for HVF VM '{}'", self.vm_name))?;
        meta.rootfs_path
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HVF VM '{}' has no rootfs path", self.vm_name))
    }

    fn device_anchors(&self) -> Result<DeviceAnchors> {
        let rootfs = self.rootfs_path()?;
        let rootfs_verity = rootfs
            .parent()
            .map(|parent| parent.join("rootfs.verity"))
            .filter(|path| path.exists());
        Ok(DeviceAnchors {
            rootfs,
            rootfs_verity,
            config: None,
            secrets: None,
            vsock: hvf_agent_socket(&self.state_dir),
        })
    }

    fn extra_content(&self, content_dir: &Path) -> Result<Vec<mvm_core::checkpoint::ContentBlob>> {
        let frame = content_dir.join(HVF_FRAME_BLOB);
        if !frame.exists() {
            return Ok(Vec::new());
        }
        Ok(vec![mvm_core::checkpoint::ContentBlob {
            name: HVF_FRAME_BLOB.into(),
            sha256: mvm_core::crypto::image_verify::sha256_file(&frame)?,
        }])
    }

    fn supervisor_config_path(&self) -> Result<Option<PathBuf>> {
        let path = self.state_dir.join("supervisor.json");
        Ok(path.is_file().then_some(path))
    }
}

impl RunningVm for HvfRunningVm {
    fn id(&self) -> &VmId {
        &self.id
    }

    fn host_process_id(&self) -> Option<u32> {
        hvf_backend::read_pid(&self.pid_file).and_then(|pid| u32::try_from(pid).ok())
    }

    fn wait(&self) -> Result<VmExitStatus> {
        Ok(mvm_vmm::host::workload_wait::wait_for_workload_exit(
            &self.state_dir,
        ))
    }

    fn kill(&self) -> Result<()> {
        self.kill_with_timing().map(|_| ())
    }

    fn kill_with_timing(&self) -> Result<Option<RunningVmStopTiming>> {
        let termination = hvf_backend::read_pid(&self.pid_file)
            .map(hvf_backend::terminate_pid_timed)
            .transpose()?
            .unwrap_or_default();
        let cleanup_started = Instant::now();
        let _ = std::fs::remove_file(&self.pid_file);
        let state_cleanup = cleanup_started.elapsed();
        Ok(Some(RunningVmStopTiming {
            supervisor_signal: termination.supervisor_signal,
            pid_disappearance: termination.pid_disappearance,
            force_kill_wait: termination.force_kill_wait,
            state_cleanup,
        }))
    }

    fn pause(&self) -> Result<()> {
        hvf_backend::signal_vm(&self.pid_file, libc::SIGUSR1, "pause")?;
        hvf_backend::wait_for_pause_state(&self.state_dir.join("pause.state"), true)
    }

    fn resume(&self) -> Result<()> {
        hvf_backend::signal_vm(&self.pid_file, libc::SIGUSR2, "resume")?;
        hvf_backend::wait_for_pause_state(&self.state_dir.join("pause.state"), false)
    }

    fn status(&self) -> Result<VmStatus> {
        Ok(match hvf_backend::read_pid(&self.pid_file) {
            Some(pid) if hvf_backend::pid_alive(pid) => VmStatus::Running,
            _ => VmStatus::Stopped,
        })
    }

    fn vsock_connect(&self, guest_port: u32) -> Result<Box<dyn DuplexStream>> {
        let socket_path = if guest_port == GUEST_AGENT_PORT {
            self.agent_socket.clone()
        } else if let Some(path) = console_socket_for_port(&self.state_dir, guest_port) {
            // Dev-only: pre-opened console data port in the CONSOLE_PORT_BASE+1..=+128
            // range. Claim 15: sealed prod specs carry no console sockets, so this
            // path is only reachable when the runner pre-bound these UDS at start.
            path
        } else {
            bail!(
                "hvf driver vsock_connect supports only the agent port \
                 ({GUEST_AGENT_PORT}) and dev console data ports ({}..={}); got {guest_port}",
                CONSOLE_PORT_BASE + 1,
                CONSOLE_PORT_BASE + 128,
            );
        };
        let stream = std::os::unix::net::UnixStream::connect(&socket_path)
            .with_context(|| format!("connect to hvf vsock socket {}", socket_path.display()))?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::SnapshotCapability;
    use mvm_vmm::driver::spec::{BlockDev, ConsoleCapture, VsockDirection, VsockPort};

    /// The capability matrix and the driver state the same fact about
    /// directory shares, and must not drift.
    ///
    /// They are read by different callers: the runner asks the driver just
    /// before assembling the spec, while a preflight refusal asks the matrix
    /// through `AnyBackend`, which cannot see the driver at all. If they
    /// disagreed, one of the two answers would be wrong — either refusing a
    /// `--mount` this backend can serve, or admitting one it cannot and
    /// failing later, which is the behaviour the preflight exists to remove.
    #[test]
    fn advertised_directory_shares_match_the_driver() {
        let driver = HvfDriver;
        assert_eq!(
            driver.capabilities().directory_shares,
            driver.supports_directory_shares(),
            "the capability matrix and the driver disagree about directory shares"
        );
    }

    #[test]
    fn handoff_response_reader_handles_a_ready_unix_stream() {
        let (mut peer, mut stream) = std::os::unix::net::UnixStream::pair().expect("unix pair");
        let writer = std::thread::spawn(move || {
            peer.write_all(b"OK\n").expect("write handoff response");
        });

        let response = read_handoff_response(&mut stream).expect("read handoff response");
        writer.join().expect("join handoff writer");
        assert_eq!(&response, b"OK\n");
    }

    fn egress_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::NetworkFlow,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn agent_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::MachineControl,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    fn broker_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::Broker,
            host_uds: uds.into(),
            direction: VsockDirection::GuestDials,
        }
    }

    fn spec_with(kernel: KernelImage, vsock: Vec<VsockPort>, blocks: Vec<BlockDev>) -> VmmSpec {
        VmmSpec {
            name: "w".into(),
            kernel,
            initramfs: Some("/img/initrd.cpio".into()),
            cmdline: String::new(),
            vcpus: 1,
            cpu_grant: None,
            memory_mib: 256,
            mem_initial_mib: None,
            blocks,
            shares: vec![],
            vsock,
            console: ConsoleCapture {
                log_path: "/tmp/console.log".into(),
            },
            trusted_builder: false,
            plan_binding: None,
        }
    }

    #[test]
    fn a_plan_bound_spec_hands_the_hvf_supervisor_what_it_needs_to_enforce_the_bound() {
        let mut spec = spec_with(KernelImage::Path("/k/Image".into()), vec![], vec![]);
        spec.plan_binding = Some(mvm_vmm::driver::spec::PlanBinding {
            plan_json: serde_json::json!({"resources": {"timeouts": {"exec_secs": 30}}}),
            audit_dir: "/fixture/audit".into(),
            signing_key_path: "/fixture/keys/host-signer.ed25519".into(),
        });
        let cfg = relay_supervisor_config(&spec, &sample_paths()).expect("config");

        // HVF is the macOS 26+ auto-detect default, so an unenforced bound here
        // is the default path. The supervisor arms its timer from `plan`.
        assert_eq!(
            cfg.plan
                .as_ref()
                .map(|p| p["resources"]["timeouts"]["exec_secs"].clone()),
            Some(serde_json::json!(30))
        );
        assert_eq!(
            cfg.audit_dir.as_deref(),
            Some(std::path::Path::new("/fixture/audit"))
        );
        assert_eq!(
            cfg.signing_key_path.as_deref(),
            Some(std::path::Path::new("/fixture/keys/host-signer.ed25519"))
        );
    }

    #[test]
    fn the_plan_bound_is_not_the_unaudited_run_backstop() {
        let mut spec = spec_with(KernelImage::Path("/k/Image".into()), vec![], vec![]);
        spec.plan_binding = Some(mvm_vmm::driver::spec::PlanBinding {
            plan_json: serde_json::json!({"resources": {"timeouts": {"exec_secs": 30}}}),
            audit_dir: "/fixture/audit".into(),
            signing_key_path: "/fixture/keys/host-signer.ed25519".into(),
        });
        let cfg = relay_supervisor_config(&spec, &sample_paths()).expect("config");

        // `timeout_secs` comes from the MVM_HVF_TIMEOUT dev hook and is unset in
        // normal use. A plan's bound must not be conflated with it: this one is
        // audited and exits 124, that one is neither.
        assert_eq!(cfg.timeout_secs, 0, "the dev backstop stays independent");
        assert!(cfg.plan.is_some(), "the plan's own bound is what enforces");
    }

    fn sample_paths() -> SupervisorPaths {
        SupervisorPaths::resolve(PathBuf::from("/state/w"), 0)
    }

    #[test]
    fn identity_and_capabilities_delegate_to_the_hvf_backend() {
        let d = HvfDriver::new();
        assert_eq!(d.name(), "hvf");
        assert_eq!(d.kind(), BackendKind::Hvf);
        assert!(d.capabilities().vsock);
        assert_eq!(d.snapshot_capability(), SnapshotCapability::SaveRestore);
        assert_eq!(d.security_profile().tier, "Tier 2");
    }

    #[test]
    fn workload_base_bootargs_delegates_to_hvf_bootargs() {
        let d = HvfDriver::new();
        assert_eq!(
            d.workload_base_bootargs(false, true),
            crate::driver::hvf_bootargs::workload_bootargs(false, true)
        );
        assert_eq!(
            d.workload_base_bootargs(true, false),
            crate::driver::hvf_bootargs::workload_bootargs(true, false)
        );
    }

    #[test]
    fn guest_channel_info_is_unsupported() {
        // The HVF driver does not expose a queryable per-VM guest channel —
        // the agent bridge is a fixed vsock port wired by the runner, not a
        // channel the driver answers on demand.
        let d = HvfDriver::new();
        let id = VmId("hvf-guest-channel-info-test-vm".into());
        assert!(d.guest_channel_info(&id).is_err());
    }

    #[test]
    fn attach_builds_a_disk_backed_handle_that_reports_stopped_for_a_missing_vm() {
        // Reattaching needs no boot state — it re-derives the state dir. A VM that
        // never ran (or has exited) reports Stopped rather than erroring.
        let vm = HvfDriver::new()
            .attach(&VmId("hvf-nonexistent-attach-test-vm".into()))
            .unwrap();
        assert_eq!(vm.id().0, "hvf-nonexistent-attach-test-vm");
        assert_eq!(vm.status().unwrap(), VmStatus::Stopped);
    }

    #[test]
    fn relay_config_wires_egress_relay_and_agent_leaves_substitution_none() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );
        let paths = sample_paths();
        let cfg = relay_supervisor_config(&spec, &paths).unwrap();

        assert_eq!(cfg.kernel, PathBuf::from("/img/Image"));
        assert_eq!(cfg.initramfs, Some(PathBuf::from("/img/initrd.cpio")));
        assert_eq!(
            cfg.egress_relay_socket,
            Some(PathBuf::from("/run/egress.sock"))
        );
        // The driver re-derives the agent bridge from the state dir (hvf-agent.sock)
        // and ignores the spec's backend-neutral agent hint (/run/agent.sock), so
        // the supervisor binds the exact path the host resolver probes.
        assert_eq!(cfg.agent_socket, Some(hvf_agent_socket(&paths.state_dir)));
        assert_ne!(cfg.agent_socket, Some(PathBuf::from("/run/agent.sock")));
        assert_eq!(cfg.substitution_socket, None);
        // No BROKER_PORT in this spec ⇒ no broker relay (unadmitted / builder).
        assert_eq!(cfg.broker_socket, None);
        assert!(cfg.vsock);
        // No blocks → no disks.
        assert!(cfg.disks.is_empty());
        // Empty spec cmdline ⇒ None (supervisor uses its workload default).
        assert_eq!(cfg.cmdline, None);
    }

    #[test]
    fn driver_agent_bind_path_equals_the_host_resolver_probe() {
        // The live regression this pins closed: the detached mvm-hvf-supervisor
        // binds the `agent_socket` the driver hands it, while the host reaches the
        // guest agent through DevConsoleTransport::for_vm / vm_hvf_agent_socket. If
        // those two ever name different sockets the guest agent is unreachable and
        // every RPC times out (the witness that caught the agent.sock/hvf-agent.sock
        // drift). Assert the exact bind path == the exact probe path for the same
        // VM so neither side can drift independently again.
        let name = "hvf-agent-socket-drift-guard-vm";
        let paths = SupervisorPaths::resolve(vm_state_dir(name), 0);
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );

        // What the supervisor binds: the agent socket the driver puts on the config.
        let cfg = relay_supervisor_config(&spec, &paths).unwrap();
        let binder = cfg
            .agent_socket
            .expect("hvf relay config must carry an agent socket");

        // What the host reaches the guest agent through.
        let resolver = mvm_core::config::vm_hvf_agent_socket(name);
        let transport = mvm_vmm::vsock_transport::DevConsoleTransport::for_vm(name)
            .socket_path(GUEST_AGENT_PORT);

        assert_eq!(
            binder, resolver,
            "supervisor bind path must equal the resolver"
        );
        assert_eq!(
            binder, transport,
            "supervisor bind path must equal the transport probe"
        );
        // The running-vm / attach handle re-derives via the same driver helper, so
        // vsock_connect(GUEST_AGENT_PORT) reaches the identical socket.
        assert_eq!(hvf_agent_socket(&paths.state_dir), resolver);
    }

    #[test]
    fn relay_config_wires_the_broker_relay_when_the_spec_carries_broker_port() {
        // An admitted workload's spec carries a BROKER_PORT channel; the
        // supervisor config must relay it so host.audit.v1 / host.secrets.v1
        // reach the broker. Absence ⇒ None (asserted above).
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
                broker_port("/run/broker.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.broker_socket, Some(PathBuf::from("/run/broker.sock")));
    }

    #[test]
    fn relay_config_threads_a_non_empty_cmdline_and_drops_an_empty_one() {
        // The builder rootfs boots a different PID 1 than the mkGuest workload
        // default, so its cmdline must reach the supervisor verbatim.
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        spec.cmdline = "  console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init  ".into();
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        // Trimmed, threaded verbatim.
        assert_eq!(
            cfg.cmdline.as_deref(),
            Some("console=ttyAMA0 root=/dev/vda ro init=/sbin/mvm-host-vm-init")
        );

        // A whitespace-only cmdline collapses to None (default applies).
        spec.cmdline = "   ".into();
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.cmdline, None);
    }

    #[test]
    fn relay_config_maps_blocks_to_disks_in_slot_order_carrying_ro_and_ephemeral() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![
                // Out of slot order, mixed flags — proves sorting + per-disk policy
                // pass through verbatim (a builder's persistent nix-store is
                // writable AND non-ephemeral).
                BlockDev {
                    source: "/img/nix-store.img".into(),
                    read_only: false,
                    ephemeral: false,
                    slot: 1,
                },
                BlockDev {
                    source: "/img/rootfs.ext4".into(),
                    read_only: true,
                    ephemeral: false,
                    slot: 0,
                },
            ],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.disks.len(), 2);
        // vda = slot 0: read-only rootfs, file-served.
        assert_eq!(cfg.disks[0].path, PathBuf::from("/img/rootfs.ext4"));
        assert!(cfg.disks[0].read_only);
        assert!(!cfg.disks[0].ephemeral);
        // vdb = slot 1: writable + persistent (not ephemeral) — writes hit the file.
        assert_eq!(cfg.disks[1].path, PathBuf::from("/img/nix-store.img"));
        assert!(!cfg.disks[1].read_only);
        assert!(!cfg.disks[1].ephemeral);
    }

    #[test]
    fn relay_config_trusted_builder_uses_the_same_egress_relay() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                agent_port("/run/agent.sock"),
                egress_port("/run/egress.sock"),
            ],
            vec![],
        );
        spec.trusted_builder = true;
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(
            cfg.egress_relay_socket,
            Some(PathBuf::from("/run/egress.sock"))
        );
    }

    #[test]
    fn only_a_trusted_builder_relays_trusted_builder_egress() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                agent_port("/run/agent.sock"),
                egress_port("/run/egress.sock"),
            ],
            vec![],
        );

        let workload = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert!(
            !workload.trusted_builder_egress,
            "a workload must stay rate-limited"
        );

        spec.trusted_builder = true;
        let builder = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert!(builder.trusted_builder_egress);
    }

    #[test]
    fn relay_config_without_egress_port_is_explicit_deny_all() {
        // No EGRESS_PORT is the explicit deny-all shape: the guest has no
        // host-side egress listener to reach, so it cannot acquire a path off
        // the box through this configuration.
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![agent_port("/run/agent.sock")],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).expect("deny-all shape");
        assert_eq!(cfg.egress_relay_socket, None);
    }

    #[test]
    fn relay_config_allows_a_channel_less_factory_parent() {
        let spec = spec_with(KernelImage::Path("/img/Image".into()), vec![], vec![]);
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.egress_relay_socket, None);
        assert!(cfg.agent_socket.is_some());
    }

    #[test]
    fn relay_config_threads_cpu_share_to_quota_scheduler() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        spec.cpu_grant = Some(CpuGrant::Share { millicores: 500 });
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.cpu_millicores, Some(500));
        assert_eq!(
            cfg.quota_record,
            Some(PathBuf::from("/state/w/vcpu_quota.json"))
        );
    }

    #[test]
    fn relay_config_leaves_quota_unset_for_fuel_and_no_grant() {
        let mut spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        spec.cpu_grant = Some(CpuGrant::Fuel {
            instructions: 1_000_000,
        });
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.cpu_millicores, None);
        assert_eq!(cfg.quota_record, None);

        spec.cpu_grant = None;
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.cpu_millicores, None);
        assert_eq!(cfg.quota_record, None);
    }

    #[test]
    fn relay_config_rejects_a_bundled_kernel() {
        // HVF has no bundled kernel; the spec must name an explicit Image.
        let spec = spec_with(
            KernelImage::Bundled,
            vec![egress_port("/run/egress.sock")],
            vec![],
        );
        assert!(relay_supervisor_config(&spec, &sample_paths()).is_err());
    }

    /// A multi-vCPU request reaches the supervisor rather than being refused.
    ///
    /// This backend used to bail here, because the VMM below described one CPU
    /// in the device tree whatever was asked for and answering a `CPU_ON` it
    /// could not honour would hang the boot. It creates the CPUs now, so the
    /// only correct thing to do with the count is pass it on — and passing it
    /// on is the whole fix, since the supervisor is the process that calls
    /// `hv_vcpu_create`.
    #[test]
    fn relay_config_carries_a_multi_vcpu_request_to_the_supervisor() {
        for requested in [1u32, 2, 4] {
            let mut spec = spec_with(
                KernelImage::Path("/img/Image".into()),
                vec![egress_port("/run/egress.sock")],
                vec![],
            );
            spec.vcpus = requested;

            let config = relay_supervisor_config(&spec, &sample_paths())
                .expect("a vCPU count this backend now honours must not be refused");

            assert_eq!(
                config.vcpus, requested,
                "the supervisor must be told the {requested} CPUs that were asked for"
            );
        }
    }

    #[test]
    fn vsock_connect_reaches_the_agent_socket_and_rejects_other_ports() {
        use mvm_vmm::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("hvf-agent.sock");
        // Stand-in for the supervisor's agent bridge: echo one byte back.
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut b = [0u8; 1];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });

        let vm = HvfRunningVm {
            id: VmId("agent-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join(PID_FILE_NAME),
            agent_socket: sock,
        };

        // The agent port connects + round-trips through the socket.
        let mut s = vm.vsock_connect(GUEST_AGENT_PORT).unwrap();
        s.write_all(b"x").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.join().unwrap();

        // Ports outside the agent port and the console data range are not host-dialable.
        assert!(vm.vsock_connect(GUEST_AGENT_PORT + 1).is_err());
    }

    #[test]
    fn running_vm_reads_the_supervisor_host_process() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join(PID_FILE_NAME);
        std::fs::write(&pid_file, "4242\n").unwrap();
        let vm = HvfRunningVm {
            id: VmId("measured-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file,
            agent_socket: dir.path().join("hvf-agent.sock"),
        };
        assert_eq!(vm.host_process_id(), Some(4242));
    }

    // --- console_socket_for_port ---

    #[test]
    fn console_socket_for_port_resolves_first_console_port() {
        let state = PathBuf::from("/state/vm");
        let got = console_socket_for_port(&state, 20001).unwrap();
        assert_eq!(got, PathBuf::from("/state/vm/vsock/vsock-20001.sock"));
    }

    #[test]
    fn console_socket_for_port_resolves_last_console_port() {
        let state = PathBuf::from("/state/vm");
        let got = console_socket_for_port(&state, 20128).unwrap();
        assert_eq!(got, PathBuf::from("/state/vm/vsock/vsock-20128.sock"));
    }

    #[test]
    fn console_socket_for_port_returns_none_for_out_of_range_ports() {
        let state = PathBuf::from("/state/vm");
        // CONSOLE_PORT_BASE itself is not a data port (data ports start at +1).
        assert!(console_socket_for_port(&state, 20000).is_none());
        // Beyond the 128-port cap.
        assert!(console_socket_for_port(&state, 20129).is_none());
        // Arbitrary unrelated port.
        assert!(console_socket_for_port(&state, 9999).is_none());
    }

    #[test]
    fn vsock_connect_console_port_resolves_to_vsock_subdir() {
        use mvm_vmm::test_support::bind_unix_listener;
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().unwrap();
        let vsock_dir = dir.path().join("vsock");
        std::fs::create_dir_all(&vsock_dir).unwrap();
        let sock = vsock_dir.join("vsock-20001.sock");
        let Some(listener) = bind_unix_listener(&sock) else {
            return;
        };
        let server = std::thread::spawn(move || {
            if let Ok((mut c, _)) = listener.accept() {
                let mut b = [0u8; 1];
                if c.read_exact(&mut b).is_ok() {
                    let _ = c.write_all(&b);
                }
            }
        });

        let vm = HvfRunningVm {
            id: VmId("console-vm".into()),
            state_dir: dir.path().to_path_buf(),
            pid_file: dir.path().join(PID_FILE_NAME),
            agent_socket: dir.path().join("hvf-agent.sock"),
        };

        // Port 20001 (first console data port) connects via the vsock subdir.
        let mut s = vm.vsock_connect(20001).unwrap();
        s.write_all(b"y").unwrap();
        let mut got = [0u8; 1];
        s.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"y");
        server.join().unwrap();

        // A port outside both the agent and console ranges still bails.
        assert!(vm.vsock_connect(9999).is_err());
    }

    // --- relay_supervisor_config: console_data_sockets ---

    fn console_vsock_port(port: u32, uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::ConsoleData { port },
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    #[test]
    fn relay_config_copies_console_ports_into_console_data_sockets() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
                console_vsock_port(20001, "/state/vsock/vsock-20001.sock"),
                console_vsock_port(20002, "/state/vsock/vsock-20002.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert_eq!(cfg.console_data_sockets.len(), 2);
        assert_eq!(cfg.console_data_sockets[0].guest_port, 20001);
        assert_eq!(
            cfg.console_data_sockets[0].host_socket,
            PathBuf::from("/state/vsock/vsock-20001.sock")
        );
        assert_eq!(cfg.console_data_sockets[1].guest_port, 20002);
    }

    #[test]
    fn relay_config_produces_empty_console_data_sockets_when_none_in_spec() {
        // Sealed prod: spec carries only the three standing ports, no console entries.
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert!(cfg.console_data_sockets.is_empty());
        // The same spec must not acquire builder control ports either.
        assert!(cfg.builder_control_sockets.is_empty());
    }

    fn builder_dispatch_port(uds: &str) -> VsockPort {
        VsockPort {
            service: GuestService::BuilderDispatch,
            host_uds: uds.into(),
            direction: VsockDirection::HostDials,
        }
    }

    #[test]
    fn relay_config_copies_builder_ports_into_builder_control_sockets() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                builder_dispatch_port("/run/vsock-21471.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();

        assert_eq!(cfg.builder_control_sockets.len(), 1);
        assert_eq!(
            cfg.builder_control_sockets[0].guest_port,
            GuestService::BuilderDispatch.port()
        );
        assert_eq!(
            cfg.builder_control_sockets[0].host_socket,
            PathBuf::from("/run/vsock-21471.sock")
        );
        // A builder port is not a console port; the two lists stay disjoint.
        assert!(cfg.console_data_sockets.is_empty());
    }

    #[test]
    fn a_workload_spec_never_yields_builder_control_sockets() {
        // The security-relevant direction: only a spec that names a
        // builder-tier service gets a listener on the build engine's ports.
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
                broker_port("/run/broker.sock"),
            ],
            vec![],
        );
        let cfg = relay_supervisor_config(&spec, &sample_paths()).unwrap();
        assert!(cfg.builder_control_sockets.is_empty());
    }

    /// Same contract as every other driver: the bound rides on the spawn.
    #[test]
    fn a_granted_share_wraps_the_supervisor_spawn() {
        let scratch = tempfile::tempdir().expect("scratch");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        mvm_core::cpu_scope::pretend_mechanism_present(&mut env, scratch.path())
            .expect("fake mechanism");

        let mut spec = spec_with(KernelImage::Bundled, vec![], vec![]);
        spec.cpu_grant = Some(mvm_contract::grants::CpuGrant::Share { millicores: 500 });
        let cmd = bounded_supervisor_command(
            Path::new("/usr/bin/mvm-hvf-supervisor"),
            &spec,
            scratch.path(),
        );
        let argv = mvm_core::cpu_scope::rendered_argv(&cmd);

        assert_eq!(argv[0], "systemd-run");
        assert!(argv.contains(&"CPUQuota=50%".to_string()), "{argv:?}");
        assert_eq!(argv.last().expect("payload"), "/usr/bin/mvm-hvf-supervisor");
    }

    #[test]
    fn hvf_spec_carries_exactly_one_network_flow_and_no_l3() {
        let spec = spec_with(
            KernelImage::Path("/img/Image".into()),
            vec![
                egress_port("/run/egress.sock"),
                agent_port("/run/agent.sock"),
            ],
            vec![],
        );
        let ports = &spec.vsock;
        let mut services: Vec<_> = ports.iter().map(|p| p.service).collect();
        services.sort();
        let expected = [GuestService::MachineControl, GuestService::NetworkFlow];
        assert_eq!(
            services, expected,
            "HVF spec vsock must contain exactly one NetworkFlow and no retired L3 services"
        );
    }
}
