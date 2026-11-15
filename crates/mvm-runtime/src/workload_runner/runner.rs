//! The driver-generic workload start mechanics. `WorkloadRunner` spawns the
//! per-VM host-side gating endpoint, maps the admitted config onto a `VmmSpec`,
//! and boots it through the `VmmDriver` seam — once, over the seam, instead of
//! copied into each backend's `start`. The endpoint spawn is itself behind the
//! `NetworkEndpointSpawner` trait so the runner is unit-testable with no real VM and no
//! real endpoint process.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mvm_core::checkpoint::CheckpointId;
use mvm_core::config::{vm_network_endpoint_socket, vm_state_dir, vms_dir};
use mvm_core::crypto::vmgenid::fresh_generation_token;
use mvm_core::plan::{ExecutionPlan, SecretBinding};
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::protocol::broker::ServiceId;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, HostDialRoute, StandbyClaim,
    StandbyError, StandbyHandle, StandbySpec, StartMode, VmBackend, VmCapabilities, VmExitStatus,
    VmId, VmInfo, VmStartConfig, VmStatus,
};
use mvm_fs::snapshot_store::FsSnapshotStore;

use crate::checkpoint::{
    CaptureVmFullParams, CheckpointChainAnchor, CheckpointStore, VmFullControl,
    capture_vm_full_into_snapshot_store, capture_vm_full_to_trusted_snapshot_backend,
    ensure_child_grants_within_parent, materialized_blob_sha256,
};
use crate::driver::{
    ChildForkRequest, PreloadChildRequest, RunningVm, RunningVmStopTiming, StandbyParentSpawn,
    VmmDriver,
};
use crate::standby_pool::SupervisorStandbyPool;
use crate::vm::name_registry::{VmNameRegistry, acquire_registry_lock, generate_vm_name};
use crate::warm_snapshot::{
    is_trusted_snapshot_id, materialize_child_from_parent, materialize_child_from_trusted_parent,
};
use crate::workload_backend::{EgressSubstitutionTransport, WorkloadBackend};
use crate::workload_runner::child_grant::{ChildGrantIssuer, issue_child_grant};
use crate::workload_runner::claim::{
    ClaimGuards, ClaimRefusal, EndpointSpawnInputs, bind_claim_policy_to_plan,
    bind_plan_to_parent_digest, claim_parent_grant_bound, ensure_child_grants_within_host_ceiling,
};
use crate::workload_runner::standby_boot::{factory_parent_config, slotted_factory_parent_spec};
use mvm_vmm::host::cmdline;
use mvm_vmm::host::egress_shared::{decode_plan_secrets_from_state, plan_stream_retention};
use mvm_vmm::host::network_endpoint_spawn::{
    EndpointTransport, SubstitutionSpawnParams, spawn_network_endpoint,
};
use mvm_vmm::host::spec_map::{WorkloadSpecInputs, workload_spec, workload_vsock_ports};
use mvm_vmm::post_restore::{ChildIdentity, PostRestoreOutcome};

mod admission;
mod backend;
mod broker;
mod claim_lease;
mod claim_standby;
mod claim_tests;
mod cold_hvf_channel;
mod console_boot;
mod durability;
mod parent_verify;
mod preload;
mod refusal;
mod sockets;
mod spawner;
mod standby;
mod standby_tests;
mod start;
mod start_tests;
mod test_support;
mod warm_claim;

pub use cold_hvf_channel::{ColdHvfChannel, NativeCompletion, OwnedRuntimeLaunch};

struct PreparedWorkloadBoot {
    spec: mvm_vmm::driver::spec::VmmSpec,
    socks: sockets::StandingSockets,
    endpoint: crate::workload_runner::claim::EndpointHandle,
    trace: Option<mvm_core::launch_trace::LaunchTraceRecorder>,
}

pub use super::console_stream::{ConsoleCapture, ConsoleStreamer, NoopConsoleStreamer};
pub use broker::{BrokerGuard, BrokerRegisterRequest, BrokerRegistrar, RealBrokerRegistrar};
use claim_lease::WarmClaimLease;
use console_boot::supervisor_owns_console;
use parent_verify::{reserve_and_verify_parent, schedule_resident_checkpoint_reclaim};
use refusal::{
    admitted_seccomp_tier, refuse, require_admitted_seccomp_tier, require_fresh_child_identity,
    require_late_volumes_mounted,
};
use sockets::{gpu_endpoint_transport, standing_sockets};
pub use spawner::{
    FlowMuxIdentitySource, NetworkEndpointSpawnRequest, NetworkEndpointSpawner,
    RealNetworkEndpointSpawner, SpawnedEndpoint, TelemetryStart,
};
/// Everything the runner needs to start a workload: the admitted launch config,
/// its tenant/secrets/redaction/policy, and the kernel cmdline the role above
/// assembled.
pub struct WorkloadLaunchInputs<'a> {
    pub config: &'a VmStartConfig,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    pub cmdline: String,
}

/// The warm-pool substrate a claim needs beyond the runner's cold-boot fields.
/// Cold boot never carries it, so it is a per-claim context rather than a runner
/// field: the standby pool, the content-addressed checkpoint + snapshot stores,
/// the signed-audit anchor, and the parent's identity a guarded fork consumes.
/// Everything a claim materializes or verifies is reached through here, so a
/// runner constructed for cold boot alone stays unchanged.
pub struct ClaimContext<'a> {
    /// Standby pool the parent is reserved in (marked `Claimed` under the lock).
    pub pool: &'a SupervisorStandbyPool,
    /// Content-addressed checkpoint store the parent + its lineage live in.
    pub checkpoints: &'a CheckpointStore,
    /// Snapshot store backing the O(1) copy-on-write child materialize.
    pub snapshots: &'a FsSnapshotStore,
    /// Resolves each checkpoint's signature-verified creation digest for saved-
    /// state claims. Resident HVF claims use their signed snapshot manifest and
    /// do not load the growing audit chain on the launch path.
    pub anchor: &'a dyn CheckpointChainAnchor,
    /// The content-addressed checkpoint the standby parent was captured as.
    pub parent_checkpoint: &'a CheckpointId,
    /// VM name registry file whose sibling lock serializes the parent reserve
    /// and the child-name mint, so two claims never double-claim one parent.
    pub registry_path: &'a Path,
    /// Host signing authority invoked only after the runner has minted the
    /// final child identity. Grant-less test contexts may omit it; a plan that
    /// requests agent verbs fails closed when it is absent.
    pub grant_issuer: Option<&'a dyn ChildGrantIssuer>,
}

/// The warm-pool substrate a spawn-and-capture needs beyond the runner's
/// cold-boot fields: the checkpoint store the parent is captured into, and the
/// launch whose boot shape the parent must mirror.
pub struct SpawnContext<'a> {
    /// Content-addressed checkpoint store the captured parent is written to.
    pub checkpoints: &'a CheckpointStore,
    /// The already-resolved launch config the parent is being warmed for — the
    /// same value the workload boot consumes, so the parent inherits whatever
    /// the layer above resolved for it (notably the verity-sealed runtime
    /// overlay carrying the guest agent). `None` when the caller is warming the
    /// pool ahead of any launch, which the spawn refuses: a parent has no boot
    /// shape of its own to fall back on.
    pub launch: Option<&'a VmStartConfig>,
}

/// Verified publication inputs used to prepare a paused child during pool
/// refill. The parent has already been audited by the caller, so this context
/// can perform the same content and lineage checks as a claim before cloning.
pub struct PreloadContext<'a> {
    /// Content-addressed checkpoint store containing the captured parent.
    pub checkpoints: &'a CheckpointStore,
    /// Snapshot store backing the copy-on-write child materialization.
    pub snapshots: &'a FsSnapshotStore,
    /// Signed audit anchor for the parent's creation entry.
    pub anchor: &'a dyn CheckpointChainAnchor,
    /// VM-name registry lock source used to avoid colliding with user VMs.
    pub registry_path: &'a Path,
}

/// Starts workloads over the `VmmDriver` seam: spawn the per-VM gating endpoint,
/// map the config to a `VmmSpec`, boot via the driver.
pub struct WorkloadRunner<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> {
    driver: D,
    spawner: S,
    broker: B,
    console_streamer: Arc<dyn ConsoleStreamer>,
}

/// Timings for the shared workload-runner stop sequence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopTiming {
    /// Time to reconstruct the live driver handle.
    pub attach: Duration,
    /// Time to reap host-side endpoint and service processes.
    pub endpoint_reaping: Duration,
    /// Time spent in the backend driver termination operation.
    pub driver_kill: Duration,
    /// Time to stop console streaming for the VM.
    pub console_cleanup: Duration,
    /// Total elapsed time for the complete stop sequence.
    pub total: Duration,
    /// Backend-specific detail, when the driver can observe its termination
    /// phases. HVF reports supervisor and PID-file teardown here.
    pub driver_detail: Option<RunningVmStopTiming>,
}

/// Append one kernel-cmdline token, space-separated only when the cmdline is
/// already non-empty: a token on an empty cmdline must not carry a leading
/// space, which the guest's `/init` would read as an empty argument.
fn append_cmdline_token(boot_cmdline: &mut String, token: &str) {
    if !boot_cmdline.is_empty() {
        boot_cmdline.push(' ');
    }
    boot_cmdline.push_str(token);
}

/// The trusted-snapshot backend is opt-in: only the exact value `1` enables it.
fn trusted_snapshot_opted_in(value: Option<&str>) -> bool {
    value == Some("1")
}

impl<D: VmmDriver, S: NetworkEndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    /// Build a runner over the process's registered console-streaming hook.
    ///
    /// Every production construction site goes through here and none of them
    /// passes a streamer, so picking the hook up from the process registration
    /// is what makes console capture reach all four backends at once — see
    /// [`console_stream`](super::console_stream) for why the wiring is a
    /// registration rather than an argument.
    pub fn new(driver: D, spawner: S, broker: B) -> Self {
        Self {
            driver,
            spawner,
            broker,
            console_streamer: super::console_stream::active_console_streamer(),
        }
    }

    /// Override the console-streaming hook for this runner alone, ignoring
    /// whatever the process registered. The seam a test drives its own double
    /// through; production wires the real streamer once at startup instead.
    #[must_use]
    pub fn with_console_streamer(mut self, streamer: Arc<dyn ConsoleStreamer>) -> Self {
        self.console_streamer = streamer;
        self
    }

    /// Whether this runner can keep a saved child VMM paused across claims.
    #[must_use]
    pub fn supports_preloaded_standby(&self) -> bool {
        self.driver.supports_preloaded_standby()
    }

    /// How many read-only volumes a claim on this runner's parents can attach.
    #[must_use]
    pub fn late_volume_slots(&self) -> u8 {
        self.driver.late_volume_slots()
    }

    /// Pause/save-memory/resume control over a running VM this runner's VMM
    /// owns — what a checkpoint capture drives. `None` when the VMM has no
    /// memory-capture mechanics to offer.
    #[must_use]
    pub fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn VmFullControl>> {
        self.driver.vm_full_control(vm_name)
    }

    /// Backend-shaped guest→host channel for the GPU endpoint. QEMU's
    /// vhost-vsock lets the endpoint bind the real port directly; every other
    /// tier proxies the guest dial to a per-VM UDS.
    fn gpu_endpoint_transport(
        kind: mvm_core::vm_backend::BackendKind,
        state_dir: &std::path::Path,
    ) -> mvm_vmm::host::network_endpoint_spawn::EndpointTransport {
        gpu_endpoint_transport(kind, state_dir)
    }

    /// Spawn the optional gating endpoint, compose the spec, and boot. A
    /// secret-free deny-all workload has no egress capability and therefore
    /// carries no endpoint process or guest egress channel.
    pub fn start_workload(&self, inputs: &WorkloadLaunchInputs<'_>) -> Result<Box<dyn RunningVm>> {
        self.start_workload_custodied(inputs, Vec::new())
    }

    /// Start with original writable-image custody, consumed only at final binding.
    pub fn start_workload_custodied(
        &self,
        inputs: &WorkloadLaunchInputs<'_>,
        writable_images: mvm_vmm::driver::prepared_disks::WritableVolumeImages,
    ) -> Result<Box<dyn RunningVm>> {
        self.start_workload_custodied_with_release(inputs, writable_images, None)
    }
}
