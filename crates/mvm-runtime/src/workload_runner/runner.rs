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

use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::config::{vm_network_endpoint_socket, vm_state_dir, vms_dir};
use mvm_core::crypto::vmgenid::fresh_generation_token;
use mvm_core::plan::{ExecutionPlan, SecretBinding, StreamRetention};
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::protocol::broker::ServiceId;
use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, StandbyClaim, StandbyError,
    StandbyHandle, StandbySpec, StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo,
    VmStartConfig, VmStatus,
};
use mvm_fs::snapshot_store::{FsSnapshotStore, SnapshotStore};

use crate::checkpoint::{
    CaptureVmFullParams, CheckpointChainAnchor, CheckpointStore, VmFullControl,
    capture_vm_full_with_snapshot_store, capture_vm_full_with_trusted_snapshot_backend,
    ensure_child_grants_within_parent, verify_content, verify_lineage,
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
    ClaimGuards, ClaimRefusal, EndpointSpawnInputs, bind_plan_to_parent,
    ensure_child_grants_within_host_ceiling, parent_rootfs_digest,
};
use crate::workload_runner::standby_boot::{factory_parent_config, factory_parent_spec};
use mvm_vmm::host::cmdline;
use mvm_vmm::host::egress_shared::{decode_plan_secrets_from_state, plan_stream_retention};
use mvm_vmm::host::network_endpoint_spawn::{
    EndpointTransport, SubstitutionSpawnParams, reap_network_endpoint, spawn_network_endpoint,
};
use mvm_vmm::host::spec_map::{
    WorkloadSpecInputs, ensure_no_dir_share_volumes, workload_spec, workload_vsock_ports,
};
use mvm_vmm::post_restore::PostRestoreOutcome;

mod admission;
mod backend;
mod broker;
mod console_boot;
mod refusal;
mod sockets;
mod spawner;
mod warm_claim;

use admission::{admitted_ingress, admitted_network_limits};
pub use broker::RealBrokerRegistrar;
use refusal::{map_lineage_refusal, refuse, require_fresh_child_identity};
use sockets::standing_sockets;
pub use spawner::{
    FlowMuxIdentitySource, NetworkEndpointSpawnRequest, NetworkEndpointSpawner,
    RealNetworkEndpointSpawner, SpawnedEndpoint,
};
/// What the runner needs to register the per-VM host-services broker after boot.
pub struct BrokerRegisterRequest<'a> {
    /// VM name — the registration's `vm_id`, workload id, and per-VM chain key.
    pub vm_name: &'a str,
    /// Per-VM state dir (audit-signer pid/sock + the daemon tenant-ref marker).
    pub state_dir: &'a Path,
    /// Tenant from the admitted plan. `None` ⇒ unadmitted ⇒ a defused no-op:
    /// no broker services and no BROKER_PORT in the spec, so a stray guest dial
    /// stays `ECONNREFUSED` (fail-closed).
    pub tenant: Option<&'a str>,
    /// The `BROKER_PORT` socket the broker/daemon binds — the same path the spec
    /// wires the guest's `BROKER_PORT` relay to. `None` on the unadmitted path.
    pub broker_listen_socket: Option<&'a Path>,
    /// Host services from the admitted plan. Empty means no broker process is
    /// needed and every broker call remains fail-closed.
    pub services: &'a [ServiceId],
    /// Exact typed capabilities carried by admitted extension bindings.
    pub capability_bindings: &'a [mvm_contract::protocol::agent_capability::CapabilityBinding],
    /// Controller-backed typed services prepared by the admitting process.
    pub service_proxies: &'a [mvm_contract::protocol::broker_control::ServiceProxyBinding],
}

/// Register/spawn the per-VM host-services broker for an admitted workload,
/// returning a guard whose Drop reaps until defused. The claims-12/13 seam:
/// Admitted host services reach the guest over `BROKER_PORT`. Behind a trait so
/// the runner is unit-testable with no real broker subprocess.
pub trait BrokerRegistrar: Send + Sync {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard>;
}

/// RAII guard around the registered broker services: Drop reaps them until the
/// VM is confirmed up and `defuse`d (the `stop` path then owns teardown). Wraps
/// the existing `ServicesGuard` so no reaping logic is duplicated.
pub struct BrokerGuard(mvm_vmm::host::host_agent_spawn::ServicesGuard);

impl BrokerGuard {
    pub(crate) fn from_services_guard(
        guard: mvm_vmm::host::host_agent_spawn::ServicesGuard,
    ) -> Self {
        Self(guard)
    }

    /// A guard that reaps nothing on drop — the unadmitted / spawn-failed path.
    fn defused() -> Self {
        Self(mvm_vmm::host::host_agent_spawn::ServicesGuard::None)
    }

    /// Disarm: the VM is up; the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.0.defuse();
    }

    /// Whether the launch came up with the host services it asked for.
    ///
    /// The guard alone cannot answer this. It records only whether anything was
    /// registered, which is the same `false` for a workload that bound no
    /// service as for one whose registration was skipped — `requested` is what
    /// separates them. Judging on the guard alone marks every workload that
    /// binds no host service as degraded, and a degraded launch is refused as a
    /// sample of a healthy one.
    #[must_use]
    pub fn services_healthy(&self, requested: &[ServiceId]) -> bool {
        requested.is_empty() || self.0.is_registered()
    }
}

/// Republishes a workload's console capture (`<state_dir>/console.log`,
/// write-only, written by every backend before the guest agent can say
/// anything) into the per-VM output-stream broker — so a guest that panics
/// on boot, fails dm-verity, or OOMs its agent still leaves a stream instead
/// of an empty one.
///
/// A hook, not a direct call: the broker this republishes into is owned by
/// the resident per-tenant daemon, which sits *above* this crate in the
/// dependency graph (the daemon depends on the runtime, never the other way
/// around), so this crate cannot name that broker's type. Same shape as
/// [`NetworkEndpointSpawner`] and [`BrokerRegistrar`] just above — both exist to
/// solve exactly this "the runtime needs the resident daemon to do
/// something" problem — and, like the ordinary `VmBackend` methods this
/// trait's two calls sit beside, `start`/`stop` are independent entry points
/// keyed by `vm_name` rather than a value threaded between them: a `start`
/// during `up` and the matching `stop` commonly run in different process
/// invocations against the same disk-backed VM state, so nothing here can
/// rely on an in-process object outliving the call that created it.
///
/// **Unconditional.** Unlike [`BrokerRegistrar`] (an unrelated, same-named
/// host-services broker for `host.audit.v1`/`host.secrets.v1`), this is never
/// gated on tenant admission. An unadmitted local run is exactly the case
/// with the fewest other ways to see a boot failure, so it must not lose
/// console capture either.
pub trait ConsoleStreamer: Send + Sync {
    /// Start capturing one workload's output. Best-effort: a real
    /// implementation logs and continues on failure rather than failing a
    /// workload boot over an observability feature.
    fn start(&self, capture: &ConsoleCapture<'_>);

    /// Stop following `vm_name`'s console, if anything started one.
    /// Idempotent — a no-op for a VM whose console was never followed,
    /// matching every other per-VM reaper `WorkloadRunner::stop` already
    /// calls unconditionally.
    fn stop(&self, vm_name: &str);
}

/// One workload's console capture: which VM, which file, the redaction policy
/// its recorded output is cleared under, and whether that output is kept.
///
/// The policy rides along rather than being resolved on the far side because
/// it is the *launch's* policy — the same value this call's caller already
/// handed the substitution endpoint. A capture that picked its own would give
/// one answer on egress and a different one in the transcript.
///
/// The retention mode rides along for the same reason and one more: it comes
/// off the *signed plan*, so a streamer that read it from anywhere else would
/// be honouring something nobody admitted.
pub struct ConsoleCapture<'a> {
    pub vm_name: &'a str,
    /// The write-only capture file the backend is already writing.
    pub console_log: &'a Path,
    pub redaction: &'a RedactionPolicy,
    /// Whether the admitted plan asked for a durable transcript. Capture and
    /// live fan-out happen either way; this decides only what outlives the run.
    pub retention: StreamRetention,
}

/// The hook a process that registered no real streamer gets: console bytes
/// keep going to the write-only capture file on disk and nothing republishes
/// them. An embedder driving this crate as a library, and every unit test
/// that does not care about output capture, land here.
pub struct NoopConsoleStreamer;

impl ConsoleStreamer for NoopConsoleStreamer {
    fn start(&self, _capture: &ConsoleCapture<'_>) {}
    fn stop(&self, _vm_name: &str) {}
}

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

    /// Pause/save-memory/resume control over a running VM this runner's VMM
    /// owns — what a checkpoint capture drives. `None` when the VMM has no
    /// memory-capture mechanics to offer.
    #[must_use]
    pub fn vm_full_control(&self, vm_name: &str) -> Option<Box<dyn VmFullControl>> {
        self.driver.vm_full_control(vm_name)
    }

    /// Spawn the optional gating endpoint, compose the spec, and boot. A
    /// secret-free deny-all workload has no egress capability and therefore
    /// carries no endpoint process or guest egress channel.
    pub fn start_workload(&self, inputs: &WorkloadLaunchInputs<'_>) -> Result<Box<dyn RunningVm>> {
        // Fail closed before any side effect (endpoint spawn) runs: a
        // `DirShare` volume has no `VmmSpec` representation on this driver
        // seam, so refuse it here rather than silently dropping it later in
        // `workload_blocks`.
        // No driver serves a live directory share any more: a `--mount` is
        // materialized into an image before it reaches here. A volume still
        // asking to be shared is one nothing materialized, and it must refuse
        // rather than be dropped — a workload booting without its mount is
        // worse than one that will not boot.
        ensure_no_dir_share_volumes(inputs.config)?;

        // A caller times this call from outside and cannot see past it, yet the
        // VMM boot and every post-boot registration happen in here. Off unless
        // a measurement asked for it.
        let mut trace =
            mvm_core::launch_trace::LaunchTraceRecorder::new(self.driver.kind().as_str());

        let state_dir = vm_state_dir(&inputs.config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;
        let network_limits = admitted_network_limits(inputs.config.plan_json.as_deref())?;
        let ingress = admitted_ingress(inputs.config.plan_json.as_deref())?;

        // Spawn the per-child substitution endpoint through the shared
        // `ClaimGuards`, so a warm claim stands up the identical guarded endpoint
        // a cold boot does, keyed on this VM's own id. A deny-all, secret-free
        // workload receives no egress channel and therefore needs no process.
        let guards = ClaimGuards::new(&self.spawner);
        let mut endpoint = guards.spawn_endpoint(
            &VmId(inputs.config.name.clone()),
            &EndpointSpawnInputs {
                state_dir: &state_dir,
                tenant: inputs.tenant,
                secrets: inputs.secrets,
                redaction: inputs.redaction,
                network_policy: inputs.network_policy,
                network_limits,
                ingress: &ingress,
                // A cold boot mints this guest's identity and hands it a drive.
                identity: FlowMuxIdentitySource::Mint,
            },
        )?;
        trace.mark("endpoint_spawn");

        let socks = standing_sockets(&state_dir, inputs.config);
        let spec = workload_spec(&WorkloadSpecInputs {
            config: inputs.config,
            identity_drive: endpoint.identity_drive(),
            sockets: socks.with_egress(endpoint.egress_uds()),
            cmdline: inputs.cmdline.clone(),
            console_log: socks.console_log.clone(),
        });

        trace.mark("spec_assembly");

        // Unconditional and best-effort. The follower can wait for a console
        // file that does not exist yet, so install it alongside VMM boot rather
        // than serializing its process setup after guest readiness.
        let capture = ConsoleCapture {
            vm_name: &inputs.config.name,
            console_log: &socks.console_log,
            redaction: inputs.redaction,
            retention: plan_stream_retention(inputs.config.plan_json.as_deref()),
        };
        let streamer = Arc::clone(&self.console_streamer);
        let vm = console_boot::boot_while_starting_console(
            || self.driver.boot(&spec),
            || streamer.start(&capture),
            || trace.mark("driver_boot"),
        )?;
        trace.mark("console_stream_start");

        // Universal initramfs path: the guest PID-1 agent waits for a signed
        // ActivateEnvironment before exposing operational RPCs. Send it now,
        // while the broker registration below still has a guard that rolls back
        // on failure. A legacy per-rootfs verity initramfs (cold universal
        // cache) keeps its own PID 1 and is never sent this verb.
        if crate::microvm::booted_with_universal_initramfs(inputs.config) {
            crate::microvm::activate_workload(&*vm, inputs.config)
                .context("activate workload after boot")?;
        }
        trace.mark("activate_workload");

        // Register the per-VM broker for the exact admitted host-service set.
        // The guard's Drop reaps on any early return until it is defused. A
        // requested service whose broker cannot start fails the launch closed.
        let (services, capability_bindings) =
            admitted_broker_bindings(inputs.config.plan_json.as_deref())?;
        let mut broker_guard = self.broker.register(&BrokerRegisterRequest {
            vm_name: &inputs.config.name,
            state_dir: &state_dir,
            tenant: inputs.config.tenant_id.as_deref(),
            broker_listen_socket: socks.broker.as_deref(),
            services: &services,
            capability_bindings: &capability_bindings,
            service_proxies: &inputs.config.service_proxies,
        })?;
        endpoint.defuse();
        broker_guard.defuse();
        trace.mark("broker_register");
        trace.degrade_unless("host_services", broker_guard.services_healthy(&services));
        trace.write_to(&state_dir);
        Ok(vm)
    }

    /// Fork a clean standby parent into a fresh, admitted child, gated exactly as
    /// strictly as a cold boot — the guarded heart of the warm pool.
    ///
    /// Runs the fail-closed sequence in order, cloning or booting nothing until
    /// every gate passes: reserve the parent atomically and verify its sealed
    /// content + signed-audit lineage; bind the already-admitted plan's image
    /// digest to that verified parent (so the audit-recorded plan describes
    /// exactly what boots); mint a fresh, registry-unique identity; materialize
    /// the child's rootfs from the parent's own verified content; run the
    /// host-side overlay-contract gate, spawn the child's own 0700 substitution
    /// endpoint keyed on its fresh id, resolve its host channel set and register
    /// its host-services broker; then fork the VMM, start following its console
    /// (the only channel that would show a hang or panic inside the handshake
    /// window that follows), and require the restored guest to prove it adopted
    /// a fresh VMGenID before the claim commits, so the child's CSPRNG diverges
    /// from the parent's.
    ///
    /// The host-side plumbing is deliberately all on the near side of the fork.
    /// A cold boot has a kernel boot between wiring its channels and the guest
    /// dialing them; a restore has nothing — the guest comes back already booted
    /// and runs the moment the fork resumes it. Anything wired afterwards would
    /// be wired against a guest already dialing sockets that do not exist.
    ///
    /// Layering the runner does NOT own (enforced at their own layers, mirroring
    /// a cold boot): claim-8 admission of the child plan (CLI mint + supervisor
    /// re-verify at attach), dm-verity inherit (CLI populates the child config),
    /// per-service confinement (guest init, inherited via the post-init parent
    /// snapshot), and the `plan.launched` chain emit (the CLI audit layer, which
    /// owns the host signer). The runner receives the admitted plan and the
    /// verity-populated config in `claim` and consumes them.
    pub fn claim_standby(
        &self,
        ctx: &ClaimContext<'_>,
        handle: &StandbyHandle,
        claim: &StandbyClaim,
    ) -> std::result::Result<VmId, StandbyError> {
        use std::io::Write;

        let claim_started = Instant::now();
        let mut claim_debug = std::env::var_os("MVM_HVF_AGENT_DEBUG").and_then(|path| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .ok()
        });
        macro_rules! claim_phase {
            ($phase:expr) => {
                warm_claim::record_phase(claim_started, &mut claim_debug, $phase);
            };
        }
        let resident_handoff = self.driver.supports_resident_handoff();
        // (1) Reserve the parent atomically, then verify it — before any clone.
        // Resident HVF claims use the signed bundle manifest as their O(1)
        // publication witness; saved-state claims retain full content hashing.
        let parent = reserve_and_verify_parent(ctx, handle, resident_handoff)?;
        claim_phase!("parent_verified");

        // The parent is now reserved (`Claimed`) and verified healthy. Arm the
        // release-unless-committed guard: any early return past this point returns
        // the good parent to claimable (so a failed claim never strands warm
        // capacity) and removes a partial child dir. Only a booted child commits.
        let preloaded_child_name = handle.preloaded_child_vm_name.clone();
        let mut cleanup = WarmClaimLease::new(ctx.pool, handle.id.as_str(), &self.driver);

        // (2) + (4) Bind the admitted plan's image digest to the verified parent.
        // A missing plan or a digest mismatch refuses before any child side effect.
        let plan = claim_plan(claim)?;
        bind_plan_to_parent(&plan.image.sha256, &parent).map_err(refuse)?;
        // The same comparison a vm_full fork makes, against the same
        // chain-verified parent record and through the same predicate. A warm
        // claim restores a child out of a parent's saved memory exactly as a
        // fork does, so it must not be the one restore path where a child can
        // ask for more than its parent held. Placed beside the image-digest
        // bind — both bind the admitted plan to this verified parent — and
        // before the child gets an identity, a state dir, or any bytes.
        ensure_child_grants_within_parent(plan.grants.as_ref(), parent.grants.as_ref()).map_err(
            |e| {
                refuse(ClaimRefusal::GrantsExceedParent {
                    reason: e.to_string(),
                })
            },
        )?;
        // A standby parent carries no grant, so the comparison above has
        // nothing to bind a claimed child's CPU share against and would admit
        // any share at all. The host's own ceiling is what bounds it instead —
        // the same operator-configured maximum every cold boot on this host
        // clears, read from host config rather than from the plan being
        // admitted. It is a host-wide maximum and not a pool-specific grant, so
        // it bounds a claim no more tightly than it bounds anything else here;
        // it is only stronger than the unbounded claim it replaces.
        //
        // Deliberately after the parent has been matched and reserved rather
        // than part of the pool's compatibility key: keying on a grant value
        // would split one pool into a pool per distinct share and cost the warm
        // hit rate the pool exists for. The price is a claim that matches and is
        // then refused, so the refusal names the ceiling and the request.
        ensure_child_grants_within_host_ceiling(
            plan.grants.as_ref(),
            &mvm_core::user_config::load(None).grant_ceiling(),
        )
        .map_err(refuse)?;

        // (6a) Fresh, registry-unique identity for the child.
        let child = match preloaded_child_name.clone() {
            Some(name) => {
                verify_preloaded_child_name_is_available(ctx, &name)?;
                VmId(name)
            }
            None => fresh_child_id(ctx)?,
        };
        let child_dir = vm_state_dir(&child.0);
        // Track it before creating or materializing anything so even a partial
        // claim is cleaned up.
        cleanup.track_child_dir(child_dir.clone());
        if preloaded_child_name.is_some() {
            cleanup.track_preloaded_child(child.0.clone());
        }

        // (3) A resident handoff transfers the already-paused HVF machine and
        // creates only the fresh child state directory. Saved-state backends
        // still materialize the verified parent content before restoring.
        let child_rootfs_dir = if resident_handoff {
            std::fs::create_dir_all(&child_dir).map_err(|e| {
                StandbyError::ClaimFailed(format!(
                    "create resident HVF child state {}: {e}",
                    child_dir.display()
                ))
            })?;
            resident_parent_rootfs_dir(handle.id.as_str())?
        } else if preloaded_child_name.is_some() {
            child_dir.clone()
        } else {
            let materialize =
                if is_trusted_snapshot_id(parent.snapshot_id.as_deref().unwrap_or_default()) {
                    let backend = mvm_fs::trusted_snapshot::platform_backend(ctx.snapshots.root())
                        .map_err(|e| {
                            StandbyError::ClaimFailed(format!("open trusted snapshot backend: {e}"))
                        })?;
                    materialize_child_from_trusted_parent(
                        ctx.checkpoints,
                        backend.as_ref(),
                        ctx.parent_checkpoint,
                        ctx.anchor,
                        &child_dir,
                    )
                } else {
                    materialize_child_from_parent(
                        ctx.checkpoints,
                        ctx.snapshots,
                        ctx.parent_checkpoint,
                        ctx.anchor,
                        &child_dir,
                    )
                };
            materialize
                .map_err(|e| StandbyError::ClaimFailed(format!("materialize child rootfs: {e}")))?;
            claim_phase!("child_materialized");
            child_dir.clone()
        };
        if resident_handoff {
            claim_phase!("resident_handoff_ready");
        }

        // (8) The runner-side host gates a cold boot runs, before the child boots:
        // the overlay contract, then the child's own 0700 substitution endpoint
        // keyed on its fresh id (never a sibling's; the factory parent has none).
        let child_cfg = child_start_config(claim, &child, &child_rootfs_dir);
        let guards = ClaimGuards::new(&self.spawner);
        // Gate the image the claim was admitted for, not the clone the child
        // boots: the sidecar describes how the image was built and is not part
        // of the captured snapshot, so it exists only beside the image.
        guards
            .admit_overlay_contract(std::path::Path::new(&claim.rootfs_path))
            .map_err(|e| StandbyError::ClaimFailed(format!("overlay contract: {e}")))?;

        let grant_envelope = issue_child_grant(&plan, &child_cfg, ctx.grant_issuer)
            .map_err(|e| StandbyError::ClaimFailed(format!("issue child verb grant: {e}")))?;

        let secrets =
            mvm_core::plan::secrets_from_signed_json(&claim.plan_json).unwrap_or_default();
        let redaction =
            mvm_core::plan::redaction_from_signed_json(&claim.plan_json).unwrap_or_default();
        let network_limits = plan
            .effective_network_limits()
            .map_err(|e| StandbyError::ClaimFailed(format!("network limits: {e}")))?;
        let ingress = plan.ingress.clone();
        if let Some(file) = claim_debug.as_mut() {
            let _ = writeln!(
                file,
                "[warm-claim] inputs allows_egress={} secrets={}",
                claim.network_policy.allows_egress(),
                secrets.len()
            );
        }
        let parent_state_dir = vm_state_dir(handle.id.as_str());
        let mut endpoint = guards
            .spawn_endpoint(
                &child,
                &EndpointSpawnInputs {
                    state_dir: &child_dir,
                    tenant: claim.tenant_id.as_str(),
                    secrets: &secrets,
                    redaction: &redaction,
                    network_policy: &claim.network_policy,
                    network_limits,
                    ingress: &ingress,
                    // A restored child already holds its parent's signing key
                    // in the memory image it woke from, and there is no way to
                    // put a different one there. Its endpoint pins what the
                    // guest actually has.
                    identity: FlowMuxIdentitySource::InheritFrom(&parent_state_dir),
                },
            )
            .map_err(|e| StandbyError::ClaimFailed(format!("spawn child endpoint: {e}")))?;
        claim_phase!("endpoint_ready");

        // The child's host channel set, resolved under its own state dir and
        // mapped through the one mapper a cold boot's set comes from. The fork
        // wires these before it resumes the child; a restored guest is already
        // booted, so it dials the instant its vCPUs run.
        let socks = standing_sockets(&child_dir, &child_cfg);
        let channels = workload_vsock_ports(&socks.with_egress(endpoint.egress_uds()));

        // Register the child's exact admitted host-service set before the fork,
        // because the restored guest can dial `BROKER_PORT` immediately. Any
        // registration failure refuses the claim; the guard reaps until commit.
        let child_capabilities: Vec<_> = plan
            .extensions
            .iter()
            .flat_map(|extension| extension.capabilities.iter().cloned())
            .collect();
        let mut broker_guard = self
            .broker
            .register(&BrokerRegisterRequest {
                vm_name: &child.0,
                state_dir: &child_dir,
                tenant: child_cfg.tenant_id.as_deref(),
                broker_listen_socket: socks.broker.as_deref(),
                services: &plan.services,
                capability_bindings: &child_capabilities,
                service_proxies: &child_cfg.service_proxies,
            })
            .map_err(|e| StandbyError::ClaimFailed(format!("register child broker: {e}")))?;
        claim_phase!("broker_registered");

        // (6b) Mint a fresh VMGenID bound to the child's content-address and fork
        // the VMM. A fork restores a running guest out of the parent's saved
        // memory, so the child comes back holding the parent's CSPRNG state and
        // the parent's wall clock — nothing is scrubbed yet at this point.
        let content_hash = parent_rootfs_digest(&parent).map_err(refuse)?.to_string();
        let genid = fresh_generation_token(content_hash);
        let token = genid.token;
        let fork_request = ChildForkRequest {
            child_vm_name: &child.0,
            child_dir: &child_dir,
            // A resident HVF claim addresses the paused parent by its stable
            // pool identity. Saved-state drivers receive no parent name and
            // restore from the materialized child directory instead.
            parent_vm_name: resident_handoff.then_some(handle.id.as_str()),
            genid,
            channels: &channels,
            // Straight off the admitted plan — the value the subset comparison
            // above cleared. Taking it from `child_cfg` instead would take it
            // from a start config the claim supplied, which is not what was
            // checked.
            cpu_grant: plan.grants.as_ref().and_then(|grants| grants.cpu),
        };
        if preloaded_child_name.is_some() {
            self.driver.resume_preloaded_child(&fork_request)?;
        } else {
            self.driver.fork_standby_child(&fork_request)?;
        }
        claim_phase!("child_forked");

        // Unconditional and best-effort, mirroring `start_workload`: started
        // the moment the restored guest is live, before the fallible
        // post-restore handshake below. A cold boot has a kernel boot to
        // blame a silent hang on; a fork has none — the guest is already
        // running the instant the fork resumes it — so the handshake window
        // this call precedes is the one place a restore can wedge or panic
        // with nothing else to show why.
        self.console_streamer.start(&ConsoleCapture {
            vm_name: &child.0,
            console_log: &socks.console_log,
            redaction: &redaction,
            retention: plan_stream_retention(child_cfg.plan_json.as_deref()),
        });

        // (7) Close that window before the claim commits: deliver the token to
        // the now-reachable guest and make it prove, on its own report, that it
        // rotated its generation identity and took the host's clock. Two children
        // of one parent that skipped this would draw identical randomness, which
        // is the whole reason a warm child needs a fresh identity — so a child
        // that cannot prove it is never admitted.
        if let Err(refusal) = self.take_fresh_child_identity(&child.0, token, grant_envelope) {
            // The child is live and still carrying its parent's random state.
            // Unwinding alone would leave running exactly the VM this refusal
            // exists to prevent, so stop it before returning. `force_stop`
            // only tears down the VMM, not the console follower this claim
            // started above and `VmBackend::stop` never runs for a name that
            // is refused here and never becomes live state, so this is the
            // one place responsible for reaping it — after the teardown, so
            // whatever the refused child prints as it dies is in the record
            // of why it was refused.
            self.force_stop(&child.0, "refused forked standby child");
            self.console_streamer.stop(&child.0);
            return Err(refusal);
        }
        claim_phase!("identity_verified");

        // The child booted and proved a fresh identity: disarm the endpoint and
        // broker reapers (the stop path owns them now) and commit — the parent
        // stays reserved and the child dir is real state.
        endpoint.defuse();
        broker_guard.defuse();
        cleanup.commit();
        if resident_handoff {
            schedule_resident_checkpoint_reclaim(ctx, &parent);
        }
        Ok(child)
    }

    /// Deliver `token` to the forked child's guest agent and judge what it
    /// reports. The driver owns the transport; the verdict is the claim's.
    fn take_fresh_child_identity(
        &self,
        child_vm_name: &str,
        token: [u8; mvm_core::crypto::vmgenid::GENID_BYTES],
        grant_envelope: Option<VerbGrantEnvelope>,
    ) -> std::result::Result<(), StandbyError> {
        let outcome = self
            .driver
            .deliver_child_identity(child_vm_name, token, grant_envelope)
            .map_err(|e| {
                StandbyError::ClaimFailed(format!(
                    "forked child '{child_vm_name}' never answered the post-restore identity \
                     handshake: {e}"
                ))
            })?;
        require_fresh_child_identity(child_vm_name, &outcome)
    }

    /// Boot a standby parent, capture its whole live state, and release it.
    ///
    /// The parent's boot inputs are derived here, from the launch it will
    /// serve, through the same mappers `start_workload` uses — a factory parent
    /// boots the device model and boot-shape cmdline a workload boots, minus
    /// the claim-time hostname and host channels a workload is entitled to and
    /// it is not. That is not a
    /// nicety: a child is restored out of the parent's saved memory and
    /// inherits both, so a parent assembled by a second recipe hands every
    /// child whatever that recipe got wrong.
    ///
    /// The driver boots those inputs and supplies the backend-specific control;
    /// capturing a live VM's memory is backend-agnostic, so it lives here rather
    /// than in any one driver. The captured checkpoint is what a later claim
    /// verifies content and lineage against.
    ///
    /// A factory parent gets no substitution endpoint and no broker: those are
    /// workload-only steps (`ClaimGuards::spawn_endpoint`, `BrokerRegistrar`,
    /// both reached from `start_workload` and neither reachable from here), and
    /// [`factory_parent_config`] drops every field that could carry workload
    /// authority into the parent's launch config in the first place.
    pub fn spawn_standby_captured(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let launch = ctx.launch.ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "standby '{}' has no launch config to mirror: a warm parent boots the same \
                 device model and boot-shape kernel cmdline a workload does, so it cannot be assembled \
                 without the launch it will serve",
                spec.id
            ))
        })?;
        let parent_config = factory_parent_config(launch, spec)?;
        let state_dir = PathBuf::from(&spec.vm_state_dir);

        // Written before boot, exactly as `start` does for a workload, so a
        // capture against this parent resolves its rootfs and boot contract the
        // same way every runner-launched VM's does.
        crate::base::runtime_meta::record_from_start_config(
            &spec.id,
            StartMode::Detached,
            &parent_config,
        )
        .map_err(|e| {
            StandbyError::SpawnFailed(format!(
                "recording standby parent '{}' runtime metadata: {e}",
                spec.id
            ))
        })?;

        let boot = factory_parent_spec(&parent_config, &state_dir, |has_disk| {
            self.driver.workload_base_bootargs(has_disk)
        });
        // The same truncation refusal a workload boot gets, for the same reason
        // and then some: a child inherits its parent's cmdline out of restored
        // memory rather than deriving its own, so a parent whose trailing tokens
        // the kernel silently dropped hands that loss to every child it produces.
        if let Some(problem) = cmdline::cmdline_overflow(&boot.cmdline) {
            return Err(StandbyError::SpawnFailed(format!(
                "refusing to boot standby parent '{}': {problem}",
                spec.id
            )));
        }
        let mut handle = self
            .driver
            .spawn_standby_parent(&StandbyParentSpawn { spec, boot: &boot })?;

        let control = self.driver.vm_full_control(&spec.id).ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "backend cannot capture a warm parent's memory for standby '{}'",
                spec.id
            ))
        })?;
        let retain_parent = control.retain_paused_after_capture();
        let snapshots = FsSnapshotStore::new(mvm_core::config::snapshots_dir())
            .map_err(|e| StandbyError::SpawnFailed(format!("open snapshot store: {e}")))?;

        let capture_params = CaptureVmFullParams {
            id: CheckpointId::new(format!("standby-{}", spec.id)),
            vm_name: spec.id.clone(),
            supervisor_config_digest: String::new(),
            runtime_overlay_version: None,
            // Firecracker keeps no supervisor-config blob; its presence is
            // what marks a checkpoint as originating from a backend that does.
            supervisor_config_src: control.supervisor_config_path().map_err(|e| {
                StandbyError::SpawnFailed(format!("resolve standby supervisor config: {e}"))
            })?,
            tag: None,
            created_unix: mvm_core::time::now_unix_secs(),
            retain_paused: true,
            // A decision, not an omission. A factory parent holds no plan and
            // no tenant by construction — `factory_parent_config` drops
            // `plan_json` and `cpu_grant` precisely so a parent cannot carry a
            // grant admitted for some other workload, and one parent serves
            // every later claim against this pool. Sealing the mirrored
            // launch's grant here would bind all of them to whichever workload
            // happened to provision the pool.
            //
            // Sealing nothing is not the same as checking nothing: the claim
            // path still compares, and an absent parent grant is deny-all
            // egress, so a claimed child asking to reach anywhere is refused.
            // It leaves CPU and wall clock unbounded by the *parent*; those are
            // bounded for a warm child by the host ceiling its own plan was
            // admitted against, never by this record.
            grants: None,
        };
        let trusted_backend = if cfg!(all(feature = "trusted-apfs", target_os = "macos"))
            && std::env::var("MVM_HVF_ENABLE_TRUSTED_SNAPSHOT").as_deref() == Ok("1")
        {
            Some(
                mvm_fs::trusted_snapshot::platform_backend(snapshots.root()).map_err(|e| {
                    StandbyError::SpawnFailed(format!("open trusted snapshot backend: {e}"))
                })?,
            )
        } else {
            None
        };
        let captured = if let Some(backend) = trusted_backend.as_deref() {
            capture_vm_full_with_trusted_snapshot_backend(
                ctx.checkpoints,
                capture_params,
                control.as_ref(),
                backend,
            )
        } else {
            capture_vm_full_with_snapshot_store(
                ctx.checkpoints,
                capture_params,
                control.as_ref(),
                &snapshots,
            )
        };

        // Saved-state backends release the source after capture because the
        // checkpoint is their claim resource. The HVF live-handoff backend
        // deliberately retains its paused supervisor: the checkpoint is an
        // integrity witness, while the resident parent remains the sole owner
        // of the HVF machine and its interrupt-controller state. A failed
        // capture never leaves that source resident.
        if captured.is_err() || !retain_parent {
            self.force_stop(&spec.id, "captured standby parent");
        }

        let meta = captured
            .map_err(|e| StandbyError::SpawnFailed(format!("capture standby parent: {e}")))?;

        // Saved-state backends have no live process after capture and use pid=0
        // as their persisted sentinel. A retained HVF parent keeps its real pid
        // so claims can verify and address the resident supervisor.
        if !retain_parent {
            handle.pid = 0;
        }
        handle.parent_checkpoint = Some(meta.id.as_str().to_string());
        Ok(handle)
    }

    /// Materialize and load one saved-state child while the pool is being
    /// refilled, leaving its VMM paused for a later claim. The child is not
    /// reachable by a workload yet: claim-time endpoint, broker, identity,
    /// and authenticated-vsock gates still run before resume.
    pub fn preload_standby_child(
        &self,
        ctx: &PreloadContext<'_>,
        handle: &mut StandbyHandle,
    ) -> std::result::Result<(), StandbyError> {
        if !self.driver.supports_preloaded_standby() {
            return Err(StandbyError::Unsupported {
                backend: self.driver.name().to_string(),
            });
        }
        if handle.preloaded_child_vm_name.is_some() {
            return Err(StandbyError::SpawnFailed(format!(
                "standby '{}' already owns a preloaded child",
                handle.id
            )));
        }
        let checkpoint = handle.parent_checkpoint.as_deref().ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "standby '{}' has no checkpoint for child preload",
                handle.id
            ))
        })?;
        let checkpoint_id = CheckpointId::new(checkpoint.to_string());
        let _registry_lock = acquire_registry_lock(ctx.registry_path)
            .map_err(|e| StandbyError::SpawnFailed(format!("acquire VM name registry: {e}")))?;
        let registry = VmNameRegistry::load(ctx.registry_path)
            .map_err(|e| StandbyError::SpawnFailed(format!("load VM name registry: {e}")))?;
        let (child_name, child_dir) = (0..MAX_CHILD_NAME_ATTEMPTS)
            .map(|_| generate_vm_name())
            .find_map(|name| {
                let dir = vm_state_dir(&name);
                (registry.lookup(&name).is_none() && !dir.exists()).then_some((name, dir))
            })
            .ok_or_else(|| {
                StandbyError::SpawnFailed("could not reserve a unique preloaded child name".into())
            })?;

        let materialized = if is_trusted_snapshot_id(checkpoint) {
            let backend = mvm_fs::trusted_snapshot::platform_backend(ctx.snapshots.root())
                .map_err(|e| {
                    StandbyError::SpawnFailed(format!("open trusted snapshot backend: {e}"))
                })?;
            materialize_child_from_trusted_parent(
                ctx.checkpoints,
                backend.as_ref(),
                &checkpoint_id,
                ctx.anchor,
                &child_dir,
            )
        } else {
            materialize_child_from_parent(
                ctx.checkpoints,
                ctx.snapshots,
                &checkpoint_id,
                ctx.anchor,
                &child_dir,
            )
        };
        if let Err(error) = materialized {
            let _ = std::fs::remove_dir_all(&child_dir);
            return Err(StandbyError::SpawnFailed(format!(
                "materialize preloaded child '{}': {error}",
                child_name
            )));
        }

        let loaded = self.driver.preload_standby_child(&PreloadChildRequest {
            child_vm_name: &child_name,
            child_dir: &child_dir,
        });
        let loaded = match loaded {
            Ok(value) => value,
            Err(error) => {
                self.force_stop(&child_name, "failed preloaded standby child");
                let _ = std::fs::remove_dir_all(&child_dir);
                return Err(error);
            }
        };
        handle.preloaded_child_vm_name = Some(child_name);
        handle.pid = loaded.pid;
        handle.control_socket = loaded.control_socket;
        Ok(())
    }

    /// Force-stop a VM the warm-pool path is done with, naming its `role` for the
    /// log. Failure is logged, never propagated: the callers are already on their
    /// way out (a captured parent, a refused child) and have nothing better to do
    /// about it, but a VM that outlives its owner must stay visible.
    fn force_stop(&self, vm_name: &str, role: &str) {
        let id = VmId(vm_name.to_string());
        match self.driver.attach(&id).and_then(|vm| vm.kill()) {
            Ok(()) => {}
            Err(e) => tracing::warn!(
                vm = vm_name,
                role,
                error = %e,
                "stopping a warm-pool VM failed; it may still be running"
            ),
        }
    }
}

/// Release-unless-committed lease for a reserved parent and a partially-built
/// child. A claim reserves the parent (`mark_claimed`) and then materializes a
/// child dir; if any later step fails, this guard returns the (verified, healthy)
/// parent to claimable — so a failed claim never strands warm capacity — and
/// removes the orphaned child dir. Only a claim that boots the child calls
/// [`commit`](Self::commit), disarming both. A parent that failed VERIFICATION is
/// quarantined by removal upstream and never reaches this guard, so releasing
/// here only ever returns a parent that verified healthy.
struct WarmClaimLease<'a> {
    pool: &'a SupervisorStandbyPool,
    driver: &'a dyn VmmDriver,
    parent_id: &'a str,
    child_dir: Option<PathBuf>,
    preloaded_child: Option<String>,
    committed: bool,
}

impl<'a> WarmClaimLease<'a> {
    fn new(pool: &'a SupervisorStandbyPool, parent_id: &'a str, driver: &'a dyn VmmDriver) -> Self {
        Self {
            pool,
            driver,
            parent_id,
            child_dir: None,
            preloaded_child: None,
            committed: false,
        }
    }

    /// Track the child dir so an early return after materialize removes it.
    fn track_child_dir(&mut self, dir: PathBuf) {
        self.child_dir = Some(dir);
    }

    /// Track a paused child process so an early claim refusal cannot leave a
    /// VMM alive after its pool reservation is returned.
    fn track_preloaded_child(&mut self, vm_name: String) {
        self.preloaded_child = Some(vm_name);
    }

    /// The child booted: disarm. The parent stays `Claimed` (the stop/reaper path
    /// owns it) and the child dir is real state, not an orphan.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for WarmClaimLease<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Err(e) = self.pool.mark_idle(self.parent_id) {
            tracing::warn!(
                parent = %self.parent_id,
                error = %e,
                "returning reserved standby parent to claimable after a failed claim"
            );
        }
        if let Some(vm_name) = &self.preloaded_child {
            let id = VmId(vm_name.clone());
            if let Err(error) = self.driver.attach(&id).and_then(|vm| vm.kill()) {
                tracing::warn!(
                    vm = %vm_name,
                    %error,
                    "stopping preloaded standby child after failed claim"
                );
            }
            // The child is gone either way — killed above, or already dead and
            // about to lose its state dir below. The record has to stop naming
            // it: left alone it keeps advertising a paused VMM that no longer
            // exists, so every later claim refuses on a missing control socket
            // while the pool still counts the parent as usable capacity. The
            // parent and its checkpoint are healthy, so demote rather than
            // remove; the next claim materializes a fresh child from it.
            if let Err(error) = self.pool.demote_to_saved_state(self.parent_id) {
                tracing::warn!(
                    parent = %self.parent_id,
                    child = %vm_name,
                    %error,
                    "could not demote standby to saved-state after its preloaded child was \
                     destroyed; it will refuse every claim until reaped"
                );
            }
        }
        if let Some(dir) = &self.child_dir {
            match std::fs::remove_dir_all(dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "removing orphaned child dir after a failed claim"
                ),
            }
        }
    }
}

/// Reserve the passed parent atomically under the registry lock (the no-double-
/// claim guard), then verify its sealed content and its content-address. Saved-
/// state claims additionally verify the metadata lineage against the signed
/// audit chain; resident HVF claims use their signed snapshot manifest as the
/// O(1) publication witness. Returns the verified parent meta. Runs before any
/// clone or boot: an unclaimable or tampered parent fails closed.
///
/// A parent that fails verification (or whose sealed record is unreadable) is
/// **quarantined by removal** — a parent that cannot be verified must never be
/// reused, so it is dropped from the pool rather than returned to claimable.
/// Replenish spawns a fresh one in its place. This is the deliberate exception to
/// the release-on-failure rule the caller's [`WarmClaimLease`] applies to a healthy
/// reserved parent.
fn reserve_and_verify_parent(
    ctx: &ClaimContext<'_>,
    handle: &StandbyHandle,
    resident_handoff: bool,
) -> std::result::Result<CheckpointMeta, StandbyError> {
    {
        let _lock = acquire_registry_lock(ctx.registry_path)
            .map_err(|e| StandbyError::ClaimFailed(format!("acquire registry lock: {e}")))?;
        let current = ctx
            .pool
            .load(&handle.id)
            .map_err(|e| StandbyError::ClaimFailed(format!("load standby {}: {e}", handle.id)))?;
        if !current.state.is_claimable() {
            // Not yet reserved (no `mark_claimed`), so nothing to release.
            return Err(refuse(ClaimRefusal::ParentNotClaimable));
        }
        ctx.pool.mark_claimed(&handle.id).map_err(|e| {
            StandbyError::ClaimFailed(format!("reserve standby {}: {e}", handle.id))
        })?;
    }

    // Quarantine (remove) the reserved parent on any verification failure — a
    // parent we cannot trust must not linger claimable OR stranded `Claimed`.
    let quarantine = |err: StandbyError| -> StandbyError {
        if let Err(e) = ctx.pool.remove(&handle.id) {
            tracing::warn!(
                parent = %handle.id,
                error = %e,
                "failed to quarantine an untrusted reserved parent; it stays claimed (unclaimable) until the pool reaper"
            );
        }
        err
    };
    let parent = ctx
        .checkpoints
        .read_meta(ctx.parent_checkpoint)
        .map_err(|e| {
            quarantine(StandbyError::ClaimFailed(format!(
                "read parent checkpoint: {e}"
            )))
        })?;
    if resident_handoff
        && !is_trusted_snapshot_id(parent.snapshot_id.as_deref().unwrap_or_default())
    {
        verify_resident_snapshot_manifest(ctx, &parent)
            .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    } else if let Some(snapshot_id) = parent
        .snapshot_id
        .as_deref()
        .filter(|id| is_trusted_snapshot_id(id))
    {
        let backend =
            mvm_fs::trusted_snapshot::platform_backend(ctx.snapshots.root()).map_err(|e| {
                quarantine(StandbyError::ClaimFailed(format!(
                    "open trusted snapshot backend: {e}"
                )))
            })?;
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().map_err(|e| {
            quarantine(StandbyError::ClaimFailed(format!(
                "load trusted snapshot signer: {e}"
            )))
        })?;
        let manifest_digest = mvm_core::checkpoint::content_manifest_digest(&parent.content);
        let manifest_digest_text = manifest_digest.to_string();
        let signer = identity.verifying_key().to_bytes();
        backend
            .validate(
                &mvm_fs::snapshot_store::SnapshotId::with_digest(
                    snapshot_id,
                    manifest_digest_text.clone(),
                ),
                &manifest_digest_text,
                &signer,
            )
            .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    } else {
        verify_content(ctx.checkpoints, &parent)
            .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    }
    if !resident_handoff {
        verify_lineage(ctx.checkpoints, ctx.parent_checkpoint, ctx.anchor)
            .map_err(|e| quarantine(refuse(map_lineage_refusal(&e))))?;
    }
    Ok(parent)
}

/// Verify the signed publication witness for a resident parent without reading
/// the bundle's large content files. The live, paused HVF parent is the machine
/// that will be transferred; the ordinary snapshot is retained as a signed,
/// user-owned publication record and remains fully verified for saved restores.
fn verify_resident_snapshot_manifest(
    ctx: &ClaimContext<'_>,
    parent: &CheckpointMeta,
) -> anyhow::Result<()> {
    let snapshot_id = parent
        .snapshot_id
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("resident parent has no staged snapshot"))?;
    if snapshot_id.is_empty()
        || snapshot_id.contains('/')
        || snapshot_id.contains('\\')
        || snapshot_id.contains('\0')
    {
        anyhow::bail!("resident parent snapshot id is not a safe store entry")
    }
    let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity()?;
    let digest = mvm_core::checkpoint::content_manifest_digest(&parent.content);
    mvm_core::crypto::snapshot_sign::verify_manifest(
        &ctx.snapshots.root().join(snapshot_id),
        &digest.to_string(),
        &[identity.verifying_key()],
    )?;
    Ok(())
}

/// Reclaim the bulky publication payload after a resident parent has become a
/// committed child. The signed manifest has already authorized the handoff,
/// and the resident parent is no longer claimable, so retaining its checkpoint
/// bytes would make every warm claim add another large saved-state artifact.
/// Saved-state claims do not use this path because their checkpoint remains the
/// restore resource and its lineage record.
fn schedule_resident_checkpoint_reclaim(ctx: &ClaimContext<'_>, parent: &CheckpointMeta) {
    let checkpoints_root = ctx.checkpoints.root().to_path_buf();
    let snapshots_root = ctx.snapshots.root().to_path_buf();
    let parent_id = parent.id.clone();
    let snapshot_id = parent.snapshot_id.clone();
    let result = std::thread::Builder::new()
        .name("mvm-resident-reclaim".to_string())
        .spawn(move || {
            if let Err(error) = reclaim_consumed_resident_checkpoint_at(
                &checkpoints_root,
                &snapshots_root,
                &parent_id,
                snapshot_id.as_deref(),
            ) {
                tracing::warn!(
                    checkpoint = %parent_id,
                    error = %error,
                    "resident parent publication cleanup failed; warm handoff remains committed"
                );
            }
        });
    if let Err(error) = result {
        tracing::warn!(
            checkpoint = %parent.id,
            error = %error,
            "could not schedule resident parent publication cleanup"
        );
    }
}

fn reclaim_consumed_resident_checkpoint_at(
    checkpoints_root: &Path,
    snapshots_root: &Path,
    parent_id: &CheckpointId,
    snapshot_id: Option<&str>,
) -> anyhow::Result<()> {
    let checkpoints = CheckpointStore::at(checkpoints_root);
    let snapshots = FsSnapshotStore::new(snapshots_root)
        .context("open resident snapshot store for deferred cleanup")?;
    let Some(snapshot_id) = snapshot_id else {
        return checkpoints
            .remove(parent_id)
            .context("remove resident checkpoint without snapshot");
    };

    if is_trusted_snapshot_id(snapshot_id) {
        // The platform snapshot provider owns trusted-snapshot reclamation;
        // ordinary filesystem snapshots are the resident publication path here.
        return Ok(());
    }

    let snapshot = mvm_fs::snapshot_store::SnapshotId::new(snapshot_id);
    match snapshots.remove(&snapshot) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove resident snapshot payload"),
    }
    checkpoints
        .remove(parent_id)
        .context("remove resident checkpoint payload")
}

/// The admitted plan from the claim.
/// The runner does not re-verify the signature — the host admitted the plan and
/// the supervisor re-verifies at attach. The runner reads the image binding and
/// child-grant fields it must enforce. A claim carrying no parseable plan fails
/// closed.
fn claim_plan(claim: &StandbyClaim) -> std::result::Result<ExecutionPlan, StandbyError> {
    mvm_core::plan::plan_from_admitted_json(&claim.plan_json)
        .map_err(|_| refuse(ClaimRefusal::PlanMissing))
}

fn admitted_broker_bindings(
    plan_json: Option<&str>,
) -> Result<(
    Vec<ServiceId>,
    Vec<mvm_contract::protocol::agent_capability::CapabilityBinding>,
)> {
    plan_json
        .map(mvm_core::plan::plan_from_admitted_json)
        .transpose()
        .context("parse admitted plan host services")
        .map(|plan| {
            plan.map_or_else(
                || (Vec::new(), Vec::new()),
                |plan| {
                    let capabilities = plan
                        .extensions
                        .iter()
                        .flat_map(|extension| extension.capabilities.iter().cloned())
                        .collect();
                    (plan.services, capabilities)
                },
            )
        })
}

/// How many times to redraw a fresh child name before giving up. A collision is
/// astronomically unlikely (random suffix), so a small bound is a fail-closed
/// backstop, never a hot loop.
const MAX_CHILD_NAME_ATTEMPTS: usize = 8;

/// Mint a fresh child [`VmId`] that collides with no existing VM registration.
/// The name is a fresh random id (never the parent's), which — with the fresh
/// VMGenID and per-child endpoint — is the identity scrub that stops a fork from
/// inheriting the parent's identity. Uniqueness comes from the random suffix
/// checked against the registry, not from mutual exclusion: the registry lock
/// only serializes the read (nothing is persisted under it here — the boot path
/// registers the name), so two truly-concurrent claims rely on the ~2^64 suffix
/// space to not collide, which is what makes a re-check-and-redraw a backstop
/// rather than a race.
fn fresh_child_id(ctx: &ClaimContext<'_>) -> std::result::Result<VmId, StandbyError> {
    let _lock = acquire_registry_lock(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("acquire registry lock: {e}")))?;
    let registry = VmNameRegistry::load(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("load vm registry: {e}")))?;
    for _ in 0..MAX_CHILD_NAME_ATTEMPTS {
        let name = generate_vm_name();
        if registry.lookup(&name).is_none() {
            return Ok(VmId(name));
        }
    }
    Err(StandbyError::ClaimFailed(
        "could not mint a registry-unique child name".into(),
    ))
}

/// Recheck a preloaded child's registry identity immediately before claim-side
/// authority is created. The preload name was collision-checked when the pool
/// record was written, but another VM may have registered the same random name
/// before a later process claimed the persisted record.
fn verify_preloaded_child_name_is_available(
    ctx: &ClaimContext<'_>,
    child_name: &str,
) -> std::result::Result<(), StandbyError> {
    let _lock = acquire_registry_lock(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("acquire registry lock: {e}")))?;
    let registry = VmNameRegistry::load(ctx.registry_path)
        .map_err(|e| StandbyError::ClaimFailed(format!("load vm registry: {e}")))?;
    if registry.lookup(child_name).is_some() {
        return Err(StandbyError::ClaimFailed(format!(
            "preloaded child name '{child_name}' is already registered"
        )));
    }
    Ok(())
}
/// The child's launch config: the CLI-populated claim config (carrying the
/// verity fields the CLI already resolved on the cloned rootfs) rekeyed onto the
/// fresh child identity and its materialized rootfs. The runner consumes verity;
/// it never derives it.
fn child_start_config(claim: &StandbyClaim, child: &VmId, rootfs_dir: &Path) -> VmStartConfig {
    let mut cfg = claim.start_config.clone().unwrap_or_default();
    cfg.name = child.0.clone();
    cfg.rootfs_path = rootfs_dir
        .join("rootfs.ext4")
        .to_string_lossy()
        .into_owned();
    cfg.tenant_id = Some(claim.tenant_id.clone());
    cfg.network_policy = claim.network_policy.clone();
    cfg.plan_json = Some(claim.plan_json.clone());
    cfg.bundle_json = claim.bundle_json.clone();
    cfg
}

/// Resolve the launch source recorded for a resident standby parent. The live
/// HVF supervisor already has this image attached; the path is used only for
/// the same host-side overlay admission gate a cold workload boot performs.
fn resident_parent_rootfs_dir(parent_vm_name: &str) -> std::result::Result<PathBuf, StandbyError> {
    let metadata = crate::base::runtime_meta::read(parent_vm_name)
        .map_err(|e| StandbyError::ClaimFailed(format!("read resident parent metadata: {e}")))?
        .ok_or_else(|| {
            StandbyError::ClaimFailed(format!(
                "resident parent '{parent_vm_name}' has no runtime metadata"
            ))
        })?;
    let rootfs = metadata
        .rootfs_path
        .ok_or_else(|| StandbyError::ClaimFailed("resident parent has no rootfs path".into()))?;
    let rootfs = PathBuf::from(rootfs);
    if !rootfs.is_file() {
        return Err(StandbyError::ClaimFailed(format!(
            "resident parent rootfs {} is not a regular file",
            rootfs.display()
        )));
    }
    rootfs.parent().map(Path::to_path_buf).ok_or_else(|| {
        StandbyError::ClaimFailed(format!(
            "resident parent rootfs {} has no containing directory",
            rootfs.display()
        ))
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use mvm_agentd::vsock::{BROKER_PORT, EGRESS_PORT, GUEST_AGENT_PORT};
    use mvm_core::plan::{Nonce, SecretBinding, SecretSource, VerbGrant, VerbId};
    use mvm_core::policy::network_policy::HostPort;
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
    use mvm_core::util::test_env::TestEnv;
    use mvm_fs::snapshot_store::SnapshotStore;

    use crate::backends::hvf::HvfDriver;
    use crate::driver::MockDriver;

    fn without_per_boot_tokens(cmdline: &str) -> String {
        cmdline
            .split_whitespace()
            .filter(|token| {
                !token.starts_with("mvm.hostname=") && !token.starts_with("mvm.hostepoch=")
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// An `NetworkEndpointSpawner` test double: records the request it was handed and
    /// returns a canned UDS without spawning any process. `Mutex` (not `RefCell`)
    /// so it satisfies the `Send + Sync` a `VmBackend` spawner must be.
    struct RecordingSpawner {
        uds: PathBuf,
        seen: Mutex<Option<Recorded>>,
    }

    struct Recorded {
        mints_identity: bool,
        tenant: String,
        secrets_len: usize,
        policy: NetworkPolicy,
        network_limits: mvm_core::plan::NetworkLimits,
    }

    impl RecordingSpawner {
        fn new(uds: &str) -> Self {
            Self {
                uds: PathBuf::from(uds),
                seen: Mutex::new(None),
            }
        }
    }

    impl NetworkEndpointSpawner for RecordingSpawner {
        fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
            *self.seen.lock().unwrap() = Some(Recorded {
                mints_identity: matches!(req.identity, FlowMuxIdentitySource::Mint),
                tenant: req.tenant.to_string(),
                secrets_len: req.secrets.len(),
                policy: req.network_policy.clone(),
                network_limits: req.network_limits,
            });
            Ok(SpawnedEndpoint {
                egress_uds: self.uds.clone(),
                identity_drive: None,
            })
        }
    }

    /// A `BrokerRegistrar` test double: records the request it saw and returns a
    /// defused no-op guard (spawns no broker subprocess). `Mutex` for the
    /// `Send + Sync` bound a `VmBackend`'s registrar must satisfy.
    struct RecordingBrokerRegistrar {
        seen: Mutex<Option<RecordedBroker>>,
    }

    struct RecordedBroker {
        vm_name: String,
        tenant: Option<String>,
        broker_listen_socket: Option<PathBuf>,
        services: Vec<ServiceId>,
    }

    impl RecordingBrokerRegistrar {
        fn new() -> Self {
            Self {
                seen: Mutex::new(None),
            }
        }
    }

    impl BrokerRegistrar for RecordingBrokerRegistrar {
        fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
            *self.seen.lock().unwrap() = Some(RecordedBroker {
                vm_name: req.vm_name.to_string(),
                tenant: req.tenant.map(str::to_string),
                broker_listen_socket: req.broker_listen_socket.map(Path::to_path_buf),
                services: req.services.to_vec(),
            });
            Ok(BrokerGuard::defused())
        }
    }

    fn service(id: &str) -> ServiceId {
        ServiceId::parse(id.to_string()).unwrap()
    }

    /// A guard that did register — the only inner variant a test can build
    /// without a live daemon, and its Drop is a no-op.
    fn registered_guard() -> BrokerGuard {
        BrokerGuard(mvm_vmm::host::host_agent_spawn::ServicesGuard::Agent(
            mvm_vmm::host::host_agent_spawn::HostAgentServicesGuard::defused(),
        ))
    }

    #[test]
    fn a_workload_that_bound_no_host_service_is_not_degraded() {
        assert!(BrokerGuard::defused().services_healthy(&[]));
    }

    #[test]
    fn a_bound_host_service_that_never_registered_is_degraded() {
        assert!(!BrokerGuard::defused().services_healthy(&[service("host.audit.v1")]));
    }

    #[test]
    fn a_bound_host_service_that_registered_is_not_degraded() {
        assert!(registered_guard().services_healthy(&[service("host.audit.v1")]));
    }

    /// A `ConsoleStreamer` double proving the *wiring*, not re-proving the
    /// follower's own polling correctness (that lives, and is tested, in
    /// `mvm-hostd::stream::console_source` — the crate this one cannot
    /// depend on, which is why the hook exists). Records every `start`/`stop`
    /// call, and on `stop` snapshots whatever the console-log path holds at
    /// that moment: a real follower's `stop` synchronously drains before
    /// returning, so a wired `stop` that runs before the file is read back
    /// would show up here as a snapshot missing bytes that were already on
    /// disk.
    #[derive(Default)]
    struct RecordingConsoleStreamer {
        started: Mutex<Vec<(String, PathBuf)>>,
        stopped: Mutex<Vec<String>>,
        captured_at_stop: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl ConsoleStreamer for RecordingConsoleStreamer {
        fn start(&self, capture: &ConsoleCapture<'_>) {
            self.started.lock().unwrap().push((
                capture.vm_name.to_string(),
                capture.console_log.to_path_buf(),
            ));
        }

        fn stop(&self, vm_name: &str) {
            self.stopped.lock().unwrap().push(vm_name.to_string());
            let path = self
                .started
                .lock()
                .unwrap()
                .iter()
                .find(|(name, _)| name == vm_name)
                .map(|(_, path)| path.clone());
            if let Some(path) = path {
                let bytes = std::fs::read(&path).unwrap_or_default();
                self.captured_at_stop
                    .lock()
                    .unwrap()
                    .insert(vm_name.to_string(), bytes);
            }
        }
    }

    #[test]
    fn boot_and_console_start_run_concurrently() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let booted = console_boot::boot_while_starting_console(
            || {
                started_rx
                    .recv_timeout(Duration::from_secs(1))
                    .map_err(|error| {
                        anyhow::anyhow!("console start did not overlap boot: {error}")
                    })?;
                Ok(7_u8)
            },
            || {
                let _ = started_tx.send(());
            },
            || {},
        )
        .expect("the console-start task runs while the driver boot is in progress");

        assert_eq!(booted, 7);
    }

    fn config(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    fn egress_allowing_policy() -> NetworkPolicy {
        NetworkPolicy::allow_list(vec![HostPort::new("example.com", 443)])
    }

    /// Seed an overlay-aware `mvm-meta.json` sidecar next to a rootfs file in a
    /// fresh tempdir and return `(dir, rootfs_path)`. `VmBackend::start`'s
    /// admission gate refuses a rootfs whose parent dir carries no overlay-aware
    /// sidecar, so every test that drives the full trait method provides one.
    /// The returned `TempDir` must stay in scope for the rootfs to exist.
    fn overlay_aware_rootfs(name: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        // sealed=false (accessible dev image), runtime_lean=true so the sidecar
        // clears the gate under every runtime-source policy, not just the default.
        mvm_build::builder_vm::GuestSidecar::for_oci_run(name, false, true)
            .write_to_dir(dir.path())
            .unwrap();
        (dir, rootfs.display().to_string())
    }

    fn keystore_secret() -> SecretBinding {
        SecretBinding {
            name: "API_KEY".into(),
            source: SecretSource::Keystore {
                address: "test-key".into(),
            },
        }
    }

    fn egress_host_uds(spec: &crate::driver::VmmSpec) -> &Path {
        spec.vsock
            .iter()
            .find(|p| p.service.port() == EGRESS_PORT)
            .map(|p| p.host_uds.as_path())
            .expect("spec carries an EGRESS_PORT vsock channel")
    }

    #[test]
    fn start_workload_threads_endpoint_uds_into_egress_port() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let policy = egress_allowing_policy();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = config("w-egress");
        let vm = runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: "root=/dev/vda".into(),
            })
            .expect("start_workload succeeds against the mock driver");

        assert_eq!(vm.id().0, "w-egress");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];

        // The endpoint UDS the spawner returned is wired to EGRESS_PORT.
        assert_eq!(egress_host_uds(spec), Path::new("/run/ep.sock"));
        // The sealed rootfs lands at /dev/vda.
        assert_eq!(spec.blocks[0].device_node(), "/dev/vda");
        assert_eq!(spec.blocks[0].source, PathBuf::from("/img/rootfs.ext4"));
        // The write-only console capture path is set under the state dir.
        assert!(spec.console.log_path.ends_with("console.log"));
    }

    #[test]
    fn start_workload_starts_console_streaming_and_stop_tears_it_down_without_losing_bytes() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        let policy = egress_allowing_policy();
        let redaction = RedactionPolicy::default();
        let streamer = Arc::new(RecordingConsoleStreamer::default());
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        )
        .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);

        let cfg = config("w-console");
        let vm = runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: "root=/dev/vda".into(),
            })
            .expect("start_workload succeeds against the mock driver");

        // Started exactly once, unconditionally (no admission gating: the
        // hook must not inherit `BrokerRegistrar`'s tenant-gated posture),
        // and pointed at the same console-log path the boot spec carries.
        let expected_console_log = vm_state_dir(&cfg.name).join("console.log");
        {
            let started = streamer.started.lock().unwrap();
            assert_eq!(
                started.as_slice(),
                [("w-console".to_string(), expected_console_log.clone())]
            );
        }
        assert!(
            streamer.stopped.lock().unwrap().is_empty(),
            "must not stop before the workload ends"
        );

        // The boot-failure case this feature exists for: output that lands
        // on the console between start and stop, with no agent involved.
        std::fs::write(&expected_console_log, b"kernel panic\n")
            .expect("write to the console-log path the hook was started with");

        runner
            .stop(vm.id())
            .expect("stop succeeds against the mock driver");

        // Stopped exactly once, by name, and the snapshot taken at that stop
        // call sees the bytes written above -- proving `stop` is wired to run
        // (and, for a real follower, drain) before the caller can observe the
        // workload as torn down, not merely that the method was called.
        assert_eq!(streamer.stopped.lock().unwrap().as_slice(), ["w-console"]);
        assert_eq!(
            streamer
                .captured_at_stop
                .lock()
                .unwrap()
                .get("w-console")
                .expect("stop captured this vm's console"),
            b"kernel panic\n"
        );
    }

    #[test]
    fn the_console_capture_outlives_the_kill_so_a_dying_guests_output_is_recorded() {
        // A guest prints its last words *during* teardown. Releasing the
        // capture before the kill leaves those bytes in the write-only
        // console file and out of the chain — which is exactly the output an
        // operator opens the transcript to find.
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        env.isolate_mvm_home(tmp.path());

        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let streamer = Arc::new(RecordingConsoleStreamer::default());
        let runner = WorkloadRunner::new(
            MockDriver::default().printing_on_kill(b"panic on the way down\n"),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        )
        .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);

        let cfg = config("w-dying");
        let vm = runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: "root=/dev/vda".into(),
            })
            .expect("start_workload succeeds against the mock driver");
        std::fs::write(
            vm_state_dir(&cfg.name).join("console.log"),
            b"while it lived\n",
        )
        .expect("write the console capture");

        runner.stop(vm.id()).expect("stop");

        // The snapshot the hook takes at `stop` is what a real follower's
        // final drain would see. It must hold the kill-time bytes.
        let captured = streamer.captured_at_stop.lock().unwrap();
        let seen = captured.get("w-dying").expect("stop captured this vm");
        assert_eq!(seen.as_slice(), b"while it lived\npanic on the way down\n");
    }

    #[test]
    fn a_kill_that_fails_still_releases_the_console_capture() {
        // The property the old ordering bought and this one must not lose: a
        // VM that will not die cannot strand its follower, or leave its
        // transcript unsealed.
        let streamer = Arc::new(RecordingConsoleStreamer::default());
        let runner = WorkloadRunner::new(
            MockDriver::default().refusing_attach(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        )
        .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);

        let err = runner
            .stop(&VmId("w-undead".to_string()))
            .expect_err("the driver refuses to attach");
        assert!(format!("{err:#}").contains("no such vm"), "{err:#}");
        assert_eq!(streamer.stopped.lock().unwrap().as_slice(), ["w-undead"]);
    }

    #[test]
    fn every_cold_boot_mints_an_identity_whether_or_not_it_carries_secrets() {
        let policy = egress_allowing_policy();
        let redaction = RedactionPolicy::default();

        // This used to be the fork that broke everything: no secrets picked
        // raw TCP, secrets picked WireRequest, and the guest was never told
        // which. There is one transport now, so carrying secrets changes what
        // the endpoint does with a flow -- not which protocol the guest speaks.
        let raw_runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let cfg = config("w-raw");
        raw_runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .unwrap();
        assert!(
            raw_runner
                .spawner
                .seen
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .mints_identity
        );

        // A secret-bearing workload mints exactly the same way.
        let wire_runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let cfg = config("w-wire");
        let secrets = [keystore_secret()];
        wire_runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &secrets,
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .unwrap();
        let recorded = wire_runner.spawner.seen.lock().unwrap();
        let recorded = recorded.as_ref().unwrap();
        assert!(
            recorded.mints_identity,
            "a secret-bearing cold boot mints an identity too -- the protocol \
             does not fork on whether secrets are present"
        );
        assert_eq!(recorded.secrets_len, 1);
        assert_eq!(
            recorded.network_limits,
            mvm_core::plan::NetworkLimits::default()
        );
    }

    #[test]
    fn start_workload_passes_the_network_policy_and_tenant_to_the_spawner() {
        let policy = egress_allowing_policy();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = config("w-policy");
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "acme",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .unwrap();

        let recorded = runner.spawner.seen.lock().unwrap();
        let recorded = recorded.as_ref().unwrap();
        assert_eq!(recorded.tenant, "acme");
        assert_eq!(recorded.policy, egress_allowing_policy());
    }

    fn admitted_config(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            tenant_id: Some("tenant-x".into()),
            ..Default::default()
        }
    }

    #[test]
    fn start_workload_registers_the_broker_and_wires_it_into_the_spec_when_admitted() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = admitted_config("w-broker-admitted");
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "tenant-x",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload succeeds");

        // register saw the tenant + the resolved BROKER_PORT bind socket.
        let expected_socket =
            mvm_core::config::vm_vsock_port_socket("w-broker-admitted", BROKER_PORT);
        let recorded = runner.broker.seen.lock().unwrap();
        let recorded = recorded.as_ref().expect("register was called");
        assert_eq!(recorded.vm_name, "w-broker-admitted");
        assert_eq!(recorded.tenant.as_deref(), Some("tenant-x"));
        assert_eq!(
            recorded.broker_listen_socket.as_deref(),
            Some(expected_socket.as_path())
        );

        // The spec carries the same socket as a GuestDials BROKER_PORT channel, so
        // the supervisor relay target and the daemon's bind path are identical.
        let specs = runner.driver.booted_specs();
        let broker = specs[0]
            .vsock
            .iter()
            .find(|p| p.service.port() == BROKER_PORT)
            .expect("admitted spec carries a BROKER_PORT channel");
        assert_eq!(broker.direction, crate::driver::VsockDirection::GuestDials);
        assert_eq!(broker.host_uds, expected_socket);
    }

    #[test]
    fn start_workload_broker_is_a_defused_no_op_when_unadmitted() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        // config() sets no tenant_id ⇒ unadmitted.
        let cfg = config("w-broker-unadmitted");
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "local",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload succeeds");

        // register is still called, but with no tenant + no broker socket.
        let recorded = runner.broker.seen.lock().unwrap();
        let recorded = recorded.as_ref().expect("register is still called");
        assert_eq!(recorded.tenant, None);
        assert_eq!(recorded.broker_listen_socket, None);

        // The spec carries NO BROKER_PORT channel, so a stray guest dial to
        // BROKER_PORT stays ECONNREFUSED (fail-closed).
        let specs = runner.driver.booted_specs();
        assert!(
            specs[0]
                .vsock
                .iter()
                .all(|p| p.service.port() != BROKER_PORT),
            "unadmitted VM must carry no broker port"
        );
    }

    #[test]
    fn stop_reaps_the_host_agent_tenant_ref_marker() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let vm_name = "runner-stop-reaps-broker";
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        // Plant the daemon-path tenant-ref marker `register` writes; the stop reap
        // must remove it, proving `reap_host_agent_services_from_state` ran.
        std::fs::write(state_dir.join("host-agent.tenant"), "tenant-x").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.stop(&VmId(vm_name.into())).expect("stop succeeds");

        assert!(
            !state_dir.join("host-agent.tenant").exists(),
            "stop must reap the host-agent registration marker"
        );
    }

    #[test]
    fn vmbackend_start_then_status_wait_stop_via_the_driver() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let exit = VmExitStatus {
            code: Some(0),
            success: true,
        };
        let runner = WorkloadRunner::new(
            MockDriver::with_exit(exit),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w");
        let cfg = VmStartConfig {
            name: "w".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        let id = runner.start(&cfg).expect("start succeeds");
        assert_eq!(id.0, "w");

        // attach hands back a MockRunningVm, so the lifecycle works with no real VM.
        assert_eq!(runner.status(&id).unwrap(), VmStatus::Running);
        assert_eq!(runner.wait(&id).unwrap(), exit);
        // stop reaps a nonexistent endpoint (no-op) then kills the attached handle.
        assert!(runner.stop(&VmId("w".into())).is_ok());
    }

    /// Write a `verb-grant.json` sidecar plus the host-signer public key
    /// under `vm_name`'s state dir, the shape the grant cmdline tokens read.
    fn seed_grant_sidecar_and_key(vm_name: &str) {
        let state_dir = mvm_core::config::vm_state_dir(vm_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        let nonce = Nonce::from_bytes([9u8; 16]);
        let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
        let envelope = VerbGrantEnvelope {
            pubkey_hex: "cc".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: VerbGrant {
                session_id: vm_name.to_string(),
                plan_nonce: nonce,
                not_after,
                verbs: vec![VerbId::new("run-entrypoint").unwrap()],
                sig: vec![0u8; 64],
            },
        };
        std::fs::write(
            state_dir.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.pub"), [0xEEu8; 32]).unwrap();
    }

    /// Seed only the host key — no verb-grant sidecar. Models the transient
    /// `machine run` path, which mints no grant.
    fn seed_host_key_only() {
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.pub"), [0xEEu8; 32]).unwrap();
    }

    /// A launch that mints no verb grant must still carry the host-signer
    /// anchor, or its guest agent has no pinned key to authenticate the control
    /// channel against, rejects every connection, and the run dies at its first
    /// RPC.
    ///
    /// The sibling test below covers the grant-*bearing* launch, and that was
    /// exactly the gap: the anchor used to be gated on the grant sidecar, so the
    /// grant-less shape shipped no anchor and nothing at this level noticed.
    /// Asserting the token builder alone did not catch it either — the
    /// regression only surfaced in an assembled cmdline.
    #[test]
    fn start_carries_the_host_anchor_without_a_grant_but_grants_no_authority() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        let vm_name = "runner-grantless-anchor";
        mvm_build::builder_vm::GuestSidecar::for_oci_run(vm_name, false, true)
            .write_to_dir(rootfs_dir.path())
            .unwrap();

        seed_host_key_only();

        let cfg = VmStartConfig {
            name: vm_name.into(),
            rootfs_path: rootfs.display().to_string(),
            network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
            ..Default::default()
        };

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let cmdline = &specs[0].cmdline;

        assert!(
            cmdline.contains("mvm.host_signer_pub="),
            "a grant-less launch must still pin the host anchor, or the agent \
             rejects every control connection: {cmdline}"
        );
        // Reachable, but no more privileged: authority stays sidecar-gated.
        assert!(
            !cmdline.contains("mvm.verb_grant="),
            "no grant was minted, so no grant token may appear: {cmdline}"
        );
        assert!(
            !cmdline.contains("mvm.require_grant="),
            "no grant was minted, so enforcement must not be demanded: {cmdline}"
        );
    }

    /// `WorkloadRunner::start` (the `VmBackend::start` production path) must
    /// assemble the same security-bearing kernel cmdline the raw HVF backend
    /// does — dm-verity, the plan-bound grant triple, vsock egress, and the
    /// runtime-source-policy token — instead of booting with an empty
    /// cmdline. Drives the whole trait method through a `MockDriver` and
    /// inspects the booted `VmmSpec` it recorded.
    #[test]
    fn start_assembles_the_security_cmdline_tokens_via_the_shared_assembler() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let rootfs_dir = tempfile::tempdir().unwrap();
        let rootfs = rootfs_dir.path().join("rootfs.ext4");
        let verity = rootfs_dir.path().join("rootfs.verity");
        let initrd = rootfs_dir.path().join("rootfs.initrd");
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(&verity, b"verity").unwrap();
        std::fs::write(&initrd, b"initrd").unwrap();
        // Overlay-aware sidecar next to the rootfs so `start`'s admission gate
        // (refuses a rootfs with no `/mvm/runtime` mount point) admits this boot.
        mvm_build::builder_vm::GuestSidecar::for_oci_run(
            "runner-security-cmdline-tokens",
            false,
            true,
        )
        .write_to_dir(rootfs_dir.path())
        .unwrap();

        let vm_name = "runner-security-cmdline-tokens";
        seed_grant_sidecar_and_key(vm_name);

        let cfg = VmStartConfig {
            name: vm_name.into(),
            rootfs_path: rootfs.display().to_string(),
            initrd_path: Some(mvm_vmm::host::cmdline::seed_universal_initramfs(
                home.path(),
            )),
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
            network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
            ..Default::default()
        };

        let driver = MockDriver::default();
        let guest = spawn_activation_guest(driver.clone(), vm_name);
        let runner = WorkloadRunner::new(
            driver,
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.start(&cfg).expect("start succeeds");
        guest.join().expect("guest thread");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let cmdline = &specs[0].cmdline;

        let require_grant = mvm_vmm::host::egress_bridge::require_grant_cmdline_token(vm_name)
            .expect("sidecar present ⇒ enforcement token");
        // Roothash and block-device tokens travel over vsock via
        // ActivateEnvironment, so the kernel cmdline only carries egress and
        // grant tokens.
        for needle in [
            "mvm.verb_grant=",
            require_grant.as_str(),
            "mvm.host_signer_pub=",
            "mvm.vsock_egress=1",
        ] {
            assert!(
                cmdline.contains(needle),
                "booted cmdline missing {needle:?}: {cmdline}"
            );
        }
    }

    /// The base console/earlycon/root bootargs the runner boots with must come
    /// from the driver (`VmmDriver::workload_base_bootargs`), not a hardcoded
    /// HVF default — proven by driving `start` through a `MockDriver` whose
    /// base uses `hvc0` rather than HVF's `ttyAMA0` and asserting the booted
    /// spec's cmdline carries that base.
    #[test]
    fn start_uses_the_drivers_base_bootargs_not_a_hardcoded_hvf_default() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let driver = MockDriver::default();
        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("runner-driver-base-bootargs");
        let cfg = VmStartConfig {
            name: "runner-driver-base-bootargs".into(),
            rootfs_path: rootfs,
            network_policy: NetworkPolicy::preset(mvm_core::network_policy::NetworkPreset::Dev),
            ..Default::default()
        };

        let runner = WorkloadRunner::new(
            driver.clone(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let cmdline = &specs[0].cmdline;

        let expected_base = driver.workload_base_bootargs(true);
        assert!(
            cmdline.starts_with(&expected_base),
            "cmdline did not start with the driver's base bootargs {expected_base:?}: {cmdline}"
        );
        assert!(
            !cmdline.contains("ttyAMA0"),
            "cmdline carried the hardcoded HVF console rather than the driver's: {cmdline}"
        );
    }

    fn spawn_activation_guest(driver: MockDriver, vm_name: &str) -> std::thread::JoinHandle<()> {
        use ed25519_dalek::SigningKey;
        use mvm_agentd::vsock::{AuthenticatedSession, GuestRequest, GuestResponse};

        let host_signer = [7u8; 32];
        let keys_dir = mvm_core::config::mvm_keys_dir();
        std::fs::create_dir_all(&keys_dir).unwrap();
        std::fs::write(keys_dir.join("host-signer.ed25519"), host_signer).unwrap();
        let vm_id = VmId(vm_name.to_string());

        std::thread::spawn(move || {
            let mut stream = {
                let mut found = None;
                for _ in 0..200 {
                    if let Some(end) = driver.take_guest_end(&vm_id, GUEST_AGENT_PORT) {
                        found = Some(end);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                found.expect("the runner connected to the guest agent port")
            };
            let host_key = SigningKey::from_bytes(&host_signer).verifying_key();
            let mut session = AuthenticatedSession::guest(
                &mut stream,
                SigningKey::from_bytes(&[9u8; 32]),
                &host_key,
            )
            .expect("guest handshake");
            let req: GuestRequest = session.read(&mut stream).expect("read request");
            assert!(
                matches!(req, GuestRequest::ActivateEnvironment(_)),
                "the first post-boot verb must be ActivateEnvironment, got: {req:?}"
            );
            session
                .write(&mut stream, &GuestResponse::ActivateEnvironmentAck)
                .expect("write ack");
        })
    }

    /// A boot that attached the universal initramfs must be sent
    /// `ActivateEnvironment` over the agent vsock port before the launch
    /// returns — proven by driving `start_workload` through the `MockDriver`
    /// loopback and answering as the guest: the host's request must BE the
    /// activation verb (not an operational RPC), and the launch must succeed
    /// on the ACK. This is the contract every runner driver (Firecracker,
    /// libkrun, HVF, QEMU) inherits: the driver's only part is a working
    /// `vsock_connect(GUEST_AGENT_PORT)`.
    #[test]
    fn start_workload_sends_activate_environment_for_a_universal_initramfs_boot() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        // An initramfs artifact under the shared cache is the discriminant
        // for the universal-initramfs boot path.
        let initrd = std::path::PathBuf::from(mvm_core::config::mvm_cache_dir())
            .join("initramfs")
            .join("test-version")
            .join("initramfs.cpio.gz");
        std::fs::create_dir_all(initrd.parent().expect("initramfs cache parent")).unwrap();
        std::fs::write(&initrd, b"initramfs").unwrap();

        let driver = MockDriver::default();
        let runner = WorkloadRunner::new(
            driver.clone(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let cfg = VmStartConfig {
            name: "runner-activation".into(),
            initrd_path: Some(initrd.to_string_lossy().into_owned()),
            ..config("runner-activation")
        };
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();

        // The guest side of the loopback authenticates, verifies that the first
        // request is the activation verb, and acknowledges it.
        let guest = spawn_activation_guest(driver, "runner-activation");

        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "local",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload succeeds once activation is ACKed");
        guest.join().expect("guest thread");
    }

    /// A legacy per-rootfs initramfs boot (an initrd NOT under the shared
    /// cache) is never sent `ActivateEnvironment` — the guest keeps its own
    /// PID 1 and the launch proceeds without the handshake.
    #[test]
    fn start_workload_skips_activation_for_a_legacy_initramfs_boot() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let legacy = home.path().join("rootfs.initrd");
        std::fs::write(&legacy, b"initrd").unwrap();

        let driver = MockDriver::default();
        let runner = WorkloadRunner::new(
            driver.clone(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let cfg = VmStartConfig {
            name: "runner-legacy-initrd".into(),
            initrd_path: Some(legacy.to_string_lossy().into_owned()),
            ..config("runner-legacy-initrd")
        };
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "local",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("a legacy initramfs boot needs no activation handshake");
        // No vsock connect was ever made for activation: the loopback guest
        // end registry is empty.
        assert!(
            driver
                .take_guest_end(&VmId("runner-legacy-initrd".into()), GUEST_AGENT_PORT)
                .is_none(),
            "a legacy initramfs boot must not connect for activation"
        );
    }

    fn disk_volume(host: &str, guest: &str, read_only: bool) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only,
            kind: mvm_core::vm_backend::VmVolumeKind::Disk,
            encrypted: false,
        }
    }

    fn dir_share_volume(host: &str, guest: &str) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            materialized_image: None,
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only: false,
            kind: mvm_core::vm_backend::VmVolumeKind::DirShare,
            encrypted: false,
        }
    }

    /// A `--volume` disk (claim 11's sealed app-dep disk, or any other
    /// `Disk`-kind volume) must reach a runner-booted guest both as an
    /// attached `BlockDev` and as an `mvm.uvols=` cmdline entry naming it —
    /// otherwise the guest has the bytes on `/dev/vdb` but no manifest saying
    /// what they are for.
    #[test]
    fn start_carries_a_disk_volume_into_both_blocks_and_the_uvols_token() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w-uvol");
        let cfg = VmStartConfig {
            name: "w-uvol".into(),
            rootfs_path: rootfs,
            volumes: vec![disk_volume("/vol/data.img", "/data", true)],
            ..Default::default()
        };
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];

        // The rootfs takes /dev/vda; the volume disk lands right after it.
        assert_eq!(
            spec.blocks
                .iter()
                .map(|b| b.device_node())
                .collect::<Vec<_>>(),
            vec!["/dev/vda", "/dev/vdb"]
        );
        assert_eq!(spec.blocks[1].source, PathBuf::from("/vol/data.img"));
        assert!(spec.blocks[1].read_only);

        assert!(
            spec.cmdline.contains("mvm.uvols=uvol0:"),
            "booted cmdline missing the uvols token: {}",
            spec.cmdline
        );
    }

    #[test]
    fn start_emits_no_uvols_token_when_there_are_no_volumes() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("w-no-uvol");
        let cfg = VmStartConfig {
            name: "w-no-uvol".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        runner.start(&cfg).expect("start succeeds");

        let specs = runner.driver.booted_specs();
        assert!(
            !specs[0].cmdline.contains("mvm.uvols="),
            "cmdline must carry no uvols token with no volumes: {}",
            specs[0].cmdline
        );
    }

    /// The lifted admission gate: `VmBackend::start` refuses a rootfs whose
    /// parent dir carries no overlay-aware sidecar (no `/mvm/runtime` mount
    /// point) before any endpoint spawn or boot, and on an admitted boot it
    /// records the per-VM runtime metadata the console accessible/sealed gate
    /// reads. Drives the whole trait method through a `MockDriver`.
    #[test]
    fn start_refuses_a_rootfs_without_the_overlay_sidecar_and_records_runtime_meta() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        // A rootfs whose parent dir carries no sidecar is refused before boot.
        let bare = tempfile::tempdir().unwrap();
        let bare_rootfs = bare.path().join("rootfs.ext4");
        std::fs::write(&bare_rootfs, b"rootfs").unwrap();
        let refused = VmStartConfig {
            name: "runner-gate-refused".into(),
            rootfs_path: bare_rootfs.display().to_string(),
            ..Default::default()
        };
        let err = runner
            .start(&refused)
            .expect_err("a rootfs with no overlay-aware sidecar must be refused");
        assert!(
            err.to_string().contains("mvm-meta.json"),
            "refusal must name the missing sidecar: {err}"
        );
        assert!(
            runner.driver.booted_specs().is_empty(),
            "the gate must fire before any boot"
        );

        // An overlay-aware rootfs is admitted, and start records runtime_meta so
        // the console accessible/sealed gate has a per-VM record to read.
        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("runner-gate-admitted");
        let admitted = VmStartConfig {
            name: "runner-gate-admitted".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        runner
            .start(&admitted)
            .expect("an overlay-aware rootfs is admitted");
        let meta = crate::base::runtime_meta::read("runner-gate-admitted")
            .expect("runtime_meta read")
            .expect("start records runtime_meta");
        assert_eq!(
            meta.rootfs_path.as_deref(),
            Some(admitted.rootfs_path.as_str())
        );
    }

    /// A `DirShare` volume has no `VmmSpec` representation on this driver
    /// seam. `start_workload` must refuse it before spawning the gating
    /// endpoint or the broker — never boot a VM missing a share the caller
    /// asked for.
    #[test]
    fn start_workload_refuses_a_dir_share_volume_before_any_side_effect() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = VmStartConfig {
            volumes: vec![dir_share_volume("/host/dir", "/mnt/share")],
            ..config("w-dirshare-refused")
        };
        let result = runner.start_workload(&WorkloadLaunchInputs {
            config: &cfg,
            tenant: "tenant-x",
            secrets: &[],
            redaction: &redaction,
            network_policy: &policy,
            cmdline: String::new(),
        });
        let message = match result {
            Ok(_) => panic!("a DirShare volume must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(message.contains("/host/dir"), "message: {message}");
        assert!(message.contains("/mnt/share"), "message: {message}");

        assert!(
            runner.driver.booted_specs().is_empty(),
            "refused start must never reach the driver"
        );
        assert!(
            runner.spawner.seen.lock().unwrap().is_none(),
            "refused start must never spawn the gating endpoint"
        );
        assert!(
            runner.broker.seen.lock().unwrap().is_none(),
            "refused start must never register the broker"
        );
    }

    #[test]
    fn vmbackend_name_and_capabilities_delegate_to_the_driver() {
        let driver = MockDriver::default();
        let want_name = driver.name().to_string();
        let want_caps = driver.capabilities();
        let runner = WorkloadRunner::new(
            driver,
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        assert_eq!(runner.name(), want_name);
        assert_eq!(runner.capabilities().vsock, want_caps.vsock);
        assert!(runner.is_available().unwrap());
    }

    #[test]
    fn vmbackend_kind_snapshot_security_and_channel_delegate_to_the_hvf_driver() {
        // Proves the runner reads these from the driver rather than the old
        // `BackendKind::Hvf` hardcode / the VmBackend trait's fail-closed
        // defaults — a runner wrapping a *different* driver would report that
        // driver's own values instead.
        let driver = HvfDriver::new();
        let want_kind = driver.kind();
        let want_snapshot = driver.snapshot_capability();
        let want_security_tier = driver.security_profile().tier;
        let id = VmId("kind-delegation-test-vm".into());
        let want_channel_err = driver.guest_channel_info(&id).is_err();
        let runner = WorkloadRunner::new(
            driver,
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        assert_eq!(runner.kind(), want_kind);
        assert_eq!(runner.kind(), BackendKind::Hvf);
        assert_eq!(runner.snapshot_capability(), want_snapshot);
        assert_eq!(runner.security_profile().tier, want_security_tier);
        assert_eq!(runner.guest_channel_info(&id).is_err(), want_channel_err);
    }

    #[test]
    fn start_workload_with_dev_console_threads_128_console_ports_into_spec() {
        use mvm_agentd::vsock::CONSOLE_PORT_BASE;
        let policy = egress_allowing_policy();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = VmStartConfig {
            dev_console: true,
            ..config("w-dev-console")
        };
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "t",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload with dev_console succeeds");

        let specs = runner.driver.booted_specs();
        let spec = &specs[0];

        // 3 standing + 128 console data = 131 vsock entries.
        assert_eq!(spec.vsock.len(), 131);

        // Every console port is in range and routed as HostDials.
        let console: Vec<_> = spec
            .vsock
            .iter()
            .filter(|p| p.service.port() > CONSOLE_PORT_BASE)
            .collect();
        assert_eq!(console.len(), 128);
        assert!(
            console
                .iter()
                .all(|p| p.direction == crate::driver::VsockDirection::HostDials),
            "console ports must be HostDials"
        );

        // Paths live under <state_dir>/vsock/ — the shared HVF vsock convention.
        let first = &console[0];
        assert!(
            first.host_uds.to_string_lossy().contains("/vsock/vsock-"),
            "path must be under vsock/ subdir: {}",
            first.host_uds.display()
        );
    }

    #[test]
    fn start_workload_without_dev_console_carries_only_three_vsock_entries() {
        let policy = egress_allowing_policy();
        let redaction = RedactionPolicy::default();
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let cfg = VmStartConfig {
            dev_console: false,
            ..config("w-sealed")
        };
        runner
            .start_workload(&WorkloadLaunchInputs {
                config: &cfg,
                tenant: "t",
                secrets: &[],
                redaction: &redaction,
                network_policy: &policy,
                cmdline: String::new(),
            })
            .expect("start_workload without dev_console succeeds");

        let specs = runner.driver.booted_specs();
        let spec = &specs[0];
        assert_eq!(
            spec.vsock.len(),
            3,
            "sealed prod boot must carry no console listeners"
        );
    }

    /// A spawned parent is claimable only once captured: the handle must carry
    /// the checkpoint a later claim verifies content and lineage against, and
    /// that checkpoint must carry saved memory — a rootfs-only capture would
    /// make every claim a cold boot.
    #[test]
    fn spawn_standby_captured_stamps_a_memory_carrying_checkpoint() {
        use mvm_core::checkpoint::CheckpointClass;

        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let rootfs = tmp.path().join("parent-rootfs.ext4");
        std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default().with_vm_full_rootfs(&rootfs),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let launch = standby_launch_config(&rootfs);
        let spec = standby_spec_for("parent-a", tmp.path(), &launch);

        let handle = runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
                    launch: Some(&launch),
                },
                &spec,
            )
            .unwrap();

        let id = handle
            .parent_checkpoint
            .expect("a captured parent must carry its checkpoint id");
        let meta = store.read_meta(&CheckpointId::new(id)).unwrap();
        assert_eq!(meta.class, CheckpointClass::VmFull);
        assert!(
            meta.content.iter().any(|b| b.name == "memory.bin"),
            "the capture must carry saved memory, got: {:?}",
            meta.content.iter().map(|b| &b.name).collect::<Vec<_>>()
        );
        // The parent is released once captured — a pool slot costs disk, not a
        // resident VM — and the handle says so.
        assert_eq!(handle.pid, 0, "a captured parent backs no live process");
        assert!(
            runner.driver.killed_vms().contains(&spec.id),
            "the captured parent must be stopped, got: {:?}",
            runner.driver.killed_vms()
        );
    }

    /// The launch a warm parent is spawned for: a plain sealed boot whose rootfs
    /// is the one the parent will attach.
    fn standby_launch_config(rootfs: &Path) -> VmStartConfig {
        VmStartConfig {
            name: "workload-a".into(),
            rootfs_path: rootfs.display().to_string(),
            kernel_path: Some("/img/kernel".into()),
            cpus: 2,
            memory_mib: 512,
            // Every launch carries the overlay triple — it is the only source
            // of the guest agent, so a parent warmed without one cannot reach
            // an agent to be captured.
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        }
    }

    /// A pool record for a parent of `rootfs`, booting no guest egress client.
    /// Tests that warm a parent *for a launch* go through [`standby_spec_for`]
    /// instead, so the record they match on is the one a real spawn would write.
    fn sample_standby_spec(
        id: &str,
        vm_state_dir: &Path,
        rootfs: &Path,
    ) -> mvm_core::vm_backend::StandbySpec {
        mvm_core::vm_backend::StandbySpec {
            id: id.to_string(),
            template_id: None,
            kernel_path: "/img/kernel".into(),
            kernel_sha256: "a".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            signing_key_path: "/keys/host-signer.ed25519".into(),
            signer_id: "host:test".into(),
            binding_nonce: "b".repeat(64),
            control_socket: vm_state_dir.join("control.sock").display().to_string(),
            vm_state_dir: vm_state_dir.display().to_string(),
            image_path: Some(rootfs.display().to_string()),
            image_sha256: Some("c".repeat(64)),
            root_strategy: Default::default(),
            vsock_egress: false,
        }
    }

    /// The pool record a spawn for `launch` would write: the base fixture plus
    /// the egress enablement the compat-key builder derives from that launch, so
    /// the parent boots the value a claim for the same launch would match on.
    fn standby_spec_for(
        id: &str,
        vm_state_dir: &Path,
        launch: &VmStartConfig,
    ) -> mvm_core::vm_backend::StandbySpec {
        mvm_core::vm_backend::StandbySpec {
            vsock_egress: mvm_vmm::host::egress_shared::effective_vsock_egress(launch),
            ..sample_standby_spec(id, vm_state_dir, Path::new(&launch.rootfs_path))
        }
    }

    /// A spawn-and-capture records a clean, pre-workload parent: the pool
    /// round-trip the CLI runs afterwards sees an idle standby, and — the
    /// invariant this test actually exercises — no substitution endpoint and no
    /// broker are ever stood up for it, unlike every real workload boot on this
    /// runner. Those two are the host-side authority a parent must never hold.
    #[test]
    fn spawn_standby_captured_records_a_parent_with_no_endpoint_and_no_broker() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let rootfs = tmp.path().join("parent-rootfs.ext4");
        std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default().with_vm_full_rootfs(&rootfs),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let launch = standby_launch_config(&rootfs);
        let spec = standby_spec_for("standby-test", &tmp.path().join("vm"), &launch);

        let handle = runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
                    launch: Some(&launch),
                },
                &spec,
            )
            .expect("spawn_standby_captured succeeds through the mock driver");

        let pool = crate::standby_pool::SupervisorStandbyPool::at(tmp.path().join("pool"));
        pool.record(&handle).unwrap();
        let recorded = pool.list().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0].state,
            mvm_core::vm_backend::StandbyState::Idle
        ));

        // The parent boots with no vsock channel at all: no egress relay, no
        // broker port, no exit report — so a stray guest dial to any of them
        // stays ECONNREFUSED. Only a claimed child gets those three; parents and
        // workloads live in disjoint namespaces and this is where that holds.
        let booted = runner.driver.booted_specs();
        assert_eq!(booted.len(), 1);
        assert!(
            booted[0].vsock.is_empty(),
            "parent boot must carry no vsock channel (no egress, broker or exit channel), got: {:?}",
            booted[0]
                .vsock
                .iter()
                .map(|p| p.service.port())
                .collect::<Vec<_>>()
        );

        // No substitution endpoint and no broker were stood up for the parent:
        // neither double was ever invoked, unlike every real `start_workload`.
        assert!(
            runner.spawner.seen.lock().unwrap().is_none(),
            "a standby parent must never get a substitution endpoint"
        );
        assert!(
            runner.broker.seen.lock().unwrap().is_none(),
            "a standby parent must never get a host-services broker"
        );
    }

    /// A parent's cmdline gets the same truncation refusal a workload's does,
    /// and needs it more: a child inherits the parent's cmdline out of restored
    /// memory rather than deriving its own, so a parent booted with its trailing
    /// tokens silently dropped by the kernel hands that loss to every child.
    #[test]
    fn spawn_standby_captured_refuses_a_parent_cmdline_the_kernel_would_truncate() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let rootfs = tmp.path().join("parent-rootfs.ext4");
        std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default().with_vm_full_rootfs(&rootfs),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let mut launch = standby_launch_config(&rootfs);
        // A sealed boot; the universal initramfs moves the roothash off the
        // cmdline, so force an overflow with an oversized verb grant instead.
        launch.verity_path = Some(tmp.path().join("rootfs.verity").display().to_string());
        launch.roothash = Some("a".repeat(4096));
        launch.initrd_path = Some(mvm_vmm::host::cmdline::seed_universal_initramfs(
            home.path(),
        ));
        let state_dir = mvm_core::config::vm_state_dir("parent-oversized");
        std::fs::create_dir_all(&state_dir).unwrap();
        let nonce = mvm_core::plan::Nonce::from_bytes([3u8; 16]);
        let not_after = mvm_core::time::parse_iso8601("2099-01-01T00:00:00Z").unwrap();
        let envelope = mvm_core::protocol::vm_backend::VerbGrantEnvelope {
            pubkey_hex: "cc".repeat(32),
            plan_nonce_hex: nonce.as_hex().to_string(),
            predecessor_session_id: None,
            predecessor_plan_nonce_hex: None,
            grant: mvm_core::plan::VerbGrant {
                session_id: "parent-oversized".into(),
                plan_nonce: nonce,
                not_after,
                verbs: vec![mvm_core::plan::VerbId::new(&"a".repeat(4000)).unwrap()],
                sig: vec![0u8; 64],
            },
        };
        std::fs::write(
            state_dir.join("verb-grant.json"),
            serde_json::to_vec(&envelope).unwrap(),
        )
        .unwrap();
        // Derive the spec from this launch: the compat key now carries the
        // launch's egress enablement, so a spec built from the rootfs alone
        // could refuse for a mismatched key rather than the oversized cmdline
        // this test is about.
        let spec = standby_spec_for("parent-oversized", tmp.path(), &launch);

        let err = runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
                    launch: Some(&launch),
                },
                &spec,
            )
            .expect_err("an oversized parent cmdline must be refused before the boot");

        assert!(
            matches!(err, StandbyError::SpawnFailed(ref m) if m.contains("command line")),
            "expected a SpawnFailed naming the kernel command line, got: {err:?}"
        );
        assert!(
            runner.driver.booted_specs().is_empty(),
            "nothing may boot before the refusal"
        );
    }

    /// A spawn with no launch to mirror is refused outright. The alternative —
    /// inventing a default boot shape — is what produced a parent that booted a
    /// bare rootfs while every workload booted a verity-sealed stack plus the
    /// runtime overlay carrying the guest agent.
    #[test]
    fn spawn_standby_captured_refuses_without_the_launch_it_must_mirror() {
        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let rootfs = tmp.path().join("parent-rootfs.ext4");
        std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default().with_vm_full_rootfs(&rootfs),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let spec = sample_standby_spec("parent-a", tmp.path(), &rootfs);

        let err = runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
                    launch: None,
                },
                &spec,
            )
            .expect_err("a parent cannot be assembled without the launch it serves");

        assert!(
            matches!(err, StandbyError::SpawnFailed(ref m) if m.contains("launch config")),
            "expected a SpawnFailed naming the missing launch, got: {err:?}"
        );
        assert!(
            runner.driver.booted_specs().is_empty(),
            "nothing may boot before the refusal"
        );
    }

    /// The same guard as `standby_boot`'s, but through the runner's real
    /// wiring: the shipped defect was not that the mappers disagreed, it was
    /// that the spawn path never called them. Boot a sealed, overlay-carrying
    /// launch as a workload and then warm a parent for it, and the two specs
    /// the driver was handed must describe the same guest.
    #[test]
    fn the_parent_and_the_workload_boot_the_same_shape_through_the_runner() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let (dir, rootfs) = overlay_aware_rootfs("shape-parity");
        std::fs::write(dir.path().join("rootfs.verity"), b"verity").unwrap();

        let launch = VmStartConfig {
            name: "shape-parity".into(),
            rootfs_path: rootfs.clone(),
            kernel_path: Some("/img/kernel".into()),
            initrd_path: Some(mvm_vmm::host::cmdline::seed_universal_initramfs(
                home.path(),
            )),
            verity_path: Some(dir.path().join("rootfs.verity").display().to_string()),
            roothash: Some("a".repeat(64)),
            runtime_overlay_path: Some(dir.path().join("overlay.ext4").display().to_string()),
            runtime_overlay_verity_path: Some(
                dir.path().join("overlay.verity").display().to_string(),
            ),
            runtime_overlay_roothash: Some("b".repeat(64)),
            runtime_overlay_version: Some("0.18.0".into()),
            cpus: 2,
            memory_mib: 512,
            ..Default::default()
        };

        let store = CheckpointStore::at(home.path().join("checkpoints"));
        let driver = MockDriver::default().with_vm_full_rootfs(Path::new(&rootfs));
        let guest = spawn_activation_guest(driver.clone(), "shape-parity");
        let runner = WorkloadRunner::new(
            driver,
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        runner.start(&launch).expect("workload boots");
        guest.join().expect("guest thread");
        let spec = standby_spec_for(
            "standby-parity",
            &home.path().join("standby-parity"),
            &launch,
        );
        runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
                    launch: Some(&launch),
                },
                &spec,
            )
            .expect("warm parent spawns for that launch");

        let booted = runner.driver.booted_specs();
        assert_eq!(booted.len(), 2, "one workload boot, then one parent boot");
        let (workload, parent) = (&booted[0], &booted[1]);
        // Non-vacuity: the fixture must actually exercise the full sealed stack,
        // or "the two match" would say nothing.
        assert_eq!(
            workload.blocks.len(),
            4,
            "fixture must boot rootfs + verity + overlay + overlay verity"
        );
        assert_eq!(
            parent.blocks, workload.blocks,
            "the warm parent must attach the workload's whole disk stack, overlay included"
        );
        assert_eq!(
            without_per_boot_tokens(&parent.cmdline),
            without_per_boot_tokens(&workload.cmdline)
        );
        assert!(!parent.cmdline.contains("mvm.hostname="));
        assert_eq!(parent.kernel, workload.kernel);
        assert_eq!(parent.initramfs, workload.initramfs);
    }

    /// The same parity, for the launch shape the pool used to refuse: one whose
    /// policy allows egress.
    ///
    /// A restored child inherits its cmdline from the parent's saved memory, so
    /// the only way a warm child ends up with the guest egress client a cold boot
    /// would have started is for the parent to have started it. This drives both
    /// paths through the real runner wiring and requires the two specs to be
    /// equal — and it names the token, so a failure says which side lost it. The
    /// parent still gets no substitution endpoint and no broker: what it boots is
    /// the enablement, not the authority.
    #[test]
    fn a_parent_warmed_for_an_egress_allowing_launch_boots_that_launchs_shape() {
        use mvm_core::network_policy::HostPort;

        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        // `_dir` holds the rootfs's temp dir alive for the whole test.
        let (_dir, rootfs) = overlay_aware_rootfs("egress-parity");
        let launch = VmStartConfig {
            name: "egress-parity".into(),
            rootfs_path: rootfs.clone(),
            kernel_path: Some("/img/kernel".into()),
            network_policy: NetworkPolicy::allow_list(vec![HostPort::new("api.example.com", 443)]),
            cpus: 2,
            memory_mib: 512,
            runtime_overlay_path: Some("/img/runtime.ext4".into()),
            runtime_overlay_verity_path: Some("/img/runtime.verity".into()),
            runtime_overlay_roothash: Some("b".repeat(64)),
            ..Default::default()
        };

        let store = CheckpointStore::at(home.path().join("checkpoints"));
        let runner = WorkloadRunner::new(
            MockDriver::default().with_vm_full_rootfs(Path::new(&rootfs)),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        runner.start(&launch).expect("workload boots");
        let spec = standby_spec_for(
            "standby-egress-parity",
            &home.path().join("standby-egress-parity"),
            &launch,
        );
        assert!(
            spec.vsock_egress,
            "the compat key for this launch must ask for an egress-enabled parent"
        );
        runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
                    launch: Some(&launch),
                },
                &spec,
            )
            .expect("warm parent spawns for an egress-allowing launch");

        let booted = runner.driver.booted_specs();
        assert_eq!(booted.len(), 2, "one workload boot, then one parent boot");
        let (workload, parent) = (&booted[0], &booted[1]);
        assert!(
            workload.cmdline.contains("mvm.vsock_egress=1"),
            "fixture must boot the guest egress client: {}",
            workload.cmdline
        );
        assert!(
            parent.cmdline.contains("mvm.vsock_egress=1"),
            "the parent must boot it too, or every child restored from it has no network: {}",
            parent.cmdline
        );
        assert_eq!(
            without_per_boot_tokens(&parent.cmdline),
            without_per_boot_tokens(&workload.cmdline)
        );
        assert!(!parent.cmdline.contains("mvm.hostname="));
        assert_eq!(parent.blocks, workload.blocks);
        assert!(
            !parent.cmdline.contains("api.example.com"),
            "the parent's cmdline must name no destination: {}",
            parent.cmdline
        );
        assert!(
            parent.vsock.is_empty(),
            "an egress-enabled parent still wires no egress channel to dial"
        );
        assert!(!parent.trusted_builder);
    }

    // ── Warm claim: the guarded fork of a clean parent into a fresh child ──────

    use mvm_core::checkpoint::CheckpointDigest;
    use mvm_core::crypto::vmgenid::GENID_BYTES;
    use mvm_core::vm_backend::StandbyState;

    use crate::checkpoint::{CaptureFsQuickParams, capture_fs_quick};

    /// A `CheckpointChainAnchor` double: reports the parent as audited (echoing
    /// its own recomputed creation digest) so the lineage gate passes, and every
    /// other checkpoint as un-audited.
    struct ClaimTestAnchor {
        verdicts: std::collections::HashMap<String, CheckpointDigest>,
    }

    impl ClaimTestAnchor {
        fn audited(meta: &CheckpointMeta) -> Self {
            let mut verdicts = std::collections::HashMap::new();
            verdicts.insert(meta.id.to_string(), meta.compute_meta_digest());
            Self { verdicts }
        }

        /// No signed creation entry for any checkpoint → the lineage gate refuses
        /// the parent as un-audited.
        fn unaudited() -> Self {
            Self {
                verdicts: std::collections::HashMap::new(),
            }
        }
    }

    impl CheckpointChainAnchor for ClaimTestAnchor {
        fn recorded_creation_digest(
            &self,
            meta: &CheckpointMeta,
        ) -> Result<Option<CheckpointDigest>> {
            Ok(self.verdicts.get(&meta.id.to_string()).cloned())
        }
    }

    /// An `NetworkEndpointSpawner` double that keys its returned socket on the vm name it
    /// is handed — mirroring `RealNetworkEndpointSpawner` — and records that name, so a
    /// test can prove the child endpoint is keyed on the child's own id and the
    /// parent got none, with no real endpoint process.
    #[derive(Default)]
    struct KeyingSpawner {
        seen_vm: Mutex<Option<String>>,
    }

    impl NetworkEndpointSpawner for KeyingSpawner {
        fn spawn(&self, req: &NetworkEndpointSpawnRequest<'_>) -> Result<SpawnedEndpoint> {
            *self.seen_vm.lock().unwrap() = Some(req.vm_name.to_string());
            Ok(SpawnedEndpoint {
                egress_uds: vm_network_endpoint_socket(req.vm_name),
                identity_drive: None,
            })
        }
    }

    /// Seed a clean, audited, pre-workload parent checkpoint and return
    /// `(store, snapshots, parent_id, parent_meta)`. With `with_overlay_sidecar`
    /// the source rootfs carries an overlay-aware sidecar so its clone clears the
    /// same host gate a cold boot runs; without it, the child's overlay-contract
    /// gate refuses — the wiring witness. The `TempDir`s must outlive the stores.
    fn seed_audited_parent(
        store_root: &Path,
        src_root: &Path,
        with_overlay_sidecar: bool,
    ) -> (
        CheckpointStore,
        FsSnapshotStore,
        CheckpointId,
        CheckpointMeta,
    ) {
        seed_audited_parent_with_grants(store_root, src_root, with_overlay_sidecar, None)
    }

    /// Seed a warm parent whose sealed record carries `grants`, so a claim has a
    /// real permission set to be bounded against.
    fn seed_audited_parent_with_grants(
        store_root: &Path,
        src_root: &Path,
        with_overlay_sidecar: bool,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> (
        CheckpointStore,
        FsSnapshotStore,
        CheckpointId,
        CheckpointMeta,
    ) {
        let checkpoints = CheckpointStore::at(store_root.join("checkpoints"));
        let snapshots = FsSnapshotStore::new(store_root.join("snapshots")).unwrap();

        let rootfs = src_root.join("rootfs.ext4");
        std::fs::write(&rootfs, b"clean-parent-rootfs").unwrap();
        if with_overlay_sidecar {
            // runtime_lean=true so the overlay sidecar clears the gate under every
            // runtime-source policy, exactly like the cold-boot admission tests.
            mvm_build::builder_vm::GuestSidecar::for_oci_run("warm-parent", false, true)
                .write_to_dir(src_root)
                .unwrap();
        }

        let parent_id = CheckpointId::new("warm-parent-cp");
        let parent_meta = capture_fs_quick(
            &checkpoints,
            CaptureFsQuickParams {
                id: parent_id.clone(),
                vm_name: "warm-parent".into(),
                rootfs,
                supervisor_config_digest: "d".into(),
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
                grants,
            },
        )
        .unwrap();
        let snapshot_id = format!(
            "checkpoint-{parent_id}-content-{}",
            mvm_core::checkpoint::content_manifest_digest(&parent_meta.content)
        );
        snapshots
            .create(
                &mvm_fs::snapshot_store::SnapshotId::with_digest(
                    snapshot_id.clone(),
                    mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string(),
                ),
                &checkpoints.content_dir(&parent_id),
            )
            .unwrap();
        let parent_meta = parent_meta.with_snapshot_id(snapshot_id);
        checkpoints.write_meta(&parent_meta).unwrap();
        (checkpoints, snapshots, parent_id, parent_meta)
    }

    #[test]
    fn resident_claim_accepts_a_valid_signed_bundle_manifest_without_hashing_blobs() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let manifest_digest =
            mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string();
        let snapshot_id = parent_meta.snapshot_id.as_deref().unwrap();
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().unwrap();
        mvm_core::crypto::snapshot_sign::sign_manifest(
            &snapshots.root().join(snapshot_id),
            &manifest_digest,
            &identity.signing,
        )
        .unwrap();
        let parent = parent_meta.clone();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent);
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        verify_resident_snapshot_manifest(&ctx, &parent)
            .expect("a host-signed resident bundle manifest must verify");

        std::fs::write(
            snapshots
                .root()
                .join(snapshot_id)
                .join(mvm_core::crypto::snapshot_sign::MANIFEST_SIGNATURE_FILENAME),
            b"tampered",
        )
        .unwrap();
        assert!(
            verify_resident_snapshot_manifest(&ctx, &parent).is_err(),
            "a tampered signed manifest must fail closed"
        );
        drop(env);
    }

    #[test]
    fn resident_claim_creates_no_child_restore_bundle() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();
        let snapshot_id = parent_meta.snapshot_id.as_deref().unwrap();
        let manifest_digest =
            mvm_core::checkpoint::content_manifest_digest(&parent_meta.content).to_string();
        let identity = mvm_core::crypto::snapshot_sign::host_snapshot_identity().unwrap();
        mvm_core::crypto::snapshot_sign::sign_manifest(
            &snapshots.root().join(snapshot_id),
            &manifest_digest,
            &identity.signing,
        )
        .unwrap();

        crate::base::runtime_meta::record_from_start_config(
            "warm-parent",
            StartMode::Detached,
            &VmStartConfig {
                name: "warm-parent".into(),
                rootfs_path: src.path().join("rootfs.ext4").display().to_string(),
                ..Default::default()
            },
        )
        .unwrap();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::unaudited();
        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );
        let runner = WorkloadRunner::new(
            MockDriver::default().with_resident_handoff(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let child = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect("resident claim");
        let child_dir = vm_state_dir(&child.0);
        assert!(child_dir.is_dir());
        assert!(
            !child_dir.join("rootfs.ext4").exists(),
            "resident claims must not materialize a child restore bundle"
        );
        assert_eq!(runner.driver.forked_children().len(), 1);
        reclaim_consumed_resident_checkpoint_at(
            checkpoints.root(),
            snapshots.root(),
            &parent_meta.id,
            parent_meta.snapshot_id.as_deref(),
        )
        .expect("resident checkpoint cleanup is idempotent");
        assert!(
            !checkpoints.dir_for(&parent_id).exists(),
            "committed resident claims must reclaim the consumed checkpoint payload"
        );
        assert!(
            !snapshots.root().join(snapshot_id).exists(),
            "committed resident claims must reclaim the consumed snapshot payload"
        );
        drop(env);
    }

    /// Build a signed, admitted child plan whose bound image digest is the
    /// parent's own verified rootfs content-address (claim-8 authority), the way
    /// the CLI mints it before handing the runner the claim.
    fn signed_child_plan_json(image_sha256: &str) -> String {
        signed_child_plan_json_with_verbs(image_sha256, None)
    }

    fn signed_child_plan_json_with_grants(
        image_sha256: &str,
        grants: Option<mvm_contract::grants::Grants>,
    ) -> String {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("tenant-x")
            .grants(grants)
            .build();
        plan.image.sha256 = image_sha256.to_string();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap()
    }

    fn signed_child_plan_json_with_verbs(
        image_sha256: &str,
        agent_verbs: Option<Vec<VerbId>>,
    ) -> String {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("tenant-x")
            .build();
        plan.image.sha256 = image_sha256.to_string();
        plan.agent_verbs = agent_verbs;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap()
    }

    #[test]
    fn admitted_network_limits_are_extracted_without_defaulting() {
        let expected = mvm_core::plan::NetworkLimits::builder()
            .max_tcp_flows(7)
            .max_udp_associations(5)
            .max_dns_bindings(3)
            .max_ingress_listeners(2)
            .build()
            .unwrap();
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.network_limits = expected;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let json =
            serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap();

        assert_eq!(admitted_network_limits(Some(&json)).unwrap(), expected);
        assert_eq!(
            admitted_network_limits(None).unwrap(),
            mvm_core::plan::NetworkLimits::default()
        );
    }

    #[derive(Default)]
    struct TestChildGrantIssuer {
        seen_child: Mutex<Option<String>>,
    }

    impl ChildGrantIssuer for TestChildGrantIssuer {
        fn issue(&self, config: &VmStartConfig) -> Result<Option<VerbGrantEnvelope>> {
            let plan_json = config.plan_json.as_deref().context("child plan missing")?;
            let plan = mvm_core::plan::plan_from_admitted_json(plan_json)?;
            let Some(verbs) = plan.agent_verbs else {
                return Ok(None);
            };
            *self.seen_child.lock().unwrap() = Some(config.name.clone());
            Ok(Some(VerbGrantEnvelope {
                pubkey_hex: "ab".repeat(32),
                plan_nonce_hex: plan.nonce.as_hex().to_string(),
                predecessor_session_id: None,
                predecessor_plan_nonce_hex: None,
                grant: mvm_core::plan::VerbGrant {
                    session_id: config.name.clone(),
                    plan_nonce: plan.nonce,
                    not_after: plan.valid_until,
                    verbs,
                    sig: vec![3u8; 64],
                },
            }))
        }
    }

    fn idle_parent_handle(id: &str, control_socket: &Path) -> StandbyHandle {
        StandbyHandle {
            id: id.to_string(),
            template_id: None,
            control_socket: control_socket.display().to_string(),
            pid: 0,
            kernel_sha256: "k".repeat(64),
            vcpus: 2,
            mem_mib: 512,
            binding_nonce: "b".repeat(64),
            spawned_unix_secs: 1,
            state: StandbyState::Idle,
            image_sha256: None,
            root_strategy: Default::default(),
            parent_checkpoint: None,
            preloaded_child_vm_name: None,
            vsock_egress: false,
        }
    }

    fn admitted_child_claim(rootfs: &Path, plan_json: String) -> StandbyClaim {
        StandbyClaim {
            start_config: Some(VmStartConfig {
                name: "unused-cold".into(),
                rootfs_path: rootfs.display().to_string(),
                tenant_id: Some("tenant-x".into()),
                ..Default::default()
            }),
            rootfs_path: rootfs.display().to_string(),
            tenant_id: "tenant-x".into(),
            audit_dir: rootfs.with_file_name("audit"),
            gateway_audit_socket: rootfs.with_file_name("gw-audit.sock"),
            gateway_events_socket: None,
            plan_json,
            bundle_json: None,
            network_policy: egress_allowing_policy(),
        }
    }

    /// The positive path: `claim_standby` forks a clean, audited parent into a
    /// fresh, admitted child that carries a fresh identity on every axis the fork
    /// controls, its own isolated endpoint, the overlay gate a cold boot runs, and
    /// a fresh VMGenID delivered with the boot.
    #[test]
    fn claim_produces_fresh_identity_and_isolated_endpoint() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json_with_verbs(
                &parent_digest,
                Some(vec![VerbId::new("run-entrypoint").unwrap()]),
            ),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let grant_issuer = TestChildGrantIssuer::default();
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: Some(&grant_issuer),
        };

        let child = runner.claim_standby(&ctx, &handle, &claim).expect("claim");

        // Fresh identity: the child differs from the parent and gets a fresh name.
        assert_ne!(child.0, handle.id, "child VmId must differ from the parent");
        assert!(
            child.0.starts_with("vm-"),
            "child gets a fresh registry name: {}",
            child.0
        );

        // Surface 5: the child's endpoint is keyed on its own fresh id, and the
        // factory parent never got one.
        let seen = runner.spawner.seen_vm.lock().unwrap().clone();
        assert_eq!(
            seen.as_deref(),
            Some(child.0.as_str()),
            "the endpoint is keyed on the child's own id"
        );
        assert_ne!(
            seen.as_deref(),
            Some(handle.id.as_str()),
            "the parent, a factory, gets no substitution endpoint"
        );

        // Surface 3: the fork delivered a fresh VMGenID bound to the child's
        // content-address, at the boot call — before any guest randomness consumer
        // runs — so the child's CSPRNG cannot share the parent's state.
        let forks = runner.driver.forked_children();
        assert_eq!(forks.len(), 1, "exactly one child fork");
        assert_eq!(forks[0].child_vm_name, child.0);
        assert_ne!(
            forks[0].genid.token, [0u8; GENID_BYTES],
            "a clean parent's baseline token is zero; the child gets a fresh non-zero one"
        );
        assert_eq!(
            forks[0].genid.content_hash, parent_digest,
            "the fresh token is bound to the child's content-address"
        );

        // The fork alone only resumes the child on the parent's saved memory, so
        // the claim also handed that same token to the child's guest agent and
        // committed only once the guest reported it had rotated onto it.
        let delivered = runner.driver.delivered_child_identities();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].child_vm_name, child.0);
        assert_eq!(delivered[0].token, forks[0].genid.token);
        let delivered_grant = delivered[0]
            .grant_envelope
            .as_ref()
            .expect("the child grant rides the post-restore handshake");
        assert_eq!(delivered_grant.grant.session_id, child.0);
        assert_eq!(
            delivered_grant.grant.verbs,
            vec![VerbId::new("run-entrypoint").unwrap()]
        );
        assert_eq!(
            grant_issuer.seen_child.lock().unwrap().as_deref(),
            Some(child.0.as_str())
        );

        // The runner-side overlay-contract gate ran on the materialized child:
        // its dir carries the overlay sidecar the clone rode plus the rootfs.
        let child_dir = mvm_core::config::vm_state_dir(&child.0);
        assert!(
            child_dir
                .join(mvm_build::builder_vm::SIDECAR_FILENAME)
                .exists(),
            "the overlay sidecar rode the clone into the child dir"
        );
        assert!(
            child_dir.join("rootfs.ext4").exists(),
            "the child rootfs was materialized from the parent's content"
        );

        // The parent was reserved (marked Claimed) atomically, never left idle for
        // a second claim to grab.
        assert_eq!(
            pool.load("warm-parent").unwrap().state,
            StandbyState::Claimed,
            "the parent is reserved so a concurrent claim cannot double-claim it"
        );
    }

    /// Where a claimed child's egress *destinations* come from: its own launch
    /// policy, threaded into its own endpoint at claim time.
    ///
    /// This is what makes keying the pool on the enablement boolean sound. The
    /// parent boots only whether a guest egress client starts; every host:port a
    /// workload may reach is resolved here, per child, from that child's policy —
    /// so a shared parent has no launch's allow-list to hand to the next claim.
    #[test]
    fn a_claimed_childs_endpoint_gets_its_own_launchs_allow_list() {
        use mvm_core::network_policy::HostPort;

        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let mut handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        // The parent was warmed for an egress-enabled launch, so it is claimable
        // by one.
        handle.vsock_egress = true;
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let policy = NetworkPolicy::allow_list(vec![
            HostPort::new("api.example.com", 443),
            HostPort::new("logs.example.com", 443),
        ]);
        let mut claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );
        claim.network_policy = policy.clone();

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        runner
            .claim_standby(&ctx, &handle, &claim)
            .expect("claim an egress-enabled parent");

        let seen = runner.spawner.seen.lock().unwrap();
        let recorded = seen.as_ref().expect("the child got its own endpoint");
        assert_eq!(
            recorded.policy, policy,
            "the child's endpoint must enforce the launch's own allow-list, not the parent's"
        );
    }

    /// A channel set described independently of which VM owns it: each port's
    /// number, direction, and where its host socket sits *relative to that VM's
    /// own* socket and state dirs. Two VMs' descriptions compare equal exactly
    /// when they carry the same channels wired to the same per-VM locations —
    /// and the relativization keeps that true even when one VM's name is long
    /// enough to push its sockets into the short hashed namespace.
    fn channel_shape(
        channels: &[crate::driver::VsockPort],
        vm: &str,
    ) -> Vec<(u32, crate::driver::VsockDirection, String)> {
        // Both roots collapse to one label on purpose. A VM's socket root is its
        // state dir until the path grows long enough to overflow the Unix-socket
        // limit, at which point it becomes a short hashed namespace instead —
        // which of the two a given VM landed on is that fallback's business, not
        // a difference in the channel set. Labelling them apart would report two
        // VMs as carrying different channels whenever only one crossed the limit.
        // Longest root first so an equal-or-nested root cannot mask a deeper one.
        let mut roots = [mvm_core::config::vm_socket_dir(vm), vm_state_dir(vm)];
        roots.sort_by_key(|r| std::cmp::Reverse(r.as_os_str().len()));
        channels
            .iter()
            .map(|p| {
                let where_ = roots
                    .iter()
                    .find_map(|root| {
                        p.host_uds
                            .strip_prefix(root)
                            .ok()
                            .map(|rest| format!("<vm>/{}", rest.display()))
                    })
                    .unwrap_or_else(|| p.host_uds.display().to_string());
                (p.service.port(), p.direction, where_)
            })
            .collect()
    }

    /// One cold boot and one warm claim on the same runner, so the two host
    /// channel sets the driver was handed can be compared directly.
    struct ColdAndWarm {
        driver: MockDriver,
        broker: Option<RecordedBroker>,
        cold_vm: String,
        child: VmId,
        /// Held so the assertions resolve the same `MVM_HOME` the run did.
        /// Declaration order is drop order: the home dir goes, then the env is
        /// restored, then the lock is released.
        _home: tempfile::TempDir,
        _env: TestEnv,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    /// Boot an admitted workload cold, then claim a child off a clean audited
    /// parent seeded from the same rootfs — both through one runner, with the
    /// endpoint spawner that keys its socket on the VM name (as the real one
    /// does), so the two channel sets differ only where the VM identity does.
    ///
    /// The isolated `MVM_HOME` is handed back alive, so the caller's assertions
    /// resolve the same per-VM paths the run wrote.
    fn cold_boot_then_claim() -> ColdAndWarm {
        let lock = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();
        let rootfs = src.path().join("rootfs.ext4");

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );

        // The cold boot: an admitted launch (tenant set), so it carries the
        // broker channel a claimed child must also get.
        let cold_vm = "cold-admitted-workload".to_string();
        runner
            .start(&VmStartConfig {
                name: cold_vm.clone(),
                rootfs_path: rootfs.display().to_string(),
                kernel_path: Some("/img/kernel".into()),
                tenant_id: Some("tenant-x".into()),
                network_policy: egress_allowing_policy(),
                cpus: 2,
                memory_mib: 512,
                ..Default::default()
            })
            .expect("the cold admitted workload boots");

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);
        let claim = admitted_child_claim(&rootfs, signed_child_plan_json(&parent_digest));

        let child = runner
            .claim_standby(
                &ClaimContext {
                    pool: &pool,
                    checkpoints: &checkpoints,
                    snapshots: &snapshots,
                    anchor: &anchor,
                    parent_checkpoint: &parent_id,
                    registry_path: &registry_path,
                    grant_issuer: None,
                },
                &handle,
                &claim,
            )
            .expect("claim");

        ColdAndWarm {
            driver: runner.driver.clone(),
            broker: runner.broker.seen.lock().unwrap().take(),
            cold_vm,
            child,
            _home: home,
            _env: env,
            _lock: lock,
        }
    }

    /// A claimed child must reach the same host-side channels a cold-booted
    /// workload does. Asserted as an equality against the cold boot's own set
    /// rather than as a list of ports: a channel added to the workload's set and
    /// not to the claim's would leave a claimed child silently less capable than
    /// a cold-booted one, and only an equality catches that.
    #[test]
    fn claim_hands_the_child_the_same_host_channels_a_cold_boot_gets() {
        use mvm_agentd::vsock::{GUEST_AGENT_PORT, WORKLOAD_EXIT_PORT};

        let run = cold_boot_then_claim();

        let booted = run.driver.booted_specs();
        assert_eq!(booted.len(), 1, "one cold workload boot");
        let cold = &booted[0].vsock;

        // Non-vacuity: the fixture must actually exercise all four standing
        // channels, or "the two match" would say nothing. These are the three
        // the fork used to drop, plus the agent RPC.
        let ports: Vec<u32> = cold.iter().map(|p| p.service.port()).collect();
        for (port, what) in [
            (EGRESS_PORT, "the gated egress endpoint"),
            (BROKER_PORT, "host.audit.v1 / host.secrets.v1"),
            (WORKLOAD_EXIT_PORT, "the guest's exit-code report"),
            (GUEST_AGENT_PORT, "the agent RPC"),
        ] {
            assert!(
                ports.contains(&port),
                "fixture must exercise {what} (port {port}), got {ports:?}"
            );
        }

        let forks = run.driver.forked_children();
        assert_eq!(forks.len(), 1, "exactly one child fork");
        assert_eq!(
            channel_shape(&forks[0].channels, &run.child.0),
            channel_shape(cold, &run.cold_vm),
            "a claimed child must be handed exactly the channel set a cold boot wires"
        );
    }

    /// The child's broker is registered on the very socket its `BROKER_PORT`
    /// channel relays to, and under the claim's tenant — otherwise the guest
    /// dials a path nothing is bound to and `host.audit.v1` / `host.secrets.v1`
    /// are silently unavailable, a real degradation versus a cold boot.
    #[test]
    fn claim_registers_the_childs_broker_on_the_socket_it_wired() {
        let run = cold_boot_then_claim();

        let broker = run
            .broker
            .as_ref()
            .expect("a claimed child registers a host-services broker");
        assert_eq!(
            broker.vm_name, run.child.0,
            "the broker is registered for the child's own id, never the parent's"
        );
        assert_eq!(broker.tenant.as_deref(), Some("tenant-x"));
        assert!(broker.services.is_empty());

        let wired = run.driver.forked_children()[0]
            .channels
            .iter()
            .find(|p| p.service.port() == BROKER_PORT)
            .map(|p| p.host_uds.clone())
            .expect("the child carries a broker channel");
        assert_eq!(
            broker.broker_listen_socket.as_ref(),
            Some(&wired),
            "the broker must bind the same path the child's BROKER_PORT relays to"
        );
        assert_eq!(
            wired,
            mvm_core::config::vm_vsock_port_socket_at(&vm_state_dir(&run.child.0), BROKER_PORT),
            "the broker socket lives under the child's own state dir"
        );
    }

    /// Count child (`vm-*`) dirs left under the VM state root — a failed claim
    /// must leave none.
    fn orphan_child_dirs() -> usize {
        match std::fs::read_dir(vms_dir()) {
            Ok(rd) => rd
                .flatten()
                .filter(|e| e.path().is_dir() && e.file_name().to_string_lossy().starts_with("vm-"))
                .count(),
            Err(_) => 0,
        }
    }

    /// What a claim driven against a scripted post-restore answer left behind.
    struct HandshakeClaimOutcome {
        result: std::result::Result<VmId, StandbyError>,
        /// The driver the claim ran on — an `Arc`-shared clone, so the fork,
        /// delivery, and kill records survive the runner it was moved into.
        driver: MockDriver,
        parent_state: StandbyState,
        orphan_child_dirs: usize,
        /// Records every `ConsoleStreamer::start`/`stop` the claim made, so a
        /// test can prove the console follower was wired into `claim_standby`
        /// itself, not only the cold-boot path — every existing caller of this
        /// helper ignores the field, so threading it through costs them nothing.
        console_streamer: Arc<RecordingConsoleStreamer>,
    }

    /// Drive one full claim over a clean audited parent against `driver`, whose
    /// `deliver_child_identity` answer the caller has scripted. Everything the
    /// claim touches (MVM_HOME, stores, pool, registry) is fresh per call, so the
    /// handshake outcomes are independent of each other.
    fn claim_with_scripted_handshake(driver: MockDriver) -> HandshakeClaimOutcome {
        claim_with_scripted_handshake_and_grant(driver, None, None)
    }

    fn claim_with_scripted_handshake_and_grant(
        driver: MockDriver,
        agent_verbs: Option<Vec<VerbId>>,
        grant_issuer: Option<&dyn ChildGrantIssuer>,
    ) -> HandshakeClaimOutcome {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);
        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json_with_verbs(&parent_digest, agent_verbs),
        );

        let probe = driver.clone();
        let streamer = Arc::new(RecordingConsoleStreamer::default());
        let runner = WorkloadRunner::new(
            driver,
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        )
        .with_console_streamer(streamer.clone() as Arc<dyn ConsoleStreamer>);
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer,
        };

        let result = runner.claim_standby(&ctx, &handle, &claim);
        HandshakeClaimOutcome {
            result,
            driver: probe,
            parent_state: pool.load("warm-parent").unwrap().state,
            orphan_child_dirs: orphan_child_dirs(),
            console_streamer: streamer,
        }
    }

    #[test]
    fn claim_refuses_a_grant_bearing_plan_before_fork_when_no_issuer_is_configured() {
        let out = claim_with_scripted_handshake_and_grant(
            MockDriver::default(),
            Some(vec![VerbId::new("run-entrypoint").unwrap()]),
            None,
        );

        let err = out.result.expect_err("the missing issuer must fail closed");
        assert!(err.to_string().contains("no child grant issuer"));
        assert!(
            out.driver.forked_children().is_empty(),
            "grant issuance is checked before a child is resumed"
        );
        assert_eq!(out.parent_state, StandbyState::Idle);
        assert_eq!(out.orphan_child_dirs, 0);
    }

    /// A forked child comes back resumed on its parent's saved memory, so until
    /// it answers the identity handshake it is still drawing on the parent's
    /// CSPRNG and reading the parent's frozen clock. Every way that proof can
    /// fail — the guest never answers, answers without acknowledging, without
    /// rotating, or without resynchronizing its clock — must refuse the claim,
    /// stop the live child, return the healthy parent to claimable, and leave no
    /// child dir. Admitting on any of them would hand out a VM whose "random"
    /// values match every sibling forked from the same parent.
    #[test]
    fn claim_refuses_a_child_that_cannot_prove_a_fresh_identity() {
        let unproven = |acknowledged: bool, reseeded: bool, clock_resynced: bool| {
            MockDriver::default().with_child_identity(PostRestoreOutcome {
                acknowledged,
                detail: None,
                reseeded,
                clock_resynced,
            })
        };
        let cases = [
            (
                "guest never answered",
                MockDriver::default().with_unreachable_child_agent(),
            ),
            ("guest did not acknowledge", unproven(false, true, true)),
            ("guest did not reseed", unproven(true, false, true)),
            (
                "guest did not resync its clock",
                unproven(true, true, false),
            ),
        ];

        for (label, driver) in cases {
            let out = claim_with_scripted_handshake(driver);
            let err = out
                .result
                .expect_err(&format!("{label}: the claim must fail closed"));
            assert!(
                matches!(err, StandbyError::ClaimFailed(_)),
                "{label}: refusal must be a ClaimFailed: {err}"
            );

            // The refusal lands AFTER the fork — the child really was live — and
            // the child was stopped rather than left running unproven.
            let forks = out.driver.forked_children();
            assert_eq!(forks.len(), 1, "{label}: the child was forked first");
            assert!(
                out.driver.killed_vms().contains(&forks[0].child_vm_name),
                "{label}: the refused child must be stopped, not left resumed: killed {:?}",
                out.driver.killed_vms()
            );
            assert_eq!(
                out.parent_state,
                StandbyState::Idle,
                "{label}: a child-side failure must return the healthy parent to claimable"
            );
            assert_eq!(
                out.orphan_child_dirs, 0,
                "{label}: a refused claim must leave no orphan child dir"
            );
        }
    }

    /// The delivered token reaches the child's agent even on the refusal path —
    /// the claim refuses on what the guest reported, not by skipping the ask.
    #[test]
    fn claim_delivers_the_token_before_judging_the_child() {
        let out = claim_with_scripted_handshake(MockDriver::default().with_child_identity(
            PostRestoreOutcome {
                acknowledged: true,
                detail: None,
                reseeded: false,
                clock_resynced: true,
            },
        ));
        assert!(out.result.is_err());
        let delivered = out.driver.delivered_child_identities();
        let forks = out.driver.forked_children();
        assert_eq!(delivered.len(), 1, "the token is delivered exactly once");
        assert_eq!(delivered[0].child_vm_name, forks[0].child_vm_name);
        assert_eq!(
            delivered[0].token, forks[0].genid.token,
            "the delivered token is the one the fork minted"
        );
    }

    /// The standby-fork analogue of
    /// `start_workload_starts_console_streaming_and_stop_tears_it_down_without_losing_bytes`:
    /// a claim that commits must have started console streaming for the
    /// child's own fresh name, at the same console-log path a cold boot would
    /// use.
    #[test]
    fn claim_standby_starts_console_streaming_for_the_committed_child() {
        let out = claim_with_scripted_handshake(MockDriver::default());
        let child = out.result.expect("a clean handshake commits the claim");

        // Not compared against a freshly-recomputed `vm_state_dir(&child.0)`:
        // that helper's `MVM_HOME` override is already unwound by the time this
        // assertion runs, so a second computation here would silently drift to
        // the real (un-isolated) home instead of proving anything. The path's
        // *shape* -- console.log directly under a dir named for the child --
        // is what `standing_sockets` actually guarantees, isolation or not.
        let started = out.console_streamer.started.lock().unwrap();
        assert_eq!(
            started.len(),
            1,
            "console streaming must start exactly once"
        );
        assert_eq!(started[0].0, child.0);
        assert_eq!(
            started[0].1.file_name(),
            Some(std::ffi::OsStr::new("console.log"))
        );
        assert_eq!(
            started[0].1.parent().and_then(|p| p.file_name()),
            Some(std::ffi::OsStr::new(child.0.as_str())),
            "the console log must live under the child's own state dir, not the parent's"
        );
        drop(started);
        assert!(
            out.console_streamer.stopped.lock().unwrap().is_empty(),
            "a committed claim leaves the console streamer running for the \
             ordinary VmBackend::stop path to tear down later, exactly like a \
             cold boot"
        );
    }

    /// A restored child that never proves a fresh identity fails inside a real
    /// window: the post-restore handshake, where the guest is already live but
    /// not yet admitted. Without a console follower running through that
    /// window, a hang or panic there leaves an operator with nothing but an
    /// opaque `ClaimFailed` string. Also proves the follower is torn down on
    /// refusal rather than leaked -- `force_stop` only kills the VMM, so
    /// `claim_standby` itself must reap the streamer it started.
    #[test]
    fn claim_standby_stops_console_streaming_when_the_post_restore_handshake_is_refused() {
        let out =
            claim_with_scripted_handshake(MockDriver::default().with_unreachable_child_agent());
        let err = out
            .result
            .expect_err("an unanswered handshake must refuse the claim");
        assert!(matches!(err, StandbyError::ClaimFailed(_)));

        let forks = out.driver.forked_children();
        assert_eq!(
            forks.len(),
            1,
            "the child was forked and resumed before the handshake ran"
        );
        let child_name = forks[0].child_vm_name.clone();

        // Started while the child was live -- the only way an operator would
        // see a hang or panic inside the handshake window this refusal covers.
        let started = out.console_streamer.started.lock().unwrap();
        assert_eq!(
            started.len(),
            1,
            "console streaming must have started for the forked child"
        );
        assert_eq!(started[0].0, child_name);
        assert_eq!(
            started[0].1.parent().and_then(|p| p.file_name()),
            Some(std::ffi::OsStr::new(child_name.as_str())),
            "the console log must live under the child's own state dir"
        );
        drop(started);
        // ...and stopped once the claim gave up on it, so the follower thread
        // does not outlive a child that was never admitted.
        assert_eq!(
            out.console_streamer.stopped.lock().unwrap().as_slice(),
            [child_name]
        );
    }

    /// A post-materialize failure (here: the overlay-contract gate refusing a
    /// child whose clone carries no overlay sidecar) must return the healthy
    /// reserved parent to claimable and remove the orphaned child dir — no leaked
    /// warm capacity, no orphaned state. This ALSO proves the overlay gate is
    /// wired into `claim_standby`: with the gate deleted, this claim would
    /// succeed.
    #[test]
    fn claim_releases_reserved_parent_and_removes_child_dir_on_overlay_refusal() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        // No overlay sidecar → the child clone fails the overlay-contract gate,
        // which runs AFTER materialize (so a child dir already exists).
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), false);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let err = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("the overlay-contract gate must refuse a sidecar-less child");
        assert!(
            err.to_string().contains("overlay contract")
                || err.to_string().contains("mvm-meta.json"),
            "refusal must name the overlay gate: {err}"
        );

        // The healthy parent is returned to claimable (not stranded `Claimed`).
        assert_eq!(
            pool.load("warm-parent").unwrap().state,
            StandbyState::Idle,
            "a non-parent-fault failure must return the parent to claimable"
        );
        // No child dir orphaned.
        assert_eq!(
            orphan_child_dirs(),
            0,
            "a failed claim must leave no orphan child dir"
        );
        // The fork never ran.
        assert!(runner.driver.forked_children().is_empty());
    }

    /// A failed claim destroys the preloaded child, so the record must stop
    /// naming it — otherwise the standby stays `Idle` advertising a paused VMM
    /// that no longer exists, and every later claim refuses on a missing control
    /// socket while `idle_count_compatible` still counts it as capacity. That
    /// made a standby single-use against even a retryable failure.
    ///
    /// The parent and its checkpoint are healthy, so it demotes to saved-state
    /// (the `pid == 0` sentinel) rather than being removed: warm capacity
    /// survives and the next claim materializes a fresh child from the
    /// checkpoint.
    #[test]
    fn a_failed_claim_demotes_a_preloaded_standby_instead_of_stranding_it() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        // No overlay sidecar → the claim fails the overlay-contract gate, which
        // is a non-parent-fault failure reached after the child is tracked.
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), false);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let mut handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        // A preloaded standby: the pool owns a paused child VMM instead of being
        // saved-only, so it carries the child's name and a live pid.
        let child_name = "preloaded-child".to_string();
        handle.preloaded_child_vm_name = Some(child_name.clone());
        handle.pid = std::process::id();
        pool.record(&handle).unwrap();
        std::fs::create_dir_all(vm_state_dir(&child_name)).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("the overlay-contract gate must refuse this claim");

        let after = pool.load("warm-parent").unwrap();
        assert_eq!(
            after.state,
            StandbyState::Idle,
            "a non-parent-fault failure must return the parent to claimable"
        );
        assert!(
            after.preloaded_child_vm_name.is_none(),
            "the record must stop naming a child the cleanup destroyed"
        );
        assert!(
            after.is_saved_state(),
            "a standby with no preloaded child is saved-only (pid == 0), so the next \
             claim materializes a fresh child from the checkpoint"
        );
        assert!(
            SupervisorStandbyPool::is_live_or_saved(&after),
            "the demoted parent must remain usable capacity, not read as dead"
        );
        assert!(
            runner.driver.killed_vms().contains(&child_name),
            "the destroyed child's VMM must be stopped, not orphaned: killed {:?}",
            runner.driver.killed_vms()
        );
    }

    /// An un-audited parent (no signed creation entry) is quarantined by removal,
    /// NOT returned to claimable — a parent that cannot be verified must never be
    /// reused. The failure is caught before any child identity/dir is minted.
    #[test]
    fn claim_quarantines_unaudited_parent_without_releasing_it() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        // The chain carries no signed creation entry for this parent.
        let anchor = ClaimTestAnchor::unaudited();

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let err = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("an un-audited parent must be refused");
        assert!(
            err.to_string().contains("no signed audit entry"),
            "refusal must be the un-audited reason: {err}"
        );

        // Quarantined by removal — NOT returned to claimable.
        assert!(
            pool.load("warm-parent").is_err(),
            "an un-audited parent must be quarantined (removed), never released"
        );
        // Nothing was minted or booted.
        assert_eq!(
            orphan_child_dirs(),
            0,
            "no child dir on a quarantine refusal"
        );
        assert!(runner.driver.forked_children().is_empty());
    }

    /// A plan whose bound image digest does not match the parent's own verified
    /// rootfs is refused before any child side effect: the bind gate runs right
    /// after reserve, so this is a non-parent-fault failure (the parent itself
    /// verified fine) and must return it to claimable, unlike an unverifiable
    /// parent which is quarantined instead.
    #[test]
    fn claim_refuses_plan_parent_image_mismatch() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        // The plan's bound image digest is unrelated to the parent's own
        // rootfs content-address.
        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&"f".repeat(64)),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let err = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("a plan bound to a different image than the parent must be refused");
        assert!(
            err.to_string()
                .contains("does not match parent rootfs digest"),
            "refusal must name the plan/parent mismatch: {err}"
        );

        // Non-parent-fault: the healthy, verified parent goes back to claimable.
        assert_eq!(
            pool.load("warm-parent").unwrap().state,
            StandbyState::Idle,
            "a plan/parent digest mismatch must return the parent to claimable"
        );
        // The refusal runs before any child identity is minted.
        assert_eq!(
            orphan_child_dirs(),
            0,
            "no child dir on a plan/parent mismatch"
        );
        assert!(runner.driver.forked_children().is_empty());
    }

    /// A warm claim restores a child out of a parent's saved state exactly as a
    /// vm_full fork does, so it must run the same subset check. A parent sealed
    /// under a tight CPU share cannot hand a claimed child a wider one.
    #[test]
    fn claim_refuses_a_child_whose_grants_exceed_the_parents() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) = seed_audited_parent_with_grants(
            store_root.path(),
            src.path(),
            true,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
                ..Default::default()
            }),
        );
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        // Bound to the parent's own rootfs, so the image-digest bind passes and
        // the grants comparison is what refuses.
        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json_with_grants(
                &parent_digest,
                Some(mvm_contract::grants::Grants {
                    cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
                    ..Default::default()
                }),
            ),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let err = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("a claimed child may not widen its parent's grants");
        assert!(
            err.to_string().contains("exceeds the parent's 1000"),
            "refusal must name the widening: {err}"
        );

        // Not the parent's fault, so warm capacity is returned rather than
        // quarantined, and nothing was minted for the refused child.
        assert_eq!(
            pool.load("warm-parent").unwrap().state,
            StandbyState::Idle,
            "a child-side grant widening must return the parent to claimable"
        );
        assert_eq!(orphan_child_dirs(), 0, "no child dir on a grant widening");
        assert!(runner.driver.forked_children().is_empty());
    }

    /// The other side of the same check: a claimed child that narrows, or that
    /// matches, is admitted. Without this the refusal test above would pass just
    /// as well against a check that refused every claim.
    #[test]
    fn claim_admits_a_child_that_narrows_the_parents_grants() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) = seed_audited_parent_with_grants(
            store_root.path(),
            src.path(),
            true,
            Some(mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
                ..Default::default()
            }),
        );
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json_with_grants(
                &parent_digest,
                Some(mvm_contract::grants::Grants {
                    cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1000 }),
                    ..Default::default()
                }),
            ),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        runner
            .claim_standby(&ctx, &handle, &claim)
            .expect("a narrowing child must still be claimable");
    }

    /// Persist a host config whose CPU ceiling is `millicores`, so a claim in
    /// this test's isolated `MVM_HOME` is bounded by a known number rather than
    /// by whatever the default config happens to carry.
    fn host_ceiling_of(millicores: u32) {
        let cfg = mvm_core::user_config::MvmConfig {
            max_cpu_millicores: Some(millicores),
            ..Default::default()
        };
        mvm_core::user_config::save(&cfg, None).expect("write host config");
    }

    /// A parent-less bound: the standby parent deliberately carries no grant,
    /// so the parent-subset comparison clears any share at all and the host's
    /// own ceiling is what refuses. Without the ceiling check this claim boots
    /// a child holding four cores on a host configured to allow two.
    #[test]
    fn a_claimed_child_over_the_host_ceiling_is_refused() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        host_ceiling_of(2000);

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        // A grant-less parent, which is what a factory parent actually is.
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent_with_grants(store_root.path(), src.path(), true, None);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json_with_grants(
                &parent_digest,
                Some(mvm_contract::grants::Grants {
                    cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
                    ..Default::default()
                }),
            ),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let err = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("a claim over the host ceiling must be refused");
        assert!(
            err.to_string().contains("grant ceiling"),
            "refusal must read as a bound: {err}"
        );

        // The host, not the parent, refused: warm capacity goes back and
        // nothing was minted for the child.
        assert_eq!(
            pool.load("warm-parent").unwrap().state,
            StandbyState::Idle,
            "a ceiling refusal must return the parent to claimable"
        );
        assert_eq!(orphan_child_dirs(), 0, "no child dir on a ceiling refusal");
        assert!(runner.driver.forked_children().is_empty());
    }

    /// The other side: a claim at or under the ceiling still gets its warm
    /// start. Without this the refusal witness above would pass equally well
    /// against a check that refused every claim.
    #[test]
    fn a_claimed_child_within_the_ceiling_is_admitted() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        host_ceiling_of(2000);

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent_with_grants(store_root.path(), src.path(), true, None);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json_with_grants(
                &parent_digest,
                Some(mvm_contract::grants::Grants {
                    cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
                    ..Default::default()
                }),
            ),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        runner
            .claim_standby(&ctx, &handle, &claim)
            .expect("a claim within the host ceiling must still be claimable");
    }

    /// Because the bound is checked after the pool has already matched, a
    /// refused claim looks superficially like a pool bug: the parent was found,
    /// reserved, and then the claim died. The message is the only thing that
    /// distinguishes the two, so it has to carry both numbers — what the host
    /// allows and what the plan asked for.
    #[test]
    fn the_refusal_names_the_ceiling_and_the_request() {
        let refusal = ensure_child_grants_within_host_ceiling(
            Some(&mvm_contract::grants::Grants {
                cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 4000 }),
                ..Default::default()
            }),
            &mvm_contract::grants::ceiling::GrantCeiling {
                max_cpu_millicores: Some(2000),
                ..Default::default()
            },
        )
        .expect_err("4000 millicores exceeds a 2000-millicore ceiling");

        let text = refusal.to_string();
        assert!(
            text.contains("2000"),
            "refusal must name the ceiling: {text}"
        );
        assert!(
            text.contains("4000"),
            "refusal must name the request: {text}"
        );
        assert!(
            text.contains("cpu.share_millicores"),
            "refusal must name the bounded dimension: {text}"
        );
        assert!(
            text.contains("ceiling"),
            "refusal must read as a bound being enforced, not a failure: {text}"
        );
    }

    /// The bound is checked after matching, never folded into the pool's
    /// compatibility key: keying on a grant would split one pool into a pool
    /// per distinct share and cost the warm hit rate the pool exists for.
    ///
    /// Two halves, both needed. The exhaustive destructure fails to compile the
    /// day a grant dimension is added to the key — which is the move this test
    /// exists to prevent — and the selection half proves the live consequence:
    /// one warm parent serves claims asking for different shares.
    #[test]
    fn pool_matching_is_unchanged_by_the_bound() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());
        host_ceiling_of(2000);

        let store_root = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();

        let mvm_core::vm_backend::StandbyCompat {
            template_id: _,
            kernel_sha256: _,
            vcpus: _,
            mem_mib: _,
            image_sha256: _,
            root_strategy: _,
            vsock_egress: _,
        } = handle.compat();

        // The key is derived from the parent's boot shape and takes no grant as
        // input, so every claim on this boot shape resolves the one warm parent
        // whatever share its plan asks for — including one the ceiling will go
        // on to refuse. Matching and bounding stay separate decisions.
        let want = handle.compat();
        let picked = pool
            .select_idle_compatible(&want)
            .unwrap()
            .expect("a claim on this boot shape must match the warm parent");
        assert_eq!(picked.id, "warm-parent");
        assert_eq!(
            picked.compat(),
            want,
            "the matched parent's key must be the one that was asked for"
        );
    }

    /// A parent whose sealed `meta.json` is edited after capture — without
    /// recomputing its content-address — drifts from its own stored digest.
    /// This is distinct from the un-audited-parent case: here the chain DOES
    /// carry a signed entry, but the on-disk record no longer matches what was
    /// signed, so the recompute-vs-stored check must catch it before the chain
    /// lookup ever runs. Quarantined by removal, the same fail-closed posture
    /// as the un-audited case, since a record that cannot be verified must
    /// never be reused.
    #[test]
    fn claim_refuses_drift_tampered_parent() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");
        // Anchored to the digest the ORIGINAL sealed record carried — the chain
        // attests to what was signed, not to whatever is on disk now.
        let anchor = ClaimTestAnchor::audited(&parent_meta);

        // Tamper the on-disk record after sealing: mutate a load-bearing field
        // without touching `meta_digest`, so the stored digest goes stale.
        let mut tampered = checkpoints.read_meta(&parent_id).unwrap();
        tampered.vm_name = "attacker-renamed".into();
        checkpoints.write_meta(&tampered).unwrap();
        assert_ne!(
            tampered.compute_meta_digest(),
            tampered.meta_digest,
            "the tamper must actually drift the digest, or this test proves nothing"
        );

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );
        let ctx = ClaimContext {
            pool: &pool,
            checkpoints: &checkpoints,
            snapshots: &snapshots,
            anchor: &anchor,
            parent_checkpoint: &parent_id,
            registry_path: &registry_path,
            grant_issuer: None,
        };

        let err = runner
            .claim_standby(&ctx, &handle, &claim)
            .expect_err("a drift-tampered parent must be refused");
        assert!(
            err.to_string().contains("drift"),
            "refusal must name the drift reason: {err}"
        );

        // Quarantined by removal — NOT returned to claimable, mirroring the
        // un-audited case: an unverifiable record must never be reused.
        assert!(
            pool.load("warm-parent").is_err(),
            "a drift-tampered parent must be quarantined (removed), never released"
        );
        assert_eq!(
            orphan_child_dirs(),
            0,
            "no child dir on a quarantine refusal"
        );
        assert!(runner.driver.forked_children().is_empty());
    }

    /// Two concurrent claims against the same idle parent: the reserve step
    /// (load + claimable check + `mark_claimed`) runs under the registry file
    /// lock, so exactly one claim can observe the parent as claimable. Real
    /// threads racing the same runner + context prove the exclusion is actually
    /// enforced, not just serialized by test structure.
    #[test]
    fn concurrent_claims_do_not_double_claim_one_parent() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        let (checkpoints, snapshots, parent_id, parent_meta) =
            seed_audited_parent(store_root.path(), src.path(), true);
        let parent_digest = parent_rootfs_digest(&parent_meta).unwrap().to_string();

        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let registry_path = store_root.path().join("vm-names.json");

        let claim = admitted_child_claim(
            &src.path().join("rootfs.ext4"),
            signed_child_plan_json(&parent_digest),
        );

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            KeyingSpawner::default(),
            RecordingBrokerRegistrar::new(),
        );

        // `dyn CheckpointChainAnchor` carries no `Sync` bound (real anchors are
        // the CLI's host-signer-backed audit-chain reader, never shared across
        // threads in production), so each thread gets its own owned anchor
        // instance and builds its own `ClaimContext` locally rather than
        // sharing one `&dyn CheckpointChainAnchor` across the thread boundary.
        let anchor1 = ClaimTestAnchor::audited(&parent_meta);
        let anchor2 = ClaimTestAnchor::audited(&parent_meta);

        let results: Vec<std::result::Result<VmId, StandbyError>> = std::thread::scope(|s| {
            let t1 = s.spawn(|| {
                let ctx = ClaimContext {
                    pool: &pool,
                    checkpoints: &checkpoints,
                    snapshots: &snapshots,
                    anchor: &anchor1,
                    parent_checkpoint: &parent_id,
                    registry_path: &registry_path,
                    grant_issuer: None,
                };
                runner.claim_standby(&ctx, &handle, &claim)
            });
            let t2 = s.spawn(|| {
                let ctx = ClaimContext {
                    pool: &pool,
                    checkpoints: &checkpoints,
                    snapshots: &snapshots,
                    anchor: &anchor2,
                    parent_checkpoint: &parent_id,
                    registry_path: &registry_path,
                    grant_issuer: None,
                };
                runner.claim_standby(&ctx, &handle, &claim)
            });
            vec![t1.join().unwrap(), t2.join().unwrap()]
        });

        let successes = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            successes, 1,
            "exactly one concurrent claim on the same parent must succeed"
        );
        let loser = results
            .iter()
            .find(|r| r.is_err())
            .unwrap()
            .as_ref()
            .unwrap_err();
        assert!(
            loser.to_string().contains("not in a claimable state"),
            "the losing claim must be refused by the reserve check, not some other error: {loser}"
        );

        // Exactly one fork happened and exactly one child dir landed — never
        // two, which is what a broken exclusion would produce.
        assert_eq!(
            runner.driver.forked_children().len(),
            1,
            "the reserve race must not let both claims through to the fork"
        );
        assert_eq!(
            orphan_child_dirs(),
            1,
            "exactly one child dir must exist after the race"
        );
        assert_eq!(
            pool.load("warm-parent").unwrap().state,
            StandbyState::Claimed,
            "the winner's parent stays reserved, never returned mid-race"
        );
    }

    /// There is no code path on this runner that takes an existing standby
    /// parent's identity and runs a workload directly on it — the guarantee is
    /// structural, not a runtime check. `claim_standby` is the only method that
    /// consumes a `StandbyHandle`, and it always mints a fresh child id distinct
    /// from the parent's own (see `claim_produces_fresh_identity_and_isolated_endpoint`).
    /// The only OTHER way this runner produces a running `VmId` is a cold
    /// `start`, which carries no reference to the standby pool at all: a parent
    /// lives under the pool root, a workload under the VM state root, so naming
    /// a cold boot after a live parent cannot promote it — it lands in a
    /// disjoint directory and leaves the parent's own record untouched.
    #[test]
    fn promoting_a_parent_to_a_workload_is_refused() {
        let _guard = crate::base::runtime_meta::HOME_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let home = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", home.path());

        let store_root = tempfile::tempdir().unwrap();
        let pool = SupervisorStandbyPool::at(store_root.path().join("pool"));
        let handle = idle_parent_handle("warm-parent", &store_root.path().join("control.sock"));
        pool.record(&handle).unwrap();
        let before = pool.load("warm-parent").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        // The closest thing to "run a workload on this VmId": a cold start
        // under the parent's own name.
        let (_rootfs_dir, rootfs) = overlay_aware_rootfs("warm-parent");
        let cfg = VmStartConfig {
            name: "warm-parent".into(),
            rootfs_path: rootfs,
            ..Default::default()
        };
        let started = runner
            .start(&cfg)
            .expect("start is an ordinary cold boot, not a claim");
        assert_eq!(started.0, "warm-parent");

        // `start` never reads or mutates the standby pool — the parent's
        // record is byte-for-byte unchanged.
        assert_eq!(
            pool.load("warm-parent").unwrap(),
            before,
            "a cold-started workload sharing the parent's name must not touch its pool record"
        );

        // Disjoint directory roots: the parent lives under the pool root, the
        // workload under the VM state root. There is no shared resource here
        // to promote.
        let workload_dir = vm_state_dir("warm-parent");
        let parent_dir = pool.root().join("warm-parent");
        assert_ne!(
            workload_dir, parent_dir,
            "the started workload and the registered parent must not share a directory"
        );
        assert_eq!(before.state, StandbyState::Idle);
    }
}
