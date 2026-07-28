//! The driver-generic workload start mechanics. `WorkloadRunner` spawns the
//! per-VM host-side gating endpoint, maps the admitted config onto a `VmmSpec`,
//! and boots it through the `VmmDriver` seam — once, over the seam, instead of
//! copied into each backend's `start`. The endpoint spawn is itself behind the
//! `EndpointSpawner` trait so the runner is unit-testable with no real VM and no
//! real endpoint process.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use mvm_agentd::vsock::BROKER_PORT;
use mvm_core::checkpoint::{CheckpointId, CheckpointMeta};
use mvm_core::config::{vm_state_dir, vm_substitution_endpoint_socket, vms_dir};
use mvm_core::crypto::vmgenid::fresh_generation_token;
use mvm_core::plan::SecretBinding;
use mvm_core::policy::RedactionPolicy;
use mvm_core::policy::network_policy::NetworkPolicy;
use mvm_core::vm_backend::{
    BackendKind, BackendSecurityProfile, GuestChannelInfo, StandbyClaim, StandbyError,
    StandbyHandle, StandbySpec, StartMode, VmBackend, VmCapabilities, VmExitStatus, VmId, VmInfo,
    VmStartConfig, VmStatus,
};
use mvm_fs::snapshot_store::FsSnapshotStore;

use crate::checkpoint::{
    CaptureVmFullParams, CheckpointChainAnchor, CheckpointStore, capture_vm_full, verify_content,
    verify_lineage,
};
use crate::driver::{ChildForkRequest, RunningVm, VmmDriver};
use crate::egress_shared::decode_plan_secrets_from_state;
use crate::standby_pool::SupervisorStandbyPool;
use crate::substitution_spawn::{
    EndpointTransport, SubstitutionSpawnParams, reap_substitution_endpoint,
    spawn_substitution_endpoint,
};
use crate::vm::name_registry::{VmNameRegistry, acquire_registry_lock, generate_vm_name};
use crate::warm_snapshot::materialize_child_from_parent;
use crate::workload_backend::{EgressSubstitutionTransport, WorkloadBackend};
use crate::workload_runner::claim::{
    ClaimGuards, ClaimRefusal, EndpointSpawnInputs, bind_plan_to_parent, parent_rootfs_digest,
};
use crate::workload_runner::cmdline;
use crate::workload_runner::spec_map::{
    WorkloadSockets, WorkloadSpecInputs, console_data_sockets, ensure_no_dir_share_volumes,
    workload_spec,
};

/// What the workload runner needs to stand up the per-VM gating endpoint.
pub struct EndpointSpawnRequest<'a> {
    pub vm_name: &'a str,
    pub state_dir: &'a Path,
    pub tenant: &'a str,
    pub secrets: &'a [SecretBinding],
    pub redaction: &'a RedactionPolicy,
    pub network_policy: &'a NetworkPolicy,
    /// Raw TCP egress (no secrets) vs the WireRequest substitution protocol.
    pub raw_egress: bool,
}

/// Stand up the per-VM gating endpoint; return the host UDS the guest's
/// EGRESS_PORT relays to. The one host-side egress bridge (claim-10 gate +
/// claims 12/13 substitution).
pub trait EndpointSpawner: Send + Sync {
    fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf>;
}

/// The production `EndpointSpawner`: spawns the real `mvm-substitution-endpoint`
/// over the in-process-VMM UDS transport.
pub struct RealEndpointSpawner;

impl EndpointSpawner for RealEndpointSpawner {
    fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf> {
        let uds = vm_substitution_endpoint_socket(req.vm_name);
        spawn_substitution_endpoint(SubstitutionSpawnParams {
            vm_name: req.vm_name,
            state_dir: req.state_dir,
            tenant: req.tenant,
            secrets: req.secrets,
            redaction: req.redaction,
            transport: EndpointTransport::Uds { path: uds.clone() },
            terminator_listen: None,
            tls_intermediate: None,
            network_policy: Some(req.network_policy),
            raw_egress: req.raw_egress,
        })?;
        Ok(uds)
    }
}

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
}

/// Register/spawn the per-VM host-services broker for an admitted workload,
/// returning a guard whose Drop reaps until defused. The claims-12/13 seam:
/// `host.audit.v1` / `host.secrets.v1` reach the guest over `BROKER_PORT`, and
/// no raw secret ever crosses that channel. Behind a trait so the runner is
/// unit-testable with no real broker subprocess.
pub trait BrokerRegistrar: Send + Sync {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard>;
}

/// RAII guard around the registered broker services: Drop reaps them until the
/// VM is confirmed up and `defuse`d (the `stop` path then owns teardown). Wraps
/// the existing `ServicesGuard` so no reaping logic is duplicated.
pub struct BrokerGuard(crate::host_agent_spawn::ServicesGuard);

impl BrokerGuard {
    /// A guard that reaps nothing on drop — the unadmitted / spawn-failed path.
    fn defused() -> Self {
        Self(crate::host_agent_spawn::ServicesGuard::None)
    }

    /// Disarm: the VM is up; the `stop` path now owns teardown.
    pub fn defuse(&mut self) {
        self.0.defuse();
    }
}

/// The production `BrokerRegistrar`: delegates to the existing per-tenant
/// host-agent registration (default) or the per-VM broker fork
/// (`MVM_HOST_AGENT_DAEMON=0`). No broker logic is reimplemented here — this is
/// the same registration the raw backend `start` paths run, lifted onto the
/// runner so a workload moved here keeps its host services.
pub struct RealBrokerRegistrar;

impl BrokerRegistrar for RealBrokerRegistrar {
    fn register(&self, req: &BrokerRegisterRequest<'_>) -> Result<BrokerGuard> {
        // Unadmitted (no tenant, hence no broker socket): register nothing. The
        // spec carries no BROKER_PORT either, so a stray guest dial fails closed.
        let (Some(tenant), Some(broker_listen_socket)) = (req.tenant, req.broker_listen_socket)
        else {
            return Ok(BrokerGuard::defused());
        };

        // Best-effort, matching the raw backends: an absent broker only disables
        // host.audit.v1 for this VM — the workload still runs and the host-side
        // audit chain is intact — so a spawn failure is logged, never a rollback.
        let guard = if crate::host_agent_spawn::host_agent_daemon_enabled() {
            match crate::host_agent_spawn::register_host_agent_services_if_admitted(
                crate::host_agent_spawn::HostAgentServicesParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                },
            ) {
                Ok(g) => crate::host_agent_spawn::ServicesGuard::Agent(g),
                Err(e) => {
                    tracing::warn!(vm = %req.vm_name, error = %e, "host-agent registration failed; host.audit.v1 unavailable for this VM");
                    crate::host_agent_spawn::ServicesGuard::None
                }
            }
        } else {
            match crate::broker_services_spawn::spawn_broker_services_if_admitted(
                crate::broker_services_spawn::BrokerServicesSpawnParams {
                    workload_id: req.vm_name,
                    tenant_id: Some(tenant),
                    vm_name: req.vm_name,
                    state_dir: req.state_dir,
                    broker_listen_socket,
                },
            ) {
                Ok(g) => crate::host_agent_spawn::ServicesGuard::Fork(g),
                Err(e) => {
                    tracing::warn!(vm = %req.vm_name, error = %e, "host-services broker spawn failed; host.audit.v1 unavailable for this VM");
                    crate::host_agent_spawn::ServicesGuard::None
                }
            }
        };
        Ok(BrokerGuard(guard))
    }
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

/// The standing host sockets a workload's vsock channels bind to, resolved
/// under its per-VM state dir. The egress gateway is the endpoint UDS the
/// spawner returns, not a state-dir path — it is the one gate off the box.
struct StandingSockets {
    agent: PathBuf,
    exit: PathBuf,
    /// Host-services broker socket, resolved only for an admitted workload
    /// (`tenant_id.is_some()`). `None` for an unadmitted VM, which carries no
    /// broker channel at all. The one path threaded into both the spec and the
    /// `BrokerRegistrar::register` call so the relay target and bind path match.
    broker: Option<PathBuf>,
    console_log: PathBuf,
    /// Per-port UDS for the interactive console data range. Non-empty only when
    /// `VmStartConfig.dev_console` is true; empty for all sealed prod boots.
    console_data: Vec<(u32, PathBuf)>,
}

fn standing_sockets(state_dir: &Path, config: &VmStartConfig) -> StandingSockets {
    StandingSockets {
        // Single source of truth shared with the host-side resolver so the
        // guest agent bridge can't drift out of the host's reach.
        agent: mvm_core::config::vm_inhouse_agent_socket_at(state_dir),
        exit: state_dir.join("workload.exit"),
        // Admitted-only: an unadmitted VM gets no broker channel, so a stray
        // guest BROKER_PORT dial stays ECONNREFUSED (fail-closed).
        broker: config
            .tenant_id
            .is_some()
            .then(|| mvm_core::config::vm_vsock_port_socket_at(state_dir, BROKER_PORT)),
        console_log: state_dir.join("console.log"),
        console_data: console_data_sockets(state_dir, config.dev_console),
    }
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
    /// Resolves each checkpoint's signature-verified creation digest — the
    /// lineage gate that refuses an un-audited or re-forged parent.
    pub anchor: &'a dyn CheckpointChainAnchor,
    /// The content-addressed checkpoint the standby parent was captured as.
    pub parent_checkpoint: &'a CheckpointId,
    /// VM name registry file whose sibling lock serializes the parent reserve
    /// and the child-name mint, so two claims never double-claim one parent.
    pub registry_path: &'a Path,
}

/// The warm-pool substrate a spawn-and-capture needs beyond the runner's
/// cold-boot fields. Only the checkpoint store: the parent is booted through the
/// driver and captured whole, so nothing else of the claim substrate is reached
/// on the way in.
pub struct SpawnContext<'a> {
    /// Content-addressed checkpoint store the captured parent is written to.
    pub checkpoints: &'a CheckpointStore,
}

/// Starts workloads over the `VmmDriver` seam: spawn the per-VM gating endpoint,
/// map the config to a `VmmSpec`, boot via the driver.
pub struct WorkloadRunner<D: VmmDriver, S: EndpointSpawner, B: BrokerRegistrar> {
    driver: D,
    spawner: S,
    broker: B,
}

impl<D: VmmDriver, S: EndpointSpawner, B: BrokerRegistrar> WorkloadRunner<D, S, B> {
    pub fn new(driver: D, spawner: S, broker: B) -> Self {
        Self {
            driver,
            spawner,
            broker,
        }
    }

    /// Spawn the gating endpoint, compose the spec, and boot. The endpoint is
    /// ALWAYS spawned — it is the sole egress gate now, even for the no-secret
    /// raw path.
    pub fn start_workload(&self, inputs: &WorkloadLaunchInputs<'_>) -> Result<Box<dyn RunningVm>> {
        // Fail closed before any side effect (endpoint spawn) runs: a
        // `DirShare` volume has no `VmmSpec` representation on this driver
        // seam, so refuse it here rather than silently dropping it later in
        // `workload_blocks`.
        ensure_no_dir_share_volumes(inputs.config)?;

        let state_dir = vm_state_dir(&inputs.config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // Spawn the per-child substitution endpoint (the sole egress gate, ALWAYS
        // spawned — even the no-secret raw path) through the shared `ClaimGuards`,
        // so a warm claim stands up the identical guarded endpoint a cold boot
        // does, keyed on this VM's own id.
        let guards = ClaimGuards::new(&self.spawner);
        let mut endpoint = guards.spawn_endpoint(
            &VmId(inputs.config.name.clone()),
            &EndpointSpawnInputs {
                state_dir: &state_dir,
                tenant: inputs.tenant,
                secrets: inputs.secrets,
                redaction: inputs.redaction,
                network_policy: inputs.network_policy,
            },
        )?;

        let socks = standing_sockets(&state_dir, inputs.config);
        let spec = workload_spec(&WorkloadSpecInputs {
            config: inputs.config,
            sockets: WorkloadSockets {
                agent: &socks.agent,
                egress_gateway: endpoint.egress_uds(),
                exit: &socks.exit,
                broker: socks.broker.as_deref(),
                console_data: socks.console_data,
            },
            cmdline: inputs.cmdline.clone(),
            console_log: socks.console_log,
        });

        let vm = self.driver.boot(&spec)?;

        // Register the per-VM host-services broker (host.audit.v1 /
        // host.secrets.v1) for an admitted workload — the same registration the
        // raw backends run, lifted here so a workload on this runner keeps those
        // services. The guard's Drop reaps on any early return until it's defused;
        // registration is best-effort (a failure is logged inside `register`,
        // never a launch rollback).
        let mut broker_guard = self.broker.register(&BrokerRegisterRequest {
            vm_name: &inputs.config.name,
            state_dir: &state_dir,
            tenant: inputs.config.tenant_id.as_deref(),
            broker_listen_socket: socks.broker.as_deref(),
        })?;
        endpoint.defuse();
        broker_guard.defuse();
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
    /// host-side overlay-contract gate and spawn the child's own 0700
    /// substitution endpoint keyed on its fresh id; then fork the VMM, delivering
    /// a fresh VMGenID at boot so the child's CSPRNG diverges from the parent's.
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
        // (1) Reserve the parent atomically, then verify it — before any clone. A
        // verification failure quarantines the parent inside this call.
        let parent = reserve_and_verify_parent(ctx, handle)?;

        // The parent is now reserved (`Claimed`) and verified healthy. Arm the
        // release-unless-committed guard: any early return past this point returns
        // the good parent to claimable (so a failed claim never strands warm
        // capacity) and removes a partial child dir. Only a booted child commits.
        let mut cleanup = ClaimCleanup::new(ctx.pool, handle.id.as_str());

        // (2) + (4) Bind the admitted plan's image digest to the verified parent.
        // A missing plan or a digest mismatch refuses before any child side effect.
        let plan_image = claim_plan_image_sha256(claim)?;
        bind_plan_to_parent(&plan_image, &parent).map_err(refuse)?;

        // (6a) Fresh, registry-unique identity for the child.
        let child = fresh_child_id(ctx)?;
        let child_dir = vm_state_dir(&child.0);
        // Track it before materialize so even a partial clone is cleaned up.
        cleanup.track_child_dir(child_dir.clone());

        // (3) Materialize the child's rootfs from the verified parent's own
        // content (self-binding, lineage-anchored copy-on-write clone).
        materialize_child_from_parent(
            ctx.checkpoints,
            ctx.snapshots,
            ctx.parent_checkpoint,
            ctx.anchor,
            &child_dir,
        )
        .map_err(|e| StandbyError::ClaimFailed(format!("materialize child rootfs: {e}")))?;

        // (8) The runner-side host gates a cold boot runs, before the child boots:
        // the overlay contract, then the child's own 0700 substitution endpoint
        // keyed on its fresh id (never a sibling's; the factory parent has none).
        let child_cfg = child_start_config(claim, &child, &child_dir);
        let guards = ClaimGuards::new(&self.spawner);
        guards
            .admit_overlay_contract(&child_cfg)
            .map_err(|e| StandbyError::ClaimFailed(format!("overlay contract: {e}")))?;

        let secrets =
            mvm_core::plan::secrets_from_signed_json(&claim.plan_json).unwrap_or_default();
        let redaction =
            mvm_core::plan::redaction_from_signed_json(&claim.plan_json).unwrap_or_default();
        let mut endpoint = guards
            .spawn_endpoint(
                &child,
                &EndpointSpawnInputs {
                    state_dir: &child_dir,
                    tenant: claim.tenant_id.as_str(),
                    secrets: &secrets,
                    redaction: &redaction,
                    network_policy: &claim.network_policy,
                },
            )
            .map_err(|e| StandbyError::ClaimFailed(format!("spawn child endpoint: {e}")))?;

        // (6b) + (7) Mint a fresh VMGenID bound to the child's content-address and
        // deliver it WITH the fork, so it reaches the guest at boot — before any
        // guest randomness consumer runs, forcing the child's CSPRNG to diverge.
        let content_hash = parent_rootfs_digest(&parent).map_err(refuse)?.to_string();
        let genid = fresh_generation_token(content_hash);
        self.driver.fork_standby_child(&ChildForkRequest {
            child_vm_name: &child.0,
            child_dir: &child_dir,
            genid,
        })?;

        // The child booted: disarm the endpoint reaper (the stop path owns it now)
        // and commit — the parent stays reserved and the child dir is real state.
        endpoint.defuse();
        cleanup.commit();
        Ok(child)
    }

    /// Boot a standby parent, capture its whole live state, and release it.
    ///
    /// The driver boots the parent and supplies the backend-specific control;
    /// capturing a live VM's memory is backend-agnostic, so it lives here rather
    /// than in any one driver. The captured checkpoint is what a later claim
    /// verifies content and lineage against.
    pub fn spawn_standby_captured(
        &self,
        ctx: &SpawnContext<'_>,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        let mut handle = self.driver.spawn_standby_parent(spec)?;

        let control = self.driver.vm_full_control(&spec.id).ok_or_else(|| {
            StandbyError::SpawnFailed(format!(
                "backend cannot capture a warm parent's memory for standby '{}'",
                spec.id
            ))
        })?;

        let captured = capture_vm_full(
            ctx.checkpoints,
            CaptureVmFullParams {
                id: CheckpointId::new(format!("standby-{}", spec.id)),
                vm_name: spec.id.clone(),
                supervisor_config_digest: String::new(),
                runtime_source_policy: None,
                runtime_overlay_version: None,
                // Firecracker keeps no supervisor-config blob; its presence is
                // what marks a checkpoint as originating from a backend that does.
                supervisor_config_src: None,
                tag: None,
                created_unix: crate::standby_pool::now_unix_secs(),
            },
            control.as_ref(),
        );

        // Release either way: the checkpoint carries the parent's full state, so
        // a pool slot costs disk rather than a resident VM, and a failed capture
        // must not strand the guest.
        self.release_standby_parent(&spec.id);

        let meta = captured
            .map_err(|e| StandbyError::SpawnFailed(format!("capture standby parent: {e}")))?;

        // No live process backs the captured parent — zero is the sentinel
        // `is_saved_state()` keys off, and it is now true.
        handle.pid = 0;
        handle.parent_checkpoint = Some(meta.id.as_str().to_string());
        Ok(handle)
    }

    /// Stop a captured standby parent. A parent that cannot be reaped must not
    /// fail an otherwise-good capture, but it must stay visible.
    fn release_standby_parent(&self, vm_name: &str) {
        let id = VmId(vm_name.to_string());
        match self.driver.attach(&id).and_then(|vm| vm.kill()) {
            Ok(()) => {}
            Err(e) => tracing::warn!(
                vm = vm_name,
                error = %e,
                "releasing captured standby parent failed; it may still be running"
            ),
        }
    }
}

/// Release-unless-committed cleanup for a reserved parent and a partially-built
/// child. A claim reserves the parent (`mark_claimed`) and then materializes a
/// child dir; if any later step fails, this guard returns the (verified, healthy)
/// parent to claimable — so a failed claim never strands warm capacity — and
/// removes the orphaned child dir. Only a claim that boots the child calls
/// [`commit`](Self::commit), disarming both. A parent that failed VERIFICATION is
/// quarantined by removal upstream and never reaches this guard, so releasing
/// here only ever returns a parent that verified healthy.
struct ClaimCleanup<'a> {
    pool: &'a SupervisorStandbyPool,
    parent_id: &'a str,
    child_dir: Option<PathBuf>,
    committed: bool,
}

impl<'a> ClaimCleanup<'a> {
    fn new(pool: &'a SupervisorStandbyPool, parent_id: &'a str) -> Self {
        Self {
            pool,
            parent_id,
            child_dir: None,
            committed: false,
        }
    }

    /// Track the child dir so an early return after materialize removes it.
    fn track_child_dir(&mut self, dir: PathBuf) {
        self.child_dir = Some(dir);
    }

    /// The child booted: disarm. The parent stays `Claimed` (the stop/reaper path
    /// owns it) and the child dir is real state, not an orphan.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ClaimCleanup<'_> {
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

/// Map a fail-closed [`ClaimRefusal`] onto the transport-agnostic
/// [`StandbyError`] the claim seam returns. The refusal reasons stay distinct in
/// the message so a caller can tell an un-audited parent from a plan mismatch.
fn refuse(refusal: ClaimRefusal) -> StandbyError {
    StandbyError::ClaimFailed(refusal.to_string())
}

/// Distinguish an un-audited parent (no signed creation entry) from a tampered
/// one (drift or a chain mismatch) by the lineage verifier's own message, so the
/// caller sees the specific fail-closed reason.
fn map_lineage_refusal(err: &anyhow::Error) -> ClaimRefusal {
    if err.to_string().contains("no signed audit entry") {
        ClaimRefusal::ParentUnaudited
    } else {
        ClaimRefusal::ParentTampered
    }
}

/// Reserve the passed parent atomically under the registry lock (the no-double-
/// claim guard), then verify its sealed content and its content-address against
/// the signed audit chain. Returns the verified parent meta. Runs before any
/// clone or boot: an unclaimable, un-audited, or tampered parent fails closed.
///
/// A parent that fails verification (or whose sealed record is unreadable) is
/// **quarantined by removal** — a parent that cannot be verified must never be
/// reused, so it is dropped from the pool rather than returned to claimable.
/// Replenish spawns a fresh one in its place. This is the deliberate exception to
/// the release-on-failure rule the caller's [`ClaimCleanup`] applies to a healthy
/// reserved parent.
fn reserve_and_verify_parent(
    ctx: &ClaimContext<'_>,
    handle: &StandbyHandle,
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
    verify_content(ctx.checkpoints, &parent)
        .map_err(|_| quarantine(refuse(ClaimRefusal::ParentTampered)))?;
    verify_lineage(ctx.checkpoints, ctx.parent_checkpoint, ctx.anchor)
        .map_err(|e| quarantine(refuse(map_lineage_refusal(&e))))?;
    Ok(parent)
}

/// The admitted plan's bound image digest (`plan.image.sha256`) from the claim.
/// The runner does not re-verify the signature — the host admitted the plan and
/// the supervisor re-verifies at attach — it only reads the digest it must bind
/// to the parent. A claim carrying no parseable plan fails closed.
fn claim_plan_image_sha256(claim: &StandbyClaim) -> std::result::Result<String, StandbyError> {
    let plan = mvm_core::plan::plan_from_admitted_json(&claim.plan_json)
        .map_err(|_| refuse(ClaimRefusal::PlanMissing))?;
    Ok(plan.image.sha256)
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

/// The child's launch config: the CLI-populated claim config (carrying the
/// verity fields the CLI already resolved on the cloned rootfs) rekeyed onto the
/// fresh child identity and its materialized rootfs. The runner consumes verity;
/// it never derives it.
fn child_start_config(claim: &StandbyClaim, child: &VmId, child_dir: &Path) -> VmStartConfig {
    let mut cfg = claim.start_config.clone().unwrap_or_default();
    cfg.name = child.0.clone();
    cfg.rootfs_path = child_dir.join("rootfs.ext4").to_string_lossy().into_owned();
    cfg.tenant_id = Some(claim.tenant_id.clone());
    cfg.network_policy = claim.network_policy.clone();
    cfg
}

/// The runner IS the workload backend: the lifecycle runs through the `VmmDriver`
/// seam (`boot` on start, `attach` for stop/status/wait/pause/resume) instead of
/// per-backend code. State is disk-backed under the per-VM `vm_state_dir`, so a
/// stateless CLI invocation reconstructs a handle by id.
impl<D: VmmDriver + 'static, S: EndpointSpawner + 'static, B: BrokerRegistrar + 'static> VmBackend
    for WorkloadRunner<D, S, B>
{
    fn name(&self) -> &str {
        self.driver.name()
    }

    fn kind(&self) -> BackendKind {
        self.driver.kind()
    }

    fn capabilities(&self) -> VmCapabilities {
        self.driver.capabilities()
    }

    fn security_profile(&self) -> BackendSecurityProfile {
        self.driver.security_profile()
    }

    fn guest_channel_info(&self, id: &VmId) -> Result<GuestChannelInfo> {
        self.driver.guest_channel_info(id)
    }

    fn is_available(&self) -> Result<bool> {
        self.driver.is_available()
    }

    /// Spawn a clean, pre-workload standby parent — a factory, never a
    /// workload. `StandbySpec` carries no plan/secret/entrypoint field, so a
    /// parent is structurally incapable of holding workload authority (the
    /// never-promote-a-parent guard is made unrepresentable here, not merely
    /// checked). The runner therefore never spawns the per-child substitution
    /// endpoint for a parent — that is a workload-only step
    /// (`ClaimGuards::spawn_endpoint`, called from `start_workload`) — and
    /// delegates the entire boot-to-ready-plus-capture sequence to the driver,
    /// which knows nothing about admission.
    fn spawn_standby(
        &self,
        spec: &StandbySpec,
    ) -> std::result::Result<StandbyHandle, StandbyError> {
        self.driver.spawn_standby_parent(spec)
    }

    fn start(&self, config: &VmStartConfig) -> Result<VmId> {
        let state_dir = vm_state_dir(&config.name);
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("create state dir {}", state_dir.display()))?;

        // Admission gate — refuse a rootfs whose parent dir carries no
        // overlay-aware sidecar (no `/mvm/runtime` mount point). Runs before any
        // endpoint/broker spawn or boot, so a refusal leaves no live process
        // behind. Routed through the shared `ClaimGuards` so a warm claim runs
        // the identical gate.
        ClaimGuards::new(&self.spawner).admit_overlay_contract(config)?;
        // Record per-VM runtime metadata (the sidecar accessibility bit + the
        // boot contract) so the `mvmctl console` accessible/sealed gate holds on
        // every runner-launched VM, matching the raw backend start paths.
        crate::base::runtime_meta::record_from_start_config(
            &config.name,
            StartMode::Detached,
            config,
        )?;

        // Owned decode + defaults must outlive the `WorkloadLaunchInputs` borrows
        // below, so bind them here rather than inline.
        let default_redaction = RedactionPolicy::default();
        let decoded = decode_plan_secrets_from_state(&state_dir)?;
        let (secrets, redaction, tenant): (&[SecretBinding], &RedactionPolicy, &str) =
            match &decoded {
                Some((s, r, t)) => (s.as_slice(), r, t.as_str()),
                None => (
                    &[],
                    &default_redaction,
                    config.tenant_id.as_deref().unwrap_or("local"),
                ),
            };

        let inputs = WorkloadLaunchInputs {
            config,
            tenant,
            secrets,
            redaction,
            network_policy: &config.network_policy,
            cmdline: cmdline::runner_cmdline(config, &state_dir, |virtiofs_root, has_disk| {
                self.driver.workload_base_bootargs(virtiofs_root, has_disk)
            }),
        };
        // The supervisor + endpoint are detached/disk-backed; the live handle is
        // reconstructed by id via `attach`, so the boot handle is dropped here.
        let _vm = self.start_workload(&inputs)?;
        Ok(VmId(config.name.clone()))
    }

    fn wait(&self, id: &VmId) -> Result<VmExitStatus> {
        self.driver.attach(id)?.wait()
    }

    fn stop(&self, id: &VmId) -> Result<()> {
        // Reap the per-VM secrets endpoint first, so a crashed VM's
        // decrypted-secret process can't outlive the guest. Idempotent + a no-op
        // when the VM spawned none.
        reap_substitution_endpoint(&vm_state_dir(&id.0), &id.0);
        // Reap the per-VM broker + audit-signer (fork path) and deregister from
        // the per-tenant host-agent daemon (daemon path), so neither can outlive
        // the guest. Each is an idempotent no-op for the other path and for a VM
        // that registered none.
        crate::broker_services_spawn::reap_broker_services(&vm_state_dir(&id.0));
        crate::host_agent_spawn::reap_host_agent_services_from_state(&vm_state_dir(&id.0), &id.0);
        self.driver.attach(id)?.kill()
    }

    fn stop_all(&self) -> Result<()> {
        for vm in self.list()? {
            let _ = self.stop(&vm.id);
        }
        Ok(())
    }

    fn pause(&self, id: &VmId) -> Result<()> {
        self.driver.attach(id)?.pause()
    }

    fn resume(&self, id: &VmId) -> Result<()> {
        self.driver.attach(id)?.resume()
    }

    fn status(&self, id: &VmId) -> Result<VmStatus> {
        self.driver.attach(id)?.status()
    }

    fn logs(&self, id: &VmId, _lines: u32, _hypervisor: bool) -> Result<String> {
        // Capture-only console; one log (no separate hypervisor stream).
        let log = vm_state_dir(&id.0).join("console.log");
        std::fs::read_to_string(&log).with_context(|| format!("read {}", log.display()))
    }

    fn list(&self) -> Result<Vec<VmInfo>> {
        let root = vms_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow::anyhow!("read {}: {e}", root.display())),
        };
        let mut vms = Vec::new();
        for entry in entries.flatten() {
            // console.log is the generic marker that a workload booted in this
            // state dir (every backend captures it). A driver-provided marker
            // could replace this later.
            if !entry.path().join("console.log").exists() {
                continue;
            }
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let id = VmId(name.clone());
            let status = self.status(&id).unwrap_or(VmStatus::Stopped);
            vms.push(VmInfo {
                id,
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

    fn install(&self) -> Result<()> {
        // The hvf VMM needs no host install.
        Ok(())
    }
}

impl<D: VmmDriver + 'static, S: EndpointSpawner + 'static, B: BrokerRegistrar + 'static>
    WorkloadBackend for WorkloadRunner<D, S, B>
{
    fn egress_substitution_transport(&self) -> EgressSubstitutionTransport {
        // The runner always routes egress through the per-VM vsock UDS endpoint —
        // the sole gate off the box. No transparent :80/:443 terminator.
        EgressSubstitutionTransport::VsockUdsChannel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use mvm_agentd::vsock::EGRESS_PORT;
    use mvm_core::plan::{Nonce, SecretBinding, SecretSource, VerbGrant, VerbId};
    use mvm_core::protocol::vm_backend::VerbGrantEnvelope;
    use mvm_core::util::test_env::TestEnv;

    use crate::driver::HvfDriver;
    use crate::driver::mock::MockDriver;

    /// An `EndpointSpawner` test double: records the request it was handed and
    /// returns a canned UDS without spawning any process. `Mutex` (not `RefCell`)
    /// so it satisfies the `Send + Sync` a `VmBackend` spawner must be.
    struct RecordingSpawner {
        uds: PathBuf,
        seen: Mutex<Option<Recorded>>,
    }

    struct Recorded {
        raw_egress: bool,
        tenant: String,
        secrets_len: usize,
        policy: NetworkPolicy,
    }

    impl RecordingSpawner {
        fn new(uds: &str) -> Self {
            Self {
                uds: PathBuf::from(uds),
                seen: Mutex::new(None),
            }
        }
    }

    impl EndpointSpawner for RecordingSpawner {
        fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf> {
            *self.seen.lock().unwrap() = Some(Recorded {
                raw_egress: req.raw_egress,
                tenant: req.tenant.to_string(),
                secrets_len: req.secrets.len(),
                policy: req.network_policy.clone(),
            });
            Ok(self.uds.clone())
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
            });
            Ok(BrokerGuard::defused())
        }
    }

    fn config(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
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
            .find(|p| p.guest_port == EGRESS_PORT)
            .map(|p| p.host_uds.as_path())
            .expect("spec carries an EGRESS_PORT vsock channel")
    }

    #[test]
    fn start_workload_threads_endpoint_uds_into_egress_port() {
        let policy = NetworkPolicy::deny_all();
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
    fn start_workload_uses_raw_egress_when_no_secrets_and_wire_when_secrets() {
        let policy = NetworkPolicy::deny_all();
        let redaction = RedactionPolicy::default();

        // No secrets ⇒ raw TCP egress.
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
                .raw_egress
        );

        // One secret ⇒ WireRequest substitution (raw_egress false).
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
        assert!(!recorded.raw_egress);
        assert_eq!(recorded.secrets_len, 1);
    }

    #[test]
    fn start_workload_passes_the_network_policy_and_tenant_to_the_spawner() {
        let policy = NetworkPolicy::deny_all();
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
        assert_eq!(recorded.policy, NetworkPolicy::deny_all());
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
            .find(|p| p.guest_port == BROKER_PORT)
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
            specs[0].vsock.iter().all(|p| p.guest_port != BROKER_PORT),
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
            verity_path: Some(verity.display().to_string()),
            roothash: Some("a".repeat(64)),
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

        let require_grant = crate::microvm::require_grant_cmdline_token(vm_name)
            .expect("sidecar present ⇒ enforcement token");
        for needle in [
            "mvm.roothash=",
            "mvm.data=/dev/vda",
            "mvm.verb_grant=",
            require_grant.as_str(),
            "mvm.host_signer_pub=",
            "mvm.vsock_egress=1",
            "mvm.runtime_source_policy=",
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

        let expected_base = driver.workload_base_bootargs(false, true);
        assert!(
            cmdline.starts_with(&expected_base),
            "cmdline did not start with the driver's base bootargs {expected_base:?}: {cmdline}"
        );
        assert!(
            !cmdline.contains("ttyAMA0"),
            "cmdline carried the hardcoded HVF console rather than the driver's: {cmdline}"
        );
    }

    fn disk_volume(host: &str, guest: &str, read_only: bool) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
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
        let policy = NetworkPolicy::deny_all();
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
            .filter(|p| p.guest_port > CONSOLE_PORT_BASE)
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
        let policy = NetworkPolicy::deny_all();
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

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path().join("checkpoints"));
        let rootfs = tmp.path().join("parent-rootfs.ext4");
        std::fs::write(&rootfs, b"parent rootfs bytes").unwrap();

        let runner = WorkloadRunner::new(
            MockDriver::default().with_vm_full_rootfs(&rootfs),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );
        let spec = sample_standby_spec("parent-a", tmp.path());

        let handle = runner
            .spawn_standby_captured(
                &SpawnContext {
                    checkpoints: &store,
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
    }

    fn sample_standby_spec(id: &str, vm_state_dir: &Path) -> mvm_core::vm_backend::StandbySpec {
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
            image_path: None,
            image_sha256: None,
        }
    }

    /// `spawn_standby` on the `WorkloadRunner` records a clean, pre-workload
    /// parent: no plan authority (`StandbySpec`/`StandbyHandle`/`VmmSpec` have
    /// no field that could carry one), and — the invariant this test actually
    /// exercises — no substitution endpoint is ever spawned for it, unlike
    /// every real workload boot on this runner.
    #[test]
    fn spawn_standby_records_pre_workload_parent_with_no_secrets_endpoint() {
        let runner = WorkloadRunner::new(
            MockDriver::default(),
            RecordingSpawner::new("/run/ep.sock"),
            RecordingBrokerRegistrar::new(),
        );

        let tmp = tempfile::tempdir().unwrap();
        let spec = sample_standby_spec("standby-test", &tmp.path().join("vm"));

        let handle = runner
            .spawn_standby(&spec)
            .expect("spawn_standby succeeds through the mock driver");

        // Record + list through the real pool — the same round-trip the CLI's
        // warm_to_target caller runs after a successful spawn_standby.
        let pool = crate::standby_pool::SupervisorStandbyPool::at(tmp.path().join("pool"));
        pool.record(&handle).unwrap();
        let recorded = pool.list().unwrap();
        assert_eq!(recorded.len(), 1);
        assert!(matches!(
            recorded[0].state,
            mvm_core::vm_backend::StandbyState::Idle
        ));

        // The parent's boot recipe carries no cmdline (no entrypoint, no plan,
        // no verb grant) and no vsock channel at all (no egress/broker port) —
        // a factory has no workload authority and no secrets endpoint.
        let booted = runner.driver.booted_specs();
        assert_eq!(booted.len(), 1);
        assert!(
            booted[0].cmdline.is_empty(),
            "parent boot must carry no cmdline: {}",
            booted[0].cmdline
        );
        assert!(
            booted[0].vsock.is_empty(),
            "parent boot must carry no vsock channel (no egress/broker endpoint)"
        );

        // No substitution endpoint was spawned for the parent: the endpoint
        // spawner was never invoked, unlike every real `start_workload` call.
        assert!(
            runner.spawner.seen.lock().unwrap().is_none(),
            "a standby parent must never get a substitution endpoint"
        );
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

    /// An `EndpointSpawner` double that keys its returned socket on the vm name it
    /// is handed — mirroring `RealEndpointSpawner` — and records that name, so a
    /// test can prove the child endpoint is keyed on the child's own id and the
    /// parent got none, with no real endpoint process.
    #[derive(Default)]
    struct KeyingSpawner {
        seen_vm: Mutex<Option<String>>,
    }

    impl EndpointSpawner for KeyingSpawner {
        fn spawn(&self, req: &EndpointSpawnRequest<'_>) -> Result<PathBuf> {
            *self.seen_vm.lock().unwrap() = Some(req.vm_name.to_string());
            Ok(vm_substitution_endpoint_socket(req.vm_name))
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
                runtime_source_policy: None,
                runtime_overlay_version: None,
                tag: None,
                created_unix: 1,
                quiesced: true,
            },
        )
        .unwrap();
        (checkpoints, snapshots, parent_id, parent_meta)
    }

    /// Build a signed, admitted child plan whose bound image digest is the
    /// parent's own verified rootfs content-address (claim-8 authority), the way
    /// the CLI mints it before handing the runner the claim.
    fn signed_child_plan_json(image_sha256: &str) -> String {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("tenant-x")
            .build();
        plan.image.sha256 = image_sha256.to_string();
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        serde_json::to_string(&mvm_core::plan::sign_plan(&plan, &key, "host:test")).unwrap()
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
            parent_checkpoint: None,
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
            network_policy: NetworkPolicy::deny_all(),
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
