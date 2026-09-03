//! `Supervisor` — aggregate that owns every component slot plus the
//! plan execution state machine, and drives the launch lifecycle.
//!
//! `Default::default()` returns a supervisor wired with every `Noop`
//! slot. `Supervisor::launch(plan)` is the happy path:
//!   1. verify the signed plan
//!   2. transition Pending → Verified
//!   3. ask the backend to launch
//!   4. transition Verified → Launched → Running
//!
//! Plus `Supervisor::stop(plan_id)` to walk Running → Stopping → Stopped.
//! The supervisor is sync today but the slot trait methods are async
//! (real impls drive HTTP / vsock); `launch` and `stop` are async.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use mvm_core::plan::{
    DepsVolumeBinding, NonceStore, PlanId, PlanValidityError, SignedExecutionPlan, TenantId,
    WorkloadId, check_window,
};
use mvm_core::time::{Clock, SystemClock};
use mvm_sdk::compile::deps_audit::{VolumeError, verify_sealed_volume};
use thiserror::Error;
use tracing::warn;

use mvm_core::network_policy::NetworkPolicy;
use mvm_core::plan::Variant;
use mvm_core::policy::{DEFAULT_BODY_CAP_BYTES, EgressPolicy, ToolPolicy};
use mvm_core::vm_backend::EnforcedGrants;
use mvm_net::{EgressEnforcer, EgressWiring, EnforcementError};

use crate::supervisor::artifact::{ArtifactCollector, NoopArtifactCollector};
use crate::supervisor::audit::{AuditSigner, NoopAuditSigner};
use crate::supervisor::backend::{BackendError, BackendLauncher, NoopBackendLauncher};
use crate::supervisor::circuit_breaker::{CircuitBreaker, InspectorReporter};
use crate::supervisor::destination::DestinationPolicy;
use crate::supervisor::egress::{NoopEgressProxy, SupervisorEgressProxy};
use crate::supervisor::firewall::seam::SupervisorEgressEnforcer;
use crate::supervisor::firewall::{
    FirewallEnforcer, FirewallError, FirewallSpec, NoopFirewallEnforcer,
};
use crate::supervisor::injection_guard::InjectionGuard;
use crate::supervisor::inspector::{Inspector, InspectorChain};
use crate::supervisor::keystore::{KeystoreReleaser, NoopKeystoreReleaser};
use crate::supervisor::l7_proxy::{DnsResolver, EgressAuditSink, L7EgressProxy};
use crate::supervisor::pii_redactor::PiiRedactor;
use crate::supervisor::policy_tool_gate::PolicyToolGate;
use crate::supervisor::secrets_scanner::SecretsScanner;
use crate::supervisor::ssrf_guard::SsrfGuard;
use crate::supervisor::state::{PlanState, PlanStateMachine, StateTransitionError};
use crate::supervisor::tool_gate::{NoopToolGate, ToolGate};

/// Stable identity shared by every revision of one tenant workload.
///
/// `PlanId` identifies one content-addressed execution and therefore changes
/// when a hot policy revision is published. Firewall state survives those
/// revisions, so it is keyed by this identity instead.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkloadKey {
    /// Tenant that owns the workload.
    pub tenant: TenantId,
    /// Stable workload identity within the tenant.
    pub workload: WorkloadId,
}

impl WorkloadKey {
    fn from_plan(plan: &mvm_core::plan::ExecutionPlan) -> Self {
        Self {
            tenant: plan.tenant.clone(),
            workload: plan.workload.clone(),
        }
    }
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("plan signature/parse failed: {0}")]
    PlanVerify(String),

    /// The plan's validity window doesn't cover
    /// `now`, or its nonce was already seen for the signer that
    /// authored it.
    #[error("plan validity check failed: {0}")]
    Validity(#[from] PlanValidityError),

    #[error("plan state transition failed: {0}")]
    State(#[from] StateTransitionError),

    #[error("backend error: {0}")]
    Backend(#[from] BackendError),

    #[error("firewall error: {0}")]
    Firewall(#[from] FirewallError),

    #[error("egress enforcement error: {0}")]
    EgressEnforcement(#[from] EnforcementError),

    #[error("firewall proxy interface not configured")]
    FirewallProxyIfaceMissing,

    #[error("egress proxy error: {0}")]
    Egress(String),

    #[error("tool gate error: {0}")]
    Tool(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("artifact error: {0}")]
    Artifact(String),

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    /// Claim 9: the plan pinned a deps
    /// volume but `verify_sealed_volume` re-derived a different hash
    /// from the on-disk content. The volume was tampered with after
    /// the plan was signed (or after the volume was sealed).
    #[error(
        "deps-volume tampered: plan pinned volume_hash {expected}, computed {actual} from on-disk content"
    )]
    DepsVolumeTampered { expected: String, actual: String },

    /// The on-disk `meta.json` parses cleanly but
    /// its bytes don't hash to the plan's `manifest_sha256`. A
    /// belt-and-suspenders check against future hash-derivation
    /// drift — if a forger ever produces content that hashes to the
    /// same `volume_hash`, the manifest sha must still mismatch.
    #[error(
        "deps-volume manifest sha mismatch: plan pinned {expected}, computed {actual} from on-disk meta.json"
    )]
    DepsVolumeManifestMismatch { expected: String, actual: String },

    /// The plan pinned a deps volume but the
    /// resolved directory doesn't exist on disk (workload built on
    /// a different host, volume was GC'd, etc.). Fail closed — no
    /// silent recovery to a "best-effort" launch.
    #[error("deps-volume missing or unreadable at {}: {source}", path.display())]
    DepsVolumeIo {
        path: PathBuf,
        #[source]
        source: VolumeError,
    },

    /// The plan's sealed image asserted it carries no
    /// workload entrypoint. The SDK's compile gate refuses to
    /// produce such an image; this admission-time refusal is defense in
    /// depth if one reaches the supervisor anyway.
    #[error("sealed image declares no entrypoint (entrypoint.absent)")]
    EntrypointAbsent,
}

pub struct Supervisor {
    pub egress: Arc<dyn SupervisorEgressProxy>,
    pub tool_gate: Arc<dyn ToolGate>,
    pub keystore: Arc<dyn KeystoreReleaser>,
    pub audit: Arc<dyn AuditSigner>,
    pub artifact: Arc<dyn ArtifactCollector>,
    pub backend: Arc<dyn BackendLauncher>,
    pub firewall: Arc<dyn FirewallEnforcer>,
    pub state: PlanStateMachine,
    /// Clock used for plan-validity-window checks. Defaults to
    /// `SystemClock`; tests inject a fixed clock.
    pub clock: Arc<dyn Clock>,
    /// Per-signer nonce ledger for replay protection. Held behind a
    /// `Mutex` because `launch` takes
    /// `&mut self` but the store may eventually be shared across
    /// concurrent admission paths. `std::sync::Mutex` is sufficient:
    /// no `await` inside the locked region.
    pub nonce_store: Arc<Mutex<NonceStore>>,
    /// False-positive circuit-breaker reporter.
    /// `None` means the L7 egress chain runs without breakers — the
    /// fail-closed default for production until an operator opts in
    /// via [`Supervisor::with_circuit_breakers`]. When `Some`, every
    /// inspector built by [`Supervisor::with_l7_egress`] is wrapped
    /// in a [`CircuitBreaker`] that consults this reporter.
    pub circuit_breakers: Option<Arc<InspectorReporter>>,

    /// Root directory the deps-volume admission gate walks to find
    /// `<volume_hash>/` directories.
    /// `None` (the default) resolves to
    /// [`mvm_core::config::mvm_deps_volumes_dir`] at admit time;
    /// tests inject a tempdir.
    pub deps_volumes_root: Option<PathBuf>,
    /// Supervisor-owned proxy interface for default-deny firewall
    /// rules. VM identity and TAP allocation come from backend
    /// launch preparation; this is the only network identifier the
    /// supervisor still owns directly.
    pub firewall_proxy_iface: Option<String>,
    /// VM-scoped firewall installs keyed by stable workload identity. A hot
    /// plan revision replaces the prior entry instead of orphaning its rules.
    pub installed_firewalls: BTreeMap<WorkloadKey, FirewallSpec>,
    /// Transient index from an execution plan to its workload key, allowing
    /// the legacy stop API to withdraw the correct workload-scoped rules.
    firewall_plan_keys: BTreeMap<PlanId, WorkloadKey>,
    /// What actually bounded each running workload, keyed by plan.
    ///
    /// The backend's read-back, not the plan's request: a receipt that
    /// reported the requested grant would assert an enforcement nobody
    /// verified, which is the failure mode the tier enum exists to prevent.
    enforced_grants: BTreeMap<PlanId, EnforcedGrants>,
    /// Host-side vsock egress telemetry probe manager (eBPF/procfs).
    ebpf_telemetry: crate::supervisor::ebpf_telemetry::EbpfTelemetryManager,
}

impl Default for Supervisor {
    /// Default is the fail-closed configuration: every component
    /// slot is `Noop`. The invariant — "tenant code never
    /// runs in Zone B unless every slot is owned by a real impl" —
    /// is encoded by the `*Error::NotWired` returns from each Noop.
    fn default() -> Self {
        Self {
            egress: Arc::new(NoopEgressProxy),
            tool_gate: Arc::new(NoopToolGate),
            keystore: Arc::new(NoopKeystoreReleaser),
            audit: Arc::new(NoopAuditSigner),
            artifact: Arc::new(NoopArtifactCollector),
            backend: Arc::new(NoopBackendLauncher),
            firewall: Arc::new(NoopFirewallEnforcer),
            state: PlanStateMachine::new(),
            clock: Arc::new(SystemClock),
            nonce_store: Arc::new(Mutex::new(NonceStore::new())),
            circuit_breakers: None,
            deps_volumes_root: None,
            firewall_proxy_iface: None,
            installed_firewalls: BTreeMap::new(),
            firewall_plan_keys: BTreeMap::new(),
            enforced_grants: BTreeMap::new(),
            ebpf_telemetry: crate::supervisor::ebpf_telemetry::EbpfTelemetryManager::new(),
        }
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Wire the backend launcher slot. The launcher owns backend
    /// runtime metadata and must implement `prepare_launch()` without
    /// starting tenant code; [`Supervisor::launch`] installs firewall
    /// policy from that metadata before calling `launch()`.
    pub fn with_backend_launcher(mut self, backend: Arc<dyn BackendLauncher>) -> Self {
        self.backend = backend;
        self
    }

    /// Wire a prebuilt egress proxy slot.
    pub fn with_egress_proxy(mut self, egress: Arc<dyn SupervisorEgressProxy>) -> Self {
        self.egress = egress;
        self
    }

    /// Wire a prebuilt tool gate slot.
    pub fn with_tool_gate_slot(mut self, tool_gate: Arc<dyn ToolGate>) -> Self {
        self.tool_gate = tool_gate;
        self
    }

    /// Wire a prebuilt keystore releaser slot.
    pub fn with_keystore_releaser(mut self, keystore: Arc<dyn KeystoreReleaser>) -> Self {
        self.keystore = keystore;
        self
    }

    /// Wire a prebuilt audit signer slot.
    pub fn with_audit_signer(mut self, audit: Arc<dyn AuditSigner>) -> Self {
        self.audit = audit;
        self
    }

    /// Wire a prebuilt artifact collector slot.
    pub fn with_artifact_collector(mut self, artifact: Arc<dyn ArtifactCollector>) -> Self {
        self.artifact = artifact;
        self
    }

    /// Wire the platform firewall enforcer slot. The default
    /// [`NoopFirewallEnforcer`] fails closed until a real enforcer is
    /// supplied.
    pub fn with_firewall_enforcer(mut self, firewall: Arc<dyn FirewallEnforcer>) -> Self {
        self.firewall = firewall;
        self
    }

    /// Configure the supervisor-owned proxy interface that VM TAP
    /// traffic is allowed to reach. Identifier validation still runs
    /// inside [`Supervisor::launch`] before any firewall backend sees
    /// the derived rule set.
    pub fn with_firewall_proxy_iface(mut self, iface: impl Into<String>) -> Self {
        self.firewall_proxy_iface = Some(iface.into());
        self
    }

    /// Inject a clock, primarily for deterministic admission tests.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Drive a workload's launch lifecycle: verify the signed plan,
    /// walk the state machine, request the backend launch.
    ///
    /// On any failure the state transitions to `PlanState::Failed`
    /// (best-effort — if the supervisor is already in a terminal
    /// state the second transition errors out, which is fine because
    /// we're already returning an error).
    ///
    /// `trusted_keys` mirrors `mvm_core::plan::verify_plan`'s contract —
    /// pass the supervisor's trusted-key set so a plan signed by an
    /// unknown party is refused before any other step runs.
    ///
    /// A later pass wires the supervisor's component slots into the
    /// launch path (apply egress policy, release secrets, etc.). Today's
    /// "happy path" is intentionally narrow: parse + verify + state
    /// walk + backend dispatch. The component slots are still all
    /// Noop by default, so a `Supervisor::default()` walking this
    /// path will fail at backend dispatch with `BackendError::NotWired`
    /// (the fail-closed invariant) until a real `BackendLauncher`
    /// is plumbed in.
    pub async fn launch(
        &mut self,
        signed: &SignedExecutionPlan,
        trusted_keys: &[(&str, &VerifyingKey)],
    ) -> Result<(), SupervisorError> {
        // Step 1: signature + schema + version pin. Done first
        // because nothing in the payload is trusted until the
        // signature checks out; the validity-window field below
        // is part of that payload.
        //
        // No audit emit on signature failure: we have no parsed
        // plan to bind to (`PlanAuditEntry` is keyed on plan_id, which
        // we do not know without trusting the payload). A later pass may
        // add a separate `EnvelopeRejected` audit type that carries
        // only the envelope's signer_id and a rejection reason; for
        // now this path is logged via `tracing` only.
        let plan = match mvm_core::plan::verify_plan(signed, trusted_keys) {
            Ok(p) => p,
            Err(e) => {
                let err = SupervisorError::PlanVerify(e.to_string());
                self.transition_or_warn(PlanState::Failed);
                return Err(err);
            }
        };

        // Step 1.1: the plan_id must be the content-address of the plan body.
        // A signature-valid plan whose id does not address its content is
        // refused before any resource-allocating work, so a run is only ever
        // launched under an id that genuinely addresses what ran. The plan is
        // signature-verified here, so its plan_id is trusted enough to bind a
        // chain-signed rejection entry to — unlike the Step 1 signature failure
        // above, which has no trusted plan to audit.
        if let Err(e) = mvm_core::plan::verify_plan_id(&plan) {
            self.emit_audit_then_fail(&plan, "plan.rejected.plan_id_mismatch", &e.to_string())
                .await?;
            return Err(SupervisorError::PlanVerify(e.to_string()));
        }

        // Step 1.5: time-window + nonce-replay
        // check. Without this, a captured signed plan is replayable
        // indefinitely. Both checks must pass before the backend is
        // asked to do any work, so a replayed plan never reaches the
        // resource-allocating path.
        if let Err(e) = check_window(&plan, self.clock.now()) {
            self.emit_audit_then_fail(&plan, "plan.rejected.validity_window", &e.to_string())
                .await?;
            return Err(SupervisorError::from(e));
        }
        // The signer_id is taken from the envelope after a successful
        // signature check above, which means it matches the trusted
        // key that validated this plan. Replay protection is
        // per-signer keyspace.
        //
        // The nonce check is performed in a tight block so the
        // `MutexGuard` is released before any subsequent `.await`
        // (clippy::await_holding_lock).
        let signer_id = signed.0.signer_id.clone();
        let nonce_check = {
            let mut store = self.nonce_store.lock().expect("nonce store mutex poisoned");
            store.check_and_insert(&signer_id, &plan)
        };
        if let Err(e) = nonce_check {
            self.emit_audit_then_fail(&plan, "plan.rejected.nonce_replay", &e.to_string())
                .await?;
            return Err(SupervisorError::from(e));
        }

        // Step 1.6 (claim 9): if the
        // plan pinned an application-dependencies volume, re-derive
        // its hash from the on-disk content and compare. A tampered
        // volume (mutated content, forged SBOM, garbage in cve.json,
        // anything that breaks the seal) fails the admission closed
        // — no silent recovery, no "best-effort" launch. The check
        // runs after nonce so a replay is rejected before we touch
        // the filesystem, but before `plan.admitted` so a tamper
        // surfaces as a dedicated rejection event in the audit chain
        // (not a fake "admitted then backend failed").
        if let Some(binding) = plan.deps_volume.as_ref()
            && let Err(e) = self.verify_deps_volume(binding)
        {
            self.emit_audit_then_fail(&plan, "plan.rejected.deps_volume", &e.to_string())
                .await?;
            return Err(e);
        }

        // Fail closed if a sealed image reached us with
        // no declared entrypoint. The SDK's compile gate refuses to
        // produce such an image; this is the admission-time defense in
        // depth. The wire field defaults to true (skip-serialized), so
        // every legacy plan admits unchanged — the guard only fires when
        // a plan explicitly carries entrypoint_present == false.
        if !plan.image.entrypoint_present {
            // NB: the audit event here is `plan.failed`, NOT the
            // `plan.rejected.*` shape the sibling admission rejects use — the
            // machine reason lives in the `entrypoint.absent` label. Don't
            // "consistency-fix" this to plan.rejected.entrypoint.
            self.emit_audit_then_fail(&plan, "plan.failed", "entrypoint.absent")
                .await?;
            return Err(SupervisorError::EntrypointAbsent);
        }

        // Plan is fully admitted at this point — signature, window,
        // nonce, and (if pinned) deps volume all check out. Emit the
        // success audit before any resource-allocating work so the
        // trail is preserved even if the backend fails next. Audit
        // failure here fails the launch fail-closed: audit emits
        // before forward.
        let admitted_extras = deps_volume_audit_extras(plan.deps_volume.as_ref());
        if let Err(e) = self
            .emit_admission_audit_with_extras(&plan, "plan.admitted", "", admitted_extras)
            .await
        {
            self.transition_or_warn(PlanState::Failed);
            return Err(e);
        }

        // Step 2: Pending → Verified.
        self.state.transition(PlanState::Verified).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;

        // Step 3: derive backend runtime networking metadata, then
        // install host firewall policy. Backend launch preparation
        // must not start tenant code; it only returns the VM slot the
        // backend will use. This keeps VM id + TAP allocation owned by
        // the backend while preserving firewall-before-launch ordering.
        let proxy_iface = match self.firewall_proxy_iface.clone() {
            Some(proxy_iface) => proxy_iface,
            None => {
                self.emit_audit_then_fail(
                    &plan,
                    "plan.rejected.firewall",
                    "firewall proxy interface not configured",
                )
                .await?;
                return Err(SupervisorError::FirewallProxyIfaceMissing);
            }
        };
        let launch_spec = match self.backend.prepare_launch(&plan).await {
            Ok(spec) => spec,
            Err(e) => {
                self.emit_audit_then_fail(&plan, "plan.rejected.backend", &e.to_string())
                    .await?;
                return Err(SupervisorError::from(e));
            }
        };
        let firewall_spec = match FirewallSpec::from_vm_slot(&launch_spec.vm_slot, proxy_iface) {
            Ok(spec) => spec,
            Err(e) => {
                self.emit_audit_then_fail(&plan, "plan.rejected.firewall", &e.to_string())
                    .await?;
                return Err(SupervisorError::from(e));
            }
        };
        if let Err(e) = firewall_spec.validate() {
            self.emit_audit_then_fail(&plan, "plan.rejected.firewall", &e.to_string())
                .await?;
            return Err(SupervisorError::from(e));
        }
        let workload_key = WorkloadKey::from_plan(&plan);
        if let Some(previous) = self.installed_firewalls.get(&workload_key) {
            if let Err(e) =
                SupervisorEgressEnforcer::new(self.firewall.clone()).withdraw(&previous.vm_id)
            {
                self.emit_audit_then_fail(&plan, "plan.rejected.firewall", &e.to_string())
                    .await?;
                return Err(SupervisorError::EgressEnforcement(e));
            }
            self.installed_firewalls.remove(&workload_key);
            self.firewall_plan_keys
                .retain(|_, key| key != &workload_key);
        }

        // Install host-side default-deny *through the EgressEnforcer seam*:
        // the supervisor enforces behind the trait instead of
        // calling the firewall directly. `SupervisorEgressEnforcer` delegates
        // to the same `install_default_deny`, so behaviour + the fail-closed
        // `NotWired` posture are unchanged.
        let egress_wiring = EgressWiring {
            vm_id: firewall_spec.vm_id.clone(),
            tap_iface: firewall_spec.tap_iface.clone(),
            proxy_iface: firewall_spec.proxy_iface.clone(),
        };
        if let Err(e) = SupervisorEgressEnforcer::new(self.firewall.clone())
            .enforce(&egress_wiring, &NetworkPolicy::deny_all())
        {
            self.emit_audit_then_fail(&plan, "plan.rejected.firewall", &e.to_string())
                .await?;
            return Err(SupervisorError::EgressEnforcement(e));
        }
        self.installed_firewalls
            .insert(workload_key.clone(), firewall_spec.clone());
        self.firewall_plan_keys
            .insert(plan.plan_id.clone(), workload_key);

        // Step 4: backend dispatch.
        if let Err(e) = self.backend.launch(&plan).await {
            self.teardown_firewall_for_plan(&plan.plan_id);
            self.emit_audit_then_fail(&plan, "plan.rejected.backend", &e.to_string())
                .await?;
            return Err(SupervisorError::from(e));
        }

        // Step 4.5: apply the plan's grants now that a VM exists to attach a
        // control to, and record what came back. Unlike the telemetry attach
        // below, this is not best-effort: a workload whose bounds could not be
        // applied is running unbounded, so the launch is undone rather than
        // completed with a record that says otherwise.
        let enforced = match self.backend.apply_grants(&plan).await {
            Ok(enforced) => enforced,
            Err(e) => {
                if let Err(stop_err) = self.backend.stop(&plan.plan_id).await {
                    warn!(
                        "stopping a VM whose grants could not be applied failed: {stop_err}; \
                         it may still be running"
                    );
                }
                self.teardown_firewall_for_plan(&plan.plan_id);
                self.emit_audit_then_fail(&plan, "plan.rejected.grants", &e.to_string())
                    .await?;
                return Err(SupervisorError::from(e));
            }
        };
        self.enforced_grants
            .insert(plan.plan_id.clone(), enforced.clone());

        // Attach host-side egress telemetry to the running VM. This is
        // best-effort: a failure here is logged but must not fail launch,
        // because the probe is observability-only.
        self.ebpf_telemetry.attach(&firewall_spec.vm_id);

        // Step 5: Verified → Launched → Running. A later real impl
        // will block between Launched and Running waiting for the
        // guest agent's first ping; today the transition is immediate
        // because there's no real guest to wait for.
        self.state.transition(PlanState::Launched).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;
        self.state.transition(PlanState::Running).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;

        let mut running_extras = deps_volume_audit_extras(plan.deps_volume.as_ref());
        running_extras.extend(enforced_grants_audit_extras(&enforced));
        if let Err(e) = self
            .emit_admission_audit_with_extras(&plan, "plan.running", "", running_extras)
            .await
        {
            self.transition_or_warn(PlanState::Failed);
            return Err(e);
        }

        Ok(())
    }

    /// What actually bounded this plan's workload, as read back by the backend
    /// at launch. `None` before a successful launch, and after a stop.
    ///
    /// Deliberately not the requested grants: a caller building a receipt gets
    /// the tier that fired, so it cannot report a bound that was only asked for.
    #[must_use]
    pub fn enforced_grants(&self, plan_id: &PlanId) -> Option<&EnforcedGrants> {
        self.enforced_grants.get(plan_id)
    }

    /// Re-derive the on-disk volume hash via
    /// `mvm_sdk::compile::deps_audit::verify_sealed_volume` and
    /// compare against the plan's pinned `DepsVolumeBinding`.
    ///
    /// Two checks:
    ///
    /// 1. The recomputed `volume_hash` must equal the plan's pin.
    /// 2. The on-disk `meta.json` bytes must sha256 to the plan's
    ///    pinned `manifest_sha256`. (`verify_sealed_volume` itself
    ///    only proves the manifest matches the artifacts; the
    ///    manifest's *bytes* are a separate pin so a forger who
    ///    finds a hash collision still hits this gate.)
    ///
    /// Both fail closed with a typed `SupervisorError` variant the
    /// admission path turns into a `plan.rejected.deps_volume`
    /// audit entry.
    fn verify_deps_volume(&self, binding: &DepsVolumeBinding) -> Result<(), SupervisorError> {
        use mvm_sdk::compile::deps_audit::FILE_MANIFEST;
        use sha2::{Digest, Sha256};

        let volume_dir = self.resolve_deps_volume_dir(&binding.volume_hash);

        // Re-derive the canonical volume hash from on-disk artifacts.
        let computed =
            verify_sealed_volume(&volume_dir).map_err(|source| SupervisorError::DepsVolumeIo {
                path: volume_dir.clone(),
                source,
            })?;
        if computed != binding.volume_hash {
            return Err(SupervisorError::DepsVolumeTampered {
                expected: binding.volume_hash.clone(),
                actual: computed,
            });
        }

        // Belt-and-suspenders: hash the on-disk meta.json bytes
        // directly and compare. Defends against a future change in
        // `derive_volume_hash` that would otherwise let two different
        // manifests resolve to the same volume hash.
        let manifest_path = volume_dir.join(FILE_MANIFEST);
        let manifest_bytes =
            std::fs::read(&manifest_path).map_err(|e| SupervisorError::DepsVolumeIo {
                path: volume_dir.clone(),
                source: VolumeError::Io {
                    path: manifest_path.clone(),
                    source: e,
                },
            })?;
        let manifest_sha = hex::encode(Sha256::digest(&manifest_bytes));
        if manifest_sha != binding.manifest_sha256 {
            return Err(SupervisorError::DepsVolumeManifestMismatch {
                expected: binding.manifest_sha256.clone(),
                actual: manifest_sha,
            });
        }

        Ok(())
    }

    /// Resolve `<volumes_root>/<volume_hash>` for a deps-volume pin.
    /// Uses the supervisor's `deps_volumes_root` override when set
    /// (tests), otherwise the canonical
    /// [`mvm_core::config::mvm_deps_volumes_dir`].
    fn resolve_deps_volume_dir(&self, volume_hash: &str) -> PathBuf {
        let root = self
            .deps_volumes_root
            .clone()
            .unwrap_or_else(|| PathBuf::from(mvm_core::config::mvm_deps_volumes_dir()));
        root.join(volume_hash)
    }

    /// Emit a rejection audit entry and then transition the state
    /// machine to `Failed`. If the audit emit itself fails, the
    /// state still transitions before we return the audit error —
    /// any rejection path must end in `Failed` regardless of audit
    /// outcome, otherwise a stuck supervisor wedges in `Pending`.
    async fn emit_audit_then_fail(
        &mut self,
        plan: &mvm_core::plan::ExecutionPlan,
        event: &str,
        reason: &str,
    ) -> Result<(), SupervisorError> {
        let audit_result = self.emit_admission_audit(plan, event, reason).await;
        self.transition_or_warn(PlanState::Failed);
        audit_result
    }

    /// Emit one admission-audit entry for `plan` with the given
    /// event name and an optional reason string in `extras["reason"]`.
    /// Every state-changing decision the
    /// supervisor makes about a plan should produce an audit entry —
    /// no unaudited control-plane mutation.
    ///
    /// Non-fatal NotWired handling: if the supervisor's audit slot is
    /// `NoopAuditSigner` (the fail-closed default), we log a tracing
    /// warning and continue. The launch itself is gated on a real
    /// AuditSigner being wired *in production*; tests use
    /// `CapturingAuditSigner`. Any other audit error (Io, etc.)
    /// propagates as `SupervisorError::Audit` and fails the launch
    /// per the invariant "audit emits before forward".
    async fn emit_admission_audit(
        &self,
        plan: &mvm_core::plan::ExecutionPlan,
        event: &str,
        reason: &str,
    ) -> Result<(), SupervisorError> {
        self.emit_admission_audit_with_extras(plan, event, reason, Vec::new())
            .await
    }

    /// Variant of [`emit_admission_audit`] that carries caller-supplied
    /// extra labels alongside the `reason` field. Used to pin the
    /// deps-volume `volume_hash` +
    /// `manifest_sha256` into every `plan.admitted` / `plan.running`
    /// entry for a deps-bound workload, so `mvmctl audit verify`
    /// detects drift if either hash changes between runs.
    async fn emit_admission_audit_with_extras(
        &self,
        plan: &mvm_core::plan::ExecutionPlan,
        event: &str,
        reason: &str,
        extras: Vec<(String, String)>,
    ) -> Result<(), SupervisorError> {
        let mut merged = extras;
        if !reason.is_empty() {
            merged.push(("reason".to_string(), reason.to_string()));
        }
        let entry = crate::supervisor::audit::for_plan(plan, None, event, merged);
        match self.audit.sign_and_emit(&entry).await {
            Ok(()) => Ok(()),
            Err(crate::supervisor::audit::AuditError::NotWired) => {
                warn!(
                    event,
                    "audit signer not wired (Noop) — admission audit dropped"
                );
                Ok(())
            }
            Err(e) => Err(SupervisorError::Audit(e.to_string())),
        }
    }

    /// Drive a workload's teardown lifecycle: Running → Stopping →
    /// Stopped, with a backend stop call in between.
    pub async fn stop(&mut self, plan_id: &PlanId) -> Result<(), SupervisorError> {
        self.state.transition(PlanState::Stopping).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;

        if let Err(e) = self.backend.stop(plan_id).await {
            self.transition_or_warn(PlanState::Failed);
            return Err(SupervisorError::from(e));
        }

        // The tiers described a running workload; keeping them past the stop
        // would let a later reader take them for a live enforcement claim.
        self.enforced_grants.remove(plan_id);

        // Detach host-side egress telemetry, using the same vm_id that
        // firewall enforcement keyed on.
        if let Some(workload_key) = self.firewall_plan_keys.get(plan_id)
            && let Some(spec) = self.installed_firewalls.get(workload_key)
        {
            self.ebpf_telemetry.detach(&spec.vm_id);
        }

        // Withdraw the host enforcement through the EgressEnforcer seam,
        // symmetric with the enforce-on-launch path. The adapter delegates to
        // the same firewall.teardown.
        if let Some(workload_key) = self.firewall_plan_keys.remove(plan_id)
            && let Some(spec) = self.installed_firewalls.remove(&workload_key)
            && let Err(e) =
                SupervisorEgressEnforcer::new(self.firewall.clone()).withdraw(&spec.vm_id)
        {
            self.transition_or_warn(PlanState::Failed);
            return Err(SupervisorError::EgressEnforcement(e));
        }

        self.state.transition(PlanState::Stopped).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;
        Ok(())
    }

    /// Best-effort transition to the given state, logging on
    /// disallowed transitions instead of bailing. Used in error
    /// paths where we want to record the failure but the state
    /// machine may already be in a terminal state.
    fn transition_or_warn(&mut self, to: PlanState) {
        if let Err(e) = self.state.transition(to) {
            warn!(?e, ?to, "state transition during error handling failed");
        }
    }

    fn teardown_firewall_for_plan(&mut self, plan_id: &PlanId) {
        // Best-effort withdraw through the seam.
        if let Some(workload_key) = self.firewall_plan_keys.remove(plan_id)
            && let Some(spec) = self.installed_firewalls.remove(&workload_key)
            && let Err(e) =
                SupervisorEgressEnforcer::new(self.firewall.clone()).withdraw(&spec.vm_id)
        {
            warn!(?e, vm_id = %spec.vm_id, "egress teardown after launch failure failed");
        }
    }

    /// Wire the L7 egress proxy slot from a workload's
    /// [`EgressPolicy`] + variant:
    ///
    /// - Builds the inspector chain from `policy.allow_list` and the
    ///   curated default rulesets, in the recommended order
    ///   (DestinationPolicy → SsrfGuard → SecretsScanner →
    ///   InjectionGuard → PiiRedactor).
    /// - **Refuses `Variant::Prod` ⊕ `policy.allow_plain_http = true`**
    ///   with a [`SupervisorError::PolicyViolation`]. This makes the
    ///   secure default louder than a comment: a production policy
    ///   bundle that opts into plain HTTP fails policy load, not
    ///   silently accepts unencrypted egress.
    /// - Honours `policy.disabled_inspectors` for opt-out by name.
    ///   Operators can disable a specific inspector (e.g.,
    ///   `pii_redactor` for an analytics workload) without rewriting
    ///   the chain order.
    /// - Honours `policy.body_cap_bytes` (defaults to
    ///   [`DEFAULT_BODY_CAP_BYTES`] when the field is 0).
    pub fn with_l7_egress(
        mut self,
        policy: &EgressPolicy,
        variant: Variant,
        resolver: Arc<dyn DnsResolver>,
        audit_sink: Arc<dyn EgressAuditSink>,
    ) -> Result<Self, SupervisorError> {
        // Variant gate — production workloads must not honour an
        // `allow_plain_http = true` field, even if a policy bundle
        // somehow ends up carrying one.
        if variant.is_prod() && policy.allow_plain_http {
            return Err(SupervisorError::PolicyViolation(
                "EgressPolicy.allow_plain_http=true forbidden for Variant::Prod".to_string(),
            ));
        }

        let chain = build_inspector_chain(policy, self.circuit_breakers.clone());
        let body_cap = if policy.body_cap_bytes == 0 {
            DEFAULT_BODY_CAP_BYTES
        } else {
            policy.body_cap_bytes
        };
        // u64 → usize: clamp at usize::MAX on 32-bit platforms.
        // 16 MiB fits in usize on all platforms we target, so this
        // is purely defensive against a malicious policy bundle.
        let body_cap = usize::try_from(body_cap).unwrap_or(usize::MAX);

        let proxy = L7EgressProxy::new(
            Arc::new(chain),
            resolver,
            audit_sink,
            body_cap,
            policy.allow_plain_http,
        );
        self.egress = Arc::new(proxy);
        Ok(self)
    }

    /// Wire the false-positive circuit breakers.
    /// When set, every inspector built by [`Supervisor::with_l7_egress`]
    /// is wrapped in a [`CircuitBreaker`] that consults this reporter
    /// on each `inspect()` call and downgrades `Deny` → `Transform`
    /// when the breaker for that inspector's name is open.
    ///
    /// Order matters: call `with_circuit_breakers` **before**
    /// `with_l7_egress` (the egress builder reads `self.circuit_breakers`
    /// at chain-build time). Calling it after has no effect on an
    /// already-built chain — the inspectors live inside the
    /// `Arc<dyn SupervisorEgressProxy>` and aren't reachable for re-wrapping.
    pub fn with_circuit_breakers(mut self, reporter: Arc<InspectorReporter>) -> Self {
        self.circuit_breakers = Some(reporter);
        self
    }

    /// Wire the tool gate slot from a workload's [`ToolPolicy`].
    /// Pure policy decision (allowlist lookup); the vsock RPC layer
    /// that drives `check()` calls from the workload lands later.
    ///
    /// An empty `ToolPolicy.allowed` is **not** treated as
    /// "anything goes" — it's a deliberate fail-closed deny-all
    /// configuration. Operators who genuinely want the workload to
    /// have no tool restrictions must wire a different gate
    /// implementation.
    pub fn with_tool_gate(mut self, policy: &ToolPolicy) -> Self {
        self.tool_gate = Arc::new(PolicyToolGate::from_policy(policy));
        self
    }
}

/// Build the `(key, value)` extras the supervisor stamps onto every
/// admission audit entry (`plan.admitted` / `plan.running`) for a
/// deps-bound workload. `mvmctl audit verify`
/// reads these back to detect drift if either hash changes between
/// the plan signing and the on-disk volume.
///
/// Returns an empty `Vec` when the plan has no deps-volume binding,
/// so the existing claim-8 audit shape (no deps_volume extras) is
/// preserved verbatim for plans that don't opt in.
fn deps_volume_audit_extras(binding: Option<&DepsVolumeBinding>) -> Vec<(String, String)> {
    match binding {
        Some(b) => vec![
            ("deps_volume_hash".to_string(), b.volume_hash.clone()),
            (
                "deps_manifest_sha256".to_string(),
                b.manifest_sha256.clone(),
            ),
        ],
        None => Vec::new(),
    }
}

/// Audit labels naming the mechanism that bounded each dimension.
///
/// The tier labels, never the requested numbers: a run that asked for 1.5 cores
/// and got nothing must not leave a record that mentions 1.5 cores, or the
/// audit trail asserts an enforcement that did not happen.
fn enforced_grants_audit_extras(enforced: &EnforcedGrants) -> Vec<(String, String)> {
    vec![
        (
            "grants_cpu_tier".to_string(),
            enforced.cpu.label().to_string(),
        ),
        (
            "grants_wall_clock_tier".to_string(),
            enforced.wall_clock.label().to_string(),
        ),
    ]
}

/// Stable identifiers for every inspector the canonical
/// [`build_inspector_chain`] wires. Matches each inspector's
/// `Inspector::name()` return value. Operators reference these
/// names in `EgressPolicy::disabled_inspectors`; [`validate_egress_policy_inspector_names`]
/// uses this list to fail-loud on typos.
///
/// Order is cheap/precise first, body inspectors last — keep it
/// that way if you add a name.
pub const KNOWN_INSPECTOR_NAMES: &[&str] = &[
    "destination_policy",
    "ssrf_guard",
    "secrets_scanner",
    "injection_guard",
    "pii_redactor",
];

/// Validation error for [`validate_egress_policy_inspector_names`].
///
/// The error carries the offending row index + the operator-supplied
/// name + the list of valid names so a single error message tells
/// the operator exactly which `[egress].disabled_inspectors` entry
/// to fix and what to put there instead.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum EgressPolicyValidationError {
    #[error(
        "disabled_inspectors[{index}] = {name:?} is not a known inspector name; \
         valid names are {valid:?}"
    )]
    UnknownDisabledInspector {
        index: usize,
        name: String,
        valid: &'static [&'static str],
    },
}

/// Verify every name in `policy.disabled_inspectors` matches a known
/// inspector (member of [`KNOWN_INSPECTOR_NAMES`]).
///
/// `build_inspector_chain` itself stays lenient — it silently skips
/// unknown names so in-process callers that own their config can
/// extend the disabled list ahead of inspector additions. This
/// function is the *admission-time* tightening: the policy
/// resolver in `mvm-cli` calls this to fail loud on typos
/// (e.g. `["ssr_guard"]` would silently leave SSRF enforced; not
/// catching that at admission means the operator thinks they
/// disabled it).
pub fn validate_egress_policy_inspector_names(
    policy: &EgressPolicy,
) -> Result<(), EgressPolicyValidationError> {
    for (index, name) in policy.disabled_inspectors.iter().enumerate() {
        if !KNOWN_INSPECTOR_NAMES.contains(&name.as_str()) {
            return Err(EgressPolicyValidationError::UnknownDisabledInspector {
                index,
                name: name.clone(),
                valid: KNOWN_INSPECTOR_NAMES,
            });
        }
    }
    Ok(())
}

/// URL schemes accepted in [`mvm_core::policy::AuditPolicy::stream_destinations`].
/// The supervisor's eventual audit-stream replicator will emit each
/// entry to its matching backend; validating shape at admission means a typo
/// (`fil:///var/log/...` vs `file:///var/log/...`) fails the boot
/// loudly instead of silently dropping audit emissions.
pub const KNOWN_AUDIT_STREAM_SCHEMES: &[&str] = &["file://", "unix://", "https://", "http://"];

/// Validation error for [`validate_audit_policy_stream_destinations`].
///
/// The error names the offending row index + the operator-supplied
/// value + the accepted scheme list so a single error message tells
/// the operator exactly which `[audit].stream_destinations` entry to
/// fix.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuditPolicyValidationError {
    #[error(
        "stream_destinations[{index}] = {value:?} doesn't use a known URL scheme; \
         valid prefixes are {valid:?}"
    )]
    UnknownStreamScheme {
        index: usize,
        value: String,
        valid: &'static [&'static str],
    },
}

/// Verify every entry in `policy.stream_destinations` starts with a
/// known scheme prefix.
///
/// The supervisor's eventual replicator (waiting on the mvm-hostd
/// lift) is the consumer; this function is the *admission-time*
/// shape gate so an operator who typo'd `htpps://` doesn't think
/// they've configured TLS audit replication while the boot proceeds
/// in silence.
pub fn validate_audit_policy_stream_destinations(
    policy: &mvm_core::policy::AuditPolicy,
) -> Result<(), AuditPolicyValidationError> {
    for (index, value) in policy.stream_destinations.iter().enumerate() {
        if !KNOWN_AUDIT_STREAM_SCHEMES
            .iter()
            .any(|scheme| value.starts_with(scheme))
        {
            return Err(AuditPolicyValidationError::UnknownStreamScheme {
                index,
                value: value.clone(),
                valid: KNOWN_AUDIT_STREAM_SCHEMES,
            });
        }
    }
    Ok(())
}

/// Build an [`InspectorChain`] from the workload's [`EgressPolicy`].
/// Order is cheap/most-precise checks first, body
/// inspectors last (so a destination-denied request never pays the
/// cost of body scanning).
///
/// `policy.disabled_inspectors` filters out by name — empty == every
/// inspector enabled. The named inspectors must match
/// `Inspector::name()` strings exactly.
///
/// When `breakers` is `Some`, each inspector is wrapped in a
/// [`CircuitBreaker`] that shares the supplied
/// [`InspectorReporter`]. The chain length is unchanged — wrappers
/// preserve the wrapped inspector's `name()` so audit binding stays
/// intact.
///
/// Public so the resolver in `mvm-cli::policy_resolver`
/// can build the same canonical chain when it turns a parsed bundle
/// into a `ResolvedSlots`. Keeping the order in one place avoids
/// chain-shape drift between the in-process supervisor path and
/// the CLI resolver.
pub fn build_inspector_chain(
    policy: &EgressPolicy,
    breakers: Option<Arc<InspectorReporter>>,
) -> InspectorChain {
    let disabled = |name: &'static str| policy.disabled_inspectors.iter().any(|d| d == name);
    let wrap = |inner: Box<dyn Inspector>| -> Box<dyn Inspector> {
        match &breakers {
            Some(r) => Box::new(CircuitBreaker::new(inner, r.clone())),
            None => inner,
        }
    };
    let mut chain = InspectorChain::new();
    if !disabled("destination_policy") {
        let dp = DestinationPolicy::new(
            policy
                .allow_list
                .iter()
                .map(|(host, port)| (host.as_str(), *port)),
        );
        chain.push(wrap(Box::new(dp) as Box<dyn Inspector>));
    }
    if !disabled("ssrf_guard") {
        chain.push(wrap(Box::new(SsrfGuard::new())));
    }
    if !disabled("secrets_scanner") {
        chain.push(wrap(Box::new(SecretsScanner::with_default_rules())));
    }
    if !disabled("injection_guard") {
        chain.push(wrap(Box::new(InjectionGuard::with_default_rules())));
    }
    if !disabled("pii_redactor") {
        chain.push(wrap(Box::new(PiiRedactor::with_default_rules())));
    }
    chain
}

/// Same as [`build_inspector_chain`] but the PII inspector is
/// constructed from a parsed [`mvm_core::policy::PiiPolicy`] (mode +
/// category filter) instead of hardwired to defaults. Used by the
/// resolver so a tenant bundle's `[pii]` section actually
/// drives runtime behavior (Mode::Detect / Redact / Block, scoped to
/// a category subset).
///
/// Returns the same canonical chain order as `build_inspector_chain`.
/// The PII inspector is *skipped entirely* when `pii.mode =
/// "disabled"` (the kill-switch for analytics workloads
/// that scrub PII upstream) — same effect as adding `"pii_redactor"`
/// to `disabled_inspectors`, but expressed through the more
/// operator-natural `pii.mode` field.
///
/// Refuses unknown `pii.mode` / `pii.categories[i]` values via
/// `PiiPolicyError` so a typo fails the boot loudly at admission
/// rather than silently scanning fewer categories than intended.
pub fn build_inspector_chain_with_pii(
    egress: &EgressPolicy,
    pii: &mvm_core::policy::PiiPolicy,
    breakers: Option<Arc<InspectorReporter>>,
) -> Result<InspectorChain, crate::supervisor::pii_redactor::PiiPolicyError> {
    let disabled = |name: &'static str| egress.disabled_inspectors.iter().any(|d| d == name);
    let wrap = |inner: Box<dyn Inspector>| -> Box<dyn Inspector> {
        match &breakers {
            Some(r) => Box::new(CircuitBreaker::new(inner, r.clone())),
            None => inner,
        }
    };
    let mut chain = InspectorChain::new();
    if !disabled("destination_policy") {
        let dp = DestinationPolicy::new(
            egress
                .allow_list
                .iter()
                .map(|(host, port)| (host.as_str(), *port)),
        );
        chain.push(wrap(Box::new(dp) as Box<dyn Inspector>));
    }
    if !disabled("ssrf_guard") {
        chain.push(wrap(Box::new(SsrfGuard::new())));
    }
    if !disabled("secrets_scanner") {
        chain.push(wrap(Box::new(SecretsScanner::with_default_rules())));
    }
    if !disabled("injection_guard") {
        chain.push(wrap(Box::new(InjectionGuard::with_default_rules())));
    }
    if !disabled("pii_redactor")
        && let Some(red) = PiiRedactor::from_policy(pii)?
    {
        chain.push(wrap(Box::new(red)));
    }
    Ok(chain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::backend::{BackendLaunchSpec, BackendLauncher};
    use async_trait::async_trait;
    use chrono::{DateTime, TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use mvm_core::plan::*;
    use rand::Rng;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Test backend that records every call and lets the test pick
    /// success or failure per method.
    struct MockBackend {
        prepare_calls: Mutex<Vec<PlanId>>,
        launch_calls: Mutex<Vec<PlanId>>,
        stop_calls: Mutex<Vec<PlanId>>,
        apply_grants_calls: Mutex<Vec<PlanId>>,
        slot: mvm_runtime::base::config::VmSlot,
        prepare_should_fail: bool,
        launch_should_fail: bool,
        stop_should_fail: bool,
        /// What this backend reports it actually bounded. A real launcher reads
        /// this back off the live control; the mock states it so a test can pin
        /// the difference between what was requested and what happened.
        enforced: EnforcedGrants,
        apply_grants_should_fail: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                prepare_calls: Mutex::new(Vec::new()),
                launch_calls: Mutex::new(Vec::new()),
                stop_calls: Mutex::new(Vec::new()),
                apply_grants_calls: Mutex::new(Vec::new()),
                slot: mvm_runtime::base::config::VmSlot::new("vm1", 0),
                prepare_should_fail: false,
                launch_should_fail: false,
                stop_should_fail: false,
                enforced: EnforcedGrants::all_declared(),
                apply_grants_should_fail: false,
            }
        }

        fn prepares(&self) -> Vec<PlanId> {
            self.prepare_calls.lock().unwrap().clone()
        }

        fn launches(&self) -> Vec<PlanId> {
            self.launch_calls.lock().unwrap().clone()
        }

        fn stops(&self) -> Vec<PlanId> {
            self.stop_calls.lock().unwrap().clone()
        }

        fn grant_applications(&self) -> Vec<PlanId> {
            self.apply_grants_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl BackendLauncher for MockBackend {
        async fn prepare_launch(
            &self,
            plan: &ExecutionPlan,
        ) -> Result<BackendLaunchSpec, BackendError> {
            self.prepare_calls
                .lock()
                .unwrap()
                .push(plan.plan_id.clone());
            if self.prepare_should_fail {
                return Err(BackendError::PrepareFailed("mock prepare".into()));
            }
            Ok(BackendLaunchSpec::new(self.slot.clone()))
        }

        async fn launch(&self, plan: &ExecutionPlan) -> Result<(), BackendError> {
            self.launch_calls.lock().unwrap().push(plan.plan_id.clone());
            if self.launch_should_fail {
                return Err(BackendError::LaunchFailed("mock".into()));
            }
            Ok(())
        }

        async fn stop(&self, plan_id: &PlanId) -> Result<(), BackendError> {
            self.stop_calls.lock().unwrap().push(plan_id.clone());
            if self.stop_should_fail {
                return Err(BackendError::StopFailed("mock".into()));
            }
            Ok(())
        }

        async fn apply_grants(&self, plan: &ExecutionPlan) -> Result<EnforcedGrants, BackendError> {
            self.apply_grants_calls
                .lock()
                .unwrap()
                .push(plan.plan_id.clone());
            if self.apply_grants_should_fail {
                return Err(BackendError::LaunchFailed("mock apply_grants".into()));
            }
            Ok(self.enforced.clone())
        }
    }

    struct MockFirewall {
        installs: Mutex<Vec<FirewallSpec>>,
        teardowns: Mutex<Vec<String>>,
        install_should_fail: bool,
        teardown_should_fail: bool,
    }

    impl MockFirewall {
        fn new() -> Self {
            Self {
                installs: Mutex::new(Vec::new()),
                teardowns: Mutex::new(Vec::new()),
                install_should_fail: false,
                teardown_should_fail: false,
            }
        }

        fn installs(&self) -> Vec<FirewallSpec> {
            self.installs.lock().unwrap().clone()
        }

        fn teardowns(&self) -> Vec<String> {
            self.teardowns.lock().unwrap().clone()
        }
    }

    impl FirewallEnforcer for MockFirewall {
        fn install_default_deny(&self, spec: &FirewallSpec) -> Result<(), FirewallError> {
            self.installs.lock().unwrap().push(spec.clone());
            if self.install_should_fail {
                return Err(FirewallError::Backend("mock firewall install".to_string()));
            }
            Ok(())
        }

        fn teardown(&self, vm_id: &str) -> Result<(), FirewallError> {
            self.teardowns.lock().unwrap().push(vm_id.to_string());
            if self.teardown_should_fail {
                return Err(FirewallError::Backend("mock firewall teardown".to_string()));
            }
            Ok(())
        }
    }

    fn sample_firewall_spec() -> FirewallSpec {
        FirewallSpec::from_vm_slot(&mvm_runtime::base::config::VmSlot::new("vm1", 0), "mvmtun0")
            .expect("valid sample firewall spec")
    }

    fn sample_plan() -> ExecutionPlan {
        let mut plan = ExecutionPlan {
            grants: None,
            environment: None,
            build_provenance: Default::default(),
            snapshot_at: Default::default(),
            network_mode: Default::default(),
            stream_retention: Default::default(),
            ingress: Vec::new(),
            network_limits: Default::default(),
            schema_version: SCHEMA_VERSION,
            // Overwritten below with the content-address, matching what
            // sign_plan stamps — so a test's `plan.plan_id` equals the id that
            // actually launches and is audited.
            plan_id: PlanId(String::new()),
            plan_version: 1,
            tenant: TenantId("tenant-a".to_string()),
            workload: WorkloadId("workload-1".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "tenant-worker-aarch64".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 2,
                mem_mib: 1024,
                disk_mib: 4096,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 600,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("default-deny".to_string()),
            fs_policy: FsPolicyRef("default".to_string()),
            secrets: vec![],
            egress_policy: PolicyRef("agent-l7".to_string()),
            redaction: Default::default(),
            reversible_replacement: Default::default(),
            tool_policy: PolicyRef("read-only".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec!["/artifacts".to_string()],
                retention_days: 30,
            },
            caller_commitment: None,
            audit_labels: BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 7 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            // Replay-protection fields. The
            // supervisor's admission gate doesn't enforce these yet —
            // that's a follow-up. Today they're populated so the
            // wire format compiles and signing roundtrips work.
            valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
            asset_identities: Vec::new(),
            agent_verbs: None,
            services: Vec::new(),
            extensions: Vec::new(),
            stream_edges: Vec::new(),
            sdk_uses_sidecar: true,
        };
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        plan
    }

    fn sign_sample(plan: &ExecutionPlan) -> (SignedExecutionPlan, SigningKey, VerifyingKey) {
        let sk = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = sk.verifying_key();
        let signed = sign_plan(plan, &sk, "test");
        (signed, sk, vk)
    }

    /// Test clock — returns a fixed `DateTime<Utc>`. Lets the
    /// validity-window tests run deterministically regardless of
    /// wall-clock time.
    struct FixedClock(DateTime<Utc>);

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            self.0
        }
    }

    /// Wall clock fixed at 2026-05-01 00:30:00 UTC, which is inside
    /// the [`sample_plan`] validity window
    /// (2026-05-01 00:00:00 .. 2026-05-01 01:00:00).
    fn fixed_clock_inside_window() -> Arc<dyn Clock> {
        Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 30, 0).unwrap(),
        ))
    }

    fn make_supervisor_with_backend(b: Arc<MockBackend>) -> Supervisor {
        // Default to a clock inside the sample plan's window so
        // happy-path tests don't depend on the wall clock. Capture
        // audit entries by default so tests can assert admission
        // audit without each test re-wiring the slot.
        Supervisor::new()
            .with_backend_launcher(b)
            .with_firewall_enforcer(Arc::new(MockFirewall::new()))
            .with_firewall_proxy_iface("mvmtun0")
            .with_clock(fixed_clock_inside_window())
            .with_audit_signer(Arc::new(
                crate::supervisor::audit::CapturingAuditSigner::new(),
            ))
    }

    /// Like `make_supervisor_with_backend` but exposes the
    /// `CapturingAuditSigner` so the test can read back the entries
    /// the supervisor emitted.
    fn make_supervisor_with_audit(
        b: Arc<MockBackend>,
    ) -> (
        Supervisor,
        Arc<crate::supervisor::audit::CapturingAuditSigner>,
    ) {
        let audit = Arc::new(crate::supervisor::audit::CapturingAuditSigner::new());
        let s = Supervisor::new()
            .with_backend_launcher(b)
            .with_firewall_enforcer(Arc::new(MockFirewall::new()))
            .with_firewall_proxy_iface("mvmtun0")
            .with_clock(fixed_clock_inside_window())
            .with_audit_signer(audit.clone());
        (s, audit)
    }

    fn make_supervisor_with_firewall(
        b: Arc<MockBackend>,
        firewall: Arc<MockFirewall>,
    ) -> Supervisor {
        make_supervisor_with_backend(b).with_firewall_enforcer(firewall)
    }

    #[tokio::test]
    async fn builder_slots_launch_without_public_field_mutation() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let firewall = Arc::new(MockFirewall::new());
        let audit = Arc::new(crate::supervisor::audit::CapturingAuditSigner::new());
        let mut s = Supervisor::new()
            .with_backend_launcher(backend.clone())
            .with_firewall_enforcer(firewall.clone())
            .with_firewall_proxy_iface("mvmtun0")
            .with_clock(fixed_clock_inside_window())
            .with_audit_signer(audit.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Running);
        assert_eq!(backend.prepares(), vec![plan.plan_id.clone()]);
        assert_eq!(backend.launches(), vec![plan.plan_id.clone()]);
        assert_eq!(firewall.installs(), vec![sample_firewall_spec()]);
        assert_eq!(
            audit
                .entries()
                .iter()
                .map(|e| e.event.as_str())
                .collect::<Vec<_>>(),
            vec!["plan.admitted", "plan.running"]
        );
    }

    #[tokio::test]
    async fn happy_path_launch_walks_to_running() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let firewall = Arc::new(MockFirewall::new());
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Running);
        assert_eq!(backend.prepares(), vec![plan.plan_id.clone()]);
        assert_eq!(backend.launches(), vec![plan.plan_id.clone()]);
        assert!(backend.stops().is_empty());
        assert_eq!(firewall.installs(), vec![sample_firewall_spec()]);
        assert!(firewall.teardowns().is_empty());
    }

    /// A plan asking for one and a half host cores.
    fn plan_granting_a_cpu_share() -> ExecutionPlan {
        let mut plan = sample_plan();
        plan.grants = Some(mvm_contract::grants::Grants {
            cpu: Some(mvm_contract::grants::CpuGrant::Share { millicores: 1500 }),
            ..mvm_contract::grants::Grants::default()
        });
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        plan
    }

    #[tokio::test]
    async fn launch_records_the_enforced_tier_not_the_requested_grant() {
        // The plan asks for a share; this backend reports it bounded CPU with a
        // cgroup and wall clock with a timer. What the supervisor keeps, and
        // what it writes to the audit chain, must be the second answer: a
        // record that repeated the request would assert an enforcement no one
        // verified.
        let plan = plan_granting_a_cpu_share();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend {
            enforced: EnforcedGrants {
                cpu: mvm_core::vm_backend::EnforcedTier::Cgroup2CpuMax,
                wall_clock: mvm_core::vm_backend::EnforcedTier::SupervisorTimer,
            },
            ..MockBackend::new()
        });
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        s.firewall = Arc::new(MockFirewall::new());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(
            backend.grant_applications(),
            vec![plan.plan_id.clone()],
            "the plan's grants must be applied to the VM that was just started"
        );
        assert_eq!(
            s.enforced_grants(&plan.plan_id),
            Some(&EnforcedGrants {
                cpu: mvm_core::vm_backend::EnforcedTier::Cgroup2CpuMax,
                wall_clock: mvm_core::vm_backend::EnforcedTier::SupervisorTimer,
            })
        );

        let running = audit
            .entries()
            .into_iter()
            .find(|e| e.event == "plan.running")
            .expect("a running entry");
        assert_eq!(
            running.labels.get("grants_cpu_tier").map(String::as_str),
            Some("cgroup2:cpu.max"),
            "the audit label names the mechanism, not the request"
        );
        assert_eq!(
            running
                .labels
                .get("grants_wall_clock_tier")
                .map(String::as_str),
            Some("supervisor:timer")
        );
        // The number that was asked for must not appear anywhere in the record
        // of what happened.
        assert!(
            !running.labels.values().any(|v| v.contains("1500")),
            "the requested share leaked into the enforcement record: {:?}",
            running.labels
        );

        // A stopped workload is no longer bounded by anything, so the tiers
        // must not outlive it and be read later as a live claim.
        s.stop(&plan.plan_id).await.unwrap();
        assert_eq!(s.enforced_grants(&plan.plan_id), None);
    }

    #[tokio::test]
    async fn a_backend_that_cannot_apply_grants_does_not_leave_the_vm_running() {
        // The VM exists by this point, so "return an error" is not enough: an
        // unbounded workload left running is exactly what the grant was for.
        let plan = plan_granting_a_cpu_share();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend {
            apply_grants_should_fail: true,
            ..MockBackend::new()
        });
        let firewall = Arc::new(MockFirewall::new());
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        let err = s.launch(&signed, &[("test", &vk)]).await.unwrap_err();
        assert!(matches!(err, SupervisorError::Backend(_)), "{err:?}");
        assert_eq!(s.state.current(), PlanState::Failed);
        assert_eq!(backend.stops(), vec![plan.plan_id.clone()]);
        assert_eq!(firewall.teardowns(), vec!["vm1".to_string()]);
        assert_eq!(s.enforced_grants(&plan.plan_id), None);
    }

    #[tokio::test]
    async fn hot_revision_replaces_firewall_for_same_workload() {
        let first = sample_plan();
        let (signed_first, _first_sk, first_vk) = sign_sample(&first);
        let mut revision = sample_plan();
        revision.plan_version = 2;
        revision.nonce = Nonce::from_bytes([0xcd; 16]);
        revision.plan_id = mvm_core::plan::compute_plan_id(&revision);
        let (signed_revision, _revision_sk, revision_vk) = sign_sample(&revision);

        let backend = Arc::new(MockBackend::new());
        let firewall = Arc::new(MockFirewall::new());
        let mut supervisor = make_supervisor_with_firewall(backend, firewall.clone());

        supervisor
            .launch(&signed_first, &[("test", &first_vk)])
            .await
            .unwrap();
        supervisor.state = PlanStateMachine::new();
        supervisor
            .launch(&signed_revision, &[("test", &revision_vk)])
            .await
            .unwrap();

        assert_eq!(supervisor.installed_firewalls.len(), 1);
        assert!(
            supervisor
                .installed_firewalls
                .contains_key(&WorkloadKey::from_plan(&revision))
        );
        assert_eq!(firewall.teardowns(), vec!["vm1".to_string()]);
    }

    #[tokio::test]
    async fn happy_path_stop_walks_to_stopped() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let firewall = Arc::new(MockFirewall::new());
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();
        s.stop(&plan.plan_id).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Stopped);
        assert!(s.state.is_terminal());
        assert_eq!(backend.stops(), vec![plan.plan_id.clone()]);
        assert_eq!(firewall.installs(), vec![sample_firewall_spec()]);
        assert_eq!(firewall.teardowns(), vec!["vm1".to_string()]);
    }

    #[tokio::test]
    async fn invalid_signature_keeps_state_pending_or_failed() {
        let plan = sample_plan();
        let (mut signed, _sk, vk) = sign_sample(&plan);
        // Corrupt the payload after signing.
        signed.0.payload[0] ^= 0x01;

        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::PlanVerify(_))));
        // We transition to Failed on error.
        assert_eq!(s.state.current(), PlanState::Failed);
        // Backend was never asked to launch.
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn unknown_signer_blocks_before_backend() {
        let plan = sample_plan();
        let (signed, _sk, _vk) = sign_sample(&plan);
        let (_other_sk, other_vk) = {
            let sk = {
                let mut __ed_seed = [0u8; 32];
                rand::rng().fill_bytes(&mut __ed_seed);
                SigningKey::from_bytes(&__ed_seed)
            };
            let vk = sk.verifying_key();
            (sk, vk)
        };

        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        let result = s.launch(&signed, &[("not-the-signer", &other_vk)]).await;
        assert!(matches!(result, Err(SupervisorError::PlanVerify(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn backend_failure_transitions_to_failed() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let mut backend = MockBackend::new();
        backend.launch_should_fail = true;
        let backend = Arc::new(backend);
        let firewall = Arc::new(MockFirewall::new());
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::Backend(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        // Backend was called, but state never reached Launched/Running.
        assert_eq!(backend.launches(), vec![plan.plan_id.clone()]);
        // Firewall was installed before backend dispatch and removed
        // when backend launch failed.
        assert_eq!(firewall.installs(), vec![sample_firewall_spec()]);
        assert_eq!(firewall.teardowns(), vec!["vm1".to_string()]);
    }

    #[tokio::test]
    async fn default_supervisor_fails_closed_without_firewall_proxy_iface() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let mut s = Supervisor::new();
        // No firewall proxy interface — default launch fails closed before backend.
        // Pin the clock inside the plan window so validity passes and
        // the test exercises the firewall-fails-closed path it's
        // supposed to.
        s.clock = fixed_clock_inside_window();

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(
            result,
            Err(SupervisorError::FirewallProxyIfaceMissing)
        ));
        assert_eq!(s.state.current(), PlanState::Failed);
    }

    #[tokio::test]
    async fn missing_firewall_proxy_iface_blocks_before_backend_prepare() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());
        s.firewall_proxy_iface = None;

        let result = s.launch(&signed, &[("test", &vk)]).await;

        assert!(matches!(
            result,
            Err(SupervisorError::FirewallProxyIfaceMissing)
        ));
        assert_eq!(s.state.current(), PlanState::Failed);
        assert!(backend.prepares().is_empty());
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn backend_prepare_failure_blocks_firewall_install_and_backend_launch() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let mut backend = MockBackend::new();
        backend.prepare_should_fail = true;
        let backend = Arc::new(backend);
        let firewall = Arc::new(MockFirewall::new());
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        assert!(matches!(result, Err(SupervisorError::Backend(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        assert_eq!(backend.prepares(), vec![plan.plan_id.clone()]);
        assert!(backend.launches().is_empty());
        assert!(firewall.installs().is_empty());
        assert!(firewall.teardowns().is_empty());
    }

    #[tokio::test]
    async fn firewall_install_failure_blocks_backend_launch() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut firewall = MockFirewall::new();
        firewall.install_should_fail = true;
        let firewall = Arc::new(firewall);
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        // The install now flows through the EgressEnforcer seam, so a
        // firewall failure surfaces as `Egress` — but the underlying
        // `install_default_deny` is still invoked (asserted below).
        assert!(matches!(result, Err(SupervisorError::EgressEnforcement(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        assert_eq!(backend.prepares(), vec![plan.plan_id.clone()]);
        assert!(backend.launches().is_empty());
        assert_eq!(firewall.installs(), vec![sample_firewall_spec()]);
        assert!(firewall.teardowns().is_empty());
    }

    #[tokio::test]
    async fn invalid_backend_slot_blocks_before_install_and_backend_launch() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let mut backend = MockBackend::new();
        backend.slot = mvm_runtime::base::config::VmSlot::new("vm/1", 0);
        let backend = Arc::new(backend);
        let firewall = Arc::new(MockFirewall::new());
        let mut s = make_supervisor_with_firewall(backend.clone(), firewall.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        assert!(matches!(result, Err(SupervisorError::Firewall(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        assert_eq!(backend.prepares(), vec![plan.plan_id.clone()]);
        assert!(backend.launches().is_empty());
        assert!(firewall.installs().is_empty());
        assert!(firewall.teardowns().is_empty());
    }

    #[test]
    fn default_supervisor_starts_in_pending() {
        let s = Supervisor::default();
        assert_eq!(s.state.current(), PlanState::Pending);
    }

    // ----- validity-window + nonce-replay enforcement -----

    #[tokio::test]
    async fn launch_rejects_expired_plan() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());
        // Clock past valid_until.
        s.clock = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 5, 1, 2, 0, 0).unwrap(),
        ));

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::Validity(_))));
        assert!(matches!(
            result,
            Err(SupervisorError::Validity(PlanValidityError::Expired { .. }))
        ));
        assert_eq!(s.state.current(), PlanState::Failed);
        // Backend never called — replayed/expired plan never
        // reaches the resource-allocating path.
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn launch_rejects_not_yet_valid_plan() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());
        // Clock before valid_from.
        s.clock = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 4, 30, 23, 0, 0).unwrap(),
        ));

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(
            result,
            Err(SupervisorError::Validity(
                PlanValidityError::NotYetValid { .. }
            ))
        ));
        assert_eq!(s.state.current(), PlanState::Failed);
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn launch_rejects_replayed_nonce() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        // First launch succeeds.
        s.launch(&signed, &[("test", &vk)]).await.unwrap();
        assert_eq!(s.state.current(), PlanState::Running);

        // Second launch of the *same* signed plan must be refused
        // as a replay. Even though the state machine is now in
        // Running rather than Pending, the nonce check fires
        // before any state transition, so the right error surfaces.
        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(
            result,
            Err(SupervisorError::Validity(
                PlanValidityError::NonceReplay { .. }
            ))
        ));
        // Backend was called exactly once (the original launch).
        assert_eq!(backend.launches(), vec![plan.plan_id.clone()]);
    }

    #[tokio::test]
    async fn validity_check_runs_after_signature_check() {
        // Tampered signatures are reported as PlanVerify, not
        // Validity, even when the validity window would also fail.
        // This pins the order: signature → window → nonce, so a
        // forged plan never gets its window/nonce examined.
        let mut plan = sample_plan();
        plan.valid_until = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(); // very expired
        plan.valid_from = Utc.with_ymd_and_hms(2019, 1, 1, 0, 0, 0).unwrap();
        let (mut signed, _sk, vk) = sign_sample(&plan);
        signed.0.payload[0] ^= 0x01; // tamper
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;
        // Signature check fires first.
        assert!(matches!(result, Err(SupervisorError::PlanVerify(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
    }

    #[tokio::test]
    async fn nonce_replay_protection_is_per_signer() {
        // Same plan signed by two different keys with two different
        // signer ids: both launches should succeed because the nonce
        // ledger keys on signer_id, not just nonce.
        let plan = sample_plan();

        let sk_a = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk_a = sk_a.verifying_key();
        let signed_a = sign_plan(&plan, &sk_a, "alice");

        let sk_b = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk_b = sk_b.verifying_key();
        let signed_b = sign_plan(&plan, &sk_b, "bob");

        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        s.launch(&signed_a, &[("alice", &vk_a), ("bob", &vk_b)])
            .await
            .unwrap();

        // Reset state to Pending so the state machine doesn't
        // reject the second launch on its own. We're testing
        // nonce-store semantics, not the state machine, so a
        // fresh supervisor is the cleaner harness.
        let mut s2 = make_supervisor_with_backend(backend.clone());
        s2.nonce_store = s.nonce_store.clone();
        s2.launch(&signed_b, &[("alice", &vk_a), ("bob", &vk_b)])
            .await
            .unwrap();

        assert_eq!(backend.launches().len(), 2);
    }

    #[tokio::test]
    async fn launch_rejects_plan_id_not_content_address() {
        use ed25519_dalek::Signer;

        // A signature-valid envelope whose inner plan_id is NOT the
        // content-address: sign_plan stamps, so mint the mismatch by hand.
        let plan = sample_plan();
        let (mut signed, sk, vk) = sign_sample(&plan);
        let mut tampered = plan.clone();
        tampered.plan_id = mvm_core::plan::PlanId("sha256:not-the-content-address".into());
        let payload = serde_json::to_vec(&tampered).unwrap();
        signed.0.signature = sk.sign(&payload).to_bytes().to_vec();
        signed.0.payload = payload;

        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        let err = s.launch(&signed, &[("test", &vk)]).await.unwrap_err();
        assert!(matches!(err, SupervisorError::PlanVerify(_)), "got {err:?}");
        assert_eq!(backend.launches().len(), 0, "mismatched plan must not boot");

        // The rejection is a chain-signed audit entry, like every other
        // admission decision — no unaudited control-plane refusal.
        assert_eq!(audit_events(&audit), vec!["plan.rejected.plan_id_mismatch"]);
        let entry = &audit.entries()[0];
        assert_eq!(entry.plan_id, tampered.plan_id);
        assert!(
            entry
                .labels
                .get("reason")
                .is_some_and(|r| r.contains("content-address")),
            "reason label names the mismatch: {:?}",
            entry.labels
        );
    }

    // ----- admission audit -----

    /// Convenience: collect just the `event` strings from captured
    /// audit entries, in emit order. Test assertions are clearer
    /// against this projection than against the full struct.
    fn audit_events(audit: &crate::supervisor::audit::CapturingAuditSigner) -> Vec<String> {
        audit.entries().into_iter().map(|e| e.event).collect()
    }

    #[tokio::test]
    async fn admitted_plan_emits_admitted_then_running() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(audit_events(&audit), vec!["plan.admitted", "plan.running"]);
        // Each entry is bound to the plan id and image.
        for entry in audit.entries() {
            assert_eq!(entry.plan_id, plan.plan_id);
            assert_eq!(entry.plan_version, plan.plan_version);
            assert_eq!(entry.image_name, plan.image.name);
        }
    }

    #[tokio::test]
    async fn expired_plan_emits_validity_window_audit() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        s.clock = Arc::new(FixedClock(
            Utc.with_ymd_and_hms(2026, 5, 1, 2, 0, 0).unwrap(),
        ));

        let _ = s.launch(&signed, &[("test", &vk)]).await;

        assert_eq!(audit_events(&audit), vec!["plan.rejected.validity_window"]);
        let entry = &audit.entries()[0];
        assert!(
            entry.labels.get("reason").unwrap().contains("expired"),
            "labels: {:?}",
            entry.labels
        );
    }

    #[tokio::test]
    async fn replayed_plan_emits_nonce_replay_audit_on_second_attempt() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();
        let _ = s.launch(&signed, &[("test", &vk)]).await;

        // First launch: admitted + running. Second: nonce_replay.
        assert_eq!(
            audit_events(&audit),
            vec![
                "plan.admitted",
                "plan.running",
                "plan.rejected.nonce_replay",
            ]
        );
    }

    /// A sealed image asserting no entrypoint is
    /// refused at admission with `EntrypointAbsent` and the plan lands
    /// in `Failed`.
    #[tokio::test]
    async fn admission_refuses_sealed_plan_with_absent_entrypoint() {
        let mut plan = sample_plan();
        plan.image.entrypoint_present = false;
        // Re-address after the edit so the fixture's id matches what sign_plan
        // stamps and what the audit chain records.
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, _audit) = make_supervisor_with_audit(backend.clone());

        let err = s.launch(&signed, &[("test", &vk)]).await.unwrap_err();
        assert!(matches!(err, SupervisorError::EntrypointAbsent), "{err:?}");
        assert_eq!(s.state.current(), PlanState::Failed);
        // The guard fires before backend dispatch — no launch attempt.
        assert!(backend.launches().is_empty());
    }

    /// The refusal is on the claim-8 audit chain as a
    /// `plan.failed` entry whose reason label is `entrypoint.absent`.
    #[tokio::test]
    async fn admission_emits_plan_failed_entrypoint_absent_audit_entry() {
        let mut plan = sample_plan();
        plan.image.entrypoint_present = false;
        // Re-address after the edit so the fixture's id matches what sign_plan
        // stamps and what the audit chain records.
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        let _ = s.launch(&signed, &[("test", &vk)]).await;

        assert_eq!(audit_events(&audit), vec!["plan.failed"]);
        let entry = &audit.entries()[0];
        assert_eq!(
            entry.labels.get("reason").map(String::as_str),
            Some("entrypoint.absent"),
            "labels: {:?}",
            entry.labels
        );
        assert_eq!(entry.plan_id, plan.plan_id);
    }

    /// A normal plan (field defaulted to true) sails
    /// past the gate — it must NOT trip `EntrypointAbsent`.
    #[tokio::test]
    async fn admission_accepts_plan_with_entrypoint_present_default() {
        let plan = sample_plan();
        assert!(plan.image.entrypoint_present, "sample defaults to present");
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(audit_events(&audit), vec!["plan.admitted", "plan.running"]);
    }

    #[tokio::test]
    async fn backend_failure_emits_backend_rejection_audit() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let mut backend = MockBackend::new();
        backend.launch_should_fail = true;
        let backend = Arc::new(backend);
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        let _ = s.launch(&signed, &[("test", &vk)]).await;

        // Admitted fires first (signature + window + nonce all
        // passed); then the backend rejection.
        assert_eq!(
            audit_events(&audit),
            vec!["plan.admitted", "plan.rejected.backend"]
        );
    }

    #[tokio::test]
    async fn signature_failure_emits_no_audit() {
        // Signature failures arrive before the plan is parsed, so
        // there's no plan_id to bind an audit entry to. Documented
        // behaviour: no admission audit on this path; tracing logs
        // the rejection. A later pass may add an envelope-rejection audit
        // type that carries only the signer_id.
        let plan = sample_plan();
        let (mut signed, _sk, vk) = sign_sample(&plan);
        signed.0.payload[0] ^= 0x01;
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        let _ = s.launch(&signed, &[("test", &vk)]).await;

        assert_eq!(audit_events(&audit), Vec::<String>::new());
    }

    #[tokio::test]
    async fn admission_audit_inherits_plan_audit_labels() {
        // The plan's `audit_labels` should be copied into every
        // admission audit entry verbatim — the "what was the
        // contract" record.
        let mut plan = sample_plan();
        plan.audit_labels
            .insert("workflow".to_string(), "etl-9".to_string());
        plan.audit_labels
            .insert("env".to_string(), "prod".to_string());
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        for entry in audit.entries() {
            assert_eq!(entry.labels.get("workflow"), Some(&"etl-9".to_string()));
            assert_eq!(entry.labels.get("env"), Some(&"prod".to_string()));
        }
    }

    #[tokio::test]
    async fn audit_signer_io_failure_fails_the_launch() {
        // A real audit signer reporting an Io error fails the
        // launch — invariant: audit emits before forward.
        // No audit means no launch.
        struct FailingAudit;
        #[async_trait]
        impl crate::supervisor::audit::AuditSigner for FailingAudit {
            async fn sign_and_emit(
                &self,
                _entry: &crate::supervisor::audit::PlanAuditEntry,
            ) -> Result<(), crate::supervisor::audit::AuditError> {
                Err(crate::supervisor::audit::AuditError::Io("disk full".into()))
            }
        }

        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());
        s.audit = Arc::new(FailingAudit);

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::Audit(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        // Backend was never called — admission failed.
        assert!(backend.launches().is_empty());
    }

    // ---- with_l7_egress builder + Variant::Prod gate ----

    use crate::supervisor::l7_proxy::{
        CapturingEgressAuditSink, DnsResolver, EgressAuditSink, NoopEgressAuditSink,
    };
    use std::net::IpAddr;

    /// Mock resolver that always returns the configured IP. Reused
    /// from l7_proxy tests via a duplicate definition here — tests
    /// don't share #[cfg(test)] fns across modules without lots of
    /// pub(crate) churn, and the type is two lines.
    struct WiringResolver(IpAddr);
    #[async_trait]
    impl DnsResolver for WiringResolver {
        async fn resolve_one(
            &self,
            _h: &str,
            _p: u16,
        ) -> Result<IpAddr, crate::supervisor::EgressError> {
            Ok(self.0)
        }
    }

    fn dev_egress_policy(allow_plain_http: bool) -> EgressPolicy {
        EgressPolicy {
            mode: Some("l3_plus_l7".to_string()),
            allow_list: vec![("api.openai.com".to_string(), 443)],
            allow_plain_http,
            body_cap_bytes: 0,
            disabled_inspectors: vec![],
            redaction: Default::default(),
            reversible_replacement: Default::default(),
        }
    }

    #[test]
    fn with_l7_egress_dev_with_plain_http_succeeds() {
        let policy = dev_egress_policy(true);
        let s = Supervisor::default()
            .with_l7_egress(
                &policy,
                Variant::Dev,
                Arc::new(WiringResolver(IpAddr::from([8, 8, 8, 8]))),
                Arc::new(NoopEgressAuditSink),
            )
            .expect("dev variant accepts plain http");
        // The egress slot is now the L7 proxy (downcast not needed —
        // confirming non-default behaviour by checking that its type
        // accepted the build is enough).
        assert_eq!(s.state.current(), PlanState::Pending);
    }

    #[test]
    fn with_l7_egress_prod_with_plain_http_rejects() {
        let policy = dev_egress_policy(true); // plain http on
        let result = Supervisor::default().with_l7_egress(
            &policy,
            Variant::Prod,
            Arc::new(WiringResolver(IpAddr::from([8, 8, 8, 8]))),
            Arc::new(NoopEgressAuditSink),
        );
        match result {
            Err(SupervisorError::PolicyViolation(msg)) => {
                assert!(msg.contains("allow_plain_http"));
                assert!(msg.contains("Prod"));
            }
            Err(other) => panic!("expected PolicyViolation, got error {other:?}"),
            Ok(_) => panic!("expected PolicyViolation, got Ok"),
        }
    }

    #[test]
    fn with_l7_egress_prod_without_plain_http_succeeds() {
        let policy = dev_egress_policy(false);
        let s = Supervisor::default()
            .with_l7_egress(
                &policy,
                Variant::Prod,
                Arc::new(WiringResolver(IpAddr::from([8, 8, 8, 8]))),
                Arc::new(NoopEgressAuditSink),
            )
            .expect("prod variant accepts plain-http=false");
        assert_eq!(s.state.current(), PlanState::Pending);
    }

    #[tokio::test]
    async fn wired_supervisor_routes_through_inspector_chain() {
        // End-to-end: build a Supervisor with the L7 proxy wired,
        // ask the egress slot to inspect a request that the chain
        // would deny, confirm the policy violation propagates.
        let policy = dev_egress_policy(false);
        let resolver = Arc::new(WiringResolver(IpAddr::from([104, 18, 32, 10])));
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let s = Supervisor::default()
            .with_l7_egress(
                &policy,
                Variant::Dev,
                resolver,
                audit.clone() as Arc<dyn EgressAuditSink>,
            )
            .expect("wire ok");

        // Disallowed destination → DestinationPolicy denies via the
        // legacy `inspect(host, path)` trait method (host-only
        // signature; doesn't trigger audit emission since that
        // happens in serve_connection, not evaluate).
        let dec = s.egress.inspect("evil.com", "/").await.expect("inspect ok");
        match dec {
            crate::supervisor::EgressDecision::Deny { reason } => {
                assert!(reason.contains("evil.com") || reason.contains("not in policy"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn build_inspector_chain_honours_disabled_inspectors() {
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors =
            vec!["secrets_scanner".to_string(), "pii_redactor".to_string()];
        let chain = build_inspector_chain(&policy, None);
        // 5 default inspectors minus 2 disabled = 3.
        assert_eq!(chain.len(), 3);
    }

    #[test]
    fn build_inspector_chain_full_default() {
        let policy = dev_egress_policy(false);
        let chain = build_inspector_chain(&policy, None);
        // All 5 inspectors present.
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn known_inspector_names_matches_chain_inspectors() {
        // Each name in KNOWN_INSPECTOR_NAMES must actually disable a
        // chain slot. Any drift between this constant and the
        // canonical build_inspector_chain order is a bug.
        for &name in KNOWN_INSPECTOR_NAMES {
            let mut policy = dev_egress_policy(false);
            policy.disabled_inspectors = vec![name.to_string()];
            let chain = build_inspector_chain(&policy, None);
            assert_eq!(
                chain.len(),
                KNOWN_INSPECTOR_NAMES.len() - 1,
                "disabling {name:?} should drop exactly one inspector from the chain"
            );
        }
    }

    #[test]
    fn validate_egress_policy_passes_known_names() {
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors = vec!["ssrf_guard".to_string(), "pii_redactor".to_string()];
        validate_egress_policy_inspector_names(&policy).expect("known names");
    }

    #[test]
    fn validate_egress_policy_passes_empty_list() {
        // Empty disabled_inspectors is the common case (all
        // inspectors enabled). Must validate cleanly.
        let policy = dev_egress_policy(false);
        validate_egress_policy_inspector_names(&policy).expect("empty list");
    }

    #[test]
    fn validate_egress_policy_refuses_typo_with_row_index() {
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors = vec![
            "ssrf_guard".to_string(),
            "secrets_scaner".to_string(), // typo
        ];
        let err = validate_egress_policy_inspector_names(&policy).expect_err("typo");
        match err {
            EgressPolicyValidationError::UnknownDisabledInspector { index, name, valid } => {
                assert_eq!(index, 1);
                assert_eq!(name, "secrets_scaner");
                assert_eq!(valid, KNOWN_INSPECTOR_NAMES);
            }
        }
    }

    fn dev_pii_policy() -> mvm_core::policy::PiiPolicy {
        mvm_core::policy::PiiPolicy {
            mode: None,
            categories: vec![],
        }
    }

    #[test]
    fn build_inspector_chain_with_pii_default_matches_default_chain() {
        // No PII policy override → chain length matches the lenient
        // 5-inspector default. Proves the new function is a strict
        // superset of `build_inspector_chain`'s shape.
        let egress = dev_egress_policy(false);
        let pii = dev_pii_policy();
        let chain = build_inspector_chain_with_pii(&egress, &pii, None).expect("default ok");
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn build_inspector_chain_with_pii_drops_inspector_when_mode_disabled() {
        // `pii.mode = "disabled"` is the operator-natural kill-switch;
        // semantically equivalent to adding `"pii_redactor"` to
        // `disabled_inspectors`. The chain shrinks to 4.
        let egress = dev_egress_policy(false);
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("disabled".to_string()),
            categories: vec![],
        };
        let chain = build_inspector_chain_with_pii(&egress, &pii, None).expect("disabled ok");
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn build_inspector_chain_with_pii_honors_redact_mode() {
        // `pii.mode = "redact"` keeps the inspector in the chain but
        // its internal Mode flips to Redact. We can't easily inspect
        // the internal Mode through the InspectorChain trait surface,
        // but we can prove from_policy preserves mode by going
        // through the redactor constructor directly.
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("redact".to_string()),
            categories: vec![],
        };
        let red = PiiRedactor::from_policy(&pii)
            .expect("ok")
            .expect("not disabled");
        assert_eq!(red.mode(), crate::supervisor::pii_redactor::Mode::Redact);
    }

    #[test]
    fn build_inspector_chain_with_pii_refuses_unknown_mode() {
        let egress = dev_egress_policy(false);
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("paranoid".to_string()),
            categories: vec![],
        };
        let err = build_inspector_chain_with_pii(&egress, &pii, None).expect_err("typo");
        match err {
            crate::supervisor::pii_redactor::PiiPolicyError::UnknownMode { value, valid } => {
                assert_eq!(value, "paranoid");
                assert!(valid.contains(&"detect"));
                assert!(valid.contains(&"disabled"));
            }
            other => panic!("expected UnknownMode, got {other:?}"),
        }
    }

    #[test]
    fn build_inspector_chain_with_pii_refuses_unknown_category() {
        let egress = dev_egress_policy(false);
        let pii = mvm_core::policy::PiiPolicy {
            mode: Some("detect".to_string()),
            categories: vec!["email".to_string(), "license_plate".to_string()],
        };
        let err = build_inspector_chain_with_pii(&egress, &pii, None).expect_err("typo");
        match err {
            crate::supervisor::pii_redactor::PiiPolicyError::UnknownCategory {
                index,
                name,
                valid,
            } => {
                assert_eq!(index, 1);
                assert_eq!(name, "license_plate");
                assert!(valid.contains(&"email"));
                assert!(valid.contains(&"us_ssn"));
            }
            other => panic!("expected UnknownCategory, got {other:?}"),
        }
    }

    #[test]
    fn validate_audit_policy_accepts_known_schemes() {
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec![
                "file:///var/log/mvm/audit.jsonl".to_string(),
                "https://audit.example.com/ingest".to_string(),
                "unix:///run/audit.sock".to_string(),
            ],
        };
        validate_audit_policy_stream_destinations(&policy).expect("known schemes ok");
    }

    #[test]
    fn validate_audit_policy_passes_empty_destinations() {
        // Empty stream_destinations is the common case — no audit
        // replication configured. Must validate cleanly.
        let policy = mvm_core::policy::AuditPolicy::default();
        validate_audit_policy_stream_destinations(&policy).expect("empty ok");
    }

    #[test]
    fn validate_audit_policy_refuses_typo_with_row_index() {
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec![
                "file:///var/log/mvm/audit.jsonl".to_string(),
                "htpps://audit.example.com/ingest".to_string(), // typo
            ],
        };
        let err = validate_audit_policy_stream_destinations(&policy).expect_err("typo");
        match err {
            AuditPolicyValidationError::UnknownStreamScheme {
                index,
                value,
                valid,
            } => {
                assert_eq!(index, 1);
                assert_eq!(value, "htpps://audit.example.com/ingest");
                assert!(valid.contains(&"https://"));
                assert!(valid.contains(&"file://"));
            }
        }
    }

    #[test]
    fn validate_audit_policy_refuses_scheme_less_value() {
        let policy = mvm_core::policy::AuditPolicy {
            chain_signing: true,
            stream_destinations: vec!["/var/log/audit.jsonl".to_string()],
        };
        let err = validate_audit_policy_stream_destinations(&policy).expect_err("no scheme");
        match err {
            AuditPolicyValidationError::UnknownStreamScheme { index, value, .. } => {
                assert_eq!(index, 0);
                assert_eq!(value, "/var/log/audit.jsonl");
            }
        }
    }

    #[test]
    fn validate_egress_policy_first_unknown_wins() {
        // Returns on the first bad row — `index` reflects the
        // earliest offender so operators fix in source order.
        let mut policy = dev_egress_policy(false);
        policy.disabled_inspectors = vec![
            "destination_policy".to_string(),
            "no_such_inspector".to_string(),
            "another_bad_name".to_string(),
        ];
        let err = validate_egress_policy_inspector_names(&policy).expect_err("first wins");
        match err {
            EgressPolicyValidationError::UnknownDisabledInspector { index, name, .. } => {
                assert_eq!(index, 1);
                assert_eq!(name, "no_such_inspector");
            }
        }
    }

    // ---- with_tool_gate builder ----

    #[tokio::test]
    async fn with_tool_gate_allows_listed_tool() {
        let policy = ToolPolicy {
            allowed: vec!["read_file".to_string(), "list_dir".to_string()],
        };
        let s = Supervisor::default().with_tool_gate(&policy);
        let v = s.tool_gate.check("read_file").await.expect("ok");
        assert_eq!(v, crate::supervisor::ToolDecision::Allow);
    }

    #[tokio::test]
    async fn with_tool_gate_denies_unlisted_tool() {
        let policy = ToolPolicy {
            allowed: vec!["read_file".to_string()],
        };
        let s = Supervisor::default().with_tool_gate(&policy);
        let v = s.tool_gate.check("rm_rf").await.expect("ok");
        match v {
            crate::supervisor::ToolDecision::Deny { reason } => {
                assert!(reason.contains("rm_rf"));
                assert!(reason.contains("read_file"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn with_tool_gate_empty_policy_is_deny_all() {
        // Fail-closed: empty allowlist denies every call.
        let policy = ToolPolicy { allowed: vec![] };
        let s = Supervisor::default().with_tool_gate(&policy);
        for name in ["read_file", "list_dir", "anything"] {
            let v = s.tool_gate.check(name).await.expect("ok");
            assert!(matches!(v, crate::supervisor::ToolDecision::Deny { .. }));
        }
    }

    // ---- circuit-breaker wiring ----

    #[test]
    fn build_inspector_chain_without_breakers_has_raw_inspectors() {
        // Sanity: when no reporter is wired the chain is unchanged.
        let policy = dev_egress_policy(false);
        let chain = build_inspector_chain(&policy, None);
        assert_eq!(chain.len(), 5);
    }

    #[test]
    fn build_inspector_chain_with_breakers_preserves_length_and_names() {
        // Wrapping must be invisible to the chain interface — same
        // count, same names — so audit binding (which keys on
        // Inspector::name) stays intact.
        let reporter = Arc::new(crate::supervisor::circuit_breaker::InspectorReporter::new(
            crate::supervisor::circuit_breaker::CircuitBreakerConfig::default(),
        ));
        let policy = dev_egress_policy(false);
        let chain = build_inspector_chain(&policy, Some(reporter));
        assert_eq!(chain.len(), 5);
        let dbg = format!("{chain:?}");
        for name in [
            "destination_policy",
            "ssrf_guard",
            "secrets_scanner",
            "injection_guard",
            "pii_redactor",
        ] {
            assert!(
                dbg.contains(name),
                "expected wrapped chain to expose {name}, got {dbg}"
            );
        }
    }

    #[tokio::test]
    async fn supervisor_breaker_downgrades_destination_deny_when_tripped() {
        // End-to-end through the supervisor: trip the destination_policy
        // breaker, then ask the egress slot to inspect a host that the
        // policy would normally deny. The deny should downgrade to a
        // (still-flagged) Allow because the breaker is open.
        let policy = dev_egress_policy(false);
        let resolver = Arc::new(WiringResolver(IpAddr::from([104, 18, 32, 10])));
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let reporter = Arc::new(crate::supervisor::circuit_breaker::InspectorReporter::new(
            crate::supervisor::circuit_breaker::CircuitBreakerConfig {
                trip_threshold: 2,
                trip_window: std::time::Duration::from_secs(60),
                auto_reset_after: None,
            },
        ));
        // Trip destination_policy before wiring the egress slot — the
        // wrapper consults the same Arc<InspectorReporter> at call
        // time, so order between "trip" and "wire" doesn't matter, but
        // it does need to be set before with_l7_egress so the chain is
        // built with breakers in place.
        reporter.report_false_positive("destination_policy");
        reporter.report_false_positive("destination_policy");
        assert!(reporter.is_tripped("destination_policy"));

        let s = Supervisor::default()
            .with_circuit_breakers(reporter.clone())
            .with_l7_egress(
                &policy,
                Variant::Dev,
                resolver,
                audit.clone() as Arc<dyn EgressAuditSink>,
            )
            .expect("wire ok");

        // The legacy `SupervisorEgressProxy::inspect(host, path)` runs the
        // chain. Because destination_policy's breaker is open, the
        // verdict is the chain's downstream "Allow" rather than the
        // `Deny` destination_policy would have produced.
        let dec = s.egress.inspect("evil.com", "/").await.expect("inspect ok");
        assert!(matches!(dec, crate::supervisor::EgressDecision::Allow));
    }

    #[tokio::test]
    async fn supervisor_without_breakers_still_denies_disallowed_destination() {
        // Control case for the previous test — same supervisor minus
        // the breaker — to make sure the deny path is genuinely the
        // thing the breaker is masking.
        let policy = dev_egress_policy(false);
        let resolver = Arc::new(WiringResolver(IpAddr::from([104, 18, 32, 10])));
        let audit = Arc::new(CapturingEgressAuditSink::new());
        let s = Supervisor::default()
            .with_l7_egress(
                &policy,
                Variant::Dev,
                resolver,
                audit.clone() as Arc<dyn EgressAuditSink>,
            )
            .expect("wire ok");
        let dec = s.egress.inspect("evil.com", "/").await.expect("inspect ok");
        assert!(matches!(
            dec,
            crate::supervisor::EgressDecision::Deny { .. }
        ));
    }

    // ----- deps-volume admission gate (claim 9) -----
    //
    // The supervisor's admission path verifies `plan.deps_volume`
    // against the on-disk sealed volume before admitting. These tests
    // cover the five cases the followup spec calls out:
    //
    //   1. plan with `deps_volume = None`  — admits cleanly (claim 8
    //      regression guard)
    //   2. plan + matching on-disk volume   — admits cleanly
    //   3. plan + tampered content         — `DepsVolumeTampered`
    //   4. plan + missing volume directory — `DepsVolumeIo`
    //   5. plan + wrong recorded hash      — `DepsVolumeTampered`
    //
    // Plus a hand-tamper round trip that proves the admission gate
    // genuinely refuses a `cve.json` mutation post-seal, and an
    // audit-chain assertion that `plan.admitted` / `plan.running`
    // entries pin both hashes when a deps-volume is bound.

    use mvm_sdk::compile::deps_audit::{FILE_CVE, FILE_MANIFEST, seal_volume};
    use sha2::Digest as _;
    use std::collections::BTreeMap as DepsBTreeMap;
    use std::fs;
    use std::path::Path as DepsPath;

    /// Build a complete sealed volume at `<root>/<volume_hash>/` and
    /// return the seal result + on-disk manifest sha256. Mirrors the
    /// `Fixture::build_sealed` helper in `mvm_sdk::deps_audit::tests`
    /// but exposes the manifest sha so a supervisor test can pin both
    /// values into a `DepsVolumeBinding`.
    fn build_sealed_volume(
        root: &DepsPath,
        name: &str,
    ) -> (
        PathBuf,
        mvm_sdk::compile::deps_audit::VolumeSealResult,
        String,
    ) {
        let v = root.join(name);
        let content = v.join("content");
        fs::create_dir_all(&content).unwrap();
        fs::write(content.join("a.txt"), b"alpha\n").unwrap();
        fs::create_dir_all(content.join("sub")).unwrap();
        fs::write(content.join("sub").join("b.txt"), b"beta\n").unwrap();

        let sbom = v.join("sbom.cdx.json");
        fs::write(&sbom, br#"{"bomFormat":"CycloneDX","specVersion":"1.5"}"#).unwrap();
        let fl = v.join("fetch.log");
        fs::write(&fl, b"GET https://pypi.org/simple/requests/\n").unwrap();
        let cve = v.join(FILE_CVE);
        fs::write(&cve, br#"{"results":[]}"#).unwrap();

        let result = seal_volume(
            &content,
            &sbom,
            &fl,
            &cve,
            "2026-05-13T00:00:00Z",
            DepsBTreeMap::new(),
        )
        .expect("seal");
        fs::write(v.join(FILE_MANIFEST), &result.manifest_bytes).unwrap();
        let manifest_sha = hex::encode(sha2::Sha256::digest(&result.manifest_bytes));
        (v, result, manifest_sha)
    }

    fn plan_with_deps_volume(
        volume_hash: &str,
        manifest_sha256: &str,
    ) -> Result<ExecutionPlan, mvm_core::plan::DepsVolumeBindingError> {
        let mut plan = sample_plan();
        plan.deps_volume = Some(DepsVolumeBinding::new(volume_hash, manifest_sha256)?);
        plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
        Ok(plan)
    }

    #[tokio::test]
    async fn no_deps_volume_admits_cleanly_preserving_claim_8() {
        // Claim-8 regression guard: a plan without `deps_volume`
        // walks the same path as before this followup landed. No
        // filesystem touch, no new audit labels.
        let plan = sample_plan();
        assert!(plan.deps_volume.is_none());
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Running);
        assert_eq!(audit_events(&audit), vec!["plan.admitted", "plan.running"]);
        for entry in audit.entries() {
            assert!(!entry.labels.contains_key("deps_volume_hash"));
            assert!(!entry.labels.contains_key("deps_manifest_sha256"));
        }
    }

    #[tokio::test]
    async fn matching_deps_volume_admits_and_audits_both_hashes() {
        let tmp = tempfile::tempdir().expect("tmp");
        let (_dir, sealed, manifest_sha) = build_sealed_volume(tmp.path(), &"a".repeat(64));
        let plan = plan_with_deps_volume(&sealed.volume_hash, &manifest_sha).expect("binding");
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        s.deps_volumes_root = Some(tmp.path().to_path_buf());
        // Rename the directory to match the volume hash so the
        // supervisor's resolver finds it.
        fs::rename(
            tmp.path().join("a".repeat(64)),
            tmp.path().join(&sealed.volume_hash),
        )
        .unwrap();

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Running);
        assert_eq!(audit_events(&audit), vec!["plan.admitted", "plan.running"]);
        for entry in audit.entries() {
            assert_eq!(
                entry.labels.get("deps_volume_hash"),
                Some(&sealed.volume_hash)
            );
            assert_eq!(
                entry.labels.get("deps_manifest_sha256"),
                Some(&manifest_sha)
            );
        }
    }

    #[tokio::test]
    async fn tampered_cve_after_seal_refuses_admission() {
        // The followup spec's "hand-tamper" gate: build a sealed
        // volume, sign a plan referencing it, prove it admits;
        // then write garbage to cve.json and prove the same plan
        // no longer admits. This is claim 9's anchor test.
        let tmp = tempfile::tempdir().expect("tmp");
        let (vol_dir, sealed, manifest_sha) = build_sealed_volume(tmp.path(), &"b".repeat(64));
        fs::rename(&vol_dir, tmp.path().join(&sealed.volume_hash)).unwrap();
        let final_vol_dir = tmp.path().join(&sealed.volume_hash);
        let plan = plan_with_deps_volume(&sealed.volume_hash, &manifest_sha).expect("binding");

        // Round 1: pristine volume admits.
        {
            let (signed, _sk, vk) = sign_sample(&plan);
            let backend = Arc::new(MockBackend::new());
            let mut s = make_supervisor_with_backend(backend.clone());
            s.deps_volumes_root = Some(tmp.path().to_path_buf());
            s.launch(&signed, &[("test", &vk)]).await.unwrap();
            assert_eq!(s.state.current(), PlanState::Running);
        }

        // Round 2: tamper cve.json and re-launch with a fresh plan
        // (fresh nonce so we're not testing replay protection).
        fs::write(final_vol_dir.join(FILE_CVE), b"{\"results\":[\"FORGED\"]}").unwrap();
        let mut tampered_plan = plan.clone();
        tampered_plan.nonce = Nonce::from_bytes([0xcd; 16]); // fresh nonce
        tampered_plan.plan_id = mvm_core::plan::compute_plan_id(&tampered_plan);
        let (signed, _sk, vk) = sign_sample(&tampered_plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        s.deps_volumes_root = Some(tmp.path().to_path_buf());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        // The supervisor sees the cve hash mismatch before the volume
        // hash check; it surfaces as DepsVolumeIo wrapping
        // VolumeError::HashMismatch — verify_sealed_volume catches the
        // tamper directly rather than getting to derive_volume_hash.
        // Either DepsVolumeTampered or DepsVolumeIo{HashMismatch} is a
        // valid fail-closed outcome.
        match &result {
            Err(SupervisorError::DepsVolumeTampered { .. }) => {}
            Err(SupervisorError::DepsVolumeIo {
                source: VolumeError::HashMismatch { kind, .. },
                ..
            }) => {
                assert_eq!(*kind, "cve");
            }
            other => panic!("expected deps-volume rejection, got {other:?}"),
        }
        assert_eq!(s.state.current(), PlanState::Failed);
        assert!(
            audit_events(&audit)
                .iter()
                .any(|e| e == "plan.rejected.deps_volume"),
            "audit events: {:?}",
            audit_events(&audit)
        );
        // No `plan.admitted` for the tampered launch — admission
        // failed before the success entry is emitted.
        assert!(!audit_events(&audit).contains(&"plan.admitted".to_string()));
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn missing_volume_directory_refuses_admission() {
        let tmp = tempfile::tempdir().expect("tmp");
        // Don't actually build the volume — the directory under
        // `<tmp>/<hash>/` will not exist.
        let fake_volume_hash = "0".repeat(64);
        let fake_manifest_sha = "1".repeat(64);
        let plan =
            plan_with_deps_volume(&fake_volume_hash, &fake_manifest_sha).expect("binding shape");
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        s.deps_volumes_root = Some(tmp.path().to_path_buf());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        match &result {
            Err(SupervisorError::DepsVolumeIo { path, source }) => {
                assert!(path.ends_with(&fake_volume_hash));
                assert!(matches!(source, VolumeError::Missing(_)));
            }
            other => panic!("expected DepsVolumeIo(Missing), got {other:?}"),
        }
        assert_eq!(s.state.current(), PlanState::Failed);
        assert!(
            audit_events(&audit)
                .iter()
                .any(|e| e == "plan.rejected.deps_volume")
        );
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn matching_content_but_wrong_recorded_hash_refuses() {
        // The on-disk volume is internally consistent (every artifact
        // hashes correctly against meta.json), but the plan pins a
        // *different* `volume_hash` than the one the on-disk content
        // actually derives. This is the "attacker swapped the plan's
        // pin to point at a different volume" case.
        let tmp = tempfile::tempdir().expect("tmp");
        let (_dir, sealed, manifest_sha) = build_sealed_volume(tmp.path(), &"c".repeat(64));
        // Place the sealed dir at a *different* hash — the supervisor
        // resolves to that path for the plan's claimed hash, finds the
        // real (other-hash) volume, but verify_sealed_volume returns
        // the actual hash and the comparison fails.
        let claimed_hash = "d".repeat(64);
        fs::rename(
            tmp.path().join("c".repeat(64)),
            tmp.path().join(&claimed_hash),
        )
        .unwrap();
        let plan = plan_with_deps_volume(&claimed_hash, &manifest_sha).expect("binding");
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let (mut s, audit) = make_supervisor_with_audit(backend.clone());
        s.deps_volumes_root = Some(tmp.path().to_path_buf());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        match &result {
            Err(SupervisorError::DepsVolumeTampered { expected, actual }) => {
                assert_eq!(*expected, claimed_hash);
                assert_eq!(*actual, sealed.volume_hash);
            }
            other => panic!("expected DepsVolumeTampered, got {other:?}"),
        }
        assert!(
            audit_events(&audit)
                .iter()
                .any(|e| e == "plan.rejected.deps_volume")
        );
        assert!(backend.launches().is_empty());
    }

    #[tokio::test]
    async fn matching_volume_hash_but_wrong_manifest_sha_refuses() {
        // The volume_hash check passes, but the pinned
        // manifest_sha256 is wrong. Belt-and-suspenders: even a
        // future hash-derivation drift that lets two manifests
        // resolve to the same volume hash still fails closed here.
        let tmp = tempfile::tempdir().expect("tmp");
        let (_dir, sealed, _real_manifest_sha) = build_sealed_volume(tmp.path(), &"e".repeat(64));
        fs::rename(
            tmp.path().join("e".repeat(64)),
            tmp.path().join(&sealed.volume_hash),
        )
        .unwrap();
        let bogus_manifest_sha = "f".repeat(64);
        let plan =
            plan_with_deps_volume(&sealed.volume_hash, &bogus_manifest_sha).expect("binding");
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());
        s.deps_volumes_root = Some(tmp.path().to_path_buf());

        let result = s.launch(&signed, &[("test", &vk)]).await;

        match &result {
            Err(SupervisorError::DepsVolumeManifestMismatch { expected, actual }) => {
                assert_eq!(*expected, bogus_manifest_sha);
                assert_ne!(*actual, bogus_manifest_sha);
            }
            other => panic!("expected DepsVolumeManifestMismatch, got {other:?}"),
        }
        assert!(backend.launches().is_empty());
    }

    #[test]
    fn deps_volume_binding_validates_hash_lengths() {
        // The wire-shape gate: a 63-char or 65-char hex string is
        // rejected at construction time so a malformed pin never
        // reaches the supervisor.
        assert!(matches!(
            DepsVolumeBinding::new("a".repeat(63), "b".repeat(64)),
            Err(mvm_core::plan::DepsVolumeBindingError::WrongLength { len: 63 })
        ));
        assert!(matches!(
            DepsVolumeBinding::new("a".repeat(64), "b".repeat(65)),
            Err(mvm_core::plan::DepsVolumeBindingError::WrongLength { len: 65 })
        ));
        assert!(matches!(
            DepsVolumeBinding::new("A".repeat(64), "b".repeat(64)),
            Err(mvm_core::plan::DepsVolumeBindingError::NonHex { ch: 'A' })
        ));
        DepsVolumeBinding::new("0".repeat(64), "1".repeat(64)).expect("valid pin");
    }

    #[test]
    fn deps_volume_binding_serde_rejects_short_hex() {
        // Wire format: a forged plan carrying a too-short volume_hash
        // must fail at deserialise (deny_unknown_fields gives us
        // unknown-field protection; this test pins the explicit
        // hex-length validator we added).
        let bad = serde_json::json!({
            "volume_hash": "abc",
            "manifest_sha256": "b".repeat(64),
        });
        let err = serde_json::from_value::<DepsVolumeBinding>(bad).unwrap_err();
        assert!(err.to_string().contains("64"));
    }
}
