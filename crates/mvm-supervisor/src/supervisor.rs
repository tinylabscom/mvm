//! `Supervisor` — aggregate that owns every component slot plus the
//! plan execution state machine, and drives the launch lifecycle.
//!
//! Wave 1.3 shipped the type with `Default::default()` returning a
//! supervisor wired with every `Noop` slot. Wave 1.4 (this module's
//! current state) adds the `Supervisor::launch(plan)` happy path:
//!   1. verify the signed plan
//!   2. transition Pending → Verified
//!   3. ask the backend to launch
//!   4. transition Verified → Launched → Running
//!
//! Plus `Supervisor::stop(plan_id)` to walk Running → Stopping → Stopped.
//! The supervisor is sync today but the slot trait methods are async
//! (real impls drive HTTP / vsock); `launch` and `stop` are async.

use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use mvm_plan::{NonceStore, PlanId, PlanValidityError, SignedExecutionPlan, check_window};
use thiserror::Error;
use tracing::warn;

use mvm_plan::Variant;
use mvm_policy::{DEFAULT_BODY_CAP_BYTES, EgressPolicy, ToolPolicy};

use crate::artifact::{ArtifactCollector, NoopArtifactCollector};
use crate::audit::{AuditSigner, NoopAuditSigner};
use crate::backend::{BackendError, BackendLauncher, NoopBackendLauncher};
use crate::circuit_breaker::{CircuitBreaker, InspectorReporter};
use crate::destination::DestinationPolicy;
use crate::egress::{EgressProxy, NoopEgressProxy};
use crate::injection_guard::InjectionGuard;
use crate::inspector::{Inspector, InspectorChain};
use crate::keystore::{KeystoreReleaser, NoopKeystoreReleaser};
use crate::l7_proxy::{DnsResolver, EgressAuditSink, L7EgressProxy};
use crate::pii_redactor::PiiRedactor;
use crate::policy_tool_gate::PolicyToolGate;
use crate::secrets_scanner::SecretsScanner;
use crate::ssrf_guard::SsrfGuard;
use crate::state::{PlanState, PlanStateMachine, StateTransitionError};
use crate::tool_gate::{NoopToolGate, ToolGate};

/// Clock abstraction. The supervisor reads the wall clock through
/// this trait so tests can drive time deterministically; production
/// uses [`SystemClock`]. Plan 37 Addendum G4 enforcement.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

/// Production clock — `chrono::Utc::now()`.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("plan signature/parse failed: {0}")]
    PlanVerify(String),

    /// Plan 37 Addendum G4: the plan's validity window doesn't cover
    /// `now`, or its nonce was already seen for the signer that
    /// authored it.
    #[error("plan validity check failed: {0}")]
    Validity(#[from] PlanValidityError),

    #[error("plan state transition failed: {0}")]
    State(#[from] StateTransitionError),

    #[error("backend error: {0}")]
    Backend(#[from] BackendError),

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
}

pub struct Supervisor {
    pub egress: Arc<dyn EgressProxy>,
    pub tool_gate: Arc<dyn ToolGate>,
    pub keystore: Arc<dyn KeystoreReleaser>,
    pub audit: Arc<dyn AuditSigner>,
    pub artifact: Arc<dyn ArtifactCollector>,
    pub backend: Arc<dyn BackendLauncher>,
    pub state: PlanStateMachine,
    /// Clock used for plan-validity-window checks. Defaults to
    /// `SystemClock`; tests inject a fixed clock.
    pub clock: Arc<dyn Clock>,
    /// Per-signer nonce ledger for replay protection. Plan 37
    /// Addendum G4. Held behind a `Mutex` because `launch` takes
    /// `&mut self` but the store may eventually be shared across
    /// concurrent admission paths. `std::sync::Mutex` is sufficient:
    /// no `await` inside the locked region.
    pub nonce_store: Arc<Mutex<NonceStore>>,
    /// False-positive circuit-breaker reporter (Plan 37 Addendum E1).
    /// `None` means the L7 egress chain runs without breakers — the
    /// fail-closed default for production until an operator opts in
    /// via [`Supervisor::with_circuit_breakers`]. When `Some`, every
    /// inspector built by [`Supervisor::with_l7_egress`] is wrapped
    /// in a [`CircuitBreaker`] that consults this reporter.
    pub circuit_breakers: Option<Arc<InspectorReporter>>,
}

impl Default for Supervisor {
    /// Default is the fail-closed configuration: every component
    /// slot is `Noop`. Plan 37 §7B's invariant — "tenant code never
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
            state: PlanStateMachine::new(),
            clock: Arc::new(SystemClock),
            nonce_store: Arc::new(Mutex::new(NonceStore::new())),
            circuit_breakers: None,
        }
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drive a workload's launch lifecycle: verify the signed plan,
    /// walk the state machine, request the backend launch.
    ///
    /// On any failure the state transitions to `PlanState::Failed`
    /// (best-effort — if the supervisor is already in a terminal
    /// state the second transition errors out, which is fine because
    /// we're already returning an error).
    ///
    /// `trusted_keys` mirrors `mvm_plan::verify_plan`'s contract —
    /// pass the supervisor's trusted-key set so a plan signed by an
    /// unknown party is refused before any other step runs.
    ///
    /// Wave 2 wires the supervisor's component slots into the launch
    /// path (apply egress policy, release secrets, etc.). Today's
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
        // plan to bind to (`AuditEntry` is keyed on plan_id, which
        // we do not know without trusting the payload). Wave 2 may
        // add a separate `EnvelopeRejected` audit type that carries
        // only the envelope's signer_id and a rejection reason; for
        // now this path is logged via `tracing` only.
        let plan = match mvm_plan::verify_plan(signed, trusted_keys) {
            Ok(p) => p,
            Err(e) => {
                let err = SupervisorError::PlanVerify(e.to_string());
                self.transition_or_warn(PlanState::Failed);
                return Err(err);
            }
        };

        // Step 1.5 (Plan 37 Addendum G4): time-window + nonce-replay
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

        // Plan is fully admitted at this point — signature, window,
        // and nonce all check out. Emit the success audit before any
        // resource-allocating work so the trail is preserved even
        // if the backend fails next. Audit failure here fails the
        // launch fail-closed (§22 / B17: audit emits before forward).
        if let Err(e) = self.emit_admission_audit(&plan, "plan.admitted", "").await {
            self.transition_or_warn(PlanState::Failed);
            return Err(e);
        }

        // Step 2: Pending → Verified.
        self.state.transition(PlanState::Verified).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;

        // Step 3: backend dispatch.
        if let Err(e) = self.backend.launch(&plan).await {
            self.emit_audit_then_fail(&plan, "plan.rejected.backend", &e.to_string())
                .await?;
            return Err(SupervisorError::from(e));
        }

        // Step 4: Verified → Launched → Running. Wave 2's real impl
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

        if let Err(e) = self.emit_admission_audit(&plan, "plan.running", "").await {
            self.transition_or_warn(PlanState::Failed);
            return Err(e);
        }

        Ok(())
    }

    /// Emit a rejection audit entry and then transition the state
    /// machine to `Failed`. If the audit emit itself fails, the
    /// state still transitions before we return the audit error —
    /// any rejection path must end in `Failed` regardless of audit
    /// outcome, otherwise a stuck supervisor wedges in `Pending`.
    async fn emit_audit_then_fail(
        &mut self,
        plan: &mvm_plan::ExecutionPlan,
        event: &str,
        reason: &str,
    ) -> Result<(), SupervisorError> {
        let audit_result = self.emit_admission_audit(plan, event, reason).await;
        self.transition_or_warn(PlanState::Failed);
        audit_result
    }

    /// Emit one admission-audit entry for `plan` with the given
    /// event name and an optional reason string in `extras["reason"]`.
    /// Plan 37 Addendum B19. Every state-changing decision the
    /// supervisor makes about a plan should produce an audit entry —
    /// no unaudited control-plane mutation (whitepaper §6 invariant).
    ///
    /// Non-fatal NotWired handling: if the supervisor's audit slot is
    /// `NoopAuditSigner` (the fail-closed default), we log a tracing
    /// warning and continue. The launch itself is gated on a real
    /// AuditSigner being wired *in production*; tests use
    /// `CapturingAuditSigner`. Any other audit error (Io, etc.)
    /// propagates as `SupervisorError::Audit` and fails the launch
    /// per the §22 / B17 invariant "audit emits before forward".
    async fn emit_admission_audit(
        &self,
        plan: &mvm_plan::ExecutionPlan,
        event: &str,
        reason: &str,
    ) -> Result<(), SupervisorError> {
        let extras = if reason.is_empty() {
            vec![]
        } else {
            vec![("reason".to_string(), reason.to_string())]
        };
        let entry = crate::audit::AuditEntry::for_plan(plan, None, event, extras);
        match self.audit.sign_and_emit(&entry).await {
            Ok(()) => Ok(()),
            Err(crate::audit::AuditError::NotWired) => {
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

    /// Wire the L7 egress proxy slot from a workload's
    /// [`EgressPolicy`] + variant. Wave 2.6 differentiator:
    ///
    /// - Builds the inspector chain from `policy.allow_list` and the
    ///   curated default rulesets, in Plan 37 §15's recommended order
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

    /// Wire the false-positive circuit breakers (Plan 37 Addendum E1).
    /// When set, every inspector built by [`Supervisor::with_l7_egress`]
    /// is wrapped in a [`CircuitBreaker`] that consults this reporter
    /// on each `inspect()` call and downgrades `Deny` → `Transform`
    /// when the breaker for that inspector's name is open.
    ///
    /// Order matters: call `with_circuit_breakers` **before**
    /// `with_l7_egress` (the egress builder reads `self.circuit_breakers`
    /// at chain-build time). Calling it after has no effect on an
    /// already-built chain — the inspectors live inside the
    /// `Arc<dyn EgressProxy>` and aren't reachable for re-wrapping.
    pub fn with_circuit_breakers(mut self, reporter: Arc<InspectorReporter>) -> Self {
        self.circuit_breakers = Some(reporter);
        self
    }

    /// Wire the tool gate slot from a workload's [`ToolPolicy`].
    /// Wave 2.7 / Phase 1 — pure policy decision (allowlist
    /// lookup); the vsock RPC layer that drives `check()` calls
    /// from the workload lands in Wave 2.7b.
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

/// Build an [`InspectorChain`] from the workload's [`EgressPolicy`].
/// Order matches Plan 37 §15: cheap/most-precise checks first, body
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
/// intact. (Plan 37 Addendum E1.)
fn build_inspector_chain(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendLauncher;
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::SigningKey;
    use mvm_plan::*;
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// Test backend that records every call and lets the test pick
    /// success or failure per method.
    struct MockBackend {
        launch_calls: Mutex<Vec<PlanId>>,
        stop_calls: Mutex<Vec<PlanId>>,
        launch_should_fail: bool,
        stop_should_fail: bool,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                launch_calls: Mutex::new(Vec::new()),
                stop_calls: Mutex::new(Vec::new()),
                launch_should_fail: false,
                stop_should_fail: false,
            }
        }

        fn launches(&self) -> Vec<PlanId> {
            self.launch_calls.lock().unwrap().clone()
        }

        fn stops(&self) -> Vec<PlanId> {
            self.stop_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl BackendLauncher for MockBackend {
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
    }

    fn sample_plan() -> ExecutionPlan {
        ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId("01HXTEST0000000000000000".to_string()),
            plan_version: 1,
            tenant: TenantId("tenant-a".to_string()),
            workload: WorkloadId("workload-1".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "tenant-worker-aarch64".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
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
            network_policy: PolicyRef("default-deny".to_string()),
            fs_policy: FsPolicyRef("default".to_string()),
            secrets: vec![],
            egress_policy: PolicyRef("agent-l7".to_string()),
            tool_policy: PolicyRef("read-only".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: vec!["/artifacts".to_string()],
                retention_days: 30,
            },
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
            // G4 (plan 37 Addendum G4) replay-protection fields. The
            // supervisor's admission gate doesn't enforce these yet —
            // that's a follow-up PR. Today they're populated so the
            // wire format compiles and signing roundtrips work.
            valid_from: Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2026, 5, 1, 1, 0, 0).unwrap(),
            nonce: Nonce::from_bytes([0xab; 16]),
        }
    }

    fn sign_sample(plan: &ExecutionPlan) -> (SignedExecutionPlan, SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
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
        let mut s = Supervisor::new();
        s.backend = b;
        // Default to a clock inside the sample plan's window so
        // happy-path tests don't depend on the wall clock.
        s.clock = fixed_clock_inside_window();
        // Capture audit entries by default so tests can assert
        // admission audit (B19) without each test re-wiring the slot.
        s.audit = Arc::new(crate::audit::CapturingAuditSigner::new());
        s
    }

    /// Like `make_supervisor_with_backend` but exposes the
    /// `CapturingAuditSigner` so the test can read back the entries
    /// the supervisor emitted.
    fn make_supervisor_with_audit(
        b: Arc<MockBackend>,
    ) -> (Supervisor, Arc<crate::audit::CapturingAuditSigner>) {
        let audit = Arc::new(crate::audit::CapturingAuditSigner::new());
        let mut s = Supervisor::new();
        s.backend = b;
        s.clock = fixed_clock_inside_window();
        s.audit = audit.clone();
        (s, audit)
    }

    #[tokio::test]
    async fn happy_path_launch_walks_to_running() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Running);
        assert_eq!(backend.launches(), vec![plan.plan_id.clone()]);
        assert!(backend.stops().is_empty());
    }

    #[tokio::test]
    async fn happy_path_stop_walks_to_stopped() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let backend = Arc::new(MockBackend::new());
        let mut s = make_supervisor_with_backend(backend.clone());

        s.launch(&signed, &[("test", &vk)]).await.unwrap();
        s.stop(&plan.plan_id).await.unwrap();

        assert_eq!(s.state.current(), PlanState::Stopped);
        assert!(s.state.is_terminal());
        assert_eq!(backend.stops(), vec![plan.plan_id.clone()]);
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
            let sk = SigningKey::generate(&mut OsRng);
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
        let mut s = make_supervisor_with_backend(backend.clone());

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::Backend(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
        // Backend was called, but state never reached Launched/Running.
        assert_eq!(backend.launches(), vec![plan.plan_id.clone()]);
    }

    #[tokio::test]
    async fn default_supervisor_fails_closed_at_backend() {
        let plan = sample_plan();
        let (signed, _sk, vk) = sign_sample(&plan);
        let mut s = Supervisor::new();
        // No backend swap — Default's NoopBackendLauncher fails closed.
        // Pin the clock inside the plan window so validity passes and
        // the test exercises the backend-fails-closed path it's
        // supposed to.
        s.clock = fixed_clock_inside_window();

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::Backend(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
    }

    #[test]
    fn default_supervisor_starts_in_pending() {
        let s = Supervisor::default();
        assert_eq!(s.state.current(), PlanState::Pending);
    }

    // ----- Plan 37 Addendum G4 enforcement -----

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

        let sk_a = SigningKey::generate(&mut OsRng);
        let vk_a = sk_a.verifying_key();
        let signed_a = sign_plan(&plan, &sk_a, "alice");

        let sk_b = SigningKey::generate(&mut OsRng);
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

    // ----- Plan 37 Addendum B19 — admission audit -----

    /// Convenience: collect just the `event` strings from captured
    /// audit entries, in emit order. Test assertions are clearer
    /// against this projection than against the full struct.
    fn audit_events(audit: &crate::audit::CapturingAuditSigner) -> Vec<String> {
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
        // Each entry is bound to the plan id and image — §22 binding.
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
        // the rejection. Wave 2 may add an envelope-rejection audit
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
        // admission audit entry verbatim (§22 — the "what was the
        // contract" record).
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
        // launch — §22 / B17 invariant: audit emits before forward.
        // No audit means no launch.
        struct FailingAudit;
        #[async_trait]
        impl crate::audit::AuditSigner for FailingAudit {
            async fn sign_and_emit(
                &self,
                _entry: &crate::audit::AuditEntry,
            ) -> Result<(), crate::audit::AuditError> {
                Err(crate::audit::AuditError::Io("disk full".into()))
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

    // ---- Wave 2.6: with_l7_egress builder + Variant::Prod gate ----

    use crate::l7_proxy::{
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
        async fn resolve_one(&self, _h: &str, _p: u16) -> Result<IpAddr, crate::EgressError> {
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
            crate::EgressDecision::Deny { reason } => {
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

    // ---- Wave 2.7: with_tool_gate builder ----

    #[tokio::test]
    async fn with_tool_gate_allows_listed_tool() {
        let policy = ToolPolicy {
            allowed: vec!["read_file".to_string(), "list_dir".to_string()],
        };
        let s = Supervisor::default().with_tool_gate(&policy);
        let v = s.tool_gate.check("read_file").await.expect("ok");
        assert_eq!(v, crate::ToolDecision::Allow);
    }

    #[tokio::test]
    async fn with_tool_gate_denies_unlisted_tool() {
        let policy = ToolPolicy {
            allowed: vec!["read_file".to_string()],
        };
        let s = Supervisor::default().with_tool_gate(&policy);
        let v = s.tool_gate.check("rm_rf").await.expect("ok");
        match v {
            crate::ToolDecision::Deny { reason } => {
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
            assert!(matches!(v, crate::ToolDecision::Deny { .. }));
        }
    }

    // ---- Plan 37 Addendum E1 — circuit-breaker wiring ----

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
        let reporter = Arc::new(crate::circuit_breaker::InspectorReporter::new(
            crate::circuit_breaker::CircuitBreakerConfig::default(),
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
        let reporter = Arc::new(crate::circuit_breaker::InspectorReporter::new(
            crate::circuit_breaker::CircuitBreakerConfig {
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

        // The legacy `EgressProxy::inspect(host, path)` runs the
        // chain. Because destination_policy's breaker is open, the
        // verdict is the chain's downstream "Allow" rather than the
        // `Deny` destination_policy would have produced.
        let dec = s.egress.inspect("evil.com", "/").await.expect("inspect ok");
        assert!(matches!(dec, crate::EgressDecision::Allow));
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
        assert!(matches!(dec, crate::EgressDecision::Deny { .. }));
    }
}
