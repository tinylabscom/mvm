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

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use mvm_plan::{PlanId, SignedExecutionPlan};
use thiserror::Error;
use tracing::warn;

use crate::artifact::{ArtifactCollector, NoopArtifactCollector};
use crate::audit::{AuditSigner, NoopAuditSigner};
use crate::backend::{BackendError, BackendLauncher, NoopBackendLauncher};
use crate::egress::{EgressProxy, NoopEgressProxy};
use crate::keystore::{KeystoreReleaser, NoopKeystoreReleaser};
use crate::state::{PlanState, PlanStateMachine, StateTransitionError};
use crate::tool_gate::{NoopToolGate, ToolGate};

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("plan signature/parse failed: {0}")]
    PlanVerify(String),

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
}

pub struct Supervisor {
    pub egress: Arc<dyn EgressProxy>,
    pub tool_gate: Arc<dyn ToolGate>,
    pub keystore: Arc<dyn KeystoreReleaser>,
    pub audit: Arc<dyn AuditSigner>,
    pub artifact: Arc<dyn ArtifactCollector>,
    pub backend: Arc<dyn BackendLauncher>,
    pub state: PlanStateMachine,
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
        // Step 1: signature + schema + version pin.
        let plan = match mvm_plan::verify_plan(signed, trusted_keys) {
            Ok(p) => p,
            Err(e) => {
                let err = SupervisorError::PlanVerify(e.to_string());
                self.transition_or_warn(PlanState::Failed);
                return Err(err);
            }
        };

        // Step 2: Pending → Verified.
        self.state.transition(PlanState::Verified).map_err(|e| {
            self.transition_or_warn(PlanState::Failed);
            SupervisorError::from(e)
        })?;

        // Step 3: backend dispatch.
        if let Err(e) = self.backend.launch(&plan).await {
            self.transition_or_warn(PlanState::Failed);
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

        Ok(())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::BackendLauncher;
    use async_trait::async_trait;
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
        }
    }

    fn sign_sample(plan: &ExecutionPlan) -> (SignedExecutionPlan, SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let signed = sign_plan(plan, &sk, "test");
        (signed, sk, vk)
    }

    fn make_supervisor_with_backend(b: Arc<MockBackend>) -> Supervisor {
        let mut s = Supervisor::new();
        s.backend = b;
        s
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

        let result = s.launch(&signed, &[("test", &vk)]).await;
        assert!(matches!(result, Err(SupervisorError::Backend(_))));
        assert_eq!(s.state.current(), PlanState::Failed);
    }

    #[test]
    fn default_supervisor_starts_in_pending() {
        let s = Supervisor::default();
        assert_eq!(s.state.current(), PlanState::Pending);
    }
}
