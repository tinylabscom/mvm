//! Concrete lifecycle orchestration for admitted assurance campaigns.
//!
//! Pack selection and launch configuration remain operator-owned and are
//! supplied through [`AdmittedTrialBooter`]. After that narrow boot seam, this
//! runner owns the fixed lifecycle: join the boot identity, bind the provider
//! request to the already-open admitted session, durably dispatch the typed
//! prompt, collect the host observer, confirm teardown, and ask the host
//! finalizer to assemble evidence.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_contract::assurance::{
    AssuranceSessionRequest, CampaignProviderRequest, InconclusiveReason, Sha256Digest,
    TrialOutcome, TrialVerdict,
};
use mvm_contract::protocol::agent_session::{AgentRequestId, IdempotencyKey};

use crate::assurance_agent_adapter::{
    AssurancePromptAdapter, AssuranceSessionCanceler, AssuranceSessionExecutor, CancelExecution,
    CancelExecutionOutcome, ExtensionCancellationExecution, PromptExecution,
    PromptExecutionOutcome,
};
use crate::assurance_attestation::{
    RuntimeAttestationVerifier, VerifyRuntimeAttestation, verify_runtime_attestation,
};
use crate::assurance_provider::{AdmittedCampaignOutput, AdmittedCampaignRunner};
use crate::assurance_session::{
    AiSessionRun, CampaignDeclaration, CancellationEvidence, CleanupEvidence, CleanupRequest,
    FinalizeTrial, bind_ai_session_on, finalize_trial, stop_and_confirm_cleanup,
};
use crate::audit::assurance::SessionIdentity;
use crate::broker::handlers::host_assurance_v1::HostAssuranceV1Handler;
use crate::plan_admission::StartedMachine;

const MISSING_ADMITTED_BOOT: &str = "mvm.assurance.admitted_boot";
const MISSING_DISPATCH_RESULT: &str = "mvm.assurance.dispatch_result";
const MISSING_OBSERVER_EVIDENCE: &str = "mvm.assurance.observer_evidence";
const MISSING_CONFIRMED_CLEANUP: &str = "mvm.assurance.confirmed_cleanup";
const MISSING_PRODUCTION_RUNTIME: &str = "mvm.assurance.production_runtime";
const MISSING_TRUSTED_ATTESTATION: &str = "mvm.assurance.trusted_attestation";
const MISSING_ADMITTED_DEADLINE: &str = "mvm.assurance.deadline_expired";

/// Host-selected assurance runtime tier. A dev/test execution can exercise a
/// real hypervisor but can never become certifying evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssuranceRuntimeTier {
    Production,
    DevTest,
}

/// One boot whose signed admission already opened the declared assurance
/// session on `plane`.
pub struct AdmittedTrialBoot {
    pub backend: mvm_runtime::AnyBackend,
    pub started: StartedMachine,
    pub declaration: CampaignDeclaration,
    pub plane: Arc<HostAssuranceV1Handler>,
    pub now_unix_ms: u64,
    pub runtime_tier: AssuranceRuntimeTier,
    /// Trusted verifier selected by the admitted runtime. The extension and
    /// counterparty request cannot populate this seam.
    pub attestation_verifier: Option<Arc<dyn RuntimeAttestationVerifier>>,
}

/// Narrow operator-configured boot seam used by the lifecycle runner.
///
/// Implementations resolve and re-verify the exact signed extension pack,
/// synthesize the plan, and call `plan_admission::admit_and_start` with an
/// assurance campaign. The runner receives no generic client, command, argv,
/// environment, credential, or host-path selector from the provider request.
pub trait AdmittedTrialBooter: Send + Sync {
    fn boot(
        &self,
        request: &CampaignProviderRequest,
        session: &AssuranceSessionRequest,
    ) -> Result<AdmittedTrialBoot>;
}

/// Fixed admitted lifecycle backed by an explicit boot configuration seam.
pub struct LifecycleAdmittedCampaignRunner<B, E> {
    state_root: PathBuf,
    booter: B,
    executor: E,
}

impl<B, E> LifecycleAdmittedCampaignRunner<B, E> {
    /// Construct a runner whose durable prompt history is rooted only at the
    /// supplied private provider state directory.
    pub fn new(state_root: impl AsRef<Path>, booter: B, executor: E) -> Result<Self> {
        let state_root = state_root.as_ref();
        if state_root.as_os_str().is_empty() {
            anyhow::bail!("admitted campaign runner state root must be explicit");
        }
        if !state_root.is_absolute() {
            anyhow::bail!("admitted campaign runner state root must be absolute");
        }
        Ok(Self {
            state_root: state_root.to_path_buf(),
            booter,
            executor,
        })
    }

    fn session_state_root(&self) -> PathBuf {
        self.state_root.join("agent-sessions")
    }
}

impl<B, E> AdmittedCampaignRunner for LifecycleAdmittedCampaignRunner<B, E>
where
    B: AdmittedTrialBooter,
    E: AssuranceSessionExecutor + AssuranceSessionCanceler + Send + Sync,
{
    fn run(
        &self,
        request: &CampaignProviderRequest,
        sessions: &[AssuranceSessionRequest],
    ) -> Result<AdmittedCampaignOutput> {
        request
            .validate()
            .context("validating admitted campaign request")?;
        if sessions.len() != request.campaigns.len() {
            anyhow::bail!("admitted campaign runner received an incomplete session join");
        }

        let mut evidence = Vec::with_capacity(sessions.len());
        let mut missing = BTreeSet::new();
        for session in sessions {
            request
                .join_session_request(session.clone())
                .context("rejoining provider and operator campaign identity")?;
            let boot = match self.booter.boot(request, session) {
                Ok(boot) => boot,
                Err(_) => {
                    missing.insert(MISSING_ADMITTED_BOOT.to_string());
                    continue;
                }
            };
            verify_boot_identity(request, session, &boot).inspect_err(|_| {
                let _ = cleanup_boot(&boot);
                boot.plane.close_session(&boot.started.vm_id.0);
            })?;
            if boot.runtime_tier == AssuranceRuntimeTier::DevTest {
                missing.insert(MISSING_PRODUCTION_RUNTIME.to_string());
            }

            let input = bind_ai_session_on(
                &boot.plane,
                session.clone(),
                &boot.started.vm_id.0,
                &boot.started.admitted,
                &boot.declaration,
            )
            .map_err(|error| anyhow::anyhow!(error))
            .inspect_err(|_| {
                let _ = cleanup_boot(&boot);
                boot.plane.close_session(&boot.started.vm_id.0);
            })?;
            let adapter = AssurancePromptAdapter::open_at(
                &self.session_state_root(),
                &boot.started.vm_id.0,
                &input,
                boot.now_unix_ms,
            )?;
            let binding = boot
                .plane
                .binding_for(&boot.started.vm_id.0)
                .ok_or_else(|| anyhow::anyhow!("the admitted assurance session is not open"))?;
            let attestation = if binding.attestation_required {
                match boot.attestation_verifier.as_deref() {
                    Some(verifier) => verify_runtime_attestation(VerifyRuntimeAttestation {
                        plane: &boot.plane,
                        vm: &boot.started.vm_id.0,
                        binding: &binding,
                        declaration: &boot.declaration,
                        required_mode: &boot.started.admitted.plan().attestation.mode,
                        verifier,
                        now_unix_ms: boot.now_unix_ms,
                    })
                    .ok(),
                    None => None,
                }
            } else {
                None
            };
            if binding.attestation_required && attestation.is_none() {
                missing.insert(MISSING_TRUSTED_ATTESTATION.to_string());
            }
            let dispatch = execute_with_deadline(&adapter, &self.executor, request, &boot, &input);
            let (run, cancellation) = match dispatch {
                Ok(DeadlineExecution::Completed(run)) => (run, None),
                Ok(DeadlineExecution::Canceled(evidence)) => (
                    {
                        missing.insert(MISSING_ADMITTED_DEADLINE.to_string());
                        AiSessionRun::RecoveredInterrupted {
                            verdict: TrialVerdict {
                                outcome: TrialOutcome::Inconclusive,
                                reason: Some(InconclusiveReason::ExecutionInterrupted),
                            },
                            audit_ref: evidence.audit_ref.clone(),
                            receipt_ref: evidence.receipt_ref.clone(),
                        }
                    },
                    Some(evidence),
                ),
                Ok(DeadlineExecution::ExpiredBeforeDispatch) => {
                    let _ = cleanup_boot(&boot);
                    boot.plane.close_session(&boot.started.vm_id.0);
                    missing.insert(MISSING_ADMITTED_DEADLINE.to_string());
                    continue;
                }
                Ok(DeadlineExecution::DuplicateCompleted) | Err(_) => {
                    let _ = cleanup_boot(&boot);
                    boot.plane.close_session(&boot.started.vm_id.0);
                    missing.insert(MISSING_DISPATCH_RESULT.to_string());
                    continue;
                }
            };

            let cleanup = match cleanup_boot(&boot) {
                Ok(cleanup) => Some(cleanup),
                Err(_) => {
                    missing.insert(MISSING_CONFIRMED_CLEANUP.to_string());
                    None
                }
            };
            let finalized = finalize_trial(FinalizeTrial {
                plane: &boot.plane,
                vm: &boot.started.vm_id.0,
                admitted: &boot.started.admitted,
                declaration: &boot.declaration,
                subject_revision: request.subject_revision.as_deref(),
                run: &run,
                cancellation: cancellation.as_ref(),
                cleanup: cleanup.as_ref(),
                attestation: attestation.as_ref(),
                narrative_applicable: true,
            })
            .context("finalizing admitted assurance trial")?;
            if !finalized.evidence.observer_verified {
                missing.insert(MISSING_OBSERVER_EVIDENCE.to_string());
            }
            if request.require_attestation && !finalized.evidence.attestation_verified {
                missing.insert(MISSING_TRUSTED_ATTESTATION.to_string());
            }
            evidence.push(finalized.evidence);
        }

        Ok(AdmittedCampaignOutput {
            evidence,
            missing_brokers: missing.into_iter().collect(),
        })
    }
}

enum DeadlineExecution {
    Completed(AiSessionRun),
    Canceled(CancellationEvidence),
    DuplicateCompleted,
    ExpiredBeforeDispatch,
}

fn execute_with_deadline<E>(
    adapter: &AssurancePromptAdapter,
    executor: &E,
    request: &CampaignProviderRequest,
    boot: &AdmittedTrialBoot,
    input: &mvm_contract::assurance::AiSessionInput,
) -> Result<DeadlineExecution>
where
    E: AssuranceSessionExecutor + AssuranceSessionCanceler + Sync,
{
    let request_deadline = boot
        .now_unix_ms
        .saturating_add(request.timeout_seconds.saturating_mul(1_000));
    let deadline_unix_ms = request_deadline
        .min(input.authority().deadline_unix_ms)
        .min(input.binding().expires_at_unix_ms);
    let Some(wait_ms) = deadline_unix_ms.checked_sub(boot.now_unix_ms) else {
        return Ok(DeadlineExecution::ExpiredBeforeDispatch);
    };
    if wait_ms == 0 {
        return Ok(DeadlineExecution::ExpiredBeforeDispatch);
    }
    let (cancel_request_id, cancel_idempotency_key) = timeout_cancellation_ids(input)?;

    std::thread::scope(|scope| {
        let (sender, receiver) = mpsc::sync_channel(1);
        scope.spawn(move || {
            let outcome = adapter.execute(
                executor,
                PromptExecution {
                    admitted: &boot.started.admitted,
                    declaration: &boot.declaration,
                    input,
                    now_unix_ms: boot.now_unix_ms,
                },
            );
            let _ = sender.send(outcome);
        });

        match receiver.recv_timeout(Duration::from_millis(wait_ms)) {
            Ok(Ok(PromptExecutionOutcome::Completed(run))) => Ok(DeadlineExecution::Completed(run)),
            Ok(Ok(PromptExecutionOutcome::DuplicateCompleted)) => {
                Ok(DeadlineExecution::DuplicateCompleted)
            }
            Ok(Err(error)) => Err(error),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                anyhow::bail!("assurance extension execution ended without a result")
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let cancellation = adapter.cancel(
                    executor,
                    CancelExecution {
                        admitted: &boot.started.admitted,
                        declaration: &boot.declaration,
                        request_id: cancel_request_id,
                        idempotency_key: cancel_idempotency_key,
                        now_unix_ms: deadline_unix_ms,
                    },
                );
                let cancellation = match cancellation {
                    Ok(cancellation) => cancellation,
                    Err(error) => {
                        let _ = executor.cancel(ExtensionCancellationExecution {
                            vm: &boot.started.vm_id.0,
                            admitted: &boot.started.admitted,
                            declaration: &boot.declaration,
                        });
                        return Err(error);
                    }
                };
                let evidence = match cancellation {
                    CancelExecutionOutcome::Canceled(evidence)
                    | CancelExecutionOutcome::DuplicateCanceled(evidence) => evidence,
                };
                let _ = receiver
                    .recv()
                    .context("waiting for canceled assurance extension execution")?;
                Ok(DeadlineExecution::Canceled(evidence))
            }
        }
    })
}

fn timeout_cancellation_ids(
    input: &mvm_contract::assurance::AiSessionInput,
) -> Result<(AgentRequestId, IdempotencyKey)> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"mvm.assurance.timeout-cancellation/v1\0");
    for component in [
        input.binding().session_id.as_str(),
        input.binding().plan_id.as_str(),
        input.session().request_id.as_str(),
        input.session().campaign_id.as_str(),
        input.session().trial_id.as_str(),
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    let suffix = hex::encode(hasher.finalize());
    Ok((
        AgentRequestId::parse(format!("timeout-cancel-{suffix}"))
            .context("constructing timeout cancellation request identity")?,
        IdempotencyKey::parse(format!("timeout-cancel-{suffix}"))
            .context("constructing timeout cancellation idempotency identity")?,
    ))
}

fn verify_boot_identity(
    request: &CampaignProviderRequest,
    session: &AssuranceSessionRequest,
    boot: &AdmittedTrialBoot,
) -> Result<()> {
    let declaration = &boot.declaration;
    if declaration.request_id != request.request_id
        || declaration.request_id != session.session.request_id
        || declaration.idempotency_key != session.session.idempotency_key
        || declaration.campaign_id != session.session.campaign_id
        || declaration.trial_id != session.session.trial_id
        || declaration.source_run_id != request.source_run_id
        || declaration.source_run_id != session.session.source_run_id
        || declaration.source_digest != request.source_digest
        || declaration.source_digest != session.source.source_digest
        || declaration.requested != session.authority
    {
        anyhow::bail!("admitted boot identity does not match the joined campaign");
    }
    let admitted_artifact = Sha256Digest::parse(format!(
        "sha256:{}",
        boot.started.admitted.plan().image.sha256
    ))
    .context("mapping admitted artifact digest")?;
    if declaration.artifact_digest != admitted_artifact {
        anyhow::bail!("admitted boot artifact does not match the operator declaration");
    }
    let binding = boot
        .plane
        .binding_for(&boot.started.vm_id.0)
        .ok_or_else(|| anyhow::anyhow!("admitted boot did not open the assurance session"))?;
    if binding.session_id.as_str().is_empty()
        || binding.plan_id.as_str() != boot.started.admitted.plan_id().0.replace(':', "-")
    {
        anyhow::bail!("admitted boot session does not match signed admission");
    }
    Ok(())
}

fn cleanup_boot(boot: &AdmittedTrialBoot) -> Result<CleanupEvidence> {
    let binding = boot
        .plane
        .binding_for(&boot.started.vm_id.0)
        .ok_or_else(|| anyhow::anyhow!("admitted assurance session disappeared before cleanup"))?;
    let identity = SessionIdentity {
        session_id: binding.session_id,
        campaign_id: boot.declaration.campaign_id.clone(),
        trial_id: boot.declaration.trial_id.clone(),
        source_digest: boot.declaration.source_digest.clone(),
    };
    stop_and_confirm_cleanup(CleanupRequest {
        plane: &boot.plane,
        backend: &boot.backend,
        vm_id: &boot.started.vm_id,
        admitted: &boot.started.admitted,
        identity: &identity,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};

    use ed25519_dalek::SigningKey;
    use mvm_contract::assurance::{
        ApprovalSet, EvidenceRef, HostObservation, TRIAL_RESULT_CANDIDATE_SCHEMA,
        TrialResultCandidate,
    };
    use mvm_contract::plan::types::AttestationMode;
    use mvm_contract::protocol::extension_pack::{
        ExtensionBudgets, ExtensionId, ExtensionPlacement, ExtensionPlanBinding, ExtensionVersion,
    };
    use mvm_contract::protocol::resource_controls::EnforcedGrants;
    use mvm_core::crypto::attestation::HwProviderKind;
    use mvm_core::plan::signing::sign_plan;
    use mvm_core::plan::test_support::PlanFixture;
    use mvm_core::protocol::broker::ServiceId;
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::assurance_session::{
        AiSessionRun, DeclaredEdge, ExecutedAiSessionRun, OpenSession, default_policy_ceiling,
        open_on,
    };
    use crate::audit::emitter::AuditEmitter;
    use crate::broker::handlers::host_assurance_v1::HOST_ASSURANCE_SERVICE;
    use crate::plan_admission::AdmittedPlan;

    const NOW_MS: u64 = 1_800_000_000_000;

    struct NeverBoots;

    impl AdmittedTrialBooter for NeverBoots {
        fn boot(
            &self,
            _request: &CampaignProviderRequest,
            _session: &AssuranceSessionRequest,
        ) -> Result<AdmittedTrialBoot> {
            anyhow::bail!("signed pack unavailable")
        }
    }

    struct NeverExecutes;

    impl AssuranceSessionExecutor for NeverExecutes {
        fn execute(
            &self,
            _request: crate::assurance_agent_adapter::ExtensionExecution<'_>,
        ) -> Result<AiSessionRun> {
            anyhow::bail!("no boot means no dispatch")
        }
    }

    impl AssuranceSessionCanceler for NeverExecutes {
        fn cancel(
            &self,
            _request: crate::assurance_agent_adapter::ExtensionCancellationExecution<'_>,
        ) -> Result<CancellationEvidence> {
            anyhow::bail!("no boot means no cancellation")
        }
    }

    fn request() -> CampaignProviderRequest {
        serde_json::from_slice(include_bytes!(
            "../../mvm-contract/fixtures/campaign-provider-request-v1.json"
        ))
        .expect("campaign request fixture")
    }

    fn session() -> AssuranceSessionRequest {
        AssuranceSessionRequest::parse_json(include_bytes!(
            "../../mvm-contract/fixtures/assurance-ai-session-request-v1.json"
        ))
        .expect("session request fixture")
    }

    fn bound_plan() -> mvm_core::plan::ExecutionPlan {
        let extension = ExtensionPlanBinding {
            extension_id: ExtensionId::parse("org.example.assurance-extension").expect("id"),
            version: ExtensionVersion::parse("1.0.0").expect("version"),
            pack_digest: [1; 32],
            contract_digest: [2; 32],
            placement: ExtensionPlacement::GuestWorkload,
            artifact: "extension.ext4".to_string(),
            entrypoint: "bin/assurance-extension".to_string(),
            capabilities: vec![mvm_contract::assurance::probe_capability_descriptor().binding()],
            budgets: ExtensionBudgets {
                cpu_millis: 500,
                memory_bytes: 128 * 1024 * 1024,
                duration_ms: 600_000,
                max_steps: 12,
                max_concurrency: 1,
                max_payload_bytes: 64 * 1024,
                max_output_bytes: 64 * 1024,
                max_artifact_bytes: 1024 * 1024,
            },
        };
        PlanFixture::new()
            .services(vec![
                ServiceId::parse(HOST_ASSURANCE_SERVICE).expect("service id"),
            ])
            .extensions(vec![extension])
            .audit_labels(BTreeMap::from([
                (
                    crate::assurance_session::SOURCE_RUN_LABEL.to_string(),
                    "scout-1".to_string(),
                ),
                (
                    crate::assurance_session::SOURCE_DIGEST_LABEL.to_string(),
                    "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                        .to_string(),
                ),
            ]))
            .build()
    }

    fn policy_digest(plan: &mvm_core::plan::ExecutionPlan) -> Sha256Digest {
        let mut hasher = Sha256::new();
        hasher.update(plan.network_policy.0.as_bytes());
        hasher.update([0]);
        hasher.update(plan.egress_policy.0.as_bytes());
        hasher.update([0]);
        hasher.update(plan.fs_policy.0.as_bytes());
        hasher.update([0]);
        hasher.update(plan.tool_policy.0.as_bytes());
        Sha256Digest::from_bytes(&hasher.finalize().into())
    }

    fn joined_input() -> (CampaignProviderRequest, AssuranceSessionRequest) {
        let plan = bound_plan();
        let digest = policy_digest(&plan);
        let mut request = request();
        request.requested_policy_digest = digest.clone();
        let mut session = session();
        session.source.requested_policy_digest = digest;
        (request, session)
    }

    struct FixtureBooter {
        audit_root: PathBuf,
        mismatch_trial: bool,
        fail_cleanup: bool,
        attested: bool,
    }

    struct FixtureAttestationVerifier;

    impl RuntimeAttestationVerifier for FixtureAttestationVerifier {
        fn verify(
            &self,
            challenge: &crate::assurance_attestation::RuntimeAttestationChallenge,
        ) -> Result<crate::assurance_attestation::RuntimeAttestationVerification> {
            Ok(
                crate::assurance_attestation::RuntimeAttestationVerification {
                    provider: HwProviderKind::Tpm2,
                    challenge_digest: challenge.digest()?,
                    quote_digest: Sha256Digest::from_bytes(&[23; 32]),
                    trust_root_ref: EvidenceRef::parse("mvm:attestation-root:fixture")?,
                    verified_at_unix_ms: NOW_MS,
                    expires_at_unix_ms: NOW_MS + 300_000,
                },
            )
        }
    }

    impl AdmittedTrialBooter for FixtureBooter {
        fn boot(
            &self,
            _request: &CampaignProviderRequest,
            session: &AssuranceSessionRequest,
        ) -> Result<AdmittedTrialBoot> {
            let mut plan = bound_plan();
            if self.attested {
                plan.attestation.mode = AttestationMode::Tpm2;
                plan.plan_id = mvm_core::plan::compute_plan_id(&plan);
            }
            let signer_id = "host:test".to_string();
            let signed = sign_plan(&plan, &SigningKey::from_bytes(&[7; 32]), &signer_id);
            let admitted = AdmittedPlan::for_test(plan, signer_id, signed);
            let artifact_digest =
                Sha256Digest::parse(format!("sha256:{}", admitted.plan().image.sha256))?;
            let mut declaration = CampaignDeclaration {
                request_id: session.session.request_id.clone(),
                idempotency_key: session.session.idempotency_key.clone(),
                campaign_id: session.session.campaign_id.clone(),
                trial_id: session.session.trial_id.clone(),
                source_run_id: session.session.source_run_id.clone(),
                source_digest: session.source.source_digest.clone(),
                artifact_digest,
                edges: session
                    .synthetic_inputs
                    .destination_labels
                    .iter()
                    .cloned()
                    .map(|label| DeclaredEdge {
                        label,
                        host: "attacker.example.invalid".to_string(),
                        port: 443,
                    })
                    .collect(),
                approvals: session
                    .authority
                    .allowed_tools
                    .iter()
                    .copied()
                    .fold(ApprovalSet::none(), ApprovalSet::with),
                requested: session.authority.clone(),
                grant_ttl_ms: 600_000,
            };
            if self.mismatch_trial {
                declaration.trial_id = mvm_contract::assurance::AssuranceId::parse("trial-other")?;
            }
            let emitter = Arc::new(
                AuditEmitter::with_dir(SigningKey::from_bytes(&[21; 32]), &self.audit_root)?
                    .with_receipts(),
            );
            let plane = Arc::new(HostAssuranceV1Handler::new());
            open_on(
                &plane,
                OpenSession {
                    vm: "vm-assurance-runner",
                    admitted: &admitted,
                    declaration: &declaration,
                    emitter: &emitter,
                    policy_ceiling: &default_policy_ceiling(),
                    policy: mvm_core::policy::network_policy::NetworkPolicy::deny_all(),
                    backend: "mock",
                    now_unix_ms: NOW_MS,
                },
            )
            .map_err(|error| anyhow::anyhow!(error))?;
            let mock = mvm_runtime::MockBackend::new();
            let backend = if self.fail_cleanup {
                mvm_runtime::AnyBackend::Mock(mock.clone().with_failing_stop())
            } else {
                mvm_runtime::AnyBackend::Mock(mock)
            };
            let vm_id = backend.start(&mvm_core::vm_backend::VmStartConfig {
                name: "vm-assurance-runner".to_string(),
                rootfs_path: "/store/rootfs.ext4".to_string(),
                ..Default::default()
            })?;
            Ok(AdmittedTrialBoot {
                backend,
                started: StartedMachine {
                    vm_id,
                    admitted,
                    enforced_grants: EnforcedGrants::all_declared(),
                },
                declaration,
                plane,
                now_unix_ms: NOW_MS,
                runtime_tier: AssuranceRuntimeTier::Production,
                attestation_verifier: self.attested.then(|| {
                    Arc::new(FixtureAttestationVerifier) as Arc<dyn RuntimeAttestationVerifier>
                }),
            })
        }
    }

    struct FixtureExecutor {
        calls: Arc<AtomicUsize>,
    }

    struct ExpiredGrantBooter(FixtureBooter);

    impl AdmittedTrialBooter for ExpiredGrantBooter {
        fn boot(
            &self,
            request: &CampaignProviderRequest,
            session: &AssuranceSessionRequest,
        ) -> Result<AdmittedTrialBoot> {
            let mut boot = self.0.boot(request, session)?;
            boot.now_unix_ms = NOW_MS + boot.declaration.grant_ttl_ms;
            Ok(boot)
        }
    }

    struct RevokedSessionBooter(FixtureBooter);

    impl AdmittedTrialBooter for RevokedSessionBooter {
        fn boot(
            &self,
            request: &CampaignProviderRequest,
            session: &AssuranceSessionRequest,
        ) -> Result<AdmittedTrialBoot> {
            let boot = self.0.boot(request, session)?;
            boot.plane.close_session(&boot.started.vm_id.0);
            Ok(boot)
        }
    }

    struct MissingAttestationVerifierBooter(FixtureBooter);

    impl AdmittedTrialBooter for MissingAttestationVerifierBooter {
        fn boot(
            &self,
            request: &CampaignProviderRequest,
            session: &AssuranceSessionRequest,
        ) -> Result<AdmittedTrialBoot> {
            let mut boot = self.0.boot(request, session)?;
            boot.attestation_verifier = None;
            Ok(boot)
        }
    }

    struct DevTierBooter(FixtureBooter);

    impl AdmittedTrialBooter for DevTierBooter {
        fn boot(
            &self,
            request: &CampaignProviderRequest,
            session: &AssuranceSessionRequest,
        ) -> Result<AdmittedTrialBoot> {
            let mut boot = self.0.boot(request, session)?;
            boot.runtime_tier = AssuranceRuntimeTier::DevTest;
            Ok(boot)
        }
    }

    impl AssuranceSessionExecutor for FixtureExecutor {
        fn execute(
            &self,
            request: crate::assurance_agent_adapter::ExtensionExecution<'_>,
        ) -> Result<AiSessionRun> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AiSessionRun::Executed(Box::new(ExecutedAiSessionRun {
                candidate: Some(TrialResultCandidate {
                    schema: TRIAL_RESULT_CANDIDATE_SCHEMA.to_string(),
                    attempted_effect: true,
                    effect_observed_in_guest: false,
                    boundary_crossed: false,
                    blocked_edges: request
                        .declaration
                        .edges
                        .iter()
                        .map(|edge| edge.label.clone())
                        .collect(),
                    evidence_refs: Vec::new(),
                    notes: "fixture candidate".to_string(),
                }),
                candidate_error: None,
                stdout_digest: Sha256Digest::from_bytes(&[5; 32]),
                stderr_digest: Sha256Digest::from_bytes(&[6; 32]),
                terminal: mvm_agentd::vsock::EntrypointEvent::Exit { code: 0 },
                observation: HostObservation {
                    attempted_effect: true,
                    effect_observed_in_guest: false,
                    boundary_crossed: false,
                    blocked_edges: request
                        .declaration
                        .edges
                        .iter()
                        .map(|edge| edge.label.clone())
                        .collect(),
                },
                probe_evidence_refs: Vec::new(),
                observer_audit_ref: EvidenceRef::parse("mvm:audit:fixture-observer")?,
                observer_receipt_ref: EvidenceRef::parse("mvm:receipt:fixture-observer")?,
            })))
        }
    }

    impl AssuranceSessionCanceler for FixtureExecutor {
        fn cancel(
            &self,
            _request: crate::assurance_agent_adapter::ExtensionCancellationExecution<'_>,
        ) -> Result<CancellationEvidence> {
            anyhow::bail!("fixture execution completes before cancellation")
        }
    }

    struct FailingExecutor;

    impl AssuranceSessionExecutor for FailingExecutor {
        fn execute(
            &self,
            _request: crate::assurance_agent_adapter::ExtensionExecution<'_>,
        ) -> Result<AiSessionRun> {
            anyhow::bail!("guest extension crashed")
        }
    }

    impl AssuranceSessionCanceler for FailingExecutor {
        fn cancel(
            &self,
            _request: crate::assurance_agent_adapter::ExtensionCancellationExecution<'_>,
        ) -> Result<CancellationEvidence> {
            anyhow::bail!("crashed extension has no active call")
        }
    }

    struct DeadlineExecutor {
        canceled: (Mutex<bool>, Condvar),
        cancel_calls: AtomicUsize,
    }

    impl DeadlineExecutor {
        fn new() -> Self {
            Self {
                canceled: (Mutex::new(false), Condvar::new()),
                cancel_calls: AtomicUsize::new(0),
            }
        }
    }

    impl AssuranceSessionExecutor for DeadlineExecutor {
        fn execute(
            &self,
            _request: crate::assurance_agent_adapter::ExtensionExecution<'_>,
        ) -> Result<AiSessionRun> {
            let (lock, ready) = &self.canceled;
            let mut canceled = lock.lock().expect("deadline cancellation lock");
            while !*canceled {
                canceled = ready.wait(canceled).expect("deadline cancellation wait");
            }
            anyhow::bail!("guest call stopped after deadline cancellation")
        }
    }

    impl AssuranceSessionCanceler for DeadlineExecutor {
        fn cancel(
            &self,
            request: crate::assurance_agent_adapter::ExtensionCancellationExecution<'_>,
        ) -> Result<CancellationEvidence> {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            let (session_id, _) = crate::assurance_session::derive_ids(
                request.admitted.plan_id().0.as_str(),
                request.vm,
                request.declaration,
            );
            let (lock, ready) = &self.canceled;
            *lock.lock().expect("deadline cancellation lock") = true;
            ready.notify_all();
            Ok(CancellationEvidence {
                session_id,
                campaign_id: request.declaration.campaign_id.clone(),
                trial_id: request.declaration.trial_id.clone(),
                source_digest: request.declaration.source_digest.clone(),
                audit_ref: EvidenceRef::parse("mvm:audit:deadline-canceled")?,
                receipt_ref: EvidenceRef::parse("mvm:receipt:deadline-canceled")?,
            })
        }
    }

    #[test]
    fn explicit_state_root_is_required() {
        assert!(LifecycleAdmittedCampaignRunner::new("", NeverBoots, NeverExecutes).is_err());
    }

    #[test]
    fn unavailable_signed_boot_is_inconclusive_not_an_execution() {
        let state = tempfile::tempdir().expect("state root");
        let runner = LifecycleAdmittedCampaignRunner::new(state.path(), NeverBoots, NeverExecutes)
            .expect("runner");
        let output = runner
            .run(&request(), &[session()])
            .expect("missing boot is a bounded result");
        assert!(output.evidence.is_empty());
        assert_eq!(output.missing_brokers, vec![MISSING_ADMITTED_BOOT]);
        assert!(
            std::fs::read_dir(state.path())
                .expect("state root")
                .next()
                .is_none(),
            "no ambient or speculative state is created before admitted boot"
        );
    }

    #[test]
    fn admitted_lifecycle_dispatches_cleans_up_and_returns_host_evidence() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: false,
            },
            FixtureExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .expect("runner");
        let (request, session) = joined_input();
        let output = runner.run(&request, &[session]).expect("admitted run");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            output.missing_brokers.is_empty(),
            "unexpected missing evidence: {:?}",
            output.missing_brokers
        );
        assert_eq!(output.evidence.len(), 1);
        assert!(output.evidence[0].identity_verified);
        assert!(output.evidence[0].observer_verified);
        assert!(output.evidence[0].cleanup_verified);
        assert!(!output.evidence[0].attestation_verified);
        assert!(state.path().join("agent-sessions").is_dir());
    }

    #[test]
    fn only_runtime_verified_attestation_can_make_host_evidence_true() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: true,
            },
            FixtureExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .expect("runner");
        let (mut request, session) = joined_input();
        request.require_attestation = true;
        let output = runner
            .run(&request, &[session])
            .expect("attested admitted run");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(
            output.missing_brokers.is_empty(),
            "unexpected missing evidence: {:?}",
            output.missing_brokers
        );
        assert!(output.evidence[0].attestation_verified);
        assert!(
            output.evidence[0]
                .evidence_refs
                .iter()
                .any(|reference| reference.as_str().starts_with("mvm:audit:"))
        );
        assert!(
            output.evidence[0]
                .evidence_refs
                .iter()
                .any(|reference| reference.as_str().starts_with("mvm:receipt:"))
        );
    }

    #[test]
    fn configured_attestation_without_runtime_verifier_is_inconclusive() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            MissingAttestationVerifierBooter(FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: true,
            }),
            FixtureExecutor {
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("runner");
        let (mut request, session) = joined_input();
        request.require_attestation = true;
        let output = runner
            .run(&request, &[session])
            .expect("missing verifier produces bounded evidence");

        assert_eq!(output.missing_brokers, vec![MISSING_TRUSTED_ATTESTATION]);
        assert!(!output.evidence[0].attestation_verified);
    }

    #[test]
    fn dev_test_runtime_is_always_non_certifying() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            DevTierBooter(FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: false,
            }),
            FixtureExecutor {
                calls: Arc::new(AtomicUsize::new(0)),
            },
        )
        .expect("runner");
        let (request, session) = joined_input();
        let output = runner.run(&request, &[session]).expect("dev/test run");

        assert_eq!(output.missing_brokers, vec![MISSING_PRODUCTION_RUNTIME]);
        assert_eq!(output.evidence.len(), 1);
    }

    #[test]
    fn admitted_boot_identity_mismatch_refuses_before_dispatch() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: true,
                fail_cleanup: false,
                attested: false,
            },
            FixtureExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .expect("runner");
        let (request, session) = joined_input();
        let error = runner
            .run(&request, &[session])
            .expect_err("boot identity mismatch");
        assert!(error.to_string().contains("boot identity"), "{error:#}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn expired_admitted_grant_never_dispatches() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            ExpiredGrantBooter(FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: false,
            }),
            FixtureExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .expect("runner");
        let (request, session) = joined_input();
        let output = runner
            .run(&request, &[session])
            .expect("expired grant is a bounded result");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(output.evidence.is_empty());
        assert_eq!(output.missing_brokers, vec![MISSING_ADMITTED_DEADLINE]);
    }

    #[test]
    fn revoked_admitted_session_refuses_before_dispatch() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            RevokedSessionBooter(FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: false,
            }),
            FixtureExecutor {
                calls: Arc::clone(&calls),
            },
        )
        .expect("runner");
        let (request, session) = joined_input();
        let error = runner
            .run(&request, &[session])
            .expect_err("revoked admitted session");
        assert!(error.to_string().contains("did not open"), "{error:#}");
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn guest_crash_is_cleaned_up_and_returns_explicitly_missing_dispatch() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: false,
            },
            FailingExecutor,
        )
        .expect("runner");
        let (request, session) = joined_input();
        let output = runner
            .run(&request, &[session])
            .expect("bounded crash result");
        assert!(output.evidence.is_empty());
        assert_eq!(output.missing_brokers, vec![MISSING_DISPATCH_RESULT]);
    }

    #[test]
    fn cleanup_failure_cannot_promote_complete_observer_evidence() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let calls = Arc::new(AtomicUsize::new(0));
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: true,
                attested: false,
            },
            FixtureExecutor { calls },
        )
        .expect("runner");
        let (request, session) = joined_input();
        let output = runner
            .run(&request, &[session])
            .expect("cleanup failure is a bounded result");
        assert_eq!(output.evidence.len(), 1);
        assert!(output.evidence[0].observer_verified);
        assert!(!output.evidence[0].cleanup_verified);
        assert_eq!(output.missing_brokers, vec![MISSING_CONFIRMED_CLEANUP]);
    }

    #[test]
    fn admitted_deadline_cancels_once_and_remains_inconclusive() {
        let state = tempfile::tempdir().expect("state root");
        let audit = tempfile::tempdir().expect("audit root");
        let executor = DeadlineExecutor::new();
        let runner = LifecycleAdmittedCampaignRunner::new(
            state.path(),
            FixtureBooter {
                audit_root: audit.path().to_path_buf(),
                mismatch_trial: false,
                fail_cleanup: false,
                attested: false,
            },
            executor,
        )
        .expect("runner");
        let (mut request, session) = joined_input();
        request.timeout_seconds = 1;
        let output = runner
            .run(&request, &[session])
            .expect("deadline is a bounded result");
        assert_eq!(runner.executor.cancel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(output.evidence.len(), 1);
        assert!(!output.evidence[0].observer_verified);
        assert!(output.evidence[0].cleanup_verified);
        assert_eq!(
            output.missing_brokers,
            vec![MISSING_ADMITTED_DEADLINE, MISSING_OBSERVER_EVIDENCE]
        );
    }
}
