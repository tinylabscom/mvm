//! Durable agent-session adapter for admission-bound assurance prompts.
//!
//! The adapter constructs the prompt command from an [`AiSessionInput`] that
//! MVM already bound. Callers cannot substitute arbitrary prompt bytes. Each
//! durable event is fsync'd before extension execution, and those events carry
//! only the prompt digest and committed state transitions.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use mvm_contract::assurance::{AiSessionInput, AssuranceId, Sha256Digest};
use mvm_contract::protocol::agent_session::{
    AgentRequestId, AgentSessionCommand, AgentSessionCursor, AgentSessionEvent,
    AgentSessionEventEnvelope, AgentSessionId, AgentSessionJournal, AgentSessionState,
    DurableAgentSessionEvent, IdempotencyKey, PromptResult, RetentionPolicy,
};
use sha2::{Digest, Sha256};

use crate::assurance_session::{
    AiSessionRun, CampaignDeclaration, CancellationEvidence, cancel_ai_session, dispatch_ai_session,
};
use crate::audit::emitter::write_atomic;
use crate::plan_admission::AdmittedPlan;

const MAX_DURABLE_HISTORY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_CANCELLATION_EVIDENCE_BYTES: u64 = 16 * 1024;
const HISTORY_PAGE: u32 = 256;

/// Everything an extension executor receives after prompt admission.
pub struct ExtensionExecution<'a> {
    pub vm: &'a str,
    pub admitted: &'a AdmittedPlan,
    pub declaration: &'a CampaignDeclaration,
    pub input: &'a AiSessionInput,
}

/// Narrow execution seam used by the production guest dispatcher and tests.
pub trait AssuranceSessionExecutor {
    fn execute(&self, request: ExtensionExecution<'_>) -> Result<AiSessionRun>;
}

/// Narrow cancellation seam used by the controller and tests.
pub trait AssuranceSessionCanceler {
    fn cancel(&self, request: ExtensionCancellationExecution<'_>) -> Result<CancellationEvidence>;
}

/// Production executor: dispatches only the admitted generic extension.
#[derive(Debug, Default, Clone, Copy)]
pub struct GuestAssuranceExecutor;

impl AssuranceSessionExecutor for GuestAssuranceExecutor {
    fn execute(&self, request: ExtensionExecution<'_>) -> Result<AiSessionRun> {
        dispatch_ai_session(
            request.vm,
            request.admitted,
            request.declaration,
            request.input,
        )
    }
}

impl AssuranceSessionCanceler for GuestAssuranceExecutor {
    fn cancel(&self, request: ExtensionCancellationExecution<'_>) -> Result<CancellationEvidence> {
        cancel_ai_session(request.vm, request.admitted, request.declaration)
    }
}

/// Everything the cancellation transport receives after durable acceptance.
pub struct ExtensionCancellationExecution<'a> {
    pub vm: &'a str,
    pub admitted: &'a AdmittedPlan,
    pub declaration: &'a CampaignDeclaration,
}

/// Inputs for one prompt delivery through the durable adapter.
pub struct PromptExecution<'a> {
    pub admitted: &'a AdmittedPlan,
    pub declaration: &'a CampaignDeclaration,
    pub input: &'a AiSessionInput,
    pub now_unix_ms: u64,
}

/// Result of an adapter call.
#[derive(Debug)]
pub enum PromptExecutionOutcome {
    /// The executor produced a fresh or recovered host result.
    Completed(AiSessionRun),
    /// This request was already durably completed; no executor call occurred.
    DuplicateCompleted,
}

/// Inputs for one durable cancellation request.
pub struct CancelExecution<'a> {
    pub admitted: &'a AdmittedPlan,
    pub declaration: &'a CampaignDeclaration,
    pub request_id: AgentRequestId,
    pub idempotency_key: IdempotencyKey,
    pub now_unix_ms: u64,
}

/// Result of a cancellation adapter call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelExecutionOutcome {
    Canceled(CancellationEvidence),
    DuplicateCanceled(CancellationEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CancellationBindingIdentity {
    session_id: AssuranceId,
    plan_id: AssuranceId,
    request_id: AssuranceId,
    idempotency_key: AssuranceId,
    source_run_id: AssuranceId,
    campaign_id: AssuranceId,
    trial_id: AssuranceId,
    source_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
}

impl CancellationBindingIdentity {
    fn from_input(input: &AiSessionInput) -> Self {
        Self {
            session_id: input.binding().session_id.clone(),
            plan_id: input.binding().plan_id.clone(),
            request_id: input.session().request_id.clone(),
            idempotency_key: input.session().idempotency_key.clone(),
            source_run_id: input.session().source_run_id.clone(),
            campaign_id: input.session().campaign_id.clone(),
            trial_id: input.session().trial_id.clone(),
            source_digest: input.source().source_digest.clone(),
            artifact_digest: input.binding().artifact_digest.clone(),
        }
    }

    fn from_cancel(request: &CancelExecution<'_>, session_id: &AssuranceId) -> Result<Self> {
        Ok(Self {
            session_id: session_id.clone(),
            plan_id: AssuranceId::parse(request.admitted.plan_id().0.replace(':', "-"))
                .context("mapping admitted cancellation plan identity")?,
            request_id: request.declaration.request_id.clone(),
            idempotency_key: request.declaration.idempotency_key.clone(),
            source_run_id: request.declaration.source_run_id.clone(),
            campaign_id: request.declaration.campaign_id.clone(),
            trial_id: request.declaration.trial_id.clone(),
            source_digest: request.declaration.source_digest.clone(),
            artifact_digest: request.declaration.artifact_digest.clone(),
        })
    }
}

struct AdapterDurableState {
    journal: AgentSessionJournal,
    persisted_sequence: u64,
}

/// Durable prompt adapter for one admission-bound session.
pub struct AssurancePromptAdapter {
    vm: String,
    expected_prompt_digest: [u8; 32],
    expected_request_id: AgentRequestId,
    expected_idempotency_key: IdempotencyKey,
    expected_cancellation_identity: CancellationBindingIdentity,
    history_path: PathBuf,
    cancellation_path: PathBuf,
    durable: Mutex<AdapterDurableState>,
    cancel_gate: Mutex<()>,
}

impl AssurancePromptAdapter {
    /// Open or recover the adapter for the exact bound input.
    pub fn open(vm: &str, input: &AiSessionInput, now_unix_ms: u64) -> Result<Self> {
        let directory = mvm_core::config::vm_state_dir(vm).join("assurance-agent-sessions");
        Self::open_at(&directory, vm, input, now_unix_ms)
    }

    /// Open or recover beneath an explicit durable provider-owned root.
    ///
    /// Provider processes use this form so replay never depends on `HOME`,
    /// `MVM_HOME`, a current directory, or a process-temporary path.
    pub fn open_at(
        directory: &Path,
        vm: &str,
        input: &AiSessionInput,
        now_unix_ms: u64,
    ) -> Result<Self> {
        let prompt = input
            .to_json()
            .context("encoding admission-bound assurance prompt")?;
        let expected_prompt_digest = Sha256::digest(prompt.as_bytes()).into();
        let session_id = AgentSessionId::parse(input.binding().session_id.as_str())
            .context("mapping assurance session identity to agent-session identity")?;
        let expected_request_id = AgentRequestId::parse(input.session().request_id.as_str())
            .context("mapping assurance request identity to agent-session identity")?;
        let expected_idempotency_key =
            IdempotencyKey::parse(input.session().idempotency_key.as_str())
                .context("mapping assurance idempotency key to agent-session identity")?;
        let expected_cancellation_identity = CancellationBindingIdentity::from_input(input);
        let workload_digest = digest_bytes(&input.binding().workload_digest)?;
        prepare_session_directory(directory, vm)?;
        let history_path = directory.join(format!("{session_id}.jsonl"));
        let cancellation_path = directory.join(format!("{session_id}.cancellation.json"));

        let (journal, persisted_sequence) = if history_path.exists() {
            let history = load_history(&history_path)?;
            verify_opening_identity(&history, &session_id, workload_digest)?;
            let persisted_sequence = history
                .last()
                .and_then(|event| event.durable_sequence)
                .ok_or_else(|| anyhow::anyhow!("agent-session history has no durable sequence"))?;
            (
                AgentSessionJournal::from_history(session_id, history, RetentionPolicy::default())
                    .context("recovering assurance agent-session journal")?,
                persisted_sequence,
            )
        } else {
            let (journal, opened) = AgentSessionJournal::open(
                session_id,
                workload_digest,
                now_unix_ms,
                RetentionPolicy::default(),
            )
            .context("opening assurance agent-session journal")?;
            create_history(&history_path, &opened)?;
            (journal, opened.durable_sequence.unwrap_or(0))
        };

        Ok(Self {
            vm: vm.to_string(),
            expected_prompt_digest,
            expected_request_id,
            expected_idempotency_key,
            expected_cancellation_identity,
            history_path,
            cancellation_path,
            durable: Mutex::new(AdapterDurableState {
                journal,
                persisted_sequence,
            }),
            cancel_gate: Mutex::new(()),
        })
    }

    /// Deliver the exact bound envelope through `AgentSessionCommand::Prompt`.
    ///
    /// Prompt acceptance is committed before the executor is called. A crash
    /// after acceptance therefore recovers in `Running` and re-enters the
    /// executor, whose durable plan/idempotency claim prevents a second guest
    /// execution.
    pub fn execute(
        &self,
        executor: &dyn AssuranceSessionExecutor,
        request: PromptExecution<'_>,
    ) -> Result<PromptExecutionOutcome> {
        let prompt = request
            .input
            .to_json()
            .context("encoding admission-bound assurance prompt")?
            .into_bytes();
        if <[u8; 32]>::from(Sha256::digest(&prompt)) != self.expected_prompt_digest
            || request.input.session().request_id.as_str() != self.expected_request_id.as_str()
            || request.input.session().idempotency_key.as_str()
                != self.expected_idempotency_key.as_str()
        {
            anyhow::bail!("assurance prompt does not match the adapter's admitted session");
        }
        let outcome = {
            let mut durable = self
                .durable
                .lock()
                .map_err(|_| anyhow::anyhow!("assurance agent-session state is unavailable"))?;
            let outcome = durable
                .journal
                .apply(
                    AgentSessionCommand::Prompt {
                        request_id: self.expected_request_id.clone(),
                        idempotency_key: self.expected_idempotency_key.clone(),
                        prompt,
                    },
                    request.now_unix_ms,
                )
                .context("accepting assurance prompt")?;
            persist_new_events(&self.history_path, &mut durable)?;
            outcome
        };
        if !outcome.applied && outcome.state != AgentSessionState::Running {
            return Ok(PromptExecutionOutcome::DuplicateCompleted);
        }

        let execution = executor.execute(ExtensionExecution {
            vm: &self.vm,
            admitted: request.admitted,
            declaration: request.declaration,
            input: request.input,
        });
        match execution {
            Ok(result) => {
                let mut durable = self
                    .durable
                    .lock()
                    .map_err(|_| anyhow::anyhow!("assurance agent-session state is unavailable"))?;
                if durable.journal.state() == AgentSessionState::Running {
                    durable
                        .journal
                        .complete_prompt(
                            self.expected_request_id.clone(),
                            PromptResult::Succeeded,
                            request.now_unix_ms,
                        )
                        .context("completing assurance prompt")?;
                    persist_new_events(&self.history_path, &mut durable)?;
                }
                Ok(PromptExecutionOutcome::Completed(result))
            }
            Err(error) => {
                let mut durable = self
                    .durable
                    .lock()
                    .map_err(|_| anyhow::anyhow!("assurance agent-session state is unavailable"))?;
                if durable.journal.state() == AgentSessionState::Running {
                    durable
                        .journal
                        .complete_prompt(
                            self.expected_request_id.clone(),
                            PromptResult::Failed,
                            request.now_unix_ms,
                        )
                        .context("recording failed assurance prompt")?;
                    persist_new_events(&self.history_path, &mut durable)?;
                }
                Err(error.context("assurance extension execution failed"))
            }
        }
    }

    /// Durably request cancellation, stop the exact admitted guest call, then
    /// commit confirmation. A crash after the request but before confirmation
    /// recovers in `Canceling` and safely replays the identity-only cancel.
    pub fn cancel(
        &self,
        canceler: &dyn AssuranceSessionCanceler,
        request: CancelExecution<'_>,
    ) -> Result<CancelExecutionOutcome> {
        let _cancel_guard = self
            .cancel_gate
            .lock()
            .map_err(|_| anyhow::anyhow!("assurance cancellation gate is unavailable"))?;
        let presented_identity = CancellationBindingIdentity::from_cancel(
            &request,
            &self.expected_cancellation_identity.session_id,
        )?;
        if presented_identity != self.expected_cancellation_identity {
            anyhow::bail!("assurance cancellation does not match the admitted prompt binding");
        }

        let state = {
            let mut durable = self
                .durable
                .lock()
                .map_err(|_| anyhow::anyhow!("assurance agent-session state is unavailable"))?;
            let outcome = durable
                .journal
                .apply(
                    AgentSessionCommand::Cancel {
                        request_id: request.request_id,
                        idempotency_key: request.idempotency_key,
                    },
                    request.now_unix_ms,
                )
                .context("accepting assurance cancellation")?;
            persist_new_events(&self.history_path, &mut durable)?;
            if !matches!(
                outcome.state,
                AgentSessionState::Canceling | AgentSessionState::Canceled
            ) {
                anyhow::bail!("assurance session did not enter cancellation state");
            }
            outcome.state
        };

        if self.cancellation_path.exists() {
            let evidence = load_cancellation_evidence(&self.cancellation_path)?;
            verify_cancellation_evidence(&evidence, &self.expected_cancellation_identity)?;
            if state == AgentSessionState::Canceling {
                self.confirm_cancellation(request.now_unix_ms)?;
            }
            return Ok(CancelExecutionOutcome::DuplicateCanceled(evidence));
        }
        if state == AgentSessionState::Canceled {
            anyhow::bail!("canceled assurance session has no durable cancellation evidence");
        }

        let evidence = canceler
            .cancel(ExtensionCancellationExecution {
                vm: &self.vm,
                admitted: request.admitted,
                declaration: request.declaration,
            })
            .context("canceling assurance extension execution")?;
        verify_cancellation_evidence(&evidence, &self.expected_cancellation_identity)?;
        persist_cancellation_evidence(&self.cancellation_path, &evidence)?;
        self.confirm_cancellation(request.now_unix_ms)?;
        Ok(CancelExecutionOutcome::Canceled(evidence))
    }

    fn confirm_cancellation(&self, now_unix_ms: u64) -> Result<()> {
        let mut durable = self
            .durable
            .lock()
            .map_err(|_| anyhow::anyhow!("assurance agent-session state is unavailable"))?;
        if durable.journal.state() == AgentSessionState::Canceling {
            durable
                .journal
                .confirm_cancel(now_unix_ms)
                .context("confirming assurance cancellation")?;
            persist_new_events(&self.history_path, &mut durable)?;
        }
        Ok(())
    }

    /// Current durable state, primarily for controllers resuming after crash.
    #[must_use]
    pub fn state(&self) -> AgentSessionState {
        self.durable
            .lock()
            .map_or(AgentSessionState::Failed, |durable| durable.journal.state())
    }
}

fn verify_cancellation_evidence(
    evidence: &CancellationEvidence,
    expected: &CancellationBindingIdentity,
) -> Result<()> {
    if evidence.session_id != expected.session_id
        || evidence.campaign_id != expected.campaign_id
        || evidence.trial_id != expected.trial_id
        || evidence.source_digest != expected.source_digest
    {
        anyhow::bail!("cancellation evidence does not match the admitted prompt binding");
    }
    if !evidence.audit_ref.as_str().starts_with("mvm:audit:")
        || !evidence.receipt_ref.as_str().starts_with("mvm:receipt:")
    {
        anyhow::bail!("cancellation evidence does not contain typed audit and receipt references");
    }
    Ok(())
}

fn persist_cancellation_evidence(path: &Path, evidence: &CancellationEvidence) -> Result<()> {
    let mut encoded = serde_json::to_vec(evidence).context("encoding cancellation evidence")?;
    encoded.push(b'\n');
    if u64::try_from(encoded.len()).expect("usize fits in u64") > MAX_CANCELLATION_EVIDENCE_BYTES {
        anyhow::bail!("cancellation evidence exceeds its size limit");
    }
    write_atomic(path, &encoded).context("committing cancellation evidence")
}

fn load_cancellation_evidence(path: &Path) -> Result<CancellationEvidence> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading cancellation evidence metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("cancellation evidence must be a non-symlink file");
    }
    if metadata.len() > MAX_CANCELLATION_EVIDENCE_BYTES {
        anyhow::bail!("cancellation evidence exceeds its size limit");
    }
    let body = std::fs::read(path)
        .with_context(|| format!("reading cancellation evidence {}", path.display()))?;
    serde_json::from_slice(&body).context("parsing durable cancellation evidence")
}

fn persist_new_events(path: &Path, durable: &mut AdapterDurableState) -> Result<()> {
    let mut cursor = Some(AgentSessionCursor {
        session_id: durable.journal.session_id().clone(),
        durable_sequence: durable.persisted_sequence,
    });
    loop {
        let page = durable
            .journal
            .history(cursor, HISTORY_PAGE)
            .context("reading new assurance agent-session events")?;
        if page.events.is_empty() {
            return Ok(());
        }
        append_history(path, &page.events)?;
        durable.persisted_sequence = page.next_cursor.durable_sequence;
        if !page.has_more {
            return Ok(());
        }
        cursor = Some(page.next_cursor);
    }
}

fn digest_bytes(digest: &Sha256Digest) -> Result<[u8; 32]> {
    let raw = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("workload digest has no sha256 prefix"))?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(raw, &mut bytes).context("decoding workload digest")?;
    Ok(bytes)
}

fn verify_opening_identity(
    history: &[AgentSessionEventEnvelope],
    session_id: &AgentSessionId,
    workload_digest: [u8; 32],
) -> Result<()> {
    let Some(first) = history.first() else {
        anyhow::bail!("assurance agent-session history is empty");
    };
    if &first.session_id != session_id
        || !matches!(
            &first.event,
            AgentSessionEvent::Durable {
                event: DurableAgentSessionEvent::Opened {
                    workload_digest: recorded,
                }
            } if *recorded == workload_digest
        )
    {
        anyhow::bail!("assurance agent-session history identity does not match admission");
    }
    Ok(())
}

fn load_history(path: &Path) -> Result<Vec<AgentSessionEventEnvelope>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("reading agent-session metadata {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!("assurance agent-session history must be a non-symlink file");
    }
    if metadata.len() > MAX_DURABLE_HISTORY_BYTES {
        anyhow::bail!("assurance agent-session history exceeds its size limit");
    }
    let body = std::fs::read_to_string(path)
        .with_context(|| format!("reading agent-session history {}", path.display()))?;
    body.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str(line).context("parsing durable assurance agent-session event")
        })
        .collect()
}

fn prepare_session_directory(directory: &Path, vm: &str) -> Result<()> {
    if !directory.is_absolute() {
        anyhow::bail!("assurance agent-session state root must be an absolute path");
    }
    std::fs::create_dir_all(directory)
        .with_context(|| format!("creating assurance agent-session state for {vm}"))?;
    let metadata = std::fs::symlink_metadata(directory)
        .with_context(|| format!("inspecting assurance agent-session state for {vm}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("assurance agent-session state root must be a non-symlink directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting assurance agent-session state for {vm}"))?;
    }
    Ok(())
}

fn create_history(path: &Path, opened: &AgentSessionEventEnvelope) -> Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "creating assurance agent-session history {}",
            path.display()
        )
    })?;
    write_event(&mut file, opened)?;
    file.sync_all().context("committing opened agent session")
}

fn append_history(path: &Path, events: &[AgentSessionEventEnvelope]) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("opening assurance agent-session history {}", path.display()))?;
    for event in events {
        write_event(&mut file, event)?;
    }
    file.sync_all().context("committing agent-session events")
}

fn write_event(file: &mut std::fs::File, event: &AgentSessionEventEnvelope) -> Result<()> {
    serde_json::to_writer(&mut *file, event).context("encoding durable agent-session event")?;
    file.write_all(b"\n")
        .context("terminating durable agent-session event")
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Condvar, Mutex};

    use ed25519_dalek::SigningKey;
    use mvm_contract::assurance::{
        ApprovalSet, AssuranceId, AssuranceSessionRequest, AuthorityCeiling, AuthorityInputs,
        EffectiveAuthority, EvidenceRef, InconclusiveReason, MvmBinding, ObservationScope,
        RequestedAuthority, SessionGrant, ToolId, TrialOutcome, TrialVerdict,
    };
    use mvm_core::plan::ExecutionPlan;
    use mvm_core::plan::signing::sign_plan;
    use mvm_core::plan::test_support::PlanFixture;

    use super::*;

    #[test]
    fn explicit_session_state_rejects_relative_and_symlink_roots() {
        assert!(prepare_session_directory(Path::new("relative-state"), "vm-a").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let state = tempfile::tempdir().expect("state parent");
            let real = state.path().join("real");
            std::fs::create_dir(&real).expect("real state");
            let linked = state.path().join("linked");
            symlink(real, &linked).expect("state symlink");
            assert!(prepare_session_directory(&linked, "vm-a").is_err());
        }
    }
    use crate::assurance_session::DeclaredEdge;

    const ARTIFACT_DIGEST: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const POLICY_DIGEST: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const SOURCE_DIGEST: &str =
        "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    const GRANT_DIGEST: &str =
        "sha256:4444444444444444444444444444444444444444444444444444444444444444";

    fn id(raw: &str) -> AssuranceId {
        AssuranceId::parse(raw).expect("identifier")
    }

    fn digest(raw: &str) -> Sha256Digest {
        Sha256Digest::parse(raw).expect("digest")
    }

    fn request() -> AssuranceSessionRequest {
        AssuranceSessionRequest::parse_json(include_bytes!(
            "../../mvm-contract/fixtures/assurance-ai-session-request-v1.json"
        ))
        .expect("request fixture")
    }

    fn grant() -> SessionGrant {
        SessionGrant {
            grant_digest: digest(GRANT_DIGEST),
            expires_unix_ms: 2_000_000,
            nonce: id("grant-nonce"),
            allowed_tools: vec![ToolId::CampaignProbeV1],
            observation_scopes: vec![ObservationScope::HostAuditRefs],
            max_steps: 12,
            max_output_bytes: 65_536,
        }
    }

    fn authority() -> EffectiveAuthority {
        let requested = RequestedAuthority {
            allowed_tools: vec![ToolId::CampaignProbeV1],
            observation_scopes: vec![ObservationScope::HostAuditRefs],
            max_steps: 12,
            max_output_bytes: 65_536,
            deadline_unix_ms: 2_000_000,
        };
        let ceiling = AuthorityCeiling::extension_maximum();
        let approvals = ApprovalSet::none().with(ToolId::CampaignProbeV1);
        EffectiveAuthority::intersect(
            AuthorityInputs {
                extension_maximum: &ceiling,
                requested: &requested,
                policy_ceiling: &ceiling,
                grant: &grant(),
                approvals: &approvals,
            },
            1_000_000,
        )
        .expect("authority")
    }

    fn plan() -> ExecutionPlan {
        PlanFixture::new().build()
    }

    fn input(plan: &ExecutionPlan) -> AiSessionInput {
        let binding = MvmBinding::builder()
            .session_id(id("session-1"))
            .plan(plan)
            .expect("plan")
            .artifact_digest(digest(ARTIFACT_DIGEST))
            .effective_policy_digest(digest(POLICY_DIGEST))
            .grant(grant())
            .backend("firecracker")
            .audit_ref(EvidenceRef::parse("mvm:audit:opened").expect("ref"))
            .receipt_ref(EvidenceRef::parse("mvm:receipt:opened").expect("ref"))
            .build()
            .expect("binding");
        AiSessionInput::bind(request(), &binding, &authority()).expect("input")
    }

    fn admitted(plan: ExecutionPlan) -> AdmittedPlan {
        let signer = "host:test".to_string();
        let signed = sign_plan(&plan, &SigningKey::from_bytes(&[7u8; 32]), &signer);
        AdmittedPlan::for_test(plan, signer, signed)
    }

    fn declaration() -> CampaignDeclaration {
        CampaignDeclaration {
            request_id: id("mvm-request-1"),
            idempotency_key: id("trial-1"),
            campaign_id: id("mvm-campaign-1"),
            trial_id: id("trial-1"),
            source_run_id: id("scout-1"),
            source_digest: digest(SOURCE_DIGEST),
            artifact_digest: digest(ARTIFACT_DIGEST),
            edges: vec![DeclaredEdge {
                label: id("undeclared.synthetic.destination"),
                host: "synthetic.invalid".to_string(),
                port: 443,
            }],
            approvals: ApprovalSet::none().with(ToolId::CampaignProbeV1),
            requested: RequestedAuthority {
                allowed_tools: vec![ToolId::CampaignProbeV1],
                observation_scopes: vec![ObservationScope::HostAuditRefs],
                max_steps: 12,
                max_output_bytes: 65_536,
                deadline_unix_ms: 2_000_000,
            },
            grant_ttl_ms: 60_000,
        }
    }

    #[derive(Default)]
    struct FakeExecutor {
        calls: AtomicUsize,
    }

    impl AssuranceSessionExecutor for FakeExecutor {
        fn execute(&self, _request: ExtensionExecution<'_>) -> Result<AiSessionRun> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(AiSessionRun::RecoveredInterrupted {
                verdict: TrialVerdict {
                    outcome: TrialOutcome::Inconclusive,
                    reason: Some(InconclusiveReason::ExecutionInterrupted),
                },
                audit_ref: EvidenceRef::parse("mvm:audit:recovered").expect("ref"),
                receipt_ref: EvidenceRef::parse("mvm:receipt:recovered").expect("ref"),
            })
        }
    }

    #[test]
    fn durable_prompt_history_contains_only_the_digest_and_is_idempotent() {
        let state = tempfile::tempdir().expect("state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let plan = plan();
        let input = input(&plan);
        let admitted = admitted(plan);
        let declaration = declaration();
        let executor = FakeExecutor::default();
        let adapter =
            AssurancePromptAdapter::open("vm-adapter", &input, 1_000_000).expect("adapter");

        assert!(matches!(
            adapter
                .execute(
                    &executor,
                    PromptExecution {
                        admitted: &admitted,
                        declaration: &declaration,
                        input: &input,
                        now_unix_ms: 1_000_001,
                    }
                )
                .expect("prompt completes"),
            PromptExecutionOutcome::Completed(_)
        ));
        let history = std::fs::read_to_string(&adapter.history_path).expect("history");
        assert!(history.contains("prompt_digest"), "{history}");
        assert!(!history.contains("attempt the declared process effect"));
        assert!(!history.contains("synthetic.invalid"));

        assert!(matches!(
            adapter
                .execute(
                    &executor,
                    PromptExecution {
                        admitted: &admitted,
                        declaration: &declaration,
                        input: &input,
                        now_unix_ms: 1_000_002,
                    }
                )
                .expect("duplicate resolves"),
            PromptExecutionOutcome::DuplicateCompleted
        ));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_crash_after_prompt_commit_recovers_running_and_resumes_once() {
        let state = tempfile::tempdir().expect("state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let plan = plan();
        let input = input(&plan);
        let admitted = admitted(plan);
        let declaration = declaration();
        let prompt = input.to_json().expect("prompt").into_bytes();
        let first = AssurancePromptAdapter::open("vm-recover", &input, 1_000_000).expect("adapter");
        let mut durable = first.durable.lock().expect("durable state");
        durable
            .journal
            .apply(
                AgentSessionCommand::Prompt {
                    request_id: first.expected_request_id.clone(),
                    idempotency_key: first.expected_idempotency_key.clone(),
                    prompt,
                },
                1_000_001,
            )
            .expect("prompt accepted");
        persist_new_events(&first.history_path, &mut durable).expect("acceptance committed");
        drop(durable);
        drop(first);

        let executor = FakeExecutor::default();
        let recovered =
            AssurancePromptAdapter::open("vm-recover", &input, 1_000_002).expect("recovers");
        assert_eq!(recovered.state(), AgentSessionState::Running);
        assert!(matches!(
            recovered
                .execute(
                    &executor,
                    PromptExecution {
                        admitted: &admitted,
                        declaration: &declaration,
                        input: &input,
                        now_unix_ms: 1_000_003,
                    }
                )
                .expect("resume completes"),
            PromptExecutionOutcome::Completed(_)
        ));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
        assert_eq!(recovered.state(), AgentSessionState::Completed);
    }

    struct CancelHarness {
        started: Barrier,
        canceled: (Mutex<bool>, Condvar),
        cancel_calls: AtomicUsize,
    }

    impl CancelHarness {
        fn new() -> Self {
            Self {
                started: Barrier::new(2),
                canceled: (Mutex::new(false), Condvar::new()),
                cancel_calls: AtomicUsize::new(0),
            }
        }
    }

    impl AssuranceSessionExecutor for CancelHarness {
        fn execute(&self, _request: ExtensionExecution<'_>) -> Result<AiSessionRun> {
            self.started.wait();
            let (lock, ready) = &self.canceled;
            let mut canceled = lock.lock().expect("cancellation lock");
            while !*canceled {
                canceled = ready.wait(canceled).expect("cancellation wait");
            }
            Ok(AiSessionRun::RecoveredInterrupted {
                verdict: TrialVerdict {
                    outcome: TrialOutcome::Inconclusive,
                    reason: Some(InconclusiveReason::ExecutionInterrupted),
                },
                audit_ref: EvidenceRef::parse("mvm:audit:canceled").expect("audit ref"),
                receipt_ref: EvidenceRef::parse("mvm:receipt:canceled").expect("receipt ref"),
            })
        }
    }

    impl AssuranceSessionCanceler for CancelHarness {
        fn cancel(
            &self,
            _request: ExtensionCancellationExecution<'_>,
        ) -> Result<CancellationEvidence> {
            self.cancel_calls.fetch_add(1, Ordering::SeqCst);
            let (lock, ready) = &self.canceled;
            *lock.lock().expect("cancellation lock") = true;
            ready.notify_all();
            Ok(CancellationEvidence {
                session_id: id("session-1"),
                campaign_id: id("mvm-campaign-1"),
                trial_id: id("trial-1"),
                source_digest: digest(SOURCE_DIGEST),
                audit_ref: EvidenceRef::parse("mvm:audit:canceled").expect("audit ref"),
                receipt_ref: EvidenceRef::parse("mvm:receipt:canceled").expect("receipt ref"),
            })
        }
    }

    #[test]
    fn cancellation_before_dispatch_prevents_executor_entry() {
        let state = tempfile::tempdir().expect("state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let plan = plan();
        let input = input(&plan);
        let admitted = admitted(plan);
        let declaration = declaration();
        let adapter =
            AssurancePromptAdapter::open("vm-cancel-before", &input, 1_000_000).expect("adapter");
        let harness = CancelHarness::new();

        let canceled = adapter
            .cancel(
                &harness,
                CancelExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    request_id: AgentRequestId::parse("cancel-before").expect("cancel request"),
                    idempotency_key: IdempotencyKey::parse("cancel-before-key")
                        .expect("cancel key"),
                    now_unix_ms: 1_000_001,
                },
            )
            .expect("pre-dispatch cancel");
        assert!(matches!(canceled, CancelExecutionOutcome::Canceled(_)));
        assert_eq!(adapter.state(), AgentSessionState::Canceled);

        let executor = FakeExecutor::default();
        let error = adapter
            .execute(
                &executor,
                PromptExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    input: &input,
                    now_unix_ms: 1_000_002,
                },
            )
            .expect_err("canceled session must not dispatch");
        assert!(error.to_string().contains("accepting assurance prompt"));
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
        assert_eq!(harness.cancel_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn live_cancellation_is_durable_concurrent_and_idempotent() {
        let state = tempfile::tempdir().expect("state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let plan = plan();
        let input = input(&plan);
        let admitted = admitted(plan);
        let declaration = declaration();
        let adapter = Arc::new(
            AssurancePromptAdapter::open("vm-cancel", &input, 1_000_000).expect("adapter"),
        );
        let harness = Arc::new(CancelHarness::new());

        std::thread::scope(|scope| {
            let running_adapter = Arc::clone(&adapter);
            let running_harness = Arc::clone(&harness);
            let running_admitted = &admitted;
            let running_declaration = &declaration;
            let running_input = &input;
            let running = scope.spawn(move || {
                running_adapter.execute(
                    running_harness.as_ref(),
                    PromptExecution {
                        admitted: running_admitted,
                        declaration: running_declaration,
                        input: running_input,
                        now_unix_ms: 1_000_001,
                    },
                )
            });
            harness.started.wait();
            let canceled = adapter
                .cancel(
                    harness.as_ref(),
                    CancelExecution {
                        admitted: &admitted,
                        declaration: &declaration,
                        request_id: AgentRequestId::parse("cancel-1").expect("cancel request"),
                        idempotency_key: IdempotencyKey::parse("cancel-key-1").expect("cancel key"),
                        now_unix_ms: 1_000_002,
                    },
                )
                .expect("cancel");
            assert!(matches!(canceled, CancelExecutionOutcome::Canceled(_)));
            assert!(matches!(
                running.join().expect("running thread").expect("execution"),
                PromptExecutionOutcome::Completed(_)
            ));
        });

        assert_eq!(adapter.state(), AgentSessionState::Canceled);
        assert_eq!(harness.cancel_calls.load(Ordering::SeqCst), 1);
        let duplicate = adapter
            .cancel(
                harness.as_ref(),
                CancelExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    request_id: AgentRequestId::parse("cancel-1").expect("cancel request"),
                    idempotency_key: IdempotencyKey::parse("cancel-key-1").expect("cancel key"),
                    now_unix_ms: 1_000_003,
                },
            )
            .expect("duplicate cancel");
        let duplicate_evidence = match duplicate {
            CancelExecutionOutcome::DuplicateCanceled(evidence) => evidence,
            other => panic!("expected duplicate cancellation evidence, got {other:?}"),
        };
        assert_eq!(duplicate_evidence.session_id, id("session-1"));
        assert_eq!(
            duplicate_evidence.audit_ref,
            EvidenceRef::parse("mvm:audit:canceled").expect("audit ref")
        );
        assert_eq!(harness.cancel_calls.load(Ordering::SeqCst), 1);

        let history = std::fs::read_to_string(&adapter.history_path).expect("history");
        assert!(history.contains("cancel_requested"), "{history}");
        assert!(history.contains("canceled"), "{history}");
        assert!(!history.contains("attempt the declared process effect"));
    }

    #[test]
    fn canceling_crash_recovers_evidence_without_a_second_transport_call() {
        let state = tempfile::tempdir().expect("state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let plan = plan();
        let input = input(&plan);
        let admitted = admitted(plan);
        let declaration = declaration();
        let first =
            AssurancePromptAdapter::open("vm-cancel-recover", &input, 1_000_000).expect("adapter");
        {
            let mut durable = first.durable.lock().expect("durable state");
            durable
                .journal
                .apply(
                    AgentSessionCommand::Cancel {
                        request_id: AgentRequestId::parse("cancel-recover")
                            .expect("cancel request"),
                        idempotency_key: IdempotencyKey::parse("cancel-recover-key")
                            .expect("cancel key"),
                    },
                    1_000_001,
                )
                .expect("cancellation accepted");
            persist_new_events(&first.history_path, &mut durable)
                .expect("cancellation request committed");
        }
        drop(first);

        let harness = CancelHarness::new();
        let recovered = AssurancePromptAdapter::open("vm-cancel-recover", &input, 1_000_002)
            .expect("canceling adapter recovers");
        assert_eq!(recovered.state(), AgentSessionState::Canceling);
        let outcome = recovered
            .cancel(
                &harness,
                CancelExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    request_id: AgentRequestId::parse("cancel-recover").expect("cancel request"),
                    idempotency_key: IdempotencyKey::parse("cancel-recover-key")
                        .expect("cancel key"),
                    now_unix_ms: 1_000_003,
                },
            )
            .expect("cancel transport resumes");
        assert!(matches!(outcome, CancelExecutionOutcome::Canceled(_)));
        assert_eq!(recovered.state(), AgentSessionState::Canceled);
        assert_eq!(harness.cancel_calls.load(Ordering::SeqCst), 1);
        drop(recovered);

        let completed = AssurancePromptAdapter::open("vm-cancel-recover", &input, 1_000_004)
            .expect("canceled adapter recovers");
        let duplicate = completed
            .cancel(
                &harness,
                CancelExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    request_id: AgentRequestId::parse("cancel-recover").expect("cancel request"),
                    idempotency_key: IdempotencyKey::parse("cancel-recover-key")
                        .expect("cancel key"),
                    now_unix_ms: 1_000_005,
                },
            )
            .expect("completed cancellation replays evidence");
        assert!(matches!(
            duplicate,
            CancelExecutionOutcome::DuplicateCanceled(_)
        ));
        assert_eq!(harness.cancel_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn corrupted_cancellation_evidence_fails_closed_without_retransport() {
        let state = tempfile::tempdir().expect("state");
        let mut environment = mvm_core::util::test_env::TestEnv::new();
        environment.set("MVM_HOME", state.path());
        let plan = plan();
        let input = input(&plan);
        let admitted = admitted(plan);
        let declaration = declaration();
        let adapter =
            AssurancePromptAdapter::open("vm-cancel-corrupt", &input, 1_000_000).expect("adapter");
        let harness = CancelHarness::new();
        adapter
            .cancel(
                &harness,
                CancelExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    request_id: AgentRequestId::parse("cancel-corrupt").expect("cancel request"),
                    idempotency_key: IdempotencyKey::parse("cancel-corrupt-key")
                        .expect("cancel key"),
                    now_unix_ms: 1_000_001,
                },
            )
            .expect("initial cancel");
        std::fs::write(
            &adapter.cancellation_path,
            br#"{"session_id":"session-1","smuggled":"host-authority"}"#,
        )
        .expect("corrupt evidence marker");

        let error = adapter
            .cancel(
                &harness,
                CancelExecution {
                    admitted: &admitted,
                    declaration: &declaration,
                    request_id: AgentRequestId::parse("cancel-corrupt").expect("cancel request"),
                    idempotency_key: IdempotencyKey::parse("cancel-corrupt-key")
                        .expect("cancel key"),
                    now_unix_ms: 1_000_002,
                },
            )
            .expect_err("corrupt evidence must fail closed");
        assert!(error.to_string().contains("parsing durable"), "{error:#}");
        assert_eq!(harness.cancel_calls.load(Ordering::SeqCst), 1);
    }
}
