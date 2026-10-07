//! Chain-signed records for prompts delivered to a guest's resident agent.
//!
//! A prompt is the most sensitive input an agent session carries, so these
//! entries name it only by content digest and size. Who was prompted, where in
//! the session's journal, and which encrypted replay artifact holds the bytes
//! is the decision worth signing; the prompt and the answer stay out of the
//! chain. A refusal is recorded as the existing `verb_denied` entry, the same
//! one every other grant refusal produces.

use super::AuditEmitter;
use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

/// Emitted once a prompt is accepted into the session journal and recorded,
/// before it is sent to the guest.
pub const DELIVERED_EVENT: &str = "agent.prompt_delivered";
/// Emitted when the guest has answered, or the delivery failed.
pub const COMPLETED_EVENT: &str = "agent.prompt_completed";
/// Label: the machine whose agent was prompted.
pub const LABEL_VM_NAME: &str = "vm_name";
/// Label: the agent session the prompt belongs to.
pub const LABEL_SESSION_ID: &str = "agent_session_id";
/// Label: the session generation.
pub const LABEL_GENERATION: &str = "agent_session_generation";
/// Label: the journal cursor the prompt was accepted at.
pub const LABEL_JOURNAL_CURSOR: &str = "journal_cursor";
/// Label: `sha256:<hex>` of the prompt bytes.
pub const LABEL_PROMPT_SHA256: &str = "prompt_sha256";
/// Label: the prompt's length in bytes.
pub const LABEL_PROMPT_BYTES: &str = "prompt_bytes";
/// Label: content address of the encrypted replay artifact.
pub const LABEL_REPLAY_INPUT: &str = "replay_input_digest";
/// Label: `live` for an operator prompt, `replay` for a re-delivery.
pub const LABEL_DELIVERY: &str = "delivery";
/// Label: how the delivery ended, a closed vocabulary.
pub const LABEL_OUTCOME: &str = "outcome";

/// Whether a prompt was sent by a caller or re-sent from a recorded step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptDelivery {
    Live,
    Replay,
}

impl PromptDelivery {
    fn label(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Replay => "replay",
        }
    }
}

/// Where one prompt sits: the machine, its session, and its journal position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptAuditBinding {
    pub vm_name: String,
    pub session_id: String,
    pub generation: u64,
    pub journal_cursor: u64,
    pub delivery: PromptDelivery,
}

impl PromptAuditBinding {
    fn labels(&self) -> [(String, String); 5] {
        [
            (LABEL_VM_NAME.to_string(), self.vm_name.clone()),
            (LABEL_SESSION_ID.to_string(), self.session_id.clone()),
            (LABEL_GENERATION.to_string(), self.generation.to_string()),
            (
                LABEL_JOURNAL_CURSOR.to_string(),
                self.journal_cursor.to_string(),
            ),
            (
                LABEL_DELIVERY.to_string(),
                self.delivery.label().to_string(),
            ),
        ]
    }
}

/// The prompt as the chain may see it: its digest and size, never its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptFingerprint {
    /// `sha256:<hex>` of the prompt.
    pub sha256: String,
    /// Length of the prompt in bytes.
    pub bytes: usize,
    /// Content address of the encrypted replay artifact holding the prompt.
    pub replay_input_digest: String,
}

impl PromptFingerprint {
    /// Fingerprint `prompt`, naming the artifact it was recorded under.
    #[must_use]
    pub fn of(prompt: &[u8], replay_input_digest: &str) -> Self {
        use sha2::Digest as _;
        Self {
            sha256: format!("sha256:{}", hex::encode(sha2::Sha256::digest(prompt))),
            bytes: prompt.len(),
            replay_input_digest: replay_input_digest.to_string(),
        }
    }
}

impl AuditEmitter {
    /// Record that a prompt is about to reach the guest. Callers send the
    /// prompt only after this returns `Ok`: a prompt the chain does not hold
    /// is a prompt that was not delivered.
    pub fn emit_agent_prompt_delivered(
        &self,
        plan: &ExecutionPlan,
        binding: &PromptAuditBinding,
        prompt: &PromptFingerprint,
    ) -> Result<()> {
        let mut labels = binding.labels().to_vec();
        labels.extend([
            (LABEL_PROMPT_SHA256.to_string(), prompt.sha256.clone()),
            (LABEL_PROMPT_BYTES.to_string(), prompt.bytes.to_string()),
            (
                LABEL_REPLAY_INPUT.to_string(),
                prompt.replay_input_digest.clone(),
            ),
        ]);
        self.emit(plan, DELIVERED_EVENT, labels)
    }

    /// Record how a delivered prompt ended. `outcome` is a closed-vocabulary
    /// label such as `exited:0` or `failed:timeout`, never agent output.
    pub fn emit_agent_prompt_completed(
        &self,
        plan: &ExecutionPlan,
        binding: &PromptAuditBinding,
        outcome: &str,
    ) -> Result<()> {
        let mut labels = binding.labels().to_vec();
        labels.push((LABEL_OUTCOME.to_string(), outcome.to_string()));
        self.emit(plan, COMPLETED_EVENT, labels)
    }
}
