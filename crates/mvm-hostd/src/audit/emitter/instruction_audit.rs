//! Chain-signed records of instruction-file provenance verdicts.
//!
//! Before a boot, every agent instruction file the boot copies into the guest
//! is verified against the operator's trust policy. Each verdict is recorded
//! here, bound to the plan the boot was admitted under, whether the policy
//! then refuses the boot, warns, or only records. The labels name the file,
//! its digest and the verdict — never the file's content.

use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

use super::AuditEmitter;

/// The verdict an instruction-file record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionTrustEvent {
    /// Signed by a publisher the policy trusts.
    Verified,
    /// No signature beside the file.
    Unsigned,
    /// Refused for a named reason: a blocked digest, a signature from an
    /// untrusted publisher, a signature that does not verify, or a file that
    /// could not be read. Whether the boot was actually stopped is the
    /// record's `action` label, which follows the enforcement mode.
    Blocked,
}

impl InstructionTrustEvent {
    /// The chain event name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            InstructionTrustEvent::Verified => "trust.instruction_verified",
            InstructionTrustEvent::Unsigned => "trust.instruction_unsigned",
            InstructionTrustEvent::Blocked => "trust.instruction_blocked",
        }
    }
}

impl AuditEmitter {
    /// Emit one instruction-file verdict under `plan`.
    pub fn emit_instruction_trust(
        &self,
        plan: &ExecutionPlan,
        event: InstructionTrustEvent,
        labels: Vec<(String, String)>,
    ) -> Result<()> {
        self.emit(plan, event.as_str(), labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::emitter::AuditEmitter;
    use ed25519_dalek::SigningKey;

    #[test]
    fn event_names_are_the_documented_wire_names() {
        assert_eq!(
            InstructionTrustEvent::Verified.as_str(),
            "trust.instruction_verified"
        );
        assert_eq!(
            InstructionTrustEvent::Unsigned.as_str(),
            "trust.instruction_unsigned"
        );
        assert_eq!(
            InstructionTrustEvent::Blocked.as_str(),
            "trust.instruction_blocked"
        );
    }

    #[test]
    fn a_verdict_is_appended_to_the_tenant_chain_with_its_labels() {
        let dir = tempfile::tempdir().unwrap();
        let emitter = AuditEmitter::with_dir(SigningKey::from_bytes(&[5; 32]), dir.path()).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-instruction-emit")
            .build();
        emitter
            .emit_instruction_trust(
                &plan,
                InstructionTrustEvent::Blocked,
                vec![
                    ("path".to_string(), "/w/CLAUDE.md".to_string()),
                    ("reason".to_string(), "bad_signature".to_string()),
                ],
            )
            .unwrap();
        let chain = std::fs::read_to_string(dir.path().join("local.jsonl")).unwrap();
        let line = chain.lines().last().expect("one entry");
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(entry["entry"]["event"], "trust.instruction_blocked");
        assert_eq!(entry["entry"]["labels"]["path"], "/w/CLAUDE.md");
        assert_eq!(entry["entry"]["labels"]["reason"], "bad_signature");
    }
}
