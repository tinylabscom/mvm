//! Chain-signed records for reviewed workspace mutations.

use super::AuditEmitter;
use anyhow::Result;
use mvm_core::plan::ExecutionPlan;

/// Wire-stable event and label names for reviewed workspace mutations.
pub mod workspace_audit {
    pub const APPLIED_EVENT: &str = "workspace.applied";
    pub const UNDONE_EVENT: &str = "workspace.undone";
    pub const REDONE_EVENT: &str = "workspace.redone";
    pub const LABEL_VM_NAME: &str = "vm_name";
    pub const LABEL_VOLUME: &str = "volume";
    pub const LABEL_APPLY_ID: &str = "apply_id";
    pub const LABEL_TARGET_ID: &str = "target_id";
    pub const LABEL_MERKLE_ROOT: &str = "merkle_root";
}

/// One committed workspace mutation to bind into the host-signed chain.
pub struct WorkspaceMutationAudit<'a> {
    pub event: &'static str,
    pub vm_name: &'a str,
    pub volume: &'a str,
    pub apply_id: &'a str,
    pub target_id: Option<&'a str>,
    pub merkle_root: &'a str,
}

impl AuditEmitter {
    /// Bind one reviewed workspace mutation and its committed manifest root
    /// into the host-signed audit chain. The host-tree bytes remain in the
    /// content-addressed apply store; the chain carries only identities and
    /// the root needed to verify them.
    pub fn emit_workspace_mutation(
        &self,
        plan: &ExecutionPlan,
        audit: WorkspaceMutationAudit<'_>,
    ) -> Result<()> {
        use workspace_audit as k;
        let mut labels = vec![
            (k::LABEL_VM_NAME.to_string(), audit.vm_name.to_string()),
            (k::LABEL_VOLUME.to_string(), audit.volume.to_string()),
            (k::LABEL_APPLY_ID.to_string(), audit.apply_id.to_string()),
            (
                k::LABEL_MERKLE_ROOT.to_string(),
                audit.merkle_root.to_string(),
            ),
        ];
        if let Some(target) = audit.target_id {
            labels.push((k::LABEL_TARGET_ID.to_string(), target.to_string()));
        }
        self.emit(plan, audit.event, labels)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use rand::Rng;

    #[test]
    fn workspace_mutation_records_committed_merkle_root() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut seed = [0u8; 32];
            rand::rng().fill_bytes(&mut seed);
            SigningKey::from_bytes(&seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-workspace")
            .build();
        let root = "a".repeat(64);
        emitter
            .emit_workspace_mutation(
                &plan,
                WorkspaceMutationAudit {
                    event: workspace_audit::UNDONE_EVENT,
                    vm_name: "agent-vm",
                    volume: "source",
                    apply_id: "undo-2",
                    target_id: Some("apply-1"),
                    merkle_root: &root,
                },
            )
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(workspace_audit::UNDONE_EVENT));
        assert!(content.contains("undo-2"));
        assert!(content.contains("apply-1"));
        assert!(content.contains(&root));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }
}
