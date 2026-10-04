//! Chain-signed records for reviewed workspace mutations.

use super::AuditEmitter;
use anyhow::{Context, Result, bail};
use mvm_core::plan::ExecutionPlan;

/// Wire-stable event and label names for reviewed workspace mutations.
pub mod workspace_audit {
    pub const SNAPSHOT_EVENT: &str = "workspace.snapshot";
    pub const APPLIED_EVENT: &str = "workspace.applied";
    pub const UNDONE_EVENT: &str = "workspace.undone";
    pub const REDONE_EVENT: &str = "workspace.redone";
    pub const LABEL_VM_NAME: &str = "vm_name";
    pub const LABEL_VOLUME: &str = "volume";
    pub const LABEL_APPLY_ID: &str = "apply_id";
    pub const LABEL_TARGET_ID: &str = "target_id";
    pub const LABEL_MERKLE_ROOT: &str = "merkle_root";
    pub const LABEL_MANIFEST_ROOT: &str = "manifest_root";
}

/// A staged host pre-image snapshot, captured before an apply can write to
/// the host tree. The manifest root links it to the later apply entry.
pub struct WorkspaceSnapshotAudit<'a> {
    pub vm_name: &'a str,
    pub volume: &'a str,
    pub apply_id: &'a str,
    pub snapshot_root: &'a str,
    pub manifest_root: &'a str,
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
    /// Record the durable pre-image snapshot before the host tree is changed.
    pub fn emit_workspace_snapshot(
        &self,
        plan: &ExecutionPlan,
        audit: WorkspaceSnapshotAudit<'_>,
    ) -> Result<()> {
        let mut labels = workspace_labels(
            audit.vm_name,
            audit.volume,
            audit.apply_id,
            audit.snapshot_root,
        );
        labels.push((
            workspace_audit::LABEL_MANIFEST_ROOT.to_string(),
            audit.manifest_root.to_string(),
        ));
        self.emit(plan, workspace_audit::SNAPSHOT_EVENT, labels)
    }

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
        let mut labels = workspace_labels(
            audit.vm_name,
            audit.volume,
            audit.apply_id,
            audit.merkle_root,
        );
        if let Some(target) = audit.target_id {
            labels.push((k::LABEL_TARGET_ID.to_string(), target.to_string()));
        }
        self.emit(plan, audit.event, labels)
    }

    /// Check the entire authenticated local chain for this exact mutation,
    /// then sync the containing segment and directory before treating it as
    /// durable. Recovery cannot trust a visible but unsynced JSON match.
    pub fn workspace_mutation_recorded(&self, audit: WorkspaceMutationAudit<'_>) -> Result<bool> {
        let segments = crate::supervisor::audit_set::read_verified_set(
            self.audit_dir(),
            "local",
            &self.verifying_key(),
        )
        .context("verifying the signed workspace audit chain")?;
        for segment in segments {
            for entry in segment.entries.unwrap_or_default() {
                if entry.event != audit.event
                    || entry
                        .labels
                        .get(workspace_audit::LABEL_APPLY_ID)
                        .map(String::as_str)
                        != Some(audit.apply_id)
                {
                    continue;
                }
                let labels = &entry.labels;
                if labels
                    .get(workspace_audit::LABEL_VM_NAME)
                    .map(String::as_str)
                    == Some(audit.vm_name)
                    && labels
                        .get(workspace_audit::LABEL_VOLUME)
                        .map(String::as_str)
                        == Some(audit.volume)
                    && labels
                        .get(workspace_audit::LABEL_MERKLE_ROOT)
                        .map(String::as_str)
                        == Some(audit.merkle_root)
                    && labels
                        .get(workspace_audit::LABEL_TARGET_ID)
                        .map(String::as_str)
                        == audit.target_id
                {
                    std::fs::File::open(&segment.path)
                        .with_context(|| {
                            format!("opening audit segment {}", segment.path.display())
                        })?
                        .sync_all()
                        .with_context(|| {
                            format!("syncing audit segment {}", segment.path.display())
                        })?;
                    std::fs::File::open(self.audit_dir())
                        .context("opening the audit directory for sync")?
                        .sync_all()
                        .context("syncing the audit directory")?;
                    return Ok(true);
                }
                bail!(
                    "signed workspace mutation labels disagree for apply {}",
                    audit.apply_id
                );
            }
        }
        Ok(false)
    }
}

fn workspace_labels(
    vm_name: &str,
    volume: &str,
    apply_id: &str,
    merkle_root: &str,
) -> Vec<(String, String)> {
    use workspace_audit as k;
    vec![
        (k::LABEL_VM_NAME.to_string(), vm_name.to_string()),
        (k::LABEL_VOLUME.to_string(), volume.to_string()),
        (k::LABEL_APPLY_ID.to_string(), apply_id.to_string()),
        (k::LABEL_MERKLE_ROOT.to_string(), merkle_root.to_string()),
    ]
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

    #[test]
    fn workspace_snapshot_is_signed_before_the_apply_and_detects_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let verifier = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("plan-snapshot")
            .build();
        let snapshot_root = "a".repeat(64);
        let manifest_root = "b".repeat(64);
        emitter
            .emit_workspace_snapshot(
                &plan,
                WorkspaceSnapshotAudit {
                    vm_name: "agent-vm",
                    volume: "source",
                    apply_id: "apply-1",
                    snapshot_root: &snapshot_root,
                    manifest_root: &manifest_root,
                },
            )
            .unwrap();
        emitter
            .emit_workspace_mutation(
                &plan,
                WorkspaceMutationAudit {
                    event: workspace_audit::APPLIED_EVENT,
                    vm_name: "agent-vm",
                    volume: "source",
                    apply_id: "apply-1",
                    target_id: None,
                    merkle_root: &manifest_root,
                },
            )
            .unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains(workspace_audit::SNAPSHOT_EVENT));
        assert!(lines[0].contains(&snapshot_root));
        assert!(lines[0].contains(&manifest_root));
        assert!(lines[1].contains(workspace_audit::APPLIED_EVENT));
        assert_eq!(verify_audit_chain(&path, &verifier).unwrap(), 2);

        std::fs::write(&path, content.replacen(&snapshot_root, &"c".repeat(64), 1)).unwrap();
        assert!(verify_audit_chain(&path, &verifier).is_err());
    }

    #[test]
    fn recovery_uses_only_a_matching_verified_workspace_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let mut seed = [0u8; 32];
        rand::rng().fill_bytes(&mut seed);
        let emitter = AuditEmitter::with_dir(SigningKey::from_bytes(&seed), dir.path()).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .plan_id("workspace-recovery")
            .build();
        let root = "a".repeat(64);
        let expected = || WorkspaceMutationAudit {
            event: workspace_audit::APPLIED_EVENT,
            vm_name: "agent-vm",
            volume: "source",
            apply_id: "apply-1",
            target_id: None,
            merkle_root: &root,
        };
        emitter
            .emit_workspace_snapshot(
                &plan,
                WorkspaceSnapshotAudit {
                    vm_name: "agent-vm",
                    volume: "source",
                    apply_id: "apply-1",
                    snapshot_root: &root,
                    manifest_root: &root,
                },
            )
            .unwrap();
        assert!(!emitter.workspace_mutation_recorded(expected()).unwrap());
        emitter.emit_workspace_mutation(&plan, expected()).unwrap();
        assert!(emitter.workspace_mutation_recorded(expected()).unwrap());
        assert!(
            emitter
                .workspace_mutation_recorded(WorkspaceMutationAudit {
                    apply_id: "another-apply",
                    ..expected()
                })
                .is_ok_and(|recorded| !recorded)
        );
        assert!(
            emitter
                .workspace_mutation_recorded(WorkspaceMutationAudit {
                    merkle_root: "wrong-root",
                    ..expected()
                })
                .is_err()
        );
        let wrong_key = SigningKey::from_bytes(&[8u8; 32]);
        assert!(
            crate::supervisor::audit_set::verify_segment_entries(
                dir.path(),
                "local",
                &wrong_key.verifying_key()
            )
            .is_err()
        );

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, content.replacen(&root, &"b".repeat(64), 1)).unwrap();
        assert!(emitter.workspace_mutation_recorded(expected()).is_err());
    }
}
