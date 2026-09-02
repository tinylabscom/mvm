// Pure checkpoint audit-binding helpers. The caller supplies the emitter, the
// admitted plan, and the checkpoint metadata; these extract the labels and
// emit. Error policy (best-effort vs fatal) belongs to the caller.

use anyhow::Result;
use chrono::Utc;
use mvm_contract::provenance::{
    ActorRef, AttestationBinding, DecisionActorRole, DecisionCategory, DecisionOutcome,
    DecisionRecord, DecisionRecordBuilder,
};
use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
use mvm_core::plan::ExecutionPlan;
use serde::Serialize;

use crate::audit::emitter::AuditEmitter;

/// Non-secret fork capability metadata recorded in `checkpoint.forked`.
/// Keystore addresses, providers, and values are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckpointForkSecretBinding {
    pub name: String,
    pub allowed_hosts: Vec<String>,
}

/// Stable on-the-wire string for a checkpoint class.
pub fn class_str(class: CheckpointClass) -> &'static str {
    match class {
        CheckpointClass::FsQuick => "fs_quick",
        CheckpointClass::VmFull => "vm_full",
    }
}

/// Emit `checkpoint.created` for a freshly captured checkpoint. The bound
/// content-address is the record's `meta_digest` — it covers the whole manifest
/// and the parent hash-link, not just the first blob's sha.
pub fn bind_checkpoint_created(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    meta: &CheckpointMeta,
) -> Result<()> {
    emitter.emit_checkpoint_created(
        plan,
        meta.id.as_str(),
        class_str(meta.class),
        meta.meta_digest.as_str(),
        &meta.vm_name,
    )?;

    if emitter.decisions_enabled() {
        let record = checkpoint_decision_record(plan, meta);
        let _ = emitter.emit_decision_record(plan, record);
    }
    Ok(())
}

fn checkpoint_decision_record(plan: &ExecutionPlan, meta: &CheckpointMeta) -> DecisionRecord {
    DecisionRecordBuilder::new()
        .version(1)
        .category(DecisionCategory::Checkpoint)
        .actor(ActorRef {
            principal: crate::audit::host_keypair::host_signer_id(),
            key_id: crate::audit::host_keypair::host_signer_id(),
            key_role: Some(DecisionActorRole::Orchestrator),
        })
        .scenario(mvm_contract::provenance::DecisionScenario {
            plan_id: Some(plan.plan_id.0.clone()),
            ..Default::default()
        })
        .reasoning(format!(
            "checkpoint {} captured (class: {})",
            meta.id.as_str(),
            class_str(meta.class)
        ))
        .outcome(DecisionOutcome::Approved)
        .timestamp(Utc::now().to_rfc3339())
        .attestation(AttestationBinding {
            plan_id: Some(plan.plan_id.0.clone()),
            ..AttestationBinding::default()
        })
        .build()
        .expect("checkpoint decision record is well-formed")
}

/// Emit `checkpoint.restored` binding a restore to the plan it launched under.
/// `restored_vm_name` is the identity that came up carrying the checkpoint's
/// state (the fresh re-admitted VM for a time-travel restore), and `via` records
/// how the restore was initiated (`revert` / `rewind` / `advance`).
pub fn bind_checkpoint_restored(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    meta: &CheckpointMeta,
    restored_vm_name: &str,
    via: &str,
) -> Result<()> {
    emitter.emit_checkpoint_restored(
        plan,
        meta.id.as_str(),
        meta.meta_digest.as_str(),
        restored_vm_name,
        via,
    )
}

/// Emit `checkpoint.forked` recording the parent→child lineage. The bound
/// `parent_digest` is the child's own hash-link (`child.parent`), so the
/// audited lineage is the content-address chain the fork actually recorded.
pub fn bind_checkpoint_forked(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    parent: &CheckpointId,
    child: &CheckpointMeta,
    child_vm_name: &str,
    secret_bindings: &[CheckpointForkSecretBinding],
) -> Result<()> {
    // A forked child is built by the fork path, which always hash-links it to
    // its parent's content-address. A genesis-shaped child (no parent) must not
    // silently chain-sign an empty parent_digest — fail loud instead.
    let parent_digest = child
        .parent
        .as_ref()
        .expect("a forked child always carries a parent hash-link");
    let secret_bindings_json = serde_json::to_string(secret_bindings)?;
    emitter.emit_checkpoint_forked(
        plan,
        crate::audit::emitter::CheckpointForkedAudit {
            parent_id: parent.as_str(),
            child_id: child.id.as_str(),
            child_vm_name,
            parent_digest: parent_digest.as_str(),
            child_digest: child.meta_digest.as_str(),
            secret_bindings_json: &secret_bindings_json,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::emitter::AuditEmitter;
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};
    use rand::Rng;

    fn fixture_plan(tenant: &str, plan_id: &str) -> mvm_core::plan::ExecutionPlan {
        mvm_core::plan::test_support::PlanFixture::new()
            .tenant(tenant)
            .plan_id(plan_id)
            .build()
    }

    fn vm_full_meta(id: &str, vm: &str) -> CheckpointMeta {
        CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::VmFull, vm)
            .content(vec![ContentBlob {
                name: "rootfs.ext4".into(),
                sha256: "abcd".into(),
            }])
            .supervisor_config_digest("d")
            .created_unix(1)
            .build()
    }

    #[test]
    fn bind_created_emits_a_verifiable_entry() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-B");
        let meta = vm_full_meta("ckpt-1", "myvm");
        bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("vm_full")); // class derived from meta
        assert!(content.contains("meta_digest"));
        // The record's content-address, sourced from meta.meta_digest.
        assert!(content.contains(meta.meta_digest.as_str()));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn class_str_maps_both_variants() {
        assert_eq!(class_str(CheckpointClass::FsQuick), "fs_quick");
        assert_eq!(class_str(CheckpointClass::VmFull), "vm_full");
    }

    #[test]
    fn bind_restored_binds_the_restored_vm_and_via() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-RV");
        // The target checkpoint is captured on `origin`; the restore comes up as
        // a fresh identity `restored-child`, which the bound entry must name.
        let target = vm_full_meta("ckpt-target", "origin");

        bind_checkpoint_restored(&emitter, &plan, &target, "restored-child", "rewind").unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.restored"));
        assert!(content.contains("ckpt-target"));
        assert!(content.contains(target.meta_digest.as_str()));
        // The restored VM name is the fresh identity, not the origin.
        assert!(content.contains("restored-child"));
        assert!(content.contains("rewind"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn bind_forked_emits_parent_and_child_content_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let key = {
            let mut __ed_seed = [0u8; 32];
            rand::rng().fill_bytes(&mut __ed_seed);
            SigningKey::from_bytes(&__ed_seed)
        };
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-F");

        // A real parent + a child hash-linked to the parent's content-address.
        let parent = CheckpointMeta::builder(
            CheckpointId::new("ckpt-parent"),
            CheckpointClass::FsQuick,
            "parentvm",
        )
        .content(vec![ContentBlob {
            name: "rootfs.ext4".into(),
            sha256: "aa".into(),
        }])
        .supervisor_config_digest("d")
        .created_unix(1)
        .build();
        let child = CheckpointMeta::builder(
            CheckpointId::new("ckpt-child"),
            CheckpointClass::FsQuick,
            "childvm",
        )
        .parent(Some(parent.meta_digest.clone()))
        .content(parent.content.clone())
        .supervisor_config_digest("d")
        .created_unix(2)
        .build();

        bind_checkpoint_forked(
            &emitter,
            &plan,
            &parent.id,
            &child,
            &child.vm_name,
            &[CheckpointForkSecretBinding {
                name: "API_KEY".into(),
                allowed_hosts: vec!["api.example.com".into()],
            }],
        )
        .unwrap();

        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        // The emitted parent_digest is the child's own hash-link; child_digest
        // is the child's content-address.
        assert!(content.contains("parent_digest"));
        assert!(content.contains("child_digest"));
        assert!(content.contains(parent.meta_digest.as_str()));
        assert!(content.contains(child.meta_digest.as_str()));
        assert!(content.contains("API_KEY"));
        assert!(content.contains("api.example.com"));
        assert!(!content.contains("keystore-address"));
        assert!(!content.contains("secret-value"));
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }
}
