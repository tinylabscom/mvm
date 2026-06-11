// Pure checkpoint audit-binding helpers. The caller supplies the emitter, the
// admitted plan, and the checkpoint metadata; these extract the labels and
// emit. Error policy (best-effort vs fatal) belongs to the caller.

use anyhow::Result;
use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
use mvm_core::plan::ExecutionPlan;

use crate::audit::emitter::AuditEmitter;

/// Stable on-the-wire string for a checkpoint class.
pub fn class_str(class: CheckpointClass) -> &'static str {
    match class {
        CheckpointClass::FsQuick => "fs_quick",
        CheckpointClass::VmFull => "vm_full",
    }
}

/// Emit `checkpoint.created` for a freshly captured checkpoint.
pub fn bind_checkpoint_created(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    meta: &CheckpointMeta,
) -> Result<()> {
    let content_sha = meta
        .content
        .first()
        .map(|b| b.sha256.as_str())
        .unwrap_or("");
    emitter.emit_checkpoint_created(
        plan,
        meta.id.as_str(),
        class_str(meta.class),
        content_sha,
        &meta.vm_name,
    )
}

/// Emit `checkpoint.restored` for a same-identity resume.
pub fn bind_checkpoint_restored(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    meta: &CheckpointMeta,
) -> Result<()> {
    emitter.emit_checkpoint_restored(plan, meta.id.as_str(), &meta.vm_name)
}

/// Emit `checkpoint.forked` recording the parent→child lineage.
pub fn bind_checkpoint_forked(
    emitter: &AuditEmitter,
    plan: &ExecutionPlan,
    parent: &CheckpointId,
    child: &CheckpointMeta,
    child_vm_name: &str,
) -> Result<()> {
    emitter.emit_checkpoint_forked(plan, parent.as_str(), child.id.as_str(), child_vm_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::emitter::AuditEmitter;
    use crate::supervisor::verify_audit_chain;
    use ed25519_dalek::SigningKey;
    use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta, ContentBlob};
    use mvm_core::plan::{
        AdmissionProfile, ArtifactPolicy, AttestationMode, AttestationRequirement, FsPolicyRef,
        KeyRotationSpec, Nonce, PlanId, PlanSeccompTier, PolicyRef, PostRunLifecycle, Resources,
        RuntimeProfileRef, SCHEMA_VERSION, SignedImageRef, TenantId, TimeoutSpec, WorkloadId,
    };
    use rand::rngs::OsRng;
    use std::collections::BTreeMap;

    fn fixture_plan(tenant: &str, plan_id: &str) -> mvm_core::plan::ExecutionPlan {
        let now = chrono::Utc::now();
        mvm_core::plan::ExecutionPlan {
            schema_version: SCHEMA_VERSION,
            plan_id: PlanId(plan_id.to_string()),
            plan_version: 1,
            tenant: TenantId(tenant.to_string()),
            workload: WorkloadId("vm-test".to_string()),
            runtime_profile: RuntimeProfileRef("firecracker".to_string()),
            image: SignedImageRef {
                name: "vm-test".to_string(),
                sha256: "a".repeat(64),
                cosign_bundle: None,
                entrypoint_present: true,
            },
            resources: Resources {
                cpus: 1,
                mem_mib: 128,
                disk_mib: 0,
                timeouts: TimeoutSpec {
                    boot_secs: 30,
                    exec_secs: 0,
                },
            },
            admission_profile: AdmissionProfile::local_default(
                "vm:boot",
                PlanSeccompTier::Standard,
            ),
            network_policy: PolicyRef("local-default".to_string()),
            fs_policy: FsPolicyRef("local-default".to_string()),
            secrets: Vec::new(),
            egress_policy: PolicyRef("local-default".to_string()),
            tool_policy: PolicyRef("local-default".to_string()),
            artifact_policy: ArtifactPolicy {
                capture_paths: Vec::new(),
                retention_days: 0,
            },
            audit_labels: BTreeMap::new(),
            key_rotation: KeyRotationSpec { interval_days: 0 },
            attestation: AttestationRequirement {
                mode: AttestationMode::Noop,
            },
            release_pin: None,
            post_run: PostRunLifecycle {
                destroy_on_exit: true,
                snapshot_on_idle: false,
                idle_secs: 0,
            },
            valid_from: now,
            valid_until: now + chrono::Duration::minutes(10),
            nonce: Nonce::from_bytes([0u8; 16]),
            bundle: None,
            deps_volume: None,
            shares: Vec::new(),
        }
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
        let key = SigningKey::generate(&mut OsRng);
        let vk = key.verifying_key();
        let emitter = AuditEmitter::with_dir(key, dir.path()).unwrap();
        let plan = fixture_plan("local", "plan-B");
        let meta = vm_full_meta("ckpt-1", "myvm");
        bind_checkpoint_created(&emitter, &plan, &meta).unwrap();
        let path = dir.path().join("local.jsonl");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("checkpoint.created"));
        assert!(content.contains("vm_full")); // class derived from meta
        assert!(content.contains("abcd")); // content hash from meta.content.first()
        assert_eq!(verify_audit_chain(&path, &vk).unwrap(), 1);
    }

    #[test]
    fn class_str_maps_both_variants() {
        assert_eq!(class_str(CheckpointClass::FsQuick), "fs_quick");
        assert_eq!(class_str(CheckpointClass::VmFull), "vm_full");
    }
}
