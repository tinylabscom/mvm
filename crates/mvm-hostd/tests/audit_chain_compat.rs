//! The legacy supervisor paths and audit-owned paths name one chain implementation.

use std::any::TypeId;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use mvm_hostd::{audit, supervisor};

#[test]
fn legacy_modules_and_flattened_exports_keep_concrete_identities() {
    assert_eq!(
        TypeId::of::<audit::audit_file::FileAuditSigner>(),
        TypeId::of::<supervisor::FileAuditSigner>()
    );
    assert_eq!(
        TypeId::of::<audit::audit_recorder::Recorder>(),
        TypeId::of::<supervisor::audit::audit_recorder::Recorder>()
    );
    assert_eq!(
        TypeId::of::<audit::bound_sink::BoundRecorder>(),
        TypeId::of::<supervisor::audit::bound_sink::BoundRecorder>()
    );
    assert_eq!(
        TypeId::of::<audit::audit_dedup::RetryStormSuppressor>(),
        TypeId::of::<supervisor::RetryStormSuppressor>()
    );
    assert_eq!(
        TypeId::of::<audit::transcript_sink::TranscriptCaptureSink>(),
        TypeId::of::<supervisor::audit::transcript_sink::TranscriptCaptureSink>()
    );
    let _: fn(&std::path::Path) -> std::path::PathBuf =
        supervisor::audit::audit_checkpoint::checkpoint_path;
    let _: fn(&audit::signer::PlanAuditEntry) = supervisor::audit::audit_mirror::emit_mirror_event;
}

#[tokio::test]
async fn both_paths_append_and_verify_the_same_chain() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("compat.jsonl");
    let key = SigningKey::from_bytes(&[7; 32]);
    let vk = key.verifying_key();
    let old: Arc<dyn supervisor::audit::signer::AuditSigner> = Arc::new(
        supervisor::audit::audit_file::FileAuditSigner::open_file(key.clone(), &path).unwrap(),
    );
    let new: Arc<dyn audit::signer::AuditSigner> =
        Arc::new(audit::audit_file::FileAuditSigner::open_file(key, &path).unwrap());
    // Trait objects cross the namespace without an adapter or a second implementation.
    let old_as_new: Arc<dyn audit::signer::AuditSigner> = old;
    let new_as_old: Arc<dyn supervisor::AuditSigner> = new;
    let plan = mvm_core::plan::test_support::PlanFixture::new().build();
    let first: audit::signer::PlanAuditEntry =
        supervisor::for_plan(&plan, None, "plan.admitted", []);
    let second: supervisor::PlanAuditEntry =
        audit::signer::for_plan(&plan, None, "plan.exited", []);
    old_as_new.sign_and_emit(&first).await.unwrap();
    new_as_old.sign_and_emit(&second).await.unwrap();
    old_as_new.sign_and_emit(&first).await.unwrap();

    let legacy = supervisor::verify_audit_chain_entries(&path, &vk).unwrap();
    let canonical = audit::audit_file::verify_audit_chain_entries(&path, &vk).unwrap();
    assert_eq!(
        serde_json::to_value(&legacy).unwrap(),
        serde_json::to_value(&canonical).unwrap()
    );
    assert_eq!(canonical.len(), 3);
    assert_eq!(canonical[0].event, "plan.admitted");
    assert_eq!(canonical[1].event, "plan.exited");
    assert_eq!(canonical[2].event, "plan.admitted");
    assert_eq!(
        supervisor::audit::audit_file::verify_audit_chain(&path, &vk).unwrap(),
        3
    );
    assert_eq!(
        audit::audit_file::verify_audit_chain(&path, &vk).unwrap(),
        3
    );
    let wrong_key = SigningKey::from_bytes(&[8; 32]).verifying_key();
    assert!(audit::audit_file::verify_audit_chain(&path, &wrong_key).is_err());
    assert!(supervisor::verify_audit_chain(&path, &wrong_key).is_err());
}
