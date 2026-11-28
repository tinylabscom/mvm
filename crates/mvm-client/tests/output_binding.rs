use std::collections::BTreeMap;

use ed25519_dalek::SigningKey;
use mvm_client::stream::{
    OutputAuditBinding, VerifyOutputBindingError, verify_output_audit_binding,
};
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::transcript::{
    CaptureBinding, CaptureBounds, LEGACY_TRANSCRIPT_MANIFEST_FORMAT_VERSION, PayloadEncoding,
    RetentionPolicy, TranscriptManifest, sealed_root_hex,
};
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};

fn manifest() -> TranscriptManifest {
    let mut manifest = TranscriptManifest {
        format_version: LEGACY_TRANSCRIPT_MANIFEST_FORMAT_VERSION,
        capture_id: "capture-1".into(),
        binding: CaptureBinding {
            tenant_id: "tenant".into(),
            vm_name: "vm".into(),
            session_id: None,
        },
        bounds: CaptureBounds {
            max_duration_secs: 60,
            max_bytes: 1024,
            max_chunks: 10,
        },
        created_unix_secs: 1,
        at_rest: None,
        generation_budget: None,
        payload_encoding: PayloadEncoding::Raw,
        sealed_unix_secs: None,
        wrapped_data_key_b64: String::new(),
        recipient: "host".into(),
        retention: RetentionPolicy::FailClosed,
        chunks: Vec::new(),
        refused_chunks: 0,
        refused_bytes: 0,
        evicted_chunks: 0,
        evicted_bytes: 0,
        adopted: false,
        sealed_root_hex: String::new(),
    };
    manifest.sealed_root_hex = sealed_root_hex(&manifest).unwrap();
    manifest
}

fn anchor(manifest: &TranscriptManifest) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: mvm_core::util::time::utc_timestamp_now(),
        tenant: TenantId("tenant".into()),
        plan_id: PlanId("sha256:exact-plan".into()),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "image".into(),
        image_sha256: "image-digest".into(),
        caller_commitment: None,
        event: "gateway.transcript_sealed".into(),
        labels: BTreeMap::from([
            ("capture_id".into(), manifest.capture_id.clone()),
            ("vm_name".into(), manifest.binding.vm_name.clone()),
            ("transcript_root".into(), manifest.sealed_root_hex.clone()),
            ("chunk_count".into(), manifest.chunks.len().to_string()),
            ("adopted".into(), manifest.adopted.to_string()),
        ]),
    }
}

fn signed_chain(entries: &[PlanAuditEntry]) -> (tempfile::TempDir, SigningKey) {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&rand::random());
    let signer = FileAuditSigner::open(key.clone(), dir.path()).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for entry in entries {
        runtime.block_on(signer.sign_and_emit(entry)).unwrap();
    }
    (dir, key)
}

fn verify(
    dir: &std::path::Path,
    key: &SigningKey,
    manifest: &TranscriptManifest,
) -> Result<mvm_client::stream::OutputBindingReport, VerifyOutputBindingError> {
    verify_output_audit_binding(
        manifest,
        &dir.join("tenant.jsonl"),
        &key.verifying_key(),
        "tenant",
        "sha256:exact-plan",
        "vm",
    )
}

#[test]
fn signed_anchor_binds_sealed_manifest_without_claiming_payload_or_run_coverage() {
    use mvm_core::transcript::{Direction, TranscriptWriter, TranscriptWriterConfig};

    let seed = manifest();
    let payload_dir = tempfile::tempdir().unwrap();
    let mut writer = TranscriptWriter::new(
        payload_dir.path(),
        mvm_core::crypto::aead::Key::from_bytes(rand::random()),
        TranscriptWriterConfig {
            capture_id: seed.capture_id,
            binding: seed.binding,
            bounds: seed.bounds,
            retention: seed.retention,
            created_unix_secs: seed.created_unix_secs,
            at_rest: seed.at_rest,
            generation_budget: seed.generation_budget,
            payload_encoding: seed.payload_encoding,
            recipient: seed.recipient,
            wrapped_data_key_b64: seed.wrapped_data_key_b64,
        },
    )
    .unwrap();
    writer.push(Direction::Stdout, b"captured output").unwrap();
    let manifest = writer.seal();
    assert_eq!(manifest.chunks.len(), 1);
    let (dir, key) = signed_chain(&[anchor(&manifest)]);
    // The binding check must not depend on retained payloads or decryption keys.
    drop(payload_dir);
    let report = verify(dir.path(), &key, &manifest).unwrap();
    assert_eq!(report.binding, OutputAuditBinding::Bound);
    assert!(!report.truncated);
    assert!(!report.adopted);
}

#[test]
fn absent_anchor_is_unbound_not_absent_output() {
    let manifest = manifest();
    let mut unrelated = anchor(&manifest);
    unrelated.labels.insert("capture_id".into(), "other".into());
    let (dir, key) = signed_chain(&[unrelated]);
    assert_eq!(
        verify(dir.path(), &key, &manifest).unwrap().binding,
        OutputAuditBinding::Unbound
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        verify(empty.path(), &key, &manifest).unwrap().binding,
        OutputAuditBinding::Unbound
    );
}

#[test]
fn conflicting_signed_anchors_fail_closed() {
    let manifest = manifest();
    for (label, value) in [
        ("vm_name", "other"),
        ("transcript_root", "wrong-root"),
        ("chunk_count", "1"),
        ("adopted", "true"),
    ] {
        let mut entry = anchor(&manifest);
        entry.labels.insert(label.into(), value.into());
        let (dir, key) = signed_chain(&[entry]);
        assert!(
            matches!(
                verify(dir.path(), &key, &manifest),
                Err(VerifyOutputBindingError::AnchorMismatch)
            ),
            "{label}"
        );
    }
    let mut wrong_plan = anchor(&manifest);
    wrong_plan.plan_id = PlanId("sha256:exact-plan-extra".into());
    let (dir, key) = signed_chain(&[wrong_plan]);
    assert!(matches!(
        verify(dir.path(), &key, &manifest),
        Err(VerifyOutputBindingError::AnchorMismatch)
    ));
    let (dir, key) = signed_chain(&[anchor(&manifest), anchor(&manifest)]);
    assert!(matches!(
        verify(dir.path(), &key, &manifest),
        Err(VerifyOutputBindingError::AnchorMismatch)
    ));
}

#[test]
fn caller_identity_and_manifest_root_are_checked() {
    let original = manifest();
    let (dir, key) = signed_chain(&[anchor(&original)]);
    for (tenant, plan, vm) in [
        ("other", "sha256:exact-plan", "vm"),
        ("tenant", "sha256:exact", "vm"),
        ("tenant", "image", "vm"),
        ("tenant", "sha256:exact-plan", "other"),
    ] {
        assert!(
            verify_output_audit_binding(
                &original,
                &dir.path().join("tenant.jsonl"),
                &key.verifying_key(),
                tenant,
                plan,
                vm
            )
            .is_err()
        );
    }
    let mut tampered = original.clone();
    tampered.refused_chunks = 1;
    assert!(matches!(
        verify(dir.path(), &key, &tampered),
        Err(VerifyOutputBindingError::Manifest(_))
    ));
    let mut different_capture = original;
    different_capture.capture_id = "other".into();
    different_capture.sealed_root_hex = sealed_root_hex(&different_capture).unwrap();
    assert_eq!(
        verify(dir.path(), &key, &different_capture)
            .unwrap()
            .binding,
        OutputAuditBinding::Unbound
    );
}

#[test]
fn signed_foreign_tenant_in_supplied_path_is_rejected() {
    let manifest = manifest();
    let mut entry = anchor(&manifest);
    entry.tenant = TenantId("foreign".into());
    let (dir, key) = signed_chain(&[entry]);
    std::fs::rename(
        dir.path().join("foreign.jsonl"),
        dir.path().join("tenant.jsonl"),
    )
    .unwrap();
    assert!(matches!(
        verify(dir.path(), &key, &manifest),
        Err(VerifyOutputBindingError::AnchorMismatch)
    ));
}

#[test]
fn invalid_signature_and_unverified_explanation_cannot_establish_binding() {
    let manifest = manifest();
    let (dir, key) = signed_chain(&[anchor(&manifest)]);
    let wrong_key = SigningKey::from_bytes(&rand::random());
    assert!(matches!(
        verify(dir.path(), &wrong_key, &manifest),
        Err(VerifyOutputBindingError::Audit(_))
    ));
    let path = dir.path().join("tenant.jsonl");
    let text = std::fs::read_to_string(&path)
        .unwrap()
        .replace("image-digest", "forged-digest");
    std::fs::write(&path, text).unwrap();
    let explanation = mvm_client::explain::collect_run(
        &path,
        &key.verifying_key(),
        "tenant",
        "sha256:exact-plan",
    )
    .unwrap();
    assert!(!explanation.chain_verified);
    assert!(
        explanation
            .events
            .iter()
            .any(|event| event.event == "gateway.transcript_sealed")
    );
    assert!(matches!(
        verify(dir.path(), &key, &manifest),
        Err(VerifyOutputBindingError::Audit(_))
    ));
}

#[test]
fn removing_a_signed_predecessor_invalidates_the_chain() {
    let manifest = manifest();
    let mut admitted = anchor(&manifest);
    admitted.event = "plan.admitted".into();
    admitted.labels.clear();
    let (dir, key) = signed_chain(&[admitted, anchor(&manifest)]);
    let path = dir.path().join("tenant.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let (_, remaining) = text.split_once('\n').unwrap();
    std::fs::write(&path, remaining).unwrap();
    assert!(matches!(
        verify(dir.path(), &key, &manifest),
        Err(VerifyOutputBindingError::Audit(_))
    ));
}

#[test]
fn missing_adopted_label_is_not_inferred_as_false() {
    let manifest = manifest();
    let mut entry = anchor(&manifest);
    entry.labels.remove("adopted");
    let (dir, key) = signed_chain(&[entry]);
    assert!(matches!(
        verify(dir.path(), &key, &manifest),
        Err(VerifyOutputBindingError::AnchorMismatch)
    ));
}

#[test]
fn loss_and_adoption_remain_explicit_even_with_valid_binding() {
    for (refused, evicted, adopted) in [(1, 0, false), (0, 1, false), (0, 0, true)] {
        let mut manifest = manifest();
        manifest.refused_chunks = refused;
        manifest.evicted_chunks = evicted;
        manifest.adopted = adopted;
        manifest.sealed_root_hex = sealed_root_hex(&manifest).unwrap();
        let (dir, key) = signed_chain(&[anchor(&manifest)]);
        let report = verify(dir.path(), &key, &manifest).unwrap();
        assert_eq!(report.binding, OutputAuditBinding::Bound);
        assert!(report.truncated);
        assert_eq!(report.adopted, adopted);
    }
}
