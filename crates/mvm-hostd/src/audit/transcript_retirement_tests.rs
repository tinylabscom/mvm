use super::*;
use mvm_core::transcript::{
    AtRestRetention, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME, RetentionPolicy,
    TranscriptWriter, TranscriptWriterConfig,
};

struct Fixture {
    root: tempfile::TempDir,
    manifest: TranscriptManifest,
    plan: ExecutionPlan,
    emitter: AuditEmitter,
}

impl Fixture {
    fn new(anchor: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        mvm_core::private_fs::ensure_private_dir(root.path()).unwrap();
        let dir = root.path().join("capture");
        mvm_core::private_fs::ensure_private_dir(&dir).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("synthetic-vm")
            .build();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[17; 32]),
            &root.path().join("audit"),
        )
        .unwrap();
        let mut writer = TranscriptWriter::try_new(
            &dir,
            mvm_core::crypto::aead::Key::random(),
            TranscriptWriterConfig {
                capture_id: "synthetic-capture".into(),
                binding: CaptureBinding {
                    tenant_id: "local".into(),
                    vm_name: "synthetic-vm".into(),
                    session_id: None,
                },
                bounds: CaptureBounds {
                    max_duration_secs: 3600,
                    max_bytes: 4096,
                    max_chunks: 10,
                },
                retention: RetentionPolicy::FailClosed,
                at_rest: Some(AtRestRetention::default()),
                generation_budget: None,
                payload_encoding: Default::default(),
                created_unix_secs: 100,
                recipient: "transcript-kek".into(),
                wrapped_data_key_b64: "synthetic-envelope".into(),
            },
        )
        .unwrap();
        writer
            .push(Direction::Stdout, b"synthetic-sensitive-marker")
            .unwrap();
        let manifest = writer.finalize_at(200).unwrap();
        std::fs::write(
            dir.join(MANIFEST_FILENAME),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        if anchor {
            emitter
                .emit_transcript_sealed(
                    &plan,
                    &manifest.capture_id,
                    &manifest.binding.vm_name,
                    &manifest.sealed_root_hex,
                    manifest.chunks.len(),
                    false,
                )
                .unwrap();
        }
        Self {
            root,
            manifest,
            plan,
            emitter,
        }
    }

    fn context(&self) -> RetirementContext<'_> {
        RetirementContext {
            root: self.root.path(),
            relative_capture: Path::new("capture"),
            capture_id: &self.manifest.capture_id,
            plan: &self.plan,
            emitter: &self.emitter,
        }
    }

    fn payload(&self) -> std::path::PathBuf {
        self.root
            .path()
            .join("capture")
            .join(&self.manifest.chunks[0].file)
    }
}

#[test]
fn authenticated_boundary_preserves_manifest_and_resumes_exactly() {
    let f = Fixture::new(true);
    assert_eq!(
        reconcile_capture(f.context(), 604_999).unwrap(),
        RetirementOutcome::NotDue
    );
    assert!(f.payload().exists());
    assert_eq!(
        reconcile_capture(f.context(), 605_000).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 1
        }
    );
    assert!(!f.payload().exists());
    assert_eq!(
        reconcile_capture(f.context(), 605_001).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 0
        }
    );
    let after: TranscriptManifest = serde_json::from_slice(
        &std::fs::read(f.root.path().join("capture").join(MANIFEST_FILENAME)).unwrap(),
    )
    .unwrap();
    assert_eq!(after, f.manifest);
    let audit = std::fs::read_to_string(f.root.path().join("audit/local.jsonl")).unwrap();
    assert!(!audit.contains("synthetic-sensitive-marker"));
    assert!(
        authenticated_retirement(
            f.emitter.audit_dir(),
            &f.emitter.verifying_key(),
            &f.manifest
        )
        .unwrap()
    );
}

#[test]
fn missing_authority_bad_clock_and_live_owner_never_unlink() {
    let f = Fixture::new(false);
    assert!(reconcile_capture(f.context(), 605_000).is_err());
    assert!(f.payload().exists());
    let f = Fixture::new(true);
    assert!(reconcile_capture(f.context(), 199).is_err());
    let lease = CaptureDirectory::for_writer(&f.root.path().join("capture")).unwrap();
    assert!(reconcile_capture(f.context(), 605_000).is_err());
    assert!(f.payload().exists());
    drop(lease);
    assert!(reconcile_capture(f.context(), 605_000).is_ok());
}

#[test]
fn crash_after_signed_evidence_before_unlink_is_resumable() {
    let f = Fixture::new(true);
    let mut entry = for_plan(&f.plan, None, TRANSCRIPT_RETIRED_EVENT, []);
    entry.labels = labels(&f.manifest).unwrap();
    f.emitter
        .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
        .unwrap();
    assert!(f.payload().exists());
    assert_eq!(
        reconcile_capture(f.context(), 605_000).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 1
        }
    );
    assert_eq!(
        reconcile_capture(f.context(), 605_000).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 0
        }
    );
}

#[test]
fn conflict_or_unsigned_missing_payload_refuses() {
    let f = Fixture::new(true);
    std::fs::remove_file(f.payload()).unwrap();
    assert!(reconcile_capture(f.context(), 605_000).is_err());
    assert!(
        !authenticated_retirement(
            f.emitter.audit_dir(),
            &f.emitter.verifying_key(),
            &f.manifest
        )
        .unwrap()
    );
    let f = Fixture::new(true);
    let mut entry = for_plan(&f.plan, None, TRANSCRIPT_RETIRED_EVENT, []);
    entry.labels = labels(&f.manifest).unwrap();
    entry
        .labels
        .insert("retention.reason".into(), "not-authorized".into());
    f.emitter
        .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
        .unwrap();
    assert!(reconcile_capture(f.context(), 605_000).is_err());
    assert!(f.payload().exists());
}

#[test]
fn signing_refusal_leaves_every_payload_and_original_root_untouched() {
    let f = Fixture::new(true);
    assert!(
        reconcile_with(f.context(), 605_000, None, |_| bail!(
            "synthetic signing refusal"
        ))
        .is_err()
    );
    assert!(f.payload().exists());
    assert!(
        !authenticated_retirement(
            f.emitter.audit_dir(),
            &f.emitter.verifying_key(),
            &f.manifest
        )
        .unwrap()
    );
}

#[test]
fn crash_after_one_payload_unlink_resumes_without_new_evidence() {
    let mut f = Fixture::new(false);
    let mut second = f.manifest.chunks[0].clone();
    second.file = "1.seg".into();
    second.seq = 1;
    second.prev_hash = second.sha256_hex.clone();
    std::fs::copy(f.payload(), f.root.path().join("capture/1.seg")).unwrap();
    f.manifest.chunks.push(second);
    f.manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&f.manifest).unwrap();
    std::fs::write(
        f.root.path().join("capture/manifest.json"),
        serde_json::to_vec(&f.manifest).unwrap(),
    )
    .unwrap();
    f.emitter
        .emit_transcript_sealed(
            &f.plan,
            &f.manifest.capture_id,
            &f.manifest.binding.vm_name,
            &f.manifest.sealed_root_hex,
            2,
            false,
        )
        .unwrap();
    let mut entry = for_plan(&f.plan, None, TRANSCRIPT_RETIRED_EVENT, []);
    entry.labels = labels(&f.manifest).unwrap();
    f.emitter
        .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
        .unwrap();
    std::fs::remove_file(f.payload()).unwrap();
    assert_eq!(
        reconcile_capture(f.context(), 605_000).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 1
        }
    );
    assert!(!f.root.path().join("capture/1.seg").exists());
}

#[test]
fn policy_rehash_without_host_authority_never_unlinks() {
    let mut f = Fixture::new(true);
    f.manifest.at_rest.as_mut().unwrap().payload_after_seal_secs = 1;
    f.manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&f.manifest).unwrap();
    std::fs::write(
        f.root.path().join("capture/manifest.json"),
        serde_json::to_vec(&f.manifest).unwrap(),
    )
    .unwrap();
    assert!(reconcile_capture(f.context(), 605_000).is_err());
    assert!(f.payload().exists());
}

#[test]
fn aggregate_pressure_requires_signed_budget_and_checked_accounting() {
    let mut f = Fixture::new(false);
    let budget = mvm_core::transcript::GenerationBudget {
        max_plaintext_bytes: f.manifest.retained_plaintext_bytes().unwrap() + 1,
        ..Default::default()
    };
    f.manifest.generation_budget = Some(budget);
    f.manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&f.manifest).unwrap();
    std::fs::write(
        f.root.path().join("capture/manifest.json"),
        serde_json::to_vec(&f.manifest).unwrap(),
    )
    .unwrap();
    f.emitter
        .emit_transcript_sealed(
            &f.plan,
            &f.manifest.capture_id,
            &f.manifest.binding.vm_name,
            &f.manifest.sealed_root_hex,
            1,
            false,
        )
        .unwrap();
    let owner = BudgetOwner::acquire(f.root.path(), &f.plan, budget).unwrap();
    assert!(BudgetOwner::acquire(f.root.path(), &f.plan, budget).is_err());
    let candidates = [f.manifest.clone()];
    assert!(
        reconcile_pressure(
            f.context(),
            &owner,
            &candidates,
            GenerationReservation {
                plaintext_bytes: 1,
                chunks: 1
            },
            300
        )
        .is_err()
    );
    assert!(f.payload().exists());
    assert!(
        reconcile_pressure(
            f.context(),
            &owner,
            &[f.manifest.clone(), f.manifest.clone()],
            GenerationReservation {
                plaintext_bytes: 2,
                chunks: 1
            },
            300
        )
        .is_err()
    );
    assert_eq!(
        reconcile_pressure(
            f.context(),
            &owner,
            &candidates,
            GenerationReservation {
                plaintext_bytes: 2,
                chunks: 1
            },
            300
        )
        .unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 1
        }
    );
    assert!(
        authenticated_retirement(
            f.emitter.audit_dir(),
            &f.emitter.verifying_key(),
            &f.manifest
        )
        .unwrap()
    );
    assert_eq!(
        reconcile_capture(f.context(), 300).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 0
        }
    );
}

#[test]
fn pressure_cannot_enroll_forensic_captures_or_trust_rehashed_totals() {
    let f = Fixture::new(true);
    let owner = BudgetOwner::acquire(f.root.path(), &f.plan, Default::default()).unwrap();
    assert!(
        reconcile_pressure(
            f.context(),
            &owner,
            std::slice::from_ref(&f.manifest),
            GenerationReservation {
                plaintext_bytes: 1,
                chunks: 1
            },
            300
        )
        .is_err()
    );
    let mut forged = f.manifest.clone();
    forged.generation_budget = Some(Default::default());
    forged.chunks[0].size_bytes = 8 << 20;
    forged.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&forged).unwrap();
    assert!(
        reconcile_pressure(
            f.context(),
            &owner,
            &[forged],
            GenerationReservation {
                plaintext_bytes: 1024,
                chunks: 1
            },
            300
        )
        .is_err()
    );
    assert!(f.payload().exists());
}
