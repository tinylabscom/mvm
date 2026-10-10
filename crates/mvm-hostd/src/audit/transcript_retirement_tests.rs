use super::*;
use crate::supervisor::audit::for_plan;
use anyhow::bail;
use mvm_core::plan::ExecutionPlan;
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
        Self::for_vm(anchor, "service-instance-1")
    }

    fn for_vm(anchor: bool, vm: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        mvm_core::private_fs::ensure_private_dir(root.path()).unwrap();
        let dir = root.path().join("capture");
        mvm_core::private_fs::ensure_private_dir(&dir).unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new()
            .tenant("local")
            .workload("service")
            .build();
        let emitter = AuditEmitter::with_dir(
            ed25519_dalek::SigningKey::from_bytes(&[17; 32]),
            &root.path().join("audit"),
        )
        .unwrap();
        let mut writer = TranscriptWriter::new(
            &dir,
            mvm_core::crypto::aead::Key::random(),
            TranscriptWriterConfig {
                capture_id: "synthetic-capture".into(),
                binding: CaptureBinding {
                    tenant_id: "local".into(),
                    vm_name: vm.into(),
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
            tenant: &self.plan.tenant.0,
            vm: &self.manifest.binding.vm_name,
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
fn authenticated_opening_is_exact_and_preserves_historical_recovery_attribution() {
    use mvm_core::transcript::evidence::{
        TRANSCRIPT_OPENED_EVENT, authenticate_opening, opening_labels, recovered_seal_entry,
    };
    let f = Fixture::new(false);
    let mut seed = f.manifest.clone();
    seed.chunks.clear();
    seed.sealed_unix_secs = None;
    seed.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&seed).unwrap();
    let key = f.emitter.verifying_key();
    assert!(authenticate_opening(f.emitter.audit_dir(), &key, &seed).is_err());
    let mut entry = for_plan(&f.plan, None, TRANSCRIPT_OPENED_EVENT, []);
    entry.labels = opening_labels(&seed).unwrap();
    f.emitter
        .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
        .unwrap();
    assert_eq!(
        authenticate_opening(f.emitter.audit_dir(), &key, &seed).unwrap(),
        entry
    );
    for mutation in ["vm", "tenant", "root"] {
        let mut wrong = seed.clone();
        match mutation {
            "vm" => wrong.binding.vm_name = "service-instance-2".into(),
            "tenant" => wrong.binding.tenant_id = "other".into(),
            _ => wrong.wrapped_data_key_b64 = "other-envelope".into(),
        }
        wrong.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&wrong).unwrap();
        assert!(authenticate_opening(f.emitter.audit_dir(), &key, &wrong).is_err());
    }
    let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[18; 32]).verifying_key();
    assert!(authenticate_opening(f.emitter.audit_dir(), &wrong_key, &seed).is_err());
    assert!(authenticated_retirement(f.emitter.audit_dir(), &key, &f.manifest).is_err());
    let mut recovered = f.manifest.clone();
    recovered.adopted = true;
    recovered.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&recovered).unwrap();
    let sealed = recovered_seal_entry(f.emitter.audit_dir(), &key, &seed, &recovered).unwrap();
    assert_eq!(sealed.plan_id, entry.plan_id);
    assert_eq!(sealed.tenant, entry.tenant);
    assert_eq!(sealed.labels["vm_name"], "service-instance-1");
    f.emitter
        .emit_entry_for_evidence(&sealed, EvidenceReceipt::Omitted)
        .unwrap();
    assert!(!authenticated_retirement(f.emitter.audit_dir(), &key, &recovered).unwrap());
    f.emitter
        .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
        .unwrap();
    assert!(authenticate_opening(f.emitter.audit_dir(), &key, &seed).is_err());
}

#[test]
fn atomic_recovery_publication_serializes_independent_signers() {
    use mvm_core::transcript::evidence::authenticated_seal;
    let (f, seed, recovered) = recovery_fixture();
    let _capture_lease = CaptureDirectory::for_writer(&f.root.path().join("capture")).unwrap();
    assert!(
        authenticated_seal(
            f.emitter.audit_dir(),
            &f.emitter.verifying_key(),
            &recovered
        )
        .unwrap()
        .is_none()
    );
    let barrier = std::sync::Barrier::new(8);
    let appended = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    let emitter = AuditEmitter::with_dir(
                        ed25519_dalek::SigningKey::from_bytes(&[17; 32]),
                        f.emitter.audit_dir(),
                    )
                    .unwrap();
                    barrier.wait();
                    emitter
                        .emit_recovered_transcript_sealed(&seed, &recovered)
                        .unwrap()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>()
    });
    assert_eq!(appended, 1);
    assert!(
        !f.emitter
            .emit_recovered_transcript_sealed(&seed, &recovered)
            .unwrap()
    );
    let entry = authenticated_seal(
        f.emitter.audit_dir(),
        &f.emitter.verifying_key(),
        &recovered,
    )
    .unwrap()
    .unwrap();
    assert_eq!(entry.plan_id, f.plan.plan_id);
    assert_eq!(entry.labels["adopted"], "true");
}

fn recovery_fixture() -> (Fixture, TranscriptManifest, TranscriptManifest) {
    use mvm_core::transcript::evidence::{TRANSCRIPT_OPENED_EVENT, opening_labels};
    let f = Fixture::new(false);
    let mut seed = f.manifest.clone();
    seed.chunks.clear();
    seed.sealed_unix_secs = None;
    seed.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&seed).unwrap();
    let mut entry = for_plan(&f.plan, None, TRANSCRIPT_OPENED_EVENT, []);
    entry.labels = opening_labels(&seed).unwrap();
    f.emitter
        .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
        .unwrap();
    let mut recovered = f.manifest.clone();
    recovered.adopted = true;
    recovered.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&recovered).unwrap();
    // Represents the already durable terminal candidate: retry must not
    // re-finalize it with a different recovery timestamp/root.
    mvm_core::util::atomic_io::write_private(
        &f.root.path().join("capture/manifest.json"),
        &serde_json::to_vec(&recovered).unwrap(),
    )
    .unwrap();
    (f, seed, recovered)
}

#[test]
fn staged_recovery_retries_after_seal_append_fsync_failure_without_duplicate() {
    use crate::supervisor::audit_file::write_faults::{Boundary, Guard};
    let (f, seed, recovered) = recovery_fixture();
    let _capture_lease = CaptureDirectory::for_writer(&f.root.path().join("capture")).unwrap();
    let fault = Guard::arm(Boundary::Sync);
    assert!(
        f.emitter
            .emit_recovered_transcript_sealed(&seed, &recovered)
            .is_err()
    );
    assert!(fault.consumed());
    drop(fault);
    let path = f.emitter.audit_dir().join("local.jsonl");
    let after_append = std::fs::read(&path).unwrap();
    assert!(
        !f.emitter
            .emit_recovered_transcript_sealed(&seed, &recovered)
            .unwrap()
    );
    assert_eq!(std::fs::read(path).unwrap(), after_append);
    assert!(f.payload().exists());
    assert_eq!(
        serde_json::from_slice::<TranscriptManifest>(
            &std::fs::read(f.root.path().join("capture/manifest.json")).unwrap(),
        )
        .unwrap(),
        recovered
    );
}

#[test]
fn seal_lookup_does_not_turn_conflicting_evidence_into_absence() {
    use mvm_core::transcript::evidence::authenticated_seal;
    for kind in ["conflict", "duplicate", "retired-first", "broken"] {
        let (f, seed, recovered) = recovery_fixture();
        let key = f.emitter.verifying_key();
        match kind {
            "retired-first" => {
                let mut entry = for_plan(&f.plan, None, TRANSCRIPT_RETIRED_EVENT, []);
                entry.labels = labels(&recovered).unwrap();
                f.emitter
                    .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
                    .unwrap();
            }
            "broken" => {
                use std::io::Write;
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(f.emitter.audit_dir().join("local.jsonl"))
                    .unwrap()
                    .write_all(b"broken\n")
                    .unwrap();
            }
            _ => {
                f.emitter
                    .emit_recovered_transcript_sealed(&seed, &recovered)
                    .unwrap();
                let mut entry = authenticated_seal(f.emitter.audit_dir(), &key, &recovered)
                    .unwrap()
                    .unwrap();
                if kind == "conflict" {
                    entry
                        .labels
                        .insert("transcript_root".into(), "0".repeat(64));
                }
                f.emitter
                    .emit_entry_for_evidence(&entry, EvidenceReceipt::Omitted)
                    .unwrap();
            }
        }
        assert!(
            authenticated_seal(f.emitter.audit_dir(), &key, &recovered).is_err(),
            "{kind}"
        );
        let before = std::fs::read(f.emitter.audit_dir().join("local.jsonl")).unwrap();
        assert!(
            f.emitter
                .emit_recovered_transcript_sealed(&seed, &recovered)
                .is_err(),
            "{kind}"
        );
        assert_eq!(
            std::fs::read(f.emitter.audit_dir().join("local.jsonl")).unwrap(),
            before
        );
        assert!(f.payload().exists());
    }
}

#[test]
fn legitimate_pruning_does_not_prove_that_a_seal_never_existed() {
    use crate::supervisor::audit_file::{FileAuditSigner, RotationPolicy};
    use mvm_core::transcript::evidence::authenticated_seal;
    let (f, seed, recovered) = recovery_fixture();
    let key = ed25519_dalek::SigningKey::from_bytes(&[17; 32]);
    let signer = std::sync::Arc::new(
        FileAuditSigner::open(key.clone(), f.emitter.audit_dir())
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(1)),
    );
    let emitter =
        AuditEmitter::with_primary_signer(key, f.emitter.audit_dir(), signer.clone()).unwrap();
    emitter
        .emit_recovered_transcript_sealed(&seed, &recovered)
        .unwrap();
    emitter
        .emit_entry_for_evidence(
            &for_plan(&f.plan, None, "test.after-seal", []),
            EvidenceReceipt::Omitted,
        )
        .unwrap();
    signer.prune_through(&f.plan.tenant, 2).unwrap();
    let verified = mvm_core::audit_verify::set::read_verified_history(
        f.emitter.audit_dir(),
        "local",
        &f.emitter.verifying_key(),
    )
    .unwrap();
    assert!(verified.pruned.is_some());
    assert!(
        authenticated_seal(
            f.emitter.audit_dir(),
            &f.emitter.verifying_key(),
            &recovered
        )
        .is_err()
    );
    let before = std::fs::read(f.emitter.audit_dir().join("local.jsonl")).unwrap();
    assert!(
        emitter
            .emit_recovered_transcript_sealed(&seed, &recovered)
            .is_err()
    );
    assert_eq!(
        std::fs::read(f.emitter.audit_dir().join("local.jsonl")).unwrap(),
        before
    );
}

#[test]
fn instances_of_one_workload_retire_independently() {
    let first = Fixture::for_vm(true, "service-instance-1");
    let second = Fixture::for_vm(true, "service-instance-2");
    assert_eq!(first.plan.workload, second.plan.workload);
    reconcile_capture(first.context(), 605_000).unwrap();
    assert!(!first.payload().exists());
    assert!(second.payload().exists());
    reconcile_capture(second.context(), 605_000).unwrap();
    assert!(!second.payload().exists());
}

#[test]
fn requested_concrete_vm_is_authenticated_not_workload_name() {
    let f = Fixture::new(true);
    let mut wrong = f.context();
    wrong.vm = "service-instance-2";
    assert!(reconcile_capture(wrong, 605_000).is_err());
    wrong.vm = "service";
    assert!(reconcile_capture(wrong, 605_000).is_err());
    assert!(f.payload().exists());
    assert!(reconcile_capture(f.context(), 605_000).is_ok());
}

#[test]
fn replacement_plan_cannot_change_original_retirement_attribution() {
    let mut f = Fixture::new(true);
    let original_plan_id = f.plan.plan_id.clone();
    f.plan = mvm_core::plan::test_support::PlanFixture::new()
        .tenant("local")
        .workload("replacement")
        .build();
    reconcile_capture(f.context(), 605_000).unwrap();
    let entries = crate::supervisor::verify_audit_chain_entries(
        &f.emitter.audit_dir().join("local.jsonl"),
        &f.emitter.verifying_key(),
    )
    .unwrap();
    let retired = entries
        .iter()
        .find(|entry| entry.event == TRANSCRIPT_RETIRED_EVENT)
        .unwrap();
    assert_eq!(retired.plan_id, original_plan_id);
}

#[test]
fn missing_authority_bad_clock_and_live_owner_never_unlink() {
    let f = Fixture::new(false);
    assert!(reconcile_capture(f.context(), 605_000).is_err());
    assert!(f.payload().exists());
    let f = Fixture::new(true);
    assert!(reconcile_capture(f.context(), 199).is_err());
    assert!(reconcile_capture(f.context(), u64::MAX).is_err());
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
fn actual_audit_append_and_fsync_failure_never_authorize_unlink() {
    use crate::supervisor::audit_file::write_faults::{Boundary, Guard};
    // These synchronous tests have no entered Tokio runtime: the emitter runs
    // its current-thread executor here. Consumption proves the seam was hit.
    for boundary in [Boundary::PartialAppend, Boundary::Sync] {
        let f = Fixture::new(true);
        let path = f.emitter.audit_dir().join("local.jsonl");
        let before = std::fs::read(&path).unwrap();
        let manifest_before = std::fs::read(f.root.path().join("capture/manifest.json")).unwrap();
        let fault = Guard::arm(boundary);
        let error = reconcile_capture(f.context(), 605_000).unwrap_err();
        assert!(
            fault.consumed(),
            "emitter did not execute the selected I/O boundary"
        );
        assert!(format!("{error:#}").contains("injected"));
        drop(fault);
        assert!(f.payload().exists());
        assert_eq!(
            std::fs::read(f.root.path().join("capture/manifest.json")).unwrap(),
            manifest_before
        );
        let after = std::fs::read(&path).unwrap();
        assert!(after.starts_with(&before));
        assert!(
            after.len() > before.len(),
            "signer never appended actual bytes"
        );
        if boundary == Boundary::PartialAppend {
            assert!(!after.ends_with(b"\n"));
            assert!(reconcile_capture(f.context(), 605_000).is_err());
            assert!(
                f.payload().exists(),
                "torn authority must remain fail-closed"
            );
        } else {
            assert!(after.ends_with(b"\n"));
            assert_eq!(
                reconcile_capture(f.context(), 605_000).unwrap(),
                RetirementOutcome::Retired {
                    removed_segments: 1
                }
            );
            assert_eq!(
                std::fs::read(&path).unwrap(),
                after,
                "retry appended duplicate evidence"
            );
        }
    }
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
    let owner = BudgetOwner::acquire(f.root.path(), "local", "service-instance-1", budget).unwrap();
    assert!(BudgetOwner::acquire(f.root.path(), "local", "service-instance-1", budget).is_err());
    let candidates = [f.manifest.clone()];
    let mut wrong_vm = f.context();
    wrong_vm.vm = "service-instance-2";
    assert!(
        reconcile_pressure(
            wrong_vm,
            &owner,
            &candidates,
            GenerationReservation {
                plaintext_bytes: 2,
                chunks: 1
            },
            300,
        )
        .is_err()
    );
    assert!(f.payload().exists());
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
    let owner = BudgetOwner::acquire(
        f.root.path(),
        "local",
        "service-instance-1",
        Default::default(),
    )
    .unwrap();
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
