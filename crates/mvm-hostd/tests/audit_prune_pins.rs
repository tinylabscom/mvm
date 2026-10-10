//! Synthetic witnesses for protected verification evidence at prune commit.
#![cfg(unix)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use mvm_core::audit_verify::set::read_verified_set;
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::transcript::evidence::{
    self, TRANSCRIPT_OPENED_EVENT, TRANSCRIPT_RETIRED_EVENT, TRANSCRIPT_SEALED_EVENT,
};
use mvm_core::transcript::{
    AtRestRetention, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME, RetentionPolicy,
    TranscriptManifest, TranscriptWriter, TranscriptWriterConfig,
};
use mvm_hostd::supervisor::audit::{AuditSigner, PlanAuditEntry};
use mvm_hostd::supervisor::audit_file::{FileAuditSigner, RotationPolicy};

struct Fixture {
    root: tempfile::TempDir,
    signer: FileAuditSigner,
    capture: PathBuf,
    manifest: TranscriptManifest,
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[71; 32])
}

fn event(kind: &str, labels: BTreeMap<String, String>) -> PlanAuditEntry {
    PlanAuditEntry {
        timestamp: chrono::Utc::now(),
        tenant: TenantId("local".into()),
        plan_id: PlanId("synthetic-run".into()),
        plan_version: 1,
        bundle_id: None,
        bundle_version: None,
        image_name: "synthetic".into(),
        image_sha256: "0".repeat(64),
        event: kind.into(),
        caller_commitment: None,
        labels,
    }
}

fn write_manifest(path: &Path, manifest: &TranscriptManifest) {
    mvm_core::util::atomic_io::atomic_write(path, &serde_json::to_vec(manifest).unwrap()).unwrap();
}

impl Fixture {
    async fn new(managed: bool, enrolled: bool, retired: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let signer = FileAuditSigner::open(key(), root.path())
            .unwrap()
            .with_rotation(RotationPolicy::at_bytes(1));
        signer
            .sign_and_emit(&event("plan.launched", BTreeMap::new()))
            .await
            .unwrap();
        let capture = if managed {
            root.path()
                .join("workload-output")
                .join(hex::encode("vm"))
                .join("generations/1-1/0")
        } else {
            root.path().join("transcripts/local/synthetic-capture")
        };
        mvm_core::config::create_private_dir(&capture).unwrap();
        let mut writer = TranscriptWriter::new(
            &capture,
            mvm_core::crypto::aead::Key::random(),
            TranscriptWriterConfig {
                capture_id: "synthetic-capture".into(),
                binding: CaptureBinding {
                    tenant_id: "local".into(),
                    vm_name: "vm".into(),
                    session_id: None,
                },
                bounds: CaptureBounds {
                    max_duration_secs: 3600,
                    max_bytes: 4096,
                    max_chunks: 10,
                },
                retention: RetentionPolicy::FailClosed,
                at_rest: enrolled.then(AtRestRetention::default),
                generation_budget: None,
                payload_encoding: Default::default(),
                created_unix_secs: 100,
                recipient: "synthetic-recipient".into(),
                wrapped_data_key_b64: "synthetic-envelope".into(),
            },
        )
        .unwrap();
        let seed = writer.sealed_manifest();
        if managed {
            write_manifest(&capture.join("capture-seed.json"), &seed);
            signer
                .sign_and_emit(&event(
                    TRANSCRIPT_OPENED_EVENT,
                    evidence::opening_labels(&seed).unwrap(),
                ))
                .await
                .unwrap();
        }
        writer
            .push(Direction::Stdout, b"SYNTHETIC_SECRET_PAYLOAD")
            .unwrap();
        let manifest = writer.finalize_at(200).unwrap();
        drop(writer);
        write_manifest(&capture.join(MANIFEST_FILENAME), &manifest);
        signer
            .sign_and_emit(&event(
                TRANSCRIPT_SEALED_EVENT,
                [
                    ("capture_id".into(), manifest.capture_id.clone()),
                    ("vm_name".into(), manifest.binding.vm_name.clone()),
                    ("transcript_root".into(), manifest.sealed_root_hex.clone()),
                    ("chunk_count".into(), manifest.chunks.len().to_string()),
                ]
                .into(),
            ))
            .await
            .unwrap();
        if retired {
            signer
                .sign_and_emit(&event(
                    TRANSCRIPT_RETIRED_EVENT,
                    evidence::labels(&manifest).unwrap(),
                ))
                .await
                .unwrap();
        }
        signer
            .sign_and_emit(&event("plan.exited", BTreeMap::new()))
            .await
            .unwrap();
        Self {
            root,
            signer,
            capture,
            manifest,
        }
    }

    fn seq(&self, kind: &str) -> u64 {
        read_verified_set(self.root.path(), "local", &key().verifying_key())
            .unwrap()
            .into_iter()
            .find(|segment| {
                segment
                    .entries
                    .as_ref()
                    .unwrap()
                    .iter()
                    .any(|e| e.event == kind)
            })
            .unwrap()
            .seq
    }

    fn audit_bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files: Vec<_> = std::fs::read_dir(self.root.path())
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "jsonl"))
            .map(|entry| (entry.path(), std::fs::read(entry.path()).unwrap()))
            .collect();
        files.sort();
        files
    }

    fn refuses_unchanged(&self, through: u64) -> String {
        let before = self.audit_bytes();
        let error = self
            .signer
            .prune_through(&TenantId("local".into()), through)
            .unwrap_err()
            .to_string();
        assert_eq!(self.audit_bytes(), before);
        assert!(!error.contains("SYNTHETIC_SECRET_PAYLOAD"));
        assert!(!error.contains(&self.capture.to_string_lossy().to_string()));
        error
    }
}

#[tokio::test]
async fn opening_seal_and_retirement_remain_pinned_after_unlink() {
    for retired in [false, true] {
        let fixture = Fixture::new(true, true, retired).await;
        if retired {
            std::fs::remove_file(fixture.capture.join(&fixture.manifest.chunks[0].file)).unwrap();
        }
        assert!(
            fixture
                .refuses_unchanged(fixture.seq(TRANSCRIPT_OPENED_EVENT))
                .contains("pins segment")
        );
        fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_SEALED_EVENT));
        if retired {
            fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_RETIRED_EVENT));
        }
        fixture
            .signer
            .prune_through(&TenantId("local".into()), 1)
            .unwrap();
        assert!(
            evidence::authenticated_retirement(
                fixture.root.path(),
                &key().verifying_key(),
                &fixture.manifest
            )
            .is_ok()
        );
    }
}

#[tokio::test]
async fn forensic_enrollment_and_unknown_missing_metadata_are_not_pruned() {
    let fixture = Fixture::new(false, true, false).await;
    fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_SEALED_EVENT));
    std::fs::remove_file(fixture.capture.join(MANIFEST_FILENAME)).unwrap();
    fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_SEALED_EVENT));
    std::fs::remove_dir_all(&fixture.capture).unwrap();
    assert!(
        fixture
            .refuses_unchanged(fixture.seq(TRANSCRIPT_SEALED_EVENT))
            .contains("unknown")
    );
    fixture
        .signer
        .prune_through(&TenantId("local".into()), 1)
        .unwrap();
}

#[tokio::test]
async fn known_unenrolled_capture_does_not_pin_its_seal() {
    let fixture = Fixture::new(false, false, false).await;
    assert_eq!(fixture.manifest.format_version, 6);
    fixture
        .signer
        .prune_through(
            &TenantId("local".into()),
            fixture.seq(TRANSCRIPT_SEALED_EVENT),
        )
        .unwrap();
    assert!(fixture.capture.join(MANIFEST_FILENAME).exists());
    fixture
        .signer
        .sign_and_emit(&event("plan.launched", BTreeMap::new()))
        .await
        .unwrap();
    let through = fixture.seq("plan.exited");
    assert!(fixture.refuses_unchanged(through).contains("authority"));
}

#[tokio::test]
async fn busy_family_is_retryable_and_does_not_mutate_evidence() {
    let fixture = Fixture::new(true, true, false).await;
    let family = fixture
        .root
        .path()
        .join("workload-output")
        .join(hex::encode("vm"));
    let lease =
        mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&family).unwrap();
    assert!(fixture.refuses_unchanged(1).contains("busy"));
    drop(lease);
    fixture
        .signer
        .prune_through(&TenantId("local".into()), 1)
        .unwrap();
}

#[tokio::test]
async fn corrupt_cross_tenant_and_symlink_metadata_refuse_without_mutation() {
    for mode in 0..3 {
        let fixture = Fixture::new(true, true, false).await;
        let path = fixture.capture.join(MANIFEST_FILENAME);
        if mode == 0 {
            mvm_core::util::atomic_io::atomic_write(&path, b"invalid").unwrap();
        } else if mode == 1 {
            let mut manifest = fixture.manifest.clone();
            manifest.binding.tenant_id = "other".into();
            manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&manifest).unwrap();
            write_manifest(&path, &manifest);
        } else {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink("/outside/synthetic", &path).unwrap();
        }
        fixture.refuses_unchanged(1);
    }
}

#[tokio::test]
async fn dry_run_is_advisory_and_commit_rechecks_new_protected_evidence() {
    let fixture = Fixture::new(false, false, false).await;
    let through = fixture.seq(TRANSCRIPT_SEALED_EVENT);
    fixture
        .signer
        .check_prune_pins(&TenantId("local".into()), through)
        .unwrap();
    // Metadata disappearance after preview makes the old seal ambiguous.
    std::fs::remove_dir_all(&fixture.capture).unwrap();
    fixture.refuses_unchanged(through);
}

#[tokio::test]
async fn unknown_foreign_busy_family_does_not_disclose_identity_and_can_retry() {
    let fixture = Fixture::new(true, true, false).await;
    let family = fixture
        .root
        .path()
        .join("workload-output")
        .join(hex::encode("foreign-sensitive-vm"));
    mvm_core::config::create_private_dir(&family).unwrap();
    let lease =
        mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&family).unwrap();
    let error = fixture.refuses_unchanged(1);
    assert!(error.contains("busy"));
    assert!(!error.contains("foreign-sensitive-vm"));
    assert!(!error.contains(&hex::encode("foreign-sensitive-vm")));
    drop(lease);
    fixture
        .signer
        .prune_through(&TenantId("local".into()), 1)
        .unwrap();
}

#[tokio::test]
async fn missing_opening_metadata_and_preseal_forensic_authority_fail_closed() {
    let fixture = Fixture::new(true, true, false).await;
    std::fs::remove_file(fixture.capture.join("capture-seed.json")).unwrap();
    fixture.refuses_unchanged(1);
    let fixture = Fixture::new(false, true, false).await;
    let mut manifest = fixture.manifest.clone();
    manifest.chunks.clear();
    manifest.sealed_unix_secs = None;
    manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&manifest).unwrap();
    write_manifest(&fixture.capture.join(MANIFEST_FILENAME), &manifest);
    fixture.refuses_unchanged(1);
}

#[tokio::test]
async fn retirement_intent_is_pinned_before_unlink_and_reconciliation_resumes() {
    use mvm_hostd::audit::emitter::AuditEmitter;
    use mvm_hostd::audit::transcript_retirement::{
        RetirementContext, RetirementOutcome, reconcile_capture,
    };
    let fixture = Fixture::new(true, true, true).await;
    let bytes = fixture.audit_bytes();
    assert!(
        fixture
            .capture
            .join(&fixture.manifest.chunks[0].file)
            .exists()
    );
    fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_RETIRED_EVENT));
    assert!(
        evidence::authenticated_retirement(
            fixture.root.path(),
            &key().verifying_key(),
            &fixture.manifest
        )
        .unwrap()
    );
    let emitter = AuditEmitter::with_dir(key(), fixture.root.path()).unwrap();
    let context = RetirementContext {
        root: fixture.root.path(),
        relative_capture: fixture.capture.strip_prefix(fixture.root.path()).unwrap(),
        capture_id: &fixture.manifest.capture_id,
        tenant: "local",
        vm: "vm",
        emitter: &emitter,
    };
    assert_eq!(
        reconcile_capture(context, 605_000).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 1
        }
    );
    assert_eq!(
        reconcile_capture(context, 605_001).unwrap(),
        RetirementOutcome::Retired {
            removed_segments: 0
        }
    );
    assert_eq!(
        fixture.audit_bytes(),
        bytes,
        "retry must not append another intent"
    );
    fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_RETIRED_EVENT));
}

#[tokio::test]
async fn ancestor_symlinks_and_inventory_bounds_refuse_without_outside_traversal() {
    let fixture = Fixture::new(false, false, false).await;
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("synthetic-outside"), b"untouched").unwrap();
    let family = fixture.root.path().join("workload-output");
    std::os::unix::fs::symlink(outside.path(), &family).unwrap();
    fixture.refuses_unchanged(1);
    assert_eq!(
        std::fs::read(outside.path().join("synthetic-outside")).unwrap(),
        b"untouched"
    );
    std::fs::remove_file(&family).unwrap();
    mvm_core::config::create_private_dir(&family).unwrap();
    for n in 0..4097 {
        std::fs::write(family.join(n.to_string()), []).unwrap();
    }
    assert!(fixture.refuses_unchanged(1).contains("bound exceeded"));
}

#[tokio::test]
async fn an_unsigned_legacy_claim_cannot_downgrade_enrolled_evidence() {
    let fixture = Fixture::new(false, true, false).await;
    let mut manifest = fixture.manifest.clone();
    manifest.format_version = 6;
    manifest.at_rest = None;
    manifest.sealed_unix_secs = None;
    manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&manifest).unwrap();
    write_manifest(&fixture.capture.join(MANIFEST_FILENAME), &manifest);
    let payload = std::fs::read(fixture.capture.join(&manifest.chunks[0].file)).unwrap();
    fixture.refuses_unchanged(fixture.seq(TRANSCRIPT_SEALED_EVENT));
    assert_eq!(
        std::fs::read(fixture.capture.join(&manifest.chunks[0].file)).unwrap(),
        payload
    );
}

#[tokio::test]
async fn metadata_tenants_are_validated_before_any_authority_lookup() {
    let outside = tempfile::tempdir().unwrap();
    let sentinel = outside.path().join("authority.jsonl");
    std::fs::write(&sentinel, b"synthetic outside authority must not be parsed").unwrap();
    let sibling = outside.path().file_name().unwrap().to_str().unwrap();
    for tenant in [
        format!("../{sibling}/authority"),
        outside
            .path()
            .join("authority")
            .to_str()
            .unwrap()
            .to_owned(),
    ] {
        for seedless in [false, true] {
            let fixture = Fixture::new(true, true, false).await;
            if seedless {
                std::fs::remove_file(fixture.capture.join("capture-seed.json")).unwrap();
                let mut manifest = fixture.manifest.clone();
                manifest.format_version = 6;
                manifest.at_rest = None;
                manifest.sealed_unix_secs = None;
                manifest.binding.tenant_id = tenant.clone();
                manifest.sealed_root_hex =
                    mvm_core::transcript::sealed_root_hex(&manifest).unwrap();
                write_manifest(&fixture.capture.join(MANIFEST_FILENAME), &manifest);
            } else {
                let path = fixture.capture.join("capture-seed.json");
                let mut seed: TranscriptManifest =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                seed.binding.tenant_id = tenant.clone();
                seed.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&seed).unwrap();
                write_manifest(&path, &seed);
            }
            let payload =
                std::fs::read(fixture.capture.join(&fixture.manifest.chunks[0].file)).unwrap();
            let error = fixture.refuses_unchanged(1);
            assert!(error.contains("invalid prune tenant component"), "{error}");
            assert!(
                !error.contains("authority refused"),
                "must not reach the outside authority reader"
            );
            assert_eq!(
                std::fs::read(fixture.capture.join(&fixture.manifest.chunks[0].file)).unwrap(),
                payload
            );
            assert_eq!(
                std::fs::read(&sentinel).unwrap(),
                b"synthetic outside authority must not be parsed"
            );
        }
    }
}

#[tokio::test]
async fn valid_foreign_tenant_authority_is_not_replaced_by_the_requested_tenant() {
    let fixture = Fixture::new(true, true, false).await;
    let path = fixture.capture.join("capture-seed.json");
    let mut seed: TranscriptManifest =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    seed.binding.tenant_id = "foreign".into();
    seed.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&seed).unwrap();
    write_manifest(&path, &seed);
    let mut manifest = fixture.manifest.clone();
    manifest.binding.tenant_id = "foreign".into();
    manifest.sealed_root_hex = mvm_core::transcript::sealed_root_hex(&manifest).unwrap();
    write_manifest(&fixture.capture.join(MANIFEST_FILENAME), &manifest);
    let foreign = FileAuditSigner::open(key(), fixture.root.path()).unwrap();
    let mut opening = event(
        TRANSCRIPT_OPENED_EVENT,
        evidence::opening_labels(&seed).unwrap(),
    );
    opening.tenant = TenantId("foreign".into());
    foreign.sign_and_emit(&opening).await.unwrap();
    let mut seal = event(
        TRANSCRIPT_SEALED_EVENT,
        [
            ("capture_id".into(), manifest.capture_id.clone()),
            ("vm_name".into(), manifest.binding.vm_name.clone()),
            ("transcript_root".into(), manifest.sealed_root_hex.clone()),
            ("chunk_count".into(), manifest.chunks.len().to_string()),
        ]
        .into(),
    );
    seal.tenant = TenantId("foreign".into());
    foreign.sign_and_emit(&seal).await.unwrap();
    fixture
        .signer
        .prune_through(&TenantId("local".into()), 1)
        .unwrap();
    assert!(
        evidence::authenticated_retirement(fixture.root.path(), &key().verifying_key(), &manifest,)
            .is_ok()
    );
}
