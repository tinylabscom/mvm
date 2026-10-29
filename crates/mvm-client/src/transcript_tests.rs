use super::*;
use mvm_core::crypto::aead;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::transcript::{
    self, AtRestRetention, CaptureBinding, Direction, RetentionPolicy, TranscriptManifest,
    TranscriptWriter, TranscriptWriterConfig,
};
use mvm_core::util::test_env::TestEnv;
use mvm_hostd::audit::{emitter::AuditEmitter, host_keypair};
use mvm_hostd::supervisor::{
    FileAuditSigner,
    audit::{AuditSigner, for_plan},
    audit_file::RotationPolicy,
};
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::Arc;

thread_local! {
    static AFTER_DISCOVERY: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

pub(super) fn after_discovery() {
    let callback = AFTER_DISCOVERY.with(|slot| slot.borrow_mut().take());
    if let Some(callback) = callback {
        callback();
    }
}

struct Hook(Option<Box<dyn FnOnce()>>);
impl Drop for Hook {
    fn drop(&mut self) {
        AFTER_DISCOVERY.with(|slot| *slot.borrow_mut() = self.0.take());
    }
}
fn hook(callback: impl FnOnce() + 'static) -> Hook {
    Hook(AFTER_DISCOVERY.with(|slot| slot.borrow_mut().replace(Box::new(callback))))
}

fn bounds() -> CaptureBounds {
    CaptureBounds {
        max_duration_secs: 3600,
        max_bytes: 16 * 1024 * 1024,
        max_chunks: 1024,
    }
}

#[test]
fn arm_refuses_static_tenant_symlink_without_external_writes_or_mode_repair() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let home = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(outside.path().join("sentinel"), b"untouched").unwrap();
    mvm_core::private_fs::ensure_private_dir(home.path().join("audit/transcripts")).unwrap();
    symlink(outside.path(), home.path().join("audit/transcripts/local")).unwrap();
    let before = snapshot(outside.path());
    let service = TranscriptService::at_home(home.path());
    assert!(service.arm("local", "vm", None, bounds()).is_err());
    assert_eq!(snapshot(outside.path()), before);
    assert!(!home.path().join("keys").exists());
    assert!(!home.path().join("audit.jsonl").exists());
}

#[test]
fn export_refuses_static_keys_symlink_without_following_existing_authority() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(true, false, b"secret");
    let moved = fixture.root.path().join("moved-keys");
    std::fs::rename(&fixture.service.keys_dir, &moved).unwrap();
    symlink(&moved, &fixture.service.keys_dir).unwrap();
    let before = snapshot(fixture.root.path());
    assert!(fixture.service.export("local", &fixture.id).is_err());
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn arm_and_export_refuse_fifo_keys_without_reading_or_replacing_them() {
    let fixture = Fixture::new(true, false, b"secret");
    let path = fixture
        .service
        .keys_dir
        .join(transcript::TRANSCRIPT_KEK_FILENAME);
    std::fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let before = snapshot(fixture.root.path());
    assert!(fixture.service.export("local", &fixture.id).is_err());
    assert!(fixture.service.arm("local", "vm", None, bounds()).is_err());
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn valid_capture_cannot_bypass_symlinked_audit_ancestor() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new(true, false, b"secret");
    let moved = fixture.root.path().join("moved-audit");
    std::fs::rename(&fixture.service.audit_dir, &moved).unwrap();
    symlink(&moved, &fixture.service.audit_dir).unwrap();
    let before = snapshot(fixture.root.path());
    assert!(fixture.service.list(None).is_err());
    assert!(fixture.service.disarm("local", &fixture.id).is_err());
    assert!(fixture.service.export("local", &fixture.id).is_err());
    assert!(fixture.service.reconcile(&fixture.request()).is_err());
    assert!(fixture.service.arm("local", "vm", None, bounds()).is_err());
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn fixed_host_authority_names_match_the_canonical_delegate() {
    assert_eq!(host_keypair::PUBLIC_FILENAME, "host-signer.pub");
    assert_eq!(host_keypair::SECRET_FILENAME, "host-signer.ed25519");
}

fn snapshot(root: &Path) -> Vec<(PathBuf, u32, String)> {
    use std::os::unix::fs::MetadataExt;
    fn walk(base: &Path, path: &Path, out: &mut Vec<(PathBuf, u32, String)>) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        let digest = if metadata.is_file() {
            mvm_core::plan::bundle::sha256_hex(&std::fs::read(path).unwrap())
        } else if metadata.is_symlink() {
            std::fs::read_link(path).unwrap().display().to_string()
        } else {
            String::new()
        };
        out.push((
            path.strip_prefix(base).unwrap().into(),
            metadata.mode() & 0o7777,
            digest,
        ));
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).unwrap() {
                walk(base, &entry.unwrap().path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

struct Fixture {
    root: tempfile::TempDir,
    _env: TestEnv,
    service: TranscriptService,
    id: String,
    manifest: TranscriptManifest,
    plan: mvm_core::plan::ExecutionPlan,
    emitter: AuditEmitter,
    signer: Arc<FileAuditSigner>,
}

impl Fixture {
    fn new(anchor: bool, expired: bool, bytes: &[u8]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.isolate_mvm_home(root.path());
        let service = TranscriptService::at_home(root.path());
        let id = service.arm("local", "vm", None, bounds()).unwrap();
        let dir = service.transcripts_dir.join("local").join(&id);
        let kek = transcript::load_kek(&service.keys_dir).unwrap().unwrap();
        let key = aead::Key::from_bytes([7; 32]);
        let now = if expired {
            100
        } else {
            transcript::retention_now().unwrap()
        };
        let mut writer = TranscriptWriter::new(
            &dir,
            key,
            TranscriptWriterConfig {
                capture_id: id.clone(),
                binding: CaptureBinding {
                    tenant_id: "local".into(),
                    vm_name: "vm".into(),
                    session_id: None,
                },
                bounds: bounds(),
                retention: RetentionPolicy::FailClosed,
                created_unix_secs: now,
                at_rest: Some(AtRestRetention::default()),
                generation_budget: None,
                payload_encoding: transcript::PayloadEncoding::Raw,
                recipient: transcript::TRANSCRIPT_KEK_RECIPIENT.into(),
                wrapped_data_key_b64: transcript::wrap_data_key(
                    &kek,
                    &aead::Key::from_bytes([7; 32]),
                ),
            },
        )
        .unwrap();
        writer.push(Direction::Egress, bytes).unwrap();
        // This fixture owns and finishes its producer. The service never seals it.
        let manifest = writer.finalize_at(if expired { 200 } else { now }).unwrap();
        drop(writer);
        mvm_core::atomic_io::write_private(
            &dir.join(transcript::MANIFEST_FILENAME),
            &serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let keys = host_keypair::load_or_init_at(&service.keys_dir).unwrap();
        let signer = Arc::new(
            FileAuditSigner::open(keys.signing.clone(), &service.audit_dir)
                .unwrap()
                .with_rotation(RotationPolicy::at_bytes(1)),
        );
        let emitter =
            AuditEmitter::with_primary_signer(keys.signing, &service.audit_dir, signer.clone())
                .unwrap();
        let plan = PlanFixture::new()
            .tenant("local")
            .workload("original-workload")
            .build();
        if anchor {
            emitter
                .emit_transcript_sealed(
                    &plan,
                    &id,
                    "vm",
                    &manifest.sealed_root_hex,
                    manifest.chunks.len(),
                    false,
                )
                .unwrap();
        }
        Self {
            root,
            _env: env,
            service,
            id,
            manifest,
            plan,
            emitter,
            signer,
        }
    }
    fn dir(&self) -> PathBuf {
        self.service.transcripts_dir.join("local").join(&self.id)
    }
    fn request(&self) -> TranscriptReconcileRequest {
        TranscriptReconcileRequest {
            tenant: "local".into(),
            capture_id: self.id.clone(),
        }
    }
    fn append(&self, kind: &str) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime
            .block_on(
                self.signer
                    .sign_and_emit(&for_plan(&self.plan, None, kind, [])),
            )
            .unwrap();
    }
}

#[test]
fn absence_and_invalid_components_do_not_initialize_keys_audit_or_capture_storage() {
    let root = tempfile::tempdir().unwrap();
    let service = TranscriptService::at_home(root.path());
    let before = snapshot(root.path());
    assert!(service.list(None).unwrap().is_empty());
    assert!(service.disarm("local", "absent").is_err());
    assert!(service.export("local", "absent").is_err());
    assert!(
        service
            .reconcile(&TranscriptReconcileRequest {
                tenant: "local".into(),
                capture_id: "absent".into()
            })
            .is_err()
    );
    for component in ["", ".", "..", "../escape", "a/b", "a\\b", "\0"] {
        assert!(service.arm(component, "vm", None, bounds()).is_err());
    }
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn manual_arm_is_encryption_only_and_disarm_cannot_bootstrap_a_seal() {
    let root = tempfile::tempdir().unwrap();
    let service = TranscriptService::at_home(root.path());
    let id = service
        .arm("local", "vm", Some("session"), bounds())
        .unwrap();
    assert!(
        service
            .keys_dir
            .join(transcript::TRANSCRIPT_KEK_FILENAME)
            .exists()
    );
    assert!(
        !service
            .keys_dir
            .join(host_keypair::SECRET_FILENAME)
            .exists()
    );
    assert!(
        !service
            .keys_dir
            .join(host_keypair::PUBLIC_FILENAME)
            .exists()
    );
    assert!(!service.audit_dir.join("local.jsonl").exists());
    let metadata = service.list(None).unwrap();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].capture_id, id);
    let before = snapshot(root.path());
    assert!(service.disarm("local", &id).is_err());
    assert!(service.export("local", &id).is_err());
    assert!(
        service
            .reconcile(&TranscriptReconcileRequest {
                tenant: "local".into(),
                capture_id: id
            })
            .is_err()
    );
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn signed_original_seal_is_idempotently_recognized_without_signing_or_current_plan() {
    let fixture = Fixture::new(true, false, b"private-payload");
    let current = fixture.root.path().join("vms/vm");
    std::fs::create_dir_all(&current).unwrap();
    std::fs::write(current.join("plan.json"), b"not an original plan authority").unwrap();
    std::fs::remove_file(fixture.service.keys_dir.join(host_keypair::SECRET_FILENAME)).unwrap();
    let before = snapshot(fixture.root.path());
    fixture.service.disarm("local", &fixture.id).unwrap();
    fixture.service.disarm("local", &fixture.id).unwrap();
    assert_eq!(
        fixture.service.export("local", &fixture.id).unwrap(),
        b"private-payload"
    );
    assert!(fixture.service.reconcile(&fixture.request()).is_err());
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn missing_and_conflicting_original_seals_refuse_without_mutation() {
    for anchor in [false, true] {
        let fixture = Fixture::new(anchor, false, b"payload");
        if anchor {
            fixture
                .emitter
                .emit_transcript_sealed(
                    &fixture.plan,
                    &fixture.id,
                    "vm",
                    &fixture.manifest.sealed_root_hex,
                    fixture.manifest.chunks.len(),
                    false,
                )
                .unwrap();
        }
        let before = snapshot(fixture.root.path());
        assert!(fixture.service.disarm("local", &fixture.id).is_err());
        assert!(fixture.service.export("local", &fixture.id).is_err());
        assert!(fixture.service.reconcile(&fixture.request()).is_err());
        assert_eq!(snapshot(fixture.root.path()), before);
    }
}

#[test]
fn seal_in_rotated_history_remains_authority_not_only_the_active_file() {
    let fixture = Fixture::new(true, false, b"payload");
    fixture.append("plan.observed");
    assert!(
        fixture
            .service
            .audit_dir
            .join("local.seg-000001.jsonl")
            .exists()
    );
    let before = snapshot(fixture.root.path());
    fixture.service.disarm("local", &fixture.id).unwrap();
    assert_eq!(
        fixture.service.export("local", &fixture.id).unwrap(),
        b"payload"
    );
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn busy_exclusive_owner_has_no_unlocked_read_or_disarm_fallback() {
    let fixture = Fixture::new(true, false, b"payload");
    let owner =
        mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&fixture.dir()).unwrap();
    let before = snapshot(fixture.root.path());
    assert!(fixture.service.list(None).is_err());
    assert!(fixture.service.export("local", &fixture.id).is_err());
    assert!(fixture.service.disarm("local", &fixture.id).is_err());
    assert!(fixture.service.reconcile(&fixture.request()).is_err());
    assert_eq!(snapshot(fixture.root.path()), before);
    drop(owner);
}

#[test]
fn missing_or_wrong_encryption_key_is_not_replaced_and_never_returns_payload() {
    let fixture = Fixture::new(true, false, b"private-payload");
    let path = fixture
        .service
        .keys_dir
        .join(transcript::TRANSCRIPT_KEK_FILENAME);
    std::fs::remove_file(&path).unwrap();
    let before = snapshot(fixture.root.path());
    assert!(fixture.service.export("local", &fixture.id).is_err());
    assert_eq!(snapshot(fixture.root.path()), before);
    mvm_core::atomic_io::write_private(&path, &[99; 32]).unwrap();
    let before = snapshot(fixture.root.path());
    let error = fixture.service.export("local", &fixture.id).unwrap_err();
    assert!(!format!("{error:#} {error:#?}").contains("private-payload"));
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn malformed_leased_manifest_diagnostics_are_redacted_including_source_chains() {
    let root = tempfile::tempdir().unwrap();
    let service = TranscriptService::at_home(root.path());
    let id = service.arm("local", "vm", None, bounds()).unwrap();
    let path = service
        .transcripts_dir
        .join("local")
        .join(&id)
        .join(transcript::MANIFEST_FILENAME);
    let marker = "private-leased-manifest-marker";
    mvm_core::atomic_io::write_private(
        &path,
        &serde_json::to_vec(&serde_json::json!({"format_version": marker})).unwrap(),
    )
    .unwrap();
    let before = snapshot(root.path());
    for error in [
        service.list(None).unwrap_err(),
        service.export("local", &id).unwrap_err(),
        service.disarm("local", &id).unwrap_err(),
        service
            .reconcile(&TranscriptReconcileRequest {
                tenant: "local".into(),
                capture_id: id.clone(),
            })
            .unwrap_err(),
    ] {
        assert!(!format!("{error} {error:#} {error:?} {error:#?}").contains(marker));
        for cause in error.chain() {
            assert!(!format!("{cause} {cause:?}").contains(marker));
        }
        let nested = error.context("caller context");
        assert!(!format!("{nested:#} {nested:#?}").contains(marker));
    }
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn export_holds_one_read_lease_through_delivery_and_writer_failure_is_not_success() {
    struct RefusingSink {
        dir: PathBuf,
        prefix: Vec<u8>,
    }
    impl std::io::Write for RefusingSink {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(
                mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&self.dir)
                    .is_err()
            );
            if self.prefix.is_empty() {
                self.prefix.push(bytes[0]);
                Ok(1)
            } else {
                Err(std::io::Error::other("sink refused"))
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let fixture = Fixture::new(true, false, b"payload");
    let before = snapshot(fixture.root.path());
    let mut sink = RefusingSink {
        dir: fixture.dir(),
        prefix: Vec::new(),
    };
    assert!(
        fixture
            .service
            .export_to_writer("local", &fixture.id, &mut sink)
            .is_err()
    );
    assert_eq!(sink.prefix, b"p");
    assert_eq!(snapshot(fixture.root.path()), before);
    drop(
        mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&fixture.dir()).unwrap(),
    );
}

#[test]
fn memory_export_bound_does_not_restrict_the_streaming_api() {
    let bytes = vec![7; MAX_IN_MEMORY_EXPORT_BYTES + 1];
    let fixture = Fixture::new(true, false, &bytes);
    let error = fixture.service.export("local", &fixture.id).unwrap_err();
    assert!(error.to_string().contains("size limit"));
    let mut count = std::io::sink();
    assert_eq!(
        fixture
            .service
            .export_to_writer("local", &fixture.id, &mut count)
            .unwrap(),
        bytes.len() as u64
    );
}

#[test]
fn expired_payload_is_refused_before_any_sink_delivery() {
    let fixture = Fixture::new(true, true, b"payload");
    let before = snapshot(fixture.root.path());
    let mut output = Vec::new();
    assert!(
        fixture
            .service
            .export_to_writer("local", &fixture.id, &mut output)
            .is_err()
    );
    assert!(output.is_empty());
    assert_eq!(snapshot(fixture.root.path()), before);
}

#[test]
fn retirement_delegates_original_attribution_and_resumes_without_current_plan() {
    let fixture = Fixture::new(true, true, b"payload");
    let plan_dir = fixture.root.path().join("vms/vm");
    std::fs::create_dir_all(&plan_dir).unwrap();
    std::fs::write(
        plan_dir.join("plan.json"),
        b"mutable replacement is not authority",
    )
    .unwrap();
    let ciphertext = fixture.dir().join(&fixture.manifest.chunks[0].file);
    let bytes = std::fs::read(&ciphertext).unwrap();
    assert_eq!(
        fixture.service.reconcile(&fixture.request()).unwrap(),
        TranscriptReconcileReport::Retired {
            removed_segments: 1
        }
    );
    assert!(!ciphertext.exists());
    let entries = mvm_hostd::supervisor::verify_audit_chain_entries(
        &fixture.service.audit_dir.join("local.jsonl"),
        &fixture.emitter.verifying_key(),
    )
    .unwrap();
    let original = entries
        .iter()
        .find(|entry| entry.event == transcript::evidence::TRANSCRIPT_SEALED_EVENT)
        .unwrap();
    let retired = entries
        .iter()
        .find(|entry| entry.event == transcript::evidence::TRANSCRIPT_RETIRED_EVENT)
        .unwrap();
    let mut expected = original.clone();
    expected.timestamp = retired.timestamp;
    expected.event = retired.event.clone();
    expected.labels = retired.labels.clone();
    assert_eq!(*retired, expected);
    // Model an interrupted cleanup with already durable retirement evidence.
    mvm_core::atomic_io::write_private(&ciphertext, &bytes).unwrap();
    assert!(
        fixture
            .service
            .export("local", &fixture.id)
            .unwrap_err()
            .to_string()
            .contains("retired")
    );
    assert_eq!(
        fixture.service.reconcile(&fixture.request()).unwrap(),
        TranscriptReconcileReport::Retired {
            removed_segments: 1
        }
    );
    assert_eq!(
        fixture.service.reconcile(&fixture.request()).unwrap(),
        TranscriptReconcileReport::Retired {
            removed_segments: 0
        }
    );
}

#[test]
fn retirement_reacquires_and_rechecks_after_discovery_lease_release() {
    let fixture = Fixture::new(true, true, b"payload");
    let dir = fixture.dir();
    let root = fixture.root.path().to_path_buf();
    let mut changed = fixture.manifest.clone();
    changed.binding.vm_name = "other-vm".into();
    changed.sealed_root_hex = transcript::sealed_root_hex(&changed).unwrap();
    let observed = std::rc::Rc::new(RefCell::new(None));
    let after = observed.clone();
    let _hook = hook(move || {
        let exclusive =
            mvm_core::transcript::secure_cleanup::CaptureDirectory::for_writer(&dir).unwrap();
        mvm_core::atomic_io::write_private(
            &dir.join(transcript::MANIFEST_FILENAME),
            &serde_json::to_vec(&changed).unwrap(),
        )
        .unwrap();
        drop(exclusive);
        *after.borrow_mut() = Some(snapshot(&root));
    });
    assert!(fixture.service.reconcile(&fixture.request()).is_err());
    assert_eq!(
        snapshot(fixture.root.path()),
        observed.borrow().as_ref().unwrap().clone()
    );
}

#[test]
fn valid_pruned_history_cannot_be_used_to_assert_a_missing_original_seal() {
    let root = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(root.path());
    let keys = host_keypair::load_or_init_at(&root.path().join("keys")).unwrap();
    mvm_core::private_fs::ensure_private_dir(root.path().join("audit")).unwrap();
    let signer = FileAuditSigner::open(keys.signing, root.path().join("audit"))
        .unwrap()
        .with_rotation(RotationPolicy::at_bytes(1));
    let plan = PlanFixture::new().tenant("local").build();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for _ in 0..3 {
        runtime
            .block_on(signer.sign_and_emit(&for_plan(&plan, None, "plan.observed", [])))
            .unwrap();
    }
    signer
        .prune_through(&mvm_core::plan::TenantId("local".into()), 1)
        .unwrap();
    let service = TranscriptService::at_home(root.path());
    let id = service.arm("local", "vm", None, bounds()).unwrap();
    let capture = mvm_core::transcript::secure_cleanup::CaptureDirectory::open(
        &service.transcripts_dir,
        &relative("local", &id).unwrap(),
    )
    .unwrap();
    let manifest = capture.read_manifest().unwrap();
    let error = transcript::evidence::authenticated_seal(
        &service.audit_dir,
        &service.store().unwrap().existing_host_public_key().unwrap(),
        &manifest,
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("pruned"));
    drop(capture);
    let before = snapshot(root.path());
    assert!(service.disarm("local", &id).is_err());
    assert!(service.export("local", &id).is_err());
    assert_eq!(snapshot(root.path()), before);
}

#[test]
fn memory_sink_is_bounded_independently_of_manifest_claims() {
    use std::io::Write;
    let mut sink = BoundedExport::default();
    assert!(
        sink.write_all(&vec![0; MAX_IN_MEMORY_EXPORT_BYTES + 1])
            .is_err()
    );
    assert!(sink.0.is_empty());
}
