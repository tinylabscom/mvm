#![cfg(unix)]

use std::path::{Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use mvm_client::stream::{
    KindFilter, OutputLocator, OutputRequest, RecordOrigin, StreamOpts, VerifiedOutput,
    VerifiedOutputRequest, open_verified_output_at,
};
use mvm_contract::stream::{StreamKind, StreamRecord, StreamSource};
use mvm_core::config;
use mvm_core::plan::{PlanId, TenantId};
use mvm_core::stream_client::protected::ProtectedRun;
use mvm_core::transcript::{
    self, AtRestRetention, CaptureBinding, CaptureBounds, Direction, MANIFEST_FILENAME,
    PayloadEncoding, RetentionPolicy, TranscriptManifest, TranscriptWriter, TranscriptWriterConfig,
};
use mvm_hostd::supervisor::{AuditSigner, FileAuditSigner, PlanAuditEntry};

struct Fixture {
    _root: tempfile::TempDir,
    locator: OutputLocator,
    audit: PathBuf,
    run_dir: PathBuf,
    key: SigningKey,
    manifests: Vec<TranscriptManifest>,
}

impl Fixture {
    fn new(kinds: &[StreamKind]) -> Self {
        let root = tempfile::tempdir().unwrap();
        let locator = OutputLocator {
            vm: "vm".into(),
            socket: root.path().join("broker.sock"),
            transcript_dir: root.path().join("legacy"),
            protected_transcript_dir: Some(root.path().join("protected")),
            console_log: root.path().join("console.log"),
            keys_dir: root.path().join("keys"),
        };
        config::create_private_dir(&locator.keys_dir).unwrap();
        let protected = locator.protected_transcript_dir.as_ref().unwrap();
        config::create_private_dir(protected).unwrap();
        let run = ProtectedRun {
            version: 1,
            run: "1-1".into(),
            persists: true,
        };
        run.publish(protected).unwrap();
        let run_dir = run.directory(protected).unwrap();
        config::create_private_dir(&run_dir).unwrap();
        let audit = root.path().join("audit");
        config::create_private_dir(&audit).unwrap();
        let key = SigningKey::from_bytes(&rand::random());
        std::fs::write(
            locator.keys_dir.join("host-signer.pub"),
            key.verifying_key().as_bytes(),
        )
        .unwrap();
        let kek = transcript::load_or_init_kek(&locator.keys_dir).unwrap();
        let now = transcript::retention_now().unwrap();
        let mut previous = [0; 32];
        let mut manifests = Vec::new();
        for (index, kind) in kinds.iter().enumerate() {
            let dir = run_dir.join(format!("{index:020}"));
            config::create_private_dir(&dir).unwrap();
            let data_key = mvm_core::crypto::aead::Key::random();
            let wrapped = transcript::wrap_data_key(&kek, &data_key);
            let mut writer = TranscriptWriter::new(
                &dir,
                data_key,
                TranscriptWriterConfig {
                    capture_id: format!("capture-{index}"),
                    binding: CaptureBinding {
                        tenant_id: "local".into(),
                        vm_name: "vm".into(),
                        session_id: None,
                    },
                    bounds: CaptureBounds {
                        max_duration_secs: 60,
                        max_bytes: 8192,
                        max_chunks: 16,
                    },
                    retention: RetentionPolicy::FailClosed,
                    at_rest: Some(AtRestRetention::default()),
                    generation_budget: None,
                    payload_encoding: PayloadEncoding::StreamRecordV1,
                    created_unix_secs: now,
                    recipient: "test".into(),
                    wrapped_data_key_b64: wrapped,
                },
            )
            .unwrap();
            let record = StreamRecord {
                seq: index as u64,
                source: StreamSource::Console,
                kind: *kind,
                host_unix_nanos: now * 1_000_000_000,
                prev_hash: previous,
                payload: format!("record-{index}\n").into_bytes(),
            };
            previous = record.hash();
            let direction = match kind {
                StreamKind::Stdout => Direction::Stdout,
                StreamKind::Stderr => Direction::Stderr,
                _ => panic!("fixture only needs stdout/stderr"),
            };
            writer
                .push(direction, &serde_json::to_vec(&record).unwrap())
                .unwrap();
            manifests.push(writer.finalize_at(now).unwrap());
        }
        let fixture = Self {
            _root: root,
            locator,
            audit,
            run_dir,
            key,
            manifests,
        };
        fixture.write_manifests();
        fixture.sign(&fixture.anchors());
        fixture
    }

    fn write_manifests(&self) {
        for (index, manifest) in self.manifests.iter().enumerate() {
            std::fs::write(
                self.manifest_path(index),
                serde_json::to_vec(manifest).unwrap(),
            )
            .unwrap();
        }
    }

    fn manifest_path(&self, index: usize) -> PathBuf {
        self.run_dir
            .join(format!("{index:020}"))
            .join(MANIFEST_FILENAME)
    }

    fn anchors(&self) -> Vec<PlanAuditEntry> {
        self.manifests
            .iter()
            .map(|manifest| PlanAuditEntry {
                timestamp: chrono::Utc::now(),
                tenant: TenantId("local".into()),
                plan_id: PlanId("sha256:exact-plan".into()),
                plan_version: 1,
                bundle_id: None,
                bundle_version: None,
                image_name: "test-image".into(),
                image_sha256: "00".repeat(32),
                caller_commitment: None,
                event: "gateway.transcript_sealed".into(),
                labels: [
                    ("capture_id".into(), manifest.capture_id.clone()),
                    ("vm_name".into(), manifest.binding.vm_name.clone()),
                    ("transcript_root".into(), manifest.sealed_root_hex.clone()),
                    ("chunk_count".into(), manifest.chunks.len().to_string()),
                    ("adopted".into(), manifest.adopted.to_string()),
                ]
                .into(),
            })
            .collect()
    }

    fn sign(&self, entries: &[PlanAuditEntry]) {
        let chain = self.audit.join("local.jsonl");
        if chain.exists() {
            std::fs::remove_file(chain).unwrap();
        }
        let signer = FileAuditSigner::open(self.key.clone(), &self.audit).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        for entry in entries {
            runtime.block_on(signer.sign_and_emit(entry)).unwrap();
        }
    }

    fn open(
        &self,
        output: OutputRequest,
    ) -> Result<VerifiedOutput, mvm_client::stream::VerifiedOutputError> {
        self.open_identity(
            &self.locator,
            &self.key.verifying_key(),
            "local",
            "sha256:exact-plan",
            output,
        )
    }

    fn open_identity(
        &self,
        locator: &OutputLocator,
        key: &VerifyingKey,
        tenant: &str,
        plan: &str,
        output: OutputRequest,
    ) -> Result<VerifiedOutput, mvm_client::stream::VerifiedOutputError> {
        open_verified_output_at(
            locator,
            &self.audit.join("local.jsonl"),
            VerifiedOutputRequest {
                tenant,
                plan_id: plan,
                trusted_key: key,
                output,
            },
        )
    }
}

fn payloads(mut verified: VerifiedOutput) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    while let Some(record) = verified.next_output().unwrap() {
        assert_eq!(record.origin, RecordOrigin::Durable);
        result.push(record.payload);
    }
    result
}

#[test]
fn sealed_generations_bind_before_delivery_and_never_connect_or_fallback() {
    let fixture = Fixture::new(&[StreamKind::Stdout, StreamKind::Stderr]);
    let listener = std::os::unix::net::UnixListener::bind(&fixture.locator.socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::fs::write(&fixture.locator.console_log, b"untrusted console").unwrap();
    let mut verified = fixture.open(OutputRequest::default()).unwrap();
    assert_eq!(verified.report().generations, 2);
    assert_eq!(verified.report().retired_generations, 0);
    assert_eq!(
        verified.next_output().unwrap().unwrap().kind,
        StreamKind::Stdout
    );
    let second = verified.next_output().unwrap().unwrap();
    assert_eq!(
        (second.seq, second.kind, second.payload),
        (1, StreamKind::Stderr, b"record-1\n".to_vec())
    );
    assert!(verified.next_output().unwrap().is_none());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        payloads(
            fixture
                .open(OutputRequest {
                    history_tail: Some(1),
                    ..Default::default()
                })
                .unwrap()
        ),
        [b"record-1\n".to_vec()]
    );
    assert_eq!(
        payloads(
            fixture
                .open(OutputRequest {
                    opts: StreamOpts::builder()
                        .kinds(KindFilter::only(StreamKind::Stdout))
                        .build(),
                    ..Default::default()
                })
                .unwrap()
        ),
        [b"record-0\n".to_vec()]
    );
}

#[test]
fn exact_identity_and_trusted_key_are_required_before_stream_is_returned() {
    let fixture = Fixture::new(&[StreamKind::Stdout]);
    for (tenant, plan) in [
        ("other", "sha256:exact-plan"),
        ("local", "sha256:exact"),
        ("local", "image"),
        ("", "sha256:exact-plan"),
    ] {
        assert!(
            fixture
                .open_identity(
                    &fixture.locator,
                    &fixture.key.verifying_key(),
                    tenant,
                    plan,
                    OutputRequest::default()
                )
                .is_err()
        );
    }
    let wrong = SigningKey::from_bytes(&rand::random()).verifying_key();
    assert!(
        fixture
            .open_identity(
                &fixture.locator,
                &wrong,
                "local",
                "sha256:exact-plan",
                OutputRequest::default()
            )
            .is_err()
    );
    let locator = OutputLocator {
        vm: "other".into(),
        ..fixture.locator.clone()
    };
    assert!(
        fixture
            .open_identity(
                &locator,
                &fixture.key.verifying_key(),
                "local",
                "sha256:exact-plan",
                OutputRequest::default()
            )
            .is_err()
    );
}

#[test]
fn invalid_or_unbound_selected_capture_refuses_even_when_tail_zero_or_filtered_out() {
    let fixture = Fixture::new(&[StreamKind::Stdout, StreamKind::Stderr]);
    let original = fixture.anchors();
    for label in ["transcript_root", "chunk_count", "adopted", "vm_name"] {
        let mut entries = original.clone();
        entries[0].labels.insert(label.into(), "wrong".into());
        fixture.sign(&entries);
        assert!(
            fixture
                .open(OutputRequest {
                    history_tail: Some(0),
                    ..Default::default()
                })
                .is_err(),
            "{label}"
        );
    }
    let mut duplicate = original.clone();
    duplicate.push(original[0].clone());
    fixture.sign(&duplicate);
    assert!(fixture.open(OutputRequest::default()).is_err());
    fixture.sign(&original[1..]);
    assert!(
        fixture
            .open(OutputRequest {
                opts: StreamOpts::builder()
                    .kinds(KindFilter::only(StreamKind::Stderr))
                    .build(),
                ..Default::default()
            })
            .is_err()
    );
}

#[test]
fn unsealed_missing_legacy_and_tampered_history_never_use_console() {
    let mut fixture = Fixture::new(&[StreamKind::Stdout]);
    std::fs::write(&fixture.locator.console_log, b"fallback forbidden").unwrap();
    let original = fixture.manifests[0].clone();
    fixture.manifests[0].sealed_unix_secs = None;
    fixture.manifests[0].sealed_root_hex =
        transcript::sealed_root_hex(&fixture.manifests[0]).unwrap();
    fixture.write_manifests();
    fixture.sign(&fixture.anchors());
    assert!(
        fixture
            .open(OutputRequest::default())
            .err()
            .unwrap()
            .to_string()
            .contains("unsealed")
    );
    fixture.manifests[0] = original.clone();
    fixture.manifests[0].at_rest = None;
    fixture.write_manifests();
    assert!(
        fixture
            .open(OutputRequest::default())
            .err()
            .unwrap()
            .to_string()
            .contains("legacy")
    );
    std::fs::remove_file(fixture.manifest_path(0)).unwrap();
    assert!(
        fixture
            .open(OutputRequest::default())
            .err()
            .unwrap()
            .to_string()
            .contains("incomplete")
    );
    fixture.manifests[0] = original;
    fixture.write_manifests();
    fixture.sign(&fixture.anchors());
    fixture.manifests[0].sealed_root_hex = "00".repeat(32);
    fixture.write_manifests();
    assert!(fixture.open(OutputRequest::default()).is_err());
    std::fs::remove_file(
        fixture
            .locator
            .protected_transcript_dir
            .as_ref()
            .unwrap()
            .join("protected-run.json"),
    )
    .unwrap();
    assert!(
        fixture
            .open(OutputRequest::default())
            .err()
            .unwrap()
            .to_string()
            .contains("missing")
    );
}

#[test]
fn adopted_history_is_explicit_and_cannot_enable_console_fallback() {
    let mut fixture = Fixture::new(&[StreamKind::Stdout]);
    fixture.manifests[0].adopted = true;
    fixture.manifests[0].refused_chunks = 1;
    fixture.manifests[0].refused_bytes = 9;
    fixture.manifests[0].sealed_root_hex =
        transcript::sealed_root_hex(&fixture.manifests[0]).unwrap();
    fixture.write_manifests();
    fixture.sign(&fixture.anchors());
    std::fs::write(&fixture.locator.console_log, b"forbidden").unwrap();
    let verified = fixture.open(OutputRequest::default()).unwrap();
    assert!(verified.stream().truncation().unwrap().adopted);
    assert_eq!(payloads(verified), [b"record-0\n".to_vec()]);
}

#[test]
fn retired_generations_remain_visible_beside_readable_output_in_either_order() {
    for retired_index in [0, 1] {
        let mut fixture = Fixture::new(&[StreamKind::Stdout, StreamKind::Stderr]);
        let old = transcript::retention_now().unwrap() - 1_000_000;
        let manifest = &mut fixture.manifests[retired_index];
        manifest.created_unix_secs = old;
        manifest.sealed_unix_secs = Some(old);
        manifest.sealed_root_hex = transcript::sealed_root_hex(manifest).unwrap();
        fixture.write_manifests();
        fixture.sign(&fixture.anchors());
        let verified = fixture.open(OutputRequest::default()).unwrap();
        assert_eq!(verified.report().retired_generations, 1);
        assert_eq!(
            payloads(verified),
            [format!("record-{}\n", 1 - retired_index).into_bytes()]
        );
    }
}

#[test]
fn retention_custody_is_rechecked_after_open_and_route_changes_cannot_splice() {
    let fixture = Fixture::new(&[StreamKind::Stdout]);
    let mut verified = fixture.open(OutputRequest::default()).unwrap();
    let root = fixture.locator.protected_transcript_dir.as_ref().unwrap();
    ProtectedRun {
        version: 1,
        run: "2-2".into(),
        persists: true,
    }
    .publish(root)
    .unwrap();
    assert!(fixture.open(OutputRequest::default()).is_err());
    assert_eq!(
        verified.next_output().unwrap().unwrap().payload,
        b"record-0\n"
    );
    ProtectedRun {
        version: 1,
        run: "1-1".into(),
        persists: true,
    }
    .publish(root)
    .unwrap();
    let mut verified = fixture.open(OutputRequest::default()).unwrap();
    std::fs::remove_file(fixture.locator.keys_dir.join("host-signer.pub")).unwrap();
    assert!(verified.next_output().is_err());
    assert_eq!(verified.stream().history_len(), 0);
}

#[test]
fn excessive_generation_enumeration_and_follow_are_refused() {
    let fixture = Fixture::new(&[StreamKind::Stdout]);
    assert!(
        fixture
            .open(OutputRequest {
                opts: StreamOpts::builder().follow(true).build(),
                ..Default::default()
            })
            .is_err()
    );
    for index in 1..4097 {
        std::fs::create_dir(fixture.run_dir.join(format!("{index:020}"))).unwrap();
    }
    assert!(
        fixture
            .open(OutputRequest::default())
            .err()
            .unwrap()
            .to_string()
            .contains("generation directory")
    );
}

#[test]
fn corrupt_ciphertext_refuses_before_any_record_is_delivered() {
    let fixture = Fixture::new(&[StreamKind::Stdout, StreamKind::Stderr]);
    let generation = fixture.manifest_path(1).parent().unwrap().to_owned();
    corrupt_segment(&generation);
    assert!(fixture.open(OutputRequest::default()).is_err());
}

fn corrupt_segment(dir: &Path) {
    let segment = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|extension| extension == "seg"))
        .unwrap();
    let mut bytes = std::fs::read(&segment).unwrap();
    bytes[0] ^= 1;
    std::fs::write(segment, bytes).unwrap();
}

#[test]
fn authenticated_empty_and_retired_output_are_not_missing_history() {
    let mut fixture = Fixture::new(&[StreamKind::Stdout]);
    fixture.manifests[0].chunks.clear();
    fixture.manifests[0].sealed_root_hex =
        transcript::sealed_root_hex(&fixture.manifests[0]).unwrap();
    fixture.write_manifests();
    fixture.sign(&fixture.anchors());
    let mut empty = fixture.open(OutputRequest::default()).unwrap();
    assert_eq!(empty.report().generations, 1);
    assert_eq!(empty.report().retired_generations, 0);
    assert_eq!(
        empty.stream().empty_history(),
        Some(mvm_client::stream::EmptyHistory::CaptureEmpty)
    );
    assert!(empty.next_output().unwrap().is_none());
    let old = transcript::retention_now().unwrap() - 1_000_000;
    fixture.manifests[0].created_unix_secs = old;
    fixture.manifests[0].sealed_unix_secs = Some(old);
    fixture.manifests[0].sealed_root_hex =
        transcript::sealed_root_hex(&fixture.manifests[0]).unwrap();
    fixture.write_manifests();
    fixture.sign(&fixture.anchors());
    let mut retired = fixture.open(OutputRequest::default()).unwrap();
    assert_eq!(retired.report().retired_generations, 1);
    assert_eq!(
        retired.stream().empty_history(),
        Some(mvm_client::stream::EmptyHistory::Retired)
    );
    assert!(retired.next_output().unwrap().is_none());
}

#[test]
fn manifest_replacement_after_open_does_not_change_authenticated_buffered_bytes() {
    let fixture = Fixture::new(&[StreamKind::Stdout]);
    let verified = fixture.open(OutputRequest::default()).unwrap();
    std::fs::write(fixture.manifest_path(0), b"replaced after open").unwrap();
    assert_eq!(payloads(verified), [b"record-0\n".to_vec()]);
    assert!(fixture.open(OutputRequest::default()).is_err());
}

#[test]
fn authenticated_retirement_after_open_revokes_buffered_output() {
    let fixture = Fixture::new(&[StreamKind::Stdout]);
    let mut verified = fixture.open(OutputRequest::default()).unwrap();
    let mut entries = fixture.anchors();
    let mut retirement = entries[0].clone();
    retirement.event = transcript::evidence::TRANSCRIPT_RETIRED_EVENT.into();
    retirement.labels = transcript::evidence::labels(&fixture.manifests[0]).unwrap();
    entries.push(retirement);
    fixture.sign(&entries);
    assert!(verified.next_output().is_err());
    assert_eq!(verified.stream().history_len(), 0);
    let retired = fixture.open(OutputRequest::default()).unwrap();
    assert_eq!(retired.report().retired_generations, 1);
    assert!(payloads(retired).is_empty());
}

#[test]
fn replacing_current_route_does_not_discover_a_previous_plans_output() {
    let fixture = Fixture::new(&[StreamKind::Stdout]);
    let protected = fixture.locator.protected_transcript_dir.as_ref().unwrap();
    let replacement = ProtectedRun {
        version: 1,
        run: "2-2".into(),
        persists: true,
    };
    let generation = replacement
        .directory(protected)
        .unwrap()
        .join("00000000000000000000");
    config::create_private_dir(&generation).unwrap();
    for entry in std::fs::read_dir(fixture.run_dir.join("00000000000000000000")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), generation.join(entry.file_name())).unwrap();
        }
    }
    let mut newer = fixture.manifests[0].clone();
    newer.capture_id = "new-capture".into();
    newer.sealed_root_hex = transcript::sealed_root_hex(&newer).unwrap();
    std::fs::write(
        generation.join(MANIFEST_FILENAME),
        serde_json::to_vec(&newer).unwrap(),
    )
    .unwrap();
    let mut anchors = fixture.anchors();
    let mut new_anchor = anchors[0].clone();
    new_anchor.plan_id = PlanId("new-plan".into());
    new_anchor
        .labels
        .insert("capture_id".into(), newer.capture_id);
    new_anchor
        .labels
        .insert("transcript_root".into(), newer.sealed_root_hex);
    anchors.push(new_anchor);
    fixture.sign(&anchors);
    replacement.publish(protected).unwrap();
    assert!(fixture.open(OutputRequest::default()).is_err());
    let newer = fixture
        .open_identity(
            &fixture.locator,
            &fixture.key.verifying_key(),
            "local",
            "new-plan",
            OutputRequest::default(),
        )
        .unwrap();
    assert_eq!(newer.report().run, "2-2");
    assert_eq!(payloads(newer), [b"record-0\n".to_vec()]);
}
