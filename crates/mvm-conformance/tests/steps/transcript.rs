//! Hermetic operator-path scenarios for authenticated transcript export.

use std::path::Path;

use cucumber::given;
use mvm_core::crypto::aead;
use mvm_core::plan::test_support::PlanFixture;
use mvm_core::transcript::{
    self, CaptureBinding, CaptureBounds, Direction, RetentionPolicy, TranscriptManifest,
    TranscriptWriter, TranscriptWriterConfig,
};
use mvm_hostd::audit::emitter::AuditEmitter;
use mvm_hostd::audit::host_keypair;

use crate::world::CliWorld;

const CAPTURE_ID: &str = "bdd-transcript";
const EVIDENCE: &[u8] = b"authenticated transcript evidence";

fn home(world: &CliWorld) -> &Path {
    world
        .isolated_home
        .as_ref()
        .expect("an isolated mvm home must be created first")
        .path()
}

fn manifest_path(root: &Path) -> std::path::PathBuf {
    root.join("audit/transcripts/local")
        .join(CAPTURE_ID)
        .join("manifest.json")
}

#[given("a sealed transcript anchored to the host audit chain")]
async fn sealed_transcript_with_chain_anchor(world: &mut CliWorld) {
    let root = home(world).to_path_buf();
    tokio::task::spawn_blocking(move || {
        let capture_dir = root.join("audit/transcripts/local").join(CAPTURE_ID);
        let keys_dir = root.join("keys");
        let audit_dir = root.join("audit");
        std::fs::create_dir_all(&capture_dir).expect("create transcript fixture directory");

        let kek = transcript::load_or_init_kek(&keys_dir).expect("create transcript KEK");
        let data_key = aead::Key::from_bytes([9u8; 32]);
        let wrapped_data_key_b64 = transcript::wrap_data_key(&kek, &data_key);
        let mut writer = TranscriptWriter::new(
            &capture_dir,
            data_key,
            TranscriptWriterConfig {
                capture_id: CAPTURE_ID.to_string(),
                binding: CaptureBinding {
                    tenant_id: "local".to_string(),
                    vm_name: "bdd-vm".to_string(),
                    session_id: Some("bdd-session".to_string()),
                },
                bounds: CaptureBounds {
                    max_duration_secs: 60,
                    max_bytes: 4096,
                    max_chunks: 4,
                },
                // A forensic capture of discrete frames, not a log stream: it
                // must refuse at its bound rather than quietly drop its head.
                retention: RetentionPolicy::FailClosed,
                created_unix_secs: 1_700_000_000,
                recipient: "transcript-kek".to_string(),
                wrapped_data_key_b64,
            },
        );
        writer
            .push(Direction::Egress, EVIDENCE)
            .expect("capture transcript fixture");
        let manifest = writer.seal();
        mvm_core::atomic_io::atomic_write(
            &manifest_path(&root),
            &serde_json::to_vec_pretty(&manifest).expect("serialize transcript manifest"),
        )
        .expect("write transcript manifest");

        let signer = host_keypair::load_or_init_at(&keys_dir).expect("create host signer");
        let emitter =
            AuditEmitter::with_dir(signer.signing, &audit_dir).expect("open audit emitter");
        let plan = PlanFixture::new()
            .tenant("local")
            .plan_id("bdd-transcript-plan")
            .build();
        emitter
            .emit_transcript_sealed(
                &plan,
                &manifest.capture_id,
                &manifest.binding.vm_name,
                &manifest.sealed_root_hex,
                manifest.chunks.len(),
                manifest.adopted,
            )
            .expect("anchor transcript root in host audit chain");
    })
    .await
    .expect("transcript audit fixture task joins");
}

#[given("the sealed transcript binding is tampered")]
fn tamper_transcript_binding(world: &mut CliWorld) {
    let path = manifest_path(home(world));
    let mut manifest: TranscriptManifest =
        serde_json::from_slice(&std::fs::read(&path).expect("read transcript manifest fixture"))
            .expect("parse transcript manifest fixture");
    manifest.binding.vm_name = "forged-vm".to_string();
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&manifest).expect("serialize tampered manifest"),
    )
    .expect("write tampered transcript manifest");
}
