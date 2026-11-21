//! Genuine `PreparedCanonicalLinux` owner for tests, included by `#[path]`.
//! Needs the actual pinned public kernel in `MVM_TEST_CANONICAL_KERNEL`.
//! Synthetic runtime members: proves kernel custody only, never a runtime.
use mvm_core::canonical_linux::PreparedCanonicalLinux;
use mvm_core::plan::bundle::*;
use mvm_core::vm_backend::BackendKind;
use std::sync::Arc;

#[path = "published_root.rs"]
mod published_root;

pub(crate) fn prepared_owner(backend: BackendKind) -> Arc<PreparedCanonicalLinux> {
    let kernel = std::fs::read(
        std::env::var_os("MVM_TEST_CANONICAL_KERNEL").expect("actual pinned public kernel"),
    )
    .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
    struct Publisher(ed25519_dalek::VerifyingKey);
    impl TrustStore for Publisher {
        fn lookup(&self, id: &KeyId) -> Option<ed25519_dalek::VerifyingKey> {
            (id == &key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }
    let mut payload = vec![
        ("kernel", kernel),
        ("linux.json", published_root::MANIFEST.to_vec()),
        ("linux.bundle", published_root::BUNDLE.to_vec()),
        ("revocations.json", include_bytes!("../../../tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json").to_vec()),
        ("revocations.bundle", include_bytes!("../../../tests/fixtures/image-set-revocations/revocation-list-v1/revocations.json.bundle").to_vec()),
    ];
    for name in [
        "runtime.tar.gz",
        "runtime.sha256",
        "runtime.bundle",
        "runtime.sha256.bundle",
        "overlay",
        "overlay.verity",
        "initrd",
    ] {
        payload.push((
            name,
            b"synthetic runtime: never native runtime authority".to_vec(),
        ));
    }
    let manifest: BundleManifest = serde_json::from_value(serde_json::json!({
        "schema_version": 7, "publisher": "unit-only", "key_id": key_id_from_pubkey(&key.verifying_key()),
        "arch": mvm_core::arch::GuestArch::host().to_string(), "created_at": "2026-10-16T00:00:00Z",
        "artifacts": payload.iter().map(|(name,bytes)| serde_json::json!({
            "name": name, "path": format!("artifacts/{name}"),
            "role": match *name { "kernel" => "kernel", "initrd" => "initrd", _ => "other" },
            "sha256": sha256_hex(bytes), "size_bytes": bytes.len(),
        })).collect::<Vec<_>>(),
        "members": [{
            "class": "embedded_cli_boot_assets", "manifest_artifact": "linux.json",
            "version": "0.24.0", "arch": mvm_core::arch::GuestArch::host().to_string(),
            "archive_artifact": "runtime.tar.gz", "checksum_artifact": "runtime.sha256",
            "signature_bundle_artifact": "runtime.bundle", "checksum_signature_bundle_artifact": "runtime.sha256.bundle",
            "overlay_artifact": "overlay", "overlay_verity_artifact": "overlay.verity",
            "initramfs_artifact": "initrd", "overlay_roothash": "a".repeat(64),
            "protocol_version": 2, "min_supported_protocol_version": 2,
        }, {
            "class": "canonical_linux_proof", "manifest_artifact": "linux.json",
            "signature_bundle_artifact": "linux.bundle", "revocation_document_artifact": "revocations.json",
            "revocation_signature_bundle_artifact": "revocations.bundle",
        }]
    })).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let archive = directory.path().join("unit.mvmpkg");
    let payload = payload
        .into_iter()
        .map(|(name, bytes)| (format!("artifacts/{name}"), bytes))
        .collect();
    std::fs::write(&archive, write_bundle(&manifest, &key, payload).unwrap()).unwrap();
    let trust = Publisher(key.verifying_key());
    let pin = verify_bundle_file(&archive, &trust)
        .unwrap()
        .plan_artifact();
    let enrolled = FsTrustStore::default_path().unwrap();
    mvm_core::config::create_private_dir(enrolled.root()).unwrap();
    std::fs::write(
        enrolled.root().join(format!("{}.pub", manifest.key_id.0)),
        key.verifying_key().to_bytes(),
    )
    .unwrap();
    Arc::new(
        mvm_core::canonical_linux::prepare_canonical_linux(
            &archive,
            &pin,
            backend,
            mvm_build::stage0_kernel::current_image_set_protocol_support(),
            &enrolled,
        )
        .unwrap(),
    )
}
