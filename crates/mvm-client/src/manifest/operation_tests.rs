use super::tests::fixture;
use super::*;
use mvm_core::manifest::{slot_current_symlink, slot_dir, slot_revision_dir};
use mvm_core::util::test_env::TestEnv;

fn artifacts(persisted: &PersistedManifest) -> PathBuf {
    let dir = PathBuf::from(slot_revision_dir(&persisted.manifest_hash, "rev"));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in [
        ("vmlinux", b"kernel".as_slice()),
        ("rootfs.ext4", b"rootfs".as_slice()),
        ("image.tar.gz", b"oci archive".as_slice()),
        (mvm_core::guest_sidecar::SIDECAR_FILENAME, b"{}".as_slice()),
    ] {
        std::fs::write(dir.join(name), bytes).unwrap();
    }
    std::os::unix::fs::symlink(
        "artifacts/revisions/rev",
        slot_current_symlink(&persisted.manifest_hash),
    )
    .unwrap();
    dir
}

#[test]
fn mutation_dtos_roundtrip_and_default_safe() {
    let remove: RemoveRequest = serde_json::from_str("{}").unwrap();
    assert!(!remove.force && !remove.manifest_file && remove.path.is_none());
    let prune: PruneRequest = serde_json::from_str("{}").unwrap();
    assert!(prune.dry_run && !prune.orphans);
    let value = serde_json::to_value(&prune).unwrap();
    assert!(
        serde_json::from_value::<PruneRequest>(value)
            .unwrap()
            .dry_run
    );
    assert!(serde_json::from_str::<RemoveRequest>(r#"{"apply":true}"#).is_err());
}

#[test]
fn remove_preserves_source_unless_explicit_and_force_only_covers_missing_slot() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (path, persisted) = fixture(&temp.path().join("project"), None);
    let mut request = RemoveRequest {
        path: Some(path.display().to_string()),
        ..Default::default()
    };
    let report = remove(&request).unwrap();
    assert_eq!(report.slot_hash, persisted.manifest_hash);
    assert!(!report.manifest_file_deleted);
    assert!(path.exists());
    assert!(remove(&request).is_err());
    request.force = true;
    request.manifest_file = true;
    assert!(remove(&request).unwrap().manifest_file_deleted);
    assert!(!path.exists());
    assert!(remove(&request).is_err());
}

#[test]
fn prune_rechecks_preview_and_preserves_live_references() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (path, persisted) = fixture(&temp.path().join("orphan"), None);
    let request = PruneRequest {
        orphans: true,
        dry_run: true,
    };
    assert!(prune(&PruneRequest::default()).is_err());
    std::fs::remove_file(&path).unwrap();
    let preview = prune(&request).unwrap();
    assert_eq!(preview.candidates.len(), 1);
    assert!(preview.removed.is_empty());
    std::fs::write(&path, "restored").unwrap();
    let apply = PruneRequest {
        dry_run: false,
        ..request
    };
    assert!(prune(&apply).unwrap().removed.is_empty());
    std::fs::remove_file(&path).unwrap();
    let vm = mvm_core::config::vm_state_dir("retained");
    std::fs::create_dir_all(&vm).unwrap();
    std::fs::write(
        vm.join("rootfs.ref"),
        format!("{}/rootfs.ext4", slot_dir(&persisted.manifest_hash)),
    )
    .unwrap();
    assert!(prune(&apply).unwrap().removed.is_empty());
    std::fs::remove_file(vm.join("rootfs.ref")).unwrap();
    let report = prune(&apply).unwrap();
    assert_eq!(report.removed, [persisted.manifest_hash]);
    assert_eq!(report.removed_count, 1);
    let value = serde_json::to_value(&report).unwrap();
    assert!(serde_json::from_value::<PruneReport>(value).is_ok());
}

#[test]
fn mismatched_identity_and_symlink_slots_are_not_removed() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (path, mut persisted) = fixture(&temp.path().join("project"), None);
    let slot = PathBuf::from(slot_dir(&persisted.manifest_hash));
    persisted.manifest_hash = "0".repeat(64);
    std::fs::write(
        slot.join("manifest.json"),
        serde_json::to_vec(&persisted).unwrap(),
    )
    .unwrap();
    let request = RemoveRequest {
        path: Some(path.display().to_string()),
        force: true,
        manifest_file: true,
    };
    assert!(remove(&request).is_err());
    assert!(path.exists() && slot.exists());
    let outside = temp.path().join("outside");
    std::fs::rename(&slot, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, &slot).unwrap();
    assert!(remove(&request).is_err());
    assert!(outside.join("manifest.json").exists());
}

#[test]
fn oci_export_copies_and_refuses_escape_or_protected_output() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (path, persisted) = fixture(&temp.path().join("project"), None);
    let rev = artifacts(&persisted);
    let mut request = ExportOciRequest {
        template: path.display().to_string(),
        out: temp.path().join("out/new/image.tar.gz"),
    };
    let report = export_oci(&request).unwrap();
    assert_eq!(std::fs::read(&report.path).unwrap(), b"oci archive");
    assert_eq!(report.size_bytes, 11);
    request.out = rev.join("rootfs.ext4");
    assert!(export_oci(&request).is_err());
    assert_eq!(std::fs::read(&request.out).unwrap(), b"rootfs");
    request.out = temp.path().join("escape.tar.gz");
    let outside = temp.path().join("outside");
    std::fs::write(&outside, "private").unwrap();
    std::fs::remove_file(rev.join("image.tar.gz")).unwrap();
    std::os::unix::fs::symlink(outside, rev.join("image.tar.gz")).unwrap();
    assert!(export_oci(&request).is_err());
    assert!(!request.out.exists());
    request.template = "0".repeat(64);
    assert!(export_oci(&request).is_err());
    request.template = "../../no-such-project".into();
    assert!(export_oci(&request).is_err());
}

#[test]
fn exports_refuse_absent_key_roots_before_signer_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (_, persisted) = fixture(&temp.path().join("project"), None);
    artifacts(&persisted);
    let keys = mvm_core::config::mvm_keys_dir();
    assert!(!keys.exists());
    let request = crate::bundle::ExportRequest {
        template: persisted.manifest_hash.clone(),
        out: keys.join("host-signer.ed25519"),
        label: None,
        cmdline: None,
        posture: None,
    };
    assert!(crate::bundle::export(&request).is_err());
    assert!(!keys.exists());
    assert!(
        export_oci(&ExportOciRequest {
            template: persisted.manifest_hash,
            out: keys.join("nested/image.tar.gz"),
        })
        .is_err()
    );
    assert!(!keys.exists());
    std::fs::create_dir_all(&keys).unwrap();
    let fixture_bytes = b"fixed non-secret key fixture";
    std::fs::write(&request.out, fixture_bytes).unwrap();
    assert!(crate::bundle::export(&request).is_err());
    assert!(std::fs::read(&request.out).unwrap() == fixture_bytes);
}

#[test]
fn destination_guard_resolves_absent_roots_and_existing_parent_aliases() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    let home = temp.path().join("home");
    env.isolate_mvm_home(&home);
    for root in [
        PathBuf::from(mvm_core::template::templates_base_dir()),
        mvm_core::config::bundles_dir(),
        mvm_core::config::mvm_keys_dir(),
        mvm_core::config::vm_state_dir(""),
        mvm_core::config::machine_state_root(),
    ] {
        assert!(check_export_destination(&root.join("nested/output")).is_err());
    }
    std::fs::create_dir_all(home.join("existing")).unwrap();
    let alias = temp.path().join("alias");
    std::os::unix::fs::symlink(home.join("existing"), &alias).unwrap();
    assert!(check_export_destination(&alias.join("../keys/nested/output")).is_err());
    assert!(check_export_destination(&home.join("missing/../keys/output")).is_err());
    check_export_destination(&home.join("keys-other/nested/output")).unwrap();
    check_export_destination(&temp.path().join("normal/nested/output")).unwrap();
    // Exercise a relative spelling without changing the process-wide cwd.
    let absolute = temp.path().canonicalize().unwrap().join("normal/output");
    let mut relative = PathBuf::new();
    for _ in std::env::current_dir().unwrap().components().skip(1) {
        relative.push("..");
    }
    relative.push(absolute.strip_prefix("/").unwrap());
    check_export_destination(&relative).unwrap();
    let protected = home.canonicalize().unwrap().join("keys/output");
    let relative_protected = relative.parent().unwrap().join("../home/keys/output");
    assert!(check_export_destination(&protected).is_err());
    assert!(check_export_destination(&relative_protected).is_err());
    let target = temp.path().join("fixed-test-bytes");
    std::fs::write(&target, b"non-secret fixture").unwrap();
    let linked = temp.path().join("linked-output");
    std::fs::hard_link(&target, &linked).unwrap();
    assert!(check_export_destination(&linked).is_err());
    std::fs::remove_file(&linked).unwrap();
    std::os::unix::fs::symlink(&target, &linked).unwrap();
    assert!(check_export_destination(&linked).is_err());
    // A dangling link or non-directory ancestor must not turn an inspection
    // failure into permission to export.
    std::fs::remove_file(&target).unwrap();
    assert!(check_export_destination(&linked).is_err());
    std::fs::write(&target, b"non-secret fixture").unwrap();
    assert!(check_export_destination(&target.join("output")).is_err());
}

#[test]
fn persisted_machine_specs_retain_slots_by_hash_and_missing_manifest_path() {
    use mvm_runtime::machine::persist::{MachineSpec, save_machine_spec};
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (path, persisted) = fixture(&temp.path().join("project"), None);
    let slot = PathBuf::from(slot_dir(&persisted.manifest_hash));
    for reference in [&persisted.manifest_hash, &persisted.manifest_path] {
        let spec: MachineSpec = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "name": "retained", "manifest": reference,
            "net": false, "allow_host": [], "cpus": 1, "memory": "512M",
            "profile": "standard"
        }))
        .unwrap();
        save_machine_spec(&spec, true).unwrap();
        std::fs::write(&path, "restored").unwrap();
        let error = remove(&RemoveRequest {
            path: Some(path.display().to_string()),
            force: true,
            manifest_file: true,
        })
        .unwrap_err();
        assert!(error.to_string().contains("retained by a machine"));
        assert!(path.exists() && slot.exists());
        std::fs::remove_file(&path).unwrap();
        let report = prune(&PruneRequest {
            orphans: true,
            dry_run: false,
        })
        .unwrap();
        assert!(report.candidates.is_empty() && report.removed.is_empty());
        assert!(slot.exists());
    }
}

#[test]
fn prune_revalidation_refuses_reclassified_and_replaced_directories() {
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (path, persisted) = fixture(&temp.path().join("project"), None);
    let slot = PathBuf::from(slot_dir(&persisted.manifest_hash));
    std::fs::remove_file(&path).unwrap();
    let report = prune(&PruneRequest {
        orphans: true,
        dry_run: true,
    })
    .unwrap();
    let candidate = &report.candidates[0];
    let before = std::fs::symlink_metadata(&slot).unwrap();
    assert!(operations::candidate_unchanged(candidate, &before).unwrap());
    std::fs::write(&path, "restored").unwrap();
    assert!(!operations::candidate_unchanged(candidate, &before).unwrap());
    std::fs::remove_file(&path).unwrap();
    let old = temp.path().join("old-slot");
    std::fs::rename(&slot, &old).unwrap();
    std::fs::create_dir(&slot).unwrap();
    std::fs::copy(old.join("manifest.json"), slot.join("manifest.json")).unwrap();
    assert!(!operations::candidate_unchanged(candidate, &before).unwrap());
    assert!(slot.exists() && old.exists());
}

#[test]
fn bundle_export_is_signed_and_carries_provenance_and_resources() {
    use crate::bundle::{self, BundleSigner, ExportRequest, HostBundleSigner};
    use ed25519_dalek::VerifyingKey;
    use mvm_core::plan::bundle::{KeyId, TrustStore, key_id_from_pubkey, read_and_verify_bundle};
    struct OneKey(VerifyingKey);
    impl TrustStore for OneKey {
        fn lookup(&self, id: &KeyId) -> Option<VerifyingKey> {
            (*id == key_id_from_pubkey(&self.0)).then_some(self.0)
        }
    }
    struct RefusingSigner<'a>(&'a dyn BundleSigner);
    impl BundleSigner for RefusingSigner<'_> {
        fn publisher_id(&self) -> String {
            self.0.publisher_id()
        }
        fn verifying_key(&self) -> VerifyingKey {
            self.0.verifying_key()
        }
        fn sign(&self, _: &[u8]) -> Result<[u8; 64]> {
            anyhow::bail!("signing refused")
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    let (_, persisted) = fixture(&temp.path().join("project"), None);
    let rev = artifacts(&persisted);
    let signer = HostBundleSigner::load_at(&temp.path().join("keys")).unwrap();
    let request = ExportRequest {
        template: persisted.manifest_hash.clone(),
        out: temp.path().join("app.mvmpkg"),
        label: Some("app".into()),
        cmdline: None,
        posture: None,
    };
    let keys = mvm_core::config::mvm_keys_dir();
    std::fs::create_dir_all(&keys).unwrap();
    let key_fixture = keys.join("fixed-test-key");
    let fixture_bytes = b"fixed non-secret key fixture";
    std::fs::write(&key_fixture, fixture_bytes).unwrap();
    let partial = temp.path().join("app.mvmpkg.partial");
    for target in [&key_fixture, &rev.join("rootfs.ext4")] {
        for hard_link in [false, true] {
            let before = std::fs::read(target).unwrap();
            if hard_link {
                std::fs::hard_link(target, &partial).unwrap();
            } else {
                std::os::unix::fs::symlink(target, &partial).unwrap();
            }
            let report = bundle::export_with_signer(&request, &signer).unwrap();
            assert_eq!(report.path, request.out);
            assert!(std::fs::read(target).unwrap() == before);
            let bytes = std::fs::read(&report.path).unwrap();
            assert!(read_and_verify_bundle(&bytes, &OneKey(signer.verifying_key())).is_ok());
            std::fs::remove_file(&partial).unwrap();
        }
    }
    let report = bundle::export_with_signer(&request, &signer).unwrap();
    assert_eq!(report.path, request.out);
    let bytes = std::fs::read(&report.path).unwrap();
    let verified = read_and_verify_bundle(&bytes, &OneKey(signer.verifying_key())).unwrap();
    assert_eq!(verified.artifacts["artifacts/rootfs.ext4"], b"rootfs");
    assert_eq!(
        verified.manifest.resources.as_ref().unwrap().vcpus,
        u32::from(persisted.vcpus)
    );
    assert_eq!(
        verified.manifest.build_provenance().unwrap().input_ref,
        persisted.flake_ref
    );
    assert_eq!(report.key_id, signer.key_id().0);
    std::fs::remove_file(&request.out).unwrap();
    let error = bundle::export_with_signer(&request, &RefusingSigner(&signer)).unwrap_err();
    assert!(format!("{error:#}").contains("signing refused"));
    assert!(!request.out.exists());
    std::fs::write(rev.join("rootfs.verity"), "half pair").unwrap();
    assert!(bundle::export_with_signer(&request, &signer).is_err());
    assert!(!request.out.exists());
}
