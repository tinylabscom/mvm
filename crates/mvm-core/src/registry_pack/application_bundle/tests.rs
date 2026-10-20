use super::*;
use crate::plan::bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, FsTrustStore,
    key_id_from_pubkey, sha256_hex, write_bundle,
};
use crate::registry_pack::tests::{accept_signature, publisher_policy};
use crate::registry_pack::{PackAdoption, VerifiedRegistryApplication, VerifiedRegistryManifest};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn fixture() -> (tempfile::TempDir, Vec<u8>, FsTrustStore, String) {
    use rand::Rng;
    let directory = tempfile::tempdir().unwrap();
    let mut seed = [0; 32];
    rand::rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let key_id = key_id_from_pubkey(&key.verifying_key());
    let trust = FsTrustStore::new(directory.path().join("trust"));
    std::fs::create_dir(trust.root()).unwrap();
    std::fs::write(
        trust.root().join(format!("{}.pub", key_id.0)),
        key.verifying_key().as_bytes(),
    )
    .unwrap();
    let bytes = b"rootfs";
    let manifest = BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        publisher: "hermetic-test".to_string(),
        key_id: key_id.clone(),
        arch: "aarch64".to_string(),
        kernel_version: None,
        profile: None,
        workload_label: None,
        created_at: "2026-01-01T00:00:00Z".to_string(),
        labels: Default::default(),
        artifacts: vec![BundleArtifact {
            name: "rootfs".to_string(),
            role: ArtifactRole::Rootfs,
            path: "artifacts/rootfs.ext4".to_string(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }],
        members: Vec::new(),
        verity: None,
        resources: None,
    };
    let archive = write_bundle(
        &manifest,
        &key,
        vec![("artifacts/rootfs.ext4".to_string(), bytes.to_vec())],
    )
    .unwrap();
    (directory, archive, trust, key_id.0)
}

fn descriptor(
    bytes: &[u8],
    key_id: &str,
    change: impl FnOnce(&mut serde_json::Value),
) -> VerifiedRegistryApplication {
    let mut document = json!({
        "schema_version": 2,
        "kind": "application",
        "reference": "runtime/python@1.2.3",
        "description": "Hermetic application",
        "application": {
            "schema_version": 1,
            "guest_arch": "aarch64",
            "bundle": {
                "source": "https://example.test/app.mvmpkg",
                "archive_sha256": sha256_hex(bytes),
                "archive_size": bytes.len(),
                "key_id": key_id
            }
        }
    });
    change(&mut document);
    let bytes = serde_json::to_vec(&document).unwrap();
    let policy = publisher_policy();
    let reference = "runtime/python@1.2.3".parse().unwrap();
    let verified = super::super::dispatch::adopt_with(
        &PackAdoption {
            requested: &reference,
            manifest_bytes: &bytes,
            signature_bundle: b"synthetic publisher signature",
            publisher_policy: &policy,
        },
        accept_signature,
    )
    .unwrap();
    let VerifiedRegistryManifest::Application(application) = verified else {
        panic!("application expected")
    };
    application
}

#[test]
fn trusted_archive_is_bound_to_descriptor_and_private_snapshot() {
    let (directory, bytes, trust, key_id) = fixture();
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    assert_eq!(verified.bundle().bundle_sha256, sha256_hex(&bytes));
    assert_eq!(verified.application(), &application);
    verified.reverify(&trust).unwrap();
    std::fs::write(&source, b"changed after verification").unwrap();
    assert_eq!(std::fs::read(verified.archive_path()).unwrap(), bytes);
    let empty_trust = FsTrustStore::new(directory.path().join("no-keys"));
    assert!(matches!(
        verified.reverify(&empty_trust),
        Err(ApplicationBundleError::Verification(_))
    ));
}

#[test]
fn size_digest_key_architecture_and_independent_trust_are_mandatory() {
    let (directory, bytes, trust, key_id) = fixture();
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    for (pointer, bad) in [
        ("/application/bundle/archive_size", json!(bytes.len() + 1)),
        ("/application/bundle/archive_sha256", json!("0".repeat(64))),
        ("/application/bundle/key_id", json!("0".repeat(32))),
        ("/application/guest_arch", json!("x86_64")),
    ] {
        let application = descriptor(&bytes, &key_id, |document| {
            *document.pointer_mut(pointer).unwrap() = bad;
        });
        let error = verify_application_bundle(&application, &source, &trust).unwrap_err();
        assert!(
            match pointer {
                "/application/bundle/archive_size" => matches!(error, ApplicationBundleError::Size),
                "/application/bundle/archive_sha256" =>
                    matches!(error, ApplicationBundleError::Digest),
                "/application/bundle/key_id" => matches!(error, ApplicationBundleError::Key),
                "/application/guest_arch" => matches!(error, ApplicationBundleError::Architecture),
                _ => unreachable!(),
            },
            "{pointer}: {error}"
        );
    }
    let application = descriptor(&bytes, &key_id, |_| {});
    let empty_trust = FsTrustStore::new(directory.path().join("not-enrolled"));
    assert!(verify_application_bundle(&application, &source, &empty_trust).is_err());
    assert!(
        !empty_trust.root().exists(),
        "descriptor must not enroll its key"
    );
    std::fs::write(&source, &bytes[..bytes.len() / 2]).unwrap();
    assert!(verify_application_bundle(&application, &source, &trust).is_err());
}

#[test]
fn archive_bounds_and_nonregular_inputs_refuse_before_verification() {
    let (directory, bytes, trust, key_id) = fixture();
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let oversized = descriptor(&bytes, &key_id, |document| {
        document["application"]["bundle"]["archive_size"] =
            json!(MAX_APPLICATION_ARCHIVE_BYTES + 1);
    });
    assert!(matches!(
        verify_application_bundle(&oversized, &source, &trust),
        Err(ApplicationBundleError::Size)
    ));
    let application = descriptor(&bytes, &key_id, |_| {});
    assert!(verify_application_bundle(&application, directory.path(), &trust).is_err());
    #[cfg(unix)]
    {
        let link = directory.path().join("symlink.mvmpkg");
        std::os::unix::fs::symlink(&source, &link).unwrap();
        assert!(verify_application_bundle(&application, &link, &trust).is_err());
        let hard_link = directory.path().join("hard-link.mvmpkg");
        std::fs::hard_link(&source, &hard_link).unwrap();
        assert!(verify_application_bundle(&application, &source, &trust).is_err());
    }
}

#[cfg(unix)]
#[test]
fn symlinked_roots_and_bundle_leases_refuse_without_following_targets() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let policy = publisher_policy();
    for leaf in ["bundles", "descriptors", "bundle-lease", "pack-lease"] {
        let case = directory.path().join(leaf);
        std::fs::create_dir(&case).unwrap();
        let store = ApplicationInstallStore::new(
            case.join("descriptors"),
            case.join("packs.lock.toml"),
            case.join("bundles"),
        );
        let target = case.join("protected");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("marker"), b"unchanged").unwrap();
        match leaf {
            "bundles" => std::os::unix::fs::symlink(&target, &store.bundle_root).unwrap(),
            "descriptors" => {
                std::os::unix::fs::symlink(&target, &store.descriptor_cache_root).unwrap()
            }
            "bundle-lease" => {
                std::fs::create_dir(&store.bundle_root).unwrap();
                std::os::unix::fs::symlink(
                    target.join("marker"),
                    store
                        .bundle_root
                        .join(format!(".{}.lock", sha256_hex(&bytes))),
                )
                .unwrap();
            }
            "pack-lease" => std::os::unix::fs::symlink(
                target.join("marker"),
                store.lock_path.with_extension("transaction.lock"),
            )
            .unwrap(),
            _ => unreachable!(),
        }
        assert!(
            install_with(
                &verified,
                &store,
                &policy,
                &trust,
                accept_signature,
                crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin
            )
            .is_err(),
            "{leaf}"
        );
        assert!(!store.lock_path.exists(), "{leaf}");
        assert_eq!(
            std::fs::read(target.join("marker")).unwrap(),
            b"unchanged",
            "{leaf}"
        );
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 1, "{leaf}");
    }
}

#[test]
fn install_commit_is_last_and_failed_commit_leaves_only_complete_unreferenced_content() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let policy = publisher_policy();
    let result = install_with(
        &verified,
        &store,
        &policy,
        &trust,
        accept_signature,
        |_, _| {
            Err(crate::registry_pack_store::RegistryPackStoreError::Parse {
                path: "injected pin save failure".to_string(),
                reason: "interrupted before commit".to_string(),
            })
        },
    );
    assert!(result.is_err());
    assert!(
        crate::registry_pack_store::load_pack_lockfile(&store.lock_path)
            .unwrap()
            .pins()
            .is_empty()
    );
    let registry = crate::plan::bundle::BundleRegistry::new(&store.bundle_root);
    let cached = registry.archive_path(&sha256_hex(&bytes));
    crate::plan::bundle::verify_bundle_file(&cached, &trust).unwrap();
    assert_eq!(
        std::fs::read(
            registry
                .install_dir(&sha256_hex(&bytes))
                .join("artifacts/rootfs.ext4")
        )
        .unwrap(),
        b"rootfs"
    );
    assert!(
        !registry
            .root()
            .join(format!("{}.partial", sha256_hex(&bytes)))
            .exists()
    );
}

#[test]
fn a_staging_dir_left_by_a_killed_install_is_never_runnable_and_the_next_install_repairs_it() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    // A SIGKILL between staging and the atomic publish leaves exactly this:
    // a half-written `<sha>.partial` beside no install directory and no pin.
    let registry = crate::plan::bundle::BundleRegistry::new(&store.bundle_root);
    let sha = sha256_hex(&bytes);
    let staging = registry.root().join(format!("{sha}.partial"));
    std::fs::create_dir_all(staging.join("artifacts")).unwrap();
    std::fs::write(staging.join("artifacts/rootfs.ext4"), b"roo").unwrap();
    assert!(!registry.install_dir(&sha).exists());
    assert!(!store.lock_path.exists());

    let policy = publisher_policy();
    let installed = install_with(
        &verified,
        &store,
        &policy,
        &trust,
        accept_signature,
        crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
    )
    .unwrap();
    assert!(!staging.exists());
    assert_eq!(
        std::fs::read(installed.bundle().root.join("artifacts/rootfs.ext4")).unwrap(),
        b"rootfs"
    );
    assert_eq!(
        crate::registry_pack_store::load_pack_lockfile(&store.lock_path)
            .unwrap()
            .pins()
            .len(),
        1
    );
}

#[test]
fn repeated_install_rechecks_trust_and_repairs_poisoned_cache_without_digest_drift() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let policy = publisher_policy();
    let install = || {
        install_with(
            &verified,
            &store,
            &policy,
            &trust,
            accept_signature,
            crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
        )
    };
    let first = install().unwrap();
    let registry = crate::plan::bundle::BundleRegistry::new(&store.bundle_root);
    let rootfs = first.bundle().root.join("artifacts/rootfs.ext4");
    std::fs::write(&rootfs, b"poisoned").unwrap();
    std::fs::write(
        registry.archive_path(&first.bundle().sha256),
        b"poisoned archive",
    )
    .unwrap();
    std::fs::write(
        first.descriptor_root().join("manifest.json"),
        b"poisoned descriptor",
    )
    .unwrap();
    let second = install().unwrap();
    assert_eq!(first.bundle().sha256, second.bundle().sha256);
    assert_eq!(std::fs::read(rootfs).unwrap(), b"rootfs");
    assert_eq!(
        std::fs::read(registry.archive_path(&first.bundle().sha256)).unwrap(),
        bytes
    );
    assert_eq!(
        std::fs::read(second.descriptor_root().join("manifest.json")).unwrap(),
        application.manifest_bytes()
    );
    assert_eq!(
        crate::registry_pack_store::load_pack_lockfile(&store.lock_path)
            .unwrap()
            .pins()
            .len(),
        1
    );
    let empty = FsTrustStore::new(directory.path().join("empty-trust"));
    assert!(
        install_with(
            &verified,
            &store,
            &policy,
            &empty,
            accept_signature,
            crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin
        )
        .is_err()
    );
}

#[test]
fn current_revocation_policy_and_same_version_pin_drift_refuse_before_installation() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let policy = publisher_policy();
    let pin = crate::registry_pack::PackPin::new(
        application.manifest().reference.clone(),
        crate::packs::Sha256Hex::from_bytes(b"drift"),
    )
    .unwrap();
    crate::registry_pack_store::save_pack_lockfile(
        &store.lock_path,
        &crate::registry_pack::PackLockfile::new(vec![pin]).unwrap(),
    )
    .unwrap();
    assert!(
        install_with(
            &verified,
            &store,
            &policy,
            &trust,
            accept_signature,
            crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin
        )
        .is_err()
    );
    assert!(!store.bundle_root.exists());
    std::fs::remove_file(&store.lock_path).unwrap();
    let path = crate::config::registry_pack_revocation_trust_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not a revocation trust policy").unwrap();
    assert!(
        install_with(
            &verified,
            &store,
            &policy,
            &trust,
            accept_signature,
            crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin
        )
        .is_err()
    );
    assert!(!store.bundle_root.exists());
    assert!(!store.lock_path.exists());
}

#[test]
fn publisher_policy_load_occurs_under_lease_and_withdrawal_before_commit_refuses() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let mut loads = 0;
    let result = super::install::install_with_loader(
        &verified,
        &store,
        || {
            let lease = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(store.lock_path.with_extension("transaction.lock"))
                .unwrap();
            assert!(matches!(
                lease.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            loads += 1;
            if loads == 1 {
                Ok(publisher_policy())
            } else {
                Ok(crate::registry_pack::RegistryPackPublisherPolicy::new(Vec::new()).unwrap())
            }
        },
        &trust,
        accept_signature,
        crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
    );
    assert!(result.is_err());
    assert_eq!(loads, 2);
    assert!(!store.lock_path.exists());
    assert!(store.bundle_root.join(sha256_hex(&bytes)).is_dir());
}

#[test]
fn bundle_removal_is_excluded_until_application_reference_commit() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let mut remover = None;
    let installed = install_with(
        &verified,
        &store,
        &publisher_policy(),
        &trust,
        accept_signature,
        |lease, app| {
            let entry_lease = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(
                    store
                        .bundle_root
                        .join(format!(".{}.lock", sha256_hex(&bytes))),
                )
                .unwrap();
            assert!(matches!(
                entry_lease.try_lock(),
                Err(std::fs::TryLockError::WouldBlock)
            ));
            let root = store.bundle_root.clone();
            let digest = sha256_hex(&bytes);
            remover = Some(std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let removed = crate::plan::bundle::BundleRegistry::new(root)
                    .remove(&digest)
                    .unwrap();
                done_tx.send(removed).unwrap();
            }));
            started_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            assert!(matches!(
                done_rx.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ));
            assert!(store.bundle_root.join(sha256_hex(&bytes)).is_dir());
            lease.commit_application_pin(app)
        },
    )
    .unwrap();
    assert_eq!(installed.bundle().sha256, sha256_hex(&bytes));
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
    );
    remover.unwrap().join().unwrap();
    assert_eq!(
        crate::registry_pack_store::load_pack_lockfile(&store.lock_path)
            .unwrap()
            .pins()
            .len(),
        1
    );
}
