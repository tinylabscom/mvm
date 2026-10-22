use super::*;
#[cfg(unix)]
use crate::plan::bundle::BundleRegistry;
use crate::plan::bundle::{
    ArtifactRole, BUNDLE_SCHEMA_VERSION, BundleArtifact, BundleManifest, FsTrustStore,
    key_id_from_pubkey, sha256_hex, write_bundle,
};
use crate::registry_pack::tests::{accept_signature, publisher_policy};
use crate::registry_pack::{
    PackAdoption, PackReference, VerifiedRegistryApplication, VerifiedRegistryManifest,
};
use crate::registry_pack_store::application_test_feed;
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
    application_test_feed::configure();
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
    application_test_feed::configure();
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
    application_test_feed::configure();
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
    application_test_feed::configure();
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
    application_test_feed::configure();
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
    application_test_feed::configure();
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
        application_test_feed::check,
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
    application_test_feed::configure();
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

struct Installed {
    _directory: tempfile::TempDir,
    _environment: crate::util::test_env::TestEnv,
    store: ApplicationInstallStore,
    trust: FsTrustStore,
    bundle_sha256: String,
    descriptor_sha256: String,
}

fn installed() -> Installed {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    application_test_feed::configure();
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    install_with(
        &verified,
        &store,
        &publisher_policy(),
        &trust,
        accept_signature,
        crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
    )
    .unwrap();
    Installed {
        bundle_sha256: sha256_hex(&bytes),
        descriptor_sha256: crate::registry_pack::AuthenticatedRegistryManifest::manifest_sha256(
            &application,
        )
        .as_str()
        .to_string(),
        _directory: directory,
        _environment: environment,
        store,
        trust,
    }
}

fn resolve(
    installed: &Installed,
    reference: &str,
) -> Result<ResolvedApplication, ApplicationLaunchError> {
    resolve_with_fixture(
        &reference.parse().unwrap(),
        &installed.store,
        &publisher_policy(),
        &installed.trust,
        accept_signature,
    )
}

fn resolve_with_fixture(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    policy: &crate::registry_pack::RegistryPackPublisherPolicy,
    trust: &dyn crate::plan::bundle::TrustStore,
    check_signature: crate::registry_pack::RegistryPackSignatureChecker,
) -> Result<ResolvedApplication, ApplicationLaunchError> {
    launch::resolve_with_checks(
        reference,
        store,
        policy,
        trust,
        check_signature,
        application_test_feed::check,
    )
}

#[cfg(unix)]
fn held_fixture_signature(
    payload: &[u8],
    signature: &[u8],
    trust: &crate::packs::KeylessTrust,
) -> Result<
    crate::crypto::image_verify::VerifiedSigner,
    crate::registry_pack::RegistryPackVerificationError,
> {
    // Private descriptor unit seam, not genuine Sigstore evidence.
    if signature == b"synthetic publisher signature" {
        accept_signature(payload, signature, trust)
    } else {
        crate::registry_pack::tests::reject_signature(payload, signature, trust)
    }
}

#[cfg(unix)]
fn resolve_held(
    installed: &Installed,
    reference: &str,
) -> Result<VerifiedApplicationBundle, ApplicationLaunchError> {
    launch::resolve_bundle_with_checks(
        &reference.parse().unwrap(),
        &installed.store,
        &publisher_policy(),
        &installed.trust,
        held_fixture_signature,
        application_test_feed::check,
    )
}

#[cfg(unix)]
#[test]
fn held_application_keeps_original_descriptor_and_snapshot_after_locator_changes() {
    let installed = installed();
    let archive =
        BundleRegistry::new(&installed.store.bundle_root).archive_path(&installed.bundle_sha256);
    let original = std::fs::read(&archive).unwrap();
    let pin_before = std::fs::read(&installed.store.lock_path).unwrap();
    let held = resolve_held(&installed, "runtime/python").unwrap();
    let snapshot = held.archive_path().to_path_buf();
    assert_ne!(snapshot, archive);
    let descriptor = held.application().manifest_bytes().to_vec();
    let signature = held.application().signature_bundle().to_vec();
    assert_eq!(
        resolve(&installed, "runtime/python").unwrap().bundle_sha256,
        installed.bundle_sha256
    );
    assert_eq!(
        std::fs::read(&installed.store.lock_path).unwrap(),
        pin_before
    );
    let cache = installed
        .store
        .descriptor_cache_root
        .join(&installed.descriptor_sha256);
    std::fs::write(cache.join("manifest.json"), b"replaced descriptor").unwrap();
    std::fs::write(cache.join("manifest.sigstore.json"), b"replaced proof").unwrap();
    std::fs::write(&archive, b"replaced archive").unwrap();
    assert_eq!(held.application().manifest_bytes(), descriptor);
    assert_eq!(held.application().signature_bundle(), signature);
    held.reverify(&installed.trust).unwrap();
    assert_eq!(std::fs::read(&snapshot).unwrap(), original);
    assert!(resolve_held(&installed, "runtime/python").is_err());
    drop(held);
    assert!(
        !snapshot.exists(),
        "final ownership releases the private snapshot"
    );
}

#[cfg(unix)]
#[test]
fn held_application_arc_and_unwind_retain_the_same_snapshot() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<VerifiedApplicationBundle>();
    let installed = installed();
    let first = std::sync::Arc::new(resolve_held(&installed, "runtime/python").unwrap());
    let snapshot = first.archive_path().to_path_buf();
    let second = std::sync::Arc::clone(&first);
    assert!(std::sync::Arc::ptr_eq(&first, &second));
    let weak = std::sync::Arc::downgrade(&first);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _preparation_owner = std::sync::Arc::clone(&first);
        panic!("synthetic preparation unwind, no native effects");
    }));
    assert!(unwind.is_err());
    drop(first);
    assert!(snapshot.exists());
    second.reverify(&installed.trust).unwrap();
    drop(second);
    assert!(weak.upgrade().is_none());
    assert!(!snapshot.exists());
}

#[cfg(unix)]
#[test]
fn held_application_production_check_requires_current_independent_feed() {
    let installed = installed();
    let reference = "runtime/python".parse().unwrap();
    let path = crate::config::registry_pack_revocation_trust_path();
    std::fs::remove_file(&path).unwrap();
    let archive =
        BundleRegistry::new(&installed.store.bundle_root).archive_path(&installed.bundle_sha256);
    std::fs::write(
        archive,
        b"must not reach archive verification without a feed",
    )
    .unwrap();
    let reopen = || {
        launch::resolve_bundle_with(
            &reference,
            &installed.store,
            &publisher_policy(),
            &installed.trust,
            held_fixture_signature,
        )
    };
    assert!(matches!(
        reopen(),
        Err(ApplicationLaunchError::Store(
            crate::registry_pack_store::RegistryPackStoreError::MissingRevocationTrust { .. }
        ))
    ));
    application_test_feed::configure();
    assert!(matches!(
        reopen(),
        Err(ApplicationLaunchError::Store(
            crate::registry_pack_store::RegistryPackStoreError::RevocationStore(
                crate::registry_pack_revocation_store::RegistryPackRevocationStoreError::Missing
            )
        ))
    ));
}

#[cfg(unix)]
#[test]
fn held_application_rechecks_pin_version_publisher_signature_and_revocation() {
    let installed = installed();
    assert!(matches!(
        resolve_held(&installed, "runtime/absent"),
        Err(ApplicationLaunchError::NotInstalled { .. })
    ));
    assert!(matches!(
        resolve_held(&installed, "runtime/python@9.9.9"),
        Err(ApplicationLaunchError::VersionNotInstalled { .. })
    ));
    assert!(matches!(
        launch::resolve_bundle_with_checks(
            &"runtime/python".parse().unwrap(),
            &installed.store,
            &crate::registry_pack::RegistryPackPublisherPolicy::new(Vec::new()).unwrap(),
            &installed.trust,
            held_fixture_signature,
            application_test_feed::check,
        ),
        Err(ApplicationLaunchError::Manifest(_))
    ));
    let proof = installed
        .store
        .descriptor_cache_root
        .join(&installed.descriptor_sha256)
        .join("manifest.sigstore.json");
    let original = std::fs::read(&proof).unwrap();
    std::fs::write(&proof, b"substituted proof").unwrap();
    assert!(matches!(
        resolve_held(&installed, "runtime/python"),
        Err(ApplicationLaunchError::Manifest(_))
    ));
    std::fs::write(&proof, original).unwrap();
    resolve_held(&installed, "runtime/python").unwrap();
    std::fs::write(
        crate::config::registry_pack_revocation_trust_path(),
        b"not a trust policy",
    )
    .unwrap();
    assert!(matches!(
        resolve_held(&installed, "runtime/python"),
        Err(ApplicationLaunchError::Store(_))
    ));
}

#[cfg(unix)]
#[test]
fn held_application_refuses_installed_metadata_tamper_and_unbounded_or_special_inputs() {
    let installed = installed();
    let root =
        BundleRegistry::new(&installed.store.bundle_root).install_dir(&installed.bundle_sha256);
    let manifest = root.join("manifest.json");
    let signature = root.join("manifest.sig");
    let original_manifest = std::fs::read(&manifest).unwrap();
    let original_signature = std::fs::read(&signature).unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
    changed["publisher"] = json!("substituted publisher");
    std::fs::write(&manifest, serde_json::to_vec(&changed).unwrap()).unwrap();
    assert!(resolve_held(&installed, "runtime/python").is_err());
    std::fs::write(&manifest, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    assert!(resolve_held(&installed, "runtime/python").is_err());
    std::fs::remove_file(&manifest).unwrap();
    std::fs::create_dir(&manifest).unwrap();
    assert!(resolve_held(&installed, "runtime/python").is_err());
    std::fs::remove_dir(&manifest).unwrap();
    std::os::unix::fs::symlink(&signature, &manifest).unwrap();
    assert!(resolve_held(&installed, "runtime/python").is_err());
    std::fs::remove_file(&manifest).unwrap();
    std::fs::write(&manifest, original_manifest).unwrap();
    std::fs::write(&signature, [0u8; 64]).unwrap();
    assert!(resolve_held(&installed, "runtime/python").is_err());
    std::fs::write(signature, original_signature).unwrap();
    resolve_held(&installed, "runtime/python").unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert!(matches!(
        resolve_held(&installed, "runtime/python"),
        Err(ApplicationLaunchError::BundleMissing { .. })
    ));
}

#[cfg(unix)]
#[test]
fn held_application_rechecks_archive_and_independent_key_without_enrollment() {
    let installed = installed();
    let archive =
        BundleRegistry::new(&installed.store.bundle_root).archive_path(&installed.bundle_sha256);
    let original = std::fs::read(&archive).unwrap();
    let mut altered = original.clone();
    altered[0] ^= 1;
    std::fs::write(&archive, altered).unwrap();
    assert!(matches!(
        resolve_held(&installed, "runtime/python"),
        Err(ApplicationLaunchError::Bundle(
            ApplicationBundleError::Digest
        ))
    ));
    std::fs::write(archive, original).unwrap();
    let empty = FsTrustStore::new(installed._directory.path().join("not-enrolled"));
    assert!(matches!(
        launch::resolve_bundle_with_checks(
            &"runtime/python".parse().unwrap(),
            &installed.store,
            &publisher_policy(),
            &empty,
            held_fixture_signature,
            application_test_feed::check,
        ),
        Err(ApplicationLaunchError::Bundle(
            ApplicationBundleError::Verification(_)
        ))
    ));
    assert!(!empty.root().exists());
}

#[cfg(unix)]
#[test]
fn held_application_binds_current_descriptor_size_key_and_architecture() {
    let installed = installed();
    let original = std::fs::read(
        installed
            .store
            .descriptor_cache_root
            .join(&installed.descriptor_sha256)
            .join("manifest.json"),
    )
    .unwrap();
    for (field, replacement) in [
        ("archive_size", json!(1)),
        ("key_id", json!("0".repeat(32))),
        ("guest_arch", json!("x86_64")),
    ] {
        let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
        if field == "guest_arch" {
            document["application"][field] = replacement;
        } else {
            document["application"]["bundle"][field] = replacement;
        }
        let bytes = serde_json::to_vec(&document).unwrap();
        let digest = crate::packs::Sha256Hex::from_bytes(&bytes);
        let cache = installed.store.descriptor_cache_root.join(digest.as_str());
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::write(cache.join("manifest.json"), bytes).unwrap();
        std::fs::write(
            cache.join("manifest.sigstore.json"),
            b"synthetic publisher signature",
        )
        .unwrap();
        let pin =
            crate::registry_pack::PackPin::new("runtime/python@1.2.3".parse().unwrap(), digest)
                .unwrap();
        crate::registry_pack_store::save_pack_lockfile(
            &installed.store.lock_path,
            &crate::registry_pack::PackLockfile::new(vec![pin]).unwrap(),
        )
        .unwrap();
        let error = resolve_held(&installed, "runtime/python").unwrap_err();
        assert!(
            matches!(
                (field, error),
                (
                    "archive_size",
                    ApplicationLaunchError::Bundle(ApplicationBundleError::Size)
                ) | (
                    "key_id",
                    ApplicationLaunchError::Bundle(ApplicationBundleError::Key)
                ) | (
                    "guest_arch",
                    ApplicationLaunchError::Bundle(ApplicationBundleError::Architecture)
                )
            ),
            "{field} must refuse at the descriptor/archive boundary"
        );
    }
}

#[cfg(unix)]
#[test]
fn held_application_public_entrypoint_has_no_injected_signature_authority() {
    let installed = installed();
    let policy = installed._directory.path().join("publisher-policy.toml");
    crate::registry_pack_store::save_publisher_policy(&policy, &publisher_policy()).unwrap();
    let reference = "runtime/python".parse().unwrap();
    resolve_held(&installed, "runtime/python").unwrap();
    for error in [
        resolve_installed_application_bundle(
            &reference,
            &installed.store,
            &policy,
            &installed.trust,
        )
        .unwrap_err(),
        resolve_installed_application(&reference, &installed.store, &policy, &installed.trust)
            .unwrap_err(),
    ] {
        assert!(matches!(
            error,
            ApplicationLaunchError::Manifest(
                crate::registry_pack::RegistryPackVerificationError::SignatureInvalid(_)
            )
        ));
    }
}

#[test]
fn an_installed_reference_resolves_with_or_without_its_exact_version() {
    let installed = installed();
    for reference in ["runtime/python", "runtime/python@1.2.3"] {
        let resolved = resolve(&installed, reference).unwrap();
        assert_eq!(resolved.reference.to_string(), "runtime/python@1.2.3");
        assert_eq!(resolved.bundle_sha256, installed.bundle_sha256);
        assert_eq!(resolved.descriptor_sha256, installed.descriptor_sha256);
    }
    assert!(names_installed_application(
        &"runtime/python".parse().unwrap(),
        &installed.store
    ));
}

#[cfg(unix)]
#[test]
fn production_resolver_requires_operator_trust_and_cached_feed_before_bundle_use() {
    let installed = installed();
    let reference = "runtime/python".parse().unwrap();
    let path = crate::config::registry_pack_revocation_trust_path();
    std::fs::remove_file(&path).unwrap();
    let resolve = || {
        launch::resolve_bundle_with(
            &reference,
            &installed.store,
            &publisher_policy(),
            &installed.trust,
            accept_signature,
        )
    };
    assert!(matches!(
        resolve(),
        Err(ApplicationLaunchError::Store(
            crate::registry_pack_store::RegistryPackStoreError::MissingRevocationTrust { .. }
        ))
    ));
    application_test_feed::configure();
    assert!(matches!(
        resolve(),
        Err(ApplicationLaunchError::Store(
            crate::registry_pack_store::RegistryPackStoreError::RevocationStore(
                crate::registry_pack_revocation_store::RegistryPackRevocationStoreError::Missing
            )
        ))
    ));
}

#[cfg(unix)]
#[test]
fn production_installer_refuses_absent_operator_trust_before_publishing_content() {
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
    let result = super::install::install_with_loader(
        &verified,
        &store,
        || Ok(publisher_policy()),
        &trust,
        accept_signature,
        VerifiedRegistryApplication::check_current_revocations,
        crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
    );
    assert!(matches!(
        result,
        Err(ApplicationBundleError::Store(
            crate::registry_pack_store::RegistryPackStoreError::MissingRevocationTrust { .. }
        ))
    ));
    assert!(!store.lock_path.exists());
    assert!(!store.bundle_root.exists());
    assert!(!store.descriptor_cache_root.exists());
}

#[cfg(unix)]
#[test]
fn production_revocation_recheck_refuses_withdrawn_trust_before_pin_commit() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    application_test_feed::configure();
    let source = directory.path().join("input.mvmpkg");
    std::fs::write(&source, &bytes).unwrap();
    let application = descriptor(&bytes, &key_id, |_| {});
    let verified = verify_application_bundle(&application, &source, &trust).unwrap();
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let mut checks = 0;
    let result = super::install::install_with_loader(
        &verified,
        &store,
        || Ok(publisher_policy()),
        &trust,
        accept_signature,
        |application| {
            checks += 1;
            if checks == 1 {
                application_test_feed::check(application)?;
                std::fs::remove_file(crate::config::registry_pack_revocation_trust_path()).unwrap();
                Ok(())
            } else {
                application.check_current_revocations()
            }
        },
        |_, _| panic!("withdrawn revocation trust must refuse before committing a pin"),
    );
    assert_eq!(checks, 2);
    assert!(matches!(
        result,
        Err(ApplicationBundleError::Store(
            crate::registry_pack_store::RegistryPackStoreError::MissingRevocationTrust { .. }
        ))
    ));
    assert!(!store.lock_path.exists());
    assert!(store.bundle_root.join(sha256_hex(&bytes)).is_dir());
}

#[test]
fn a_missing_or_different_version_names_the_pull_that_fixes_it() {
    let installed = installed();
    let missing = resolve(&installed, "runtime/other")
        .unwrap_err()
        .to_string();
    assert!(
        missing.contains("mvmctl pack pull runtime/other"),
        "{missing}"
    );
    assert!(!names_installed_application(
        &"runtime/other".parse().unwrap(),
        &installed.store
    ));
    let version = resolve(&installed, "runtime/python@9.9.9")
        .unwrap_err()
        .to_string();
    assert!(
        version.contains("installed at runtime/python@1.2.3"),
        "{version}"
    );
    assert!(
        version.contains("mvmctl pack pull runtime/python@9.9.9"),
        "{version}"
    );
}

#[test]
fn post_install_tampering_and_withdrawn_trust_refuse_at_launch() {
    let installed = installed();
    let registry = crate::plan::bundle::BundleRegistry::new(&installed.store.bundle_root);
    let archive = registry.archive_path(&installed.bundle_sha256);
    let original = std::fs::read(&archive).unwrap();

    let empty = FsTrustStore::new(installed._directory.path().join("withdrawn"));
    let withdrawn = resolve_with_fixture(
        &"runtime/python".parse().unwrap(),
        &installed.store,
        &publisher_policy(),
        &empty,
        accept_signature,
    );
    assert!(matches!(withdrawn, Err(ApplicationLaunchError::Bundle(_))));

    std::fs::write(&archive, b"poisoned archive").unwrap();
    assert!(matches!(
        resolve(&installed, "runtime/python"),
        Err(ApplicationLaunchError::Bundle(_))
    ));
    std::fs::write(&archive, &original).unwrap();
    resolve(&installed, "runtime/python").unwrap();

    std::fs::remove_dir_all(registry.install_dir(&installed.bundle_sha256)).unwrap();
    assert!(matches!(
        resolve(&installed, "runtime/python"),
        Err(ApplicationLaunchError::BundleMissing { .. })
    ));

    let descriptor = installed
        .store
        .descriptor_cache_root
        .join(&installed.descriptor_sha256)
        .join("manifest.json");
    std::fs::write(descriptor, b"poisoned descriptor").unwrap();
    assert!(matches!(
        resolve(&installed, "runtime/python"),
        Err(ApplicationLaunchError::Manifest(_))
    ));
}

#[test]
fn a_withdrawn_publisher_policy_or_unreadable_revocation_trust_refuses_at_launch() {
    let installed = installed();
    let no_policy = resolve_with_fixture(
        &"runtime/python".parse().unwrap(),
        &installed.store,
        &crate::registry_pack::RegistryPackPublisherPolicy::new(Vec::new()).unwrap(),
        &installed.trust,
        accept_signature,
    );
    assert!(matches!(
        no_policy,
        Err(ApplicationLaunchError::Manifest(_))
    ));
    let path = crate::config::registry_pack_revocation_trust_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not a revocation trust policy").unwrap();
    assert!(matches!(
        resolve(&installed, "runtime/python"),
        Err(ApplicationLaunchError::Store(_))
    ));
}

#[test]
fn the_resolved_bundle_is_the_archive_a_mvmpkg_run_would_install() {
    let installed = installed();
    let archive = crate::plan::bundle::BundleRegistry::new(&installed.store.bundle_root)
        .archive_path(&installed.bundle_sha256);
    let bytes = std::fs::read(archive).unwrap();
    let resolved = resolve(&installed, "runtime/python").unwrap();
    assert_eq!(resolved.bundle_sha256, sha256_hex(&bytes));
}

#[test]
fn a_policy_pack_pin_is_not_an_application_and_never_resolves() {
    let installed = installed();
    let legacy = br#"{"schema_version":1,"reference":"runtime/policy@1.0.0"}"#;
    let digest = crate::packs::Sha256Hex::from_bytes(legacy);
    let reference: PackReference = "runtime/policy@1.0.0".parse().unwrap();
    let python = crate::registry_pack_store::load_pack_lockfile(&installed.store.lock_path)
        .unwrap()
        .pins()
        .to_vec();
    let pin = crate::registry_pack::PackPin::new(reference.clone(), digest.clone()).unwrap();
    crate::registry_pack_store::save_pack_lockfile(
        &installed.store.lock_path,
        &crate::registry_pack::PackLockfile::new([python, vec![pin]].concat()).unwrap(),
    )
    .unwrap();
    let directory = installed.store.descriptor_cache_root.join(digest.as_str());
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("manifest.json"), legacy).unwrap();
    assert!(!names_installed_application(&reference, &installed.store));
    assert!(names_installed_policy_pack(&reference, &installed.store));
    assert!(!names_installed_policy_pack(
        &"runtime/python".parse().unwrap(),
        &installed.store
    ));
    assert!(resolve(&installed, "runtime/policy").is_err());
    resolve(&installed, "runtime/python").unwrap();
}

/// A synthetic local registry: a root catalog advertising the descriptor's
/// digest, the descriptor and its signature bundle beside it, and the archive.
/// Fulcio is unreachable offline, so the publisher signature is the injected
/// `accept_signature` seam every test in this module uses.
fn publish_to_local_registry(
    root: &std::path::Path,
    application: &VerifiedRegistryApplication,
    archive: &[u8],
) {
    let digest = sha256_hex(application.manifest_bytes());
    let leaf = root.join("runtime/python/1.2.3");
    std::fs::create_dir_all(&leaf).unwrap();
    std::fs::write(leaf.join("manifest.json"), application.manifest_bytes()).unwrap();
    std::fs::write(
        leaf.join("manifest.sigstore"),
        application.signature_bundle(),
    )
    .unwrap();
    std::fs::write(root.join("app.mvmpkg"), archive).unwrap();
    let catalog = json!({
        "schema_version": 2,
        "packs": [{
            "namespace": "runtime", "name": "python", "description": "Hermetic application",
            "versions": [{"version": "1.2.3", "manifest_sha256": digest}]
        }]
    });
    std::fs::write(
        root.join("index.json"),
        serde_json::to_vec(&catalog).unwrap(),
    )
    .unwrap();
}

#[test]
fn a_catalogued_application_installs_atomically_and_resolves_for_launch() {
    let (directory, bytes, trust, key_id) = fixture();
    let mut environment = crate::util::test_env::TestEnv::new();
    environment.isolate_mvm_home(directory.path().join("home"));
    application_test_feed::configure();
    let registry = directory.path().join("registry");
    publish_to_local_registry(&registry, &descriptor(&bytes, &key_id, |_| {}), &bytes);

    // Catalog: the advertised digest for the requested coordinate.
    let catalog: serde_json::Value =
        serde_json::from_slice(&std::fs::read(registry.join("index.json")).unwrap()).unwrap();
    let advertised = catalog["packs"][0]["versions"][0]["manifest_sha256"]
        .as_str()
        .unwrap();

    // Authenticated descriptor: fetched bytes match the catalog, then the
    // signature and publisher policy admit them.
    let leaf = registry.join("runtime/python/1.2.3");
    let manifest = std::fs::read(leaf.join("manifest.json")).unwrap();
    assert_eq!(sha256_hex(&manifest), advertised);
    let reference: PackReference = "runtime/python@1.2.3".parse().unwrap();
    let VerifiedRegistryManifest::Application(application) = super::super::dispatch::adopt_with(
        &PackAdoption {
            requested: &reference,
            manifest_bytes: &manifest,
            signature_bundle: &std::fs::read(leaf.join("manifest.sigstore")).unwrap(),
            publisher_policy: &publisher_policy(),
        },
        accept_signature,
    )
    .unwrap() else {
        panic!("application expected")
    };

    // Verified bundle, then atomic install: nothing resolves before the pin.
    let store = ApplicationInstallStore::new(
        directory.path().join("descriptors"),
        directory.path().join("packs.lock.toml"),
        directory.path().join("bundles"),
    );
    let verified =
        verify_application_bundle(&application, &registry.join("app.mvmpkg"), &trust).unwrap();
    assert!(!names_installed_application(&reference, &store));
    install_with(
        &verified,
        &store,
        &publisher_policy(),
        &trust,
        accept_signature,
        crate::registry_pack_store::RegistryPackStoreLease::commit_application_pin,
    )
    .unwrap();

    // Launch: the reference resolves to the bundle the descriptor names.
    assert!(names_installed_application(&reference, &store));
    let resolved = resolve_with_fixture(
        &"runtime/python".parse().unwrap(),
        &store,
        &publisher_policy(),
        &trust,
        accept_signature,
    )
    .unwrap();
    assert_eq!(resolved.bundle_sha256, sha256_hex(&bytes));
    assert_eq!(resolved.descriptor_sha256, advertised);
}

#[test]
fn removing_an_application_pin_never_deletes_the_bundle_store_content() {
    let installed = installed();
    let python: PackReference = "runtime/python@1.2.3".parse().unwrap();
    assert!(
        crate::registry_pack_store::remove_installed_registry_pack(
            &installed.store.descriptor_cache_root,
            &installed.store.lock_path,
            &python,
        )
        .unwrap()
    );
    assert!(
        installed
            .store
            .bundle_root
            .join(&installed.bundle_sha256)
            .is_dir()
    );
    assert!(!names_installed_application(&python, &installed.store));
}
