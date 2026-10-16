#![cfg(feature = "manifest-verify")]

use mvm_client::registry_pack_local::{LocalRegistryPackPaths, install_local_registry_pack};
use mvm_core::packs::Sha256Hex;
use mvm_core::registry_pack::{
    PackPin, RegistryPackImage, RegistryPackPublisher, RegistryPackPublisherPolicy,
};
use mvm_core::registry_pack_store as store;
use mvm_core::util::test_env::TestEnv;
use std::path::{Path, PathBuf};

const SOURCE: &str = "runtime/python@1.1.0";
const IDENTITY: &str = "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/feat/3716-python-image-pack";

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../mvm-cli/tests/fixtures")
}

fn stage_fixture(root: &Path, name: &str) -> (LocalRegistryPackPaths, PackPin) {
    let source = fixture_root().join(name);
    let manifest = std::fs::read(source.join("manifest.json")).unwrap();
    let wire: mvm_core::registry_pack::RegistryPackManifest =
        serde_json::from_slice(&manifest).unwrap();
    std::fs::create_dir_all(root.join("files")).unwrap();
    std::fs::write(root.join("manifest.json"), &manifest).unwrap();
    std::fs::copy(
        source.join("manifest.sigstore.json"),
        root.join("bundle.json"),
    )
    .unwrap();
    for file in wire.files {
        let destination = root.join("files").join(&file.path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        std::fs::copy(source.join("files").join(file.path), destination).unwrap();
    }
    (
        LocalRegistryPackPaths::new(
            root.join("manifest.json"),
            root.join("bundle.json"),
            root.join("files"),
        )
        .unwrap(),
        PackPin::new(wire.reference, Sha256Hex::from_bytes(&manifest)).unwrap(),
    )
}

fn isolated_home(root: &Path) -> (TestEnv, RegistryPackPublisherPolicy) {
    let mut env = TestEnv::new();
    env.isolate_mvm_home(root.join("home"));
    env.set("MVM_PACK_REGISTRY", "https://invalid.invalid/no-fallback");
    let policy = RegistryPackPublisherPolicy::new(vec![
        RegistryPackPublisher::new("runtime", "https://token.actions.githubusercontent.com", vec![IDENTITY.to_string()]).unwrap(),
        RegistryPackPublisher::new("agent", "https://token.actions.githubusercontent.com",
            vec!["https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main".to_string()]).unwrap(),
    ]).unwrap();
    store::save_publisher_policy(
        &mvm_core::config::registry_pack_publisher_policy_path(),
        &policy,
    )
    .unwrap();
    (env, policy)
}

#[test]
fn genuine_signed_source_installs_and_reopens_offline_without_runtime_proof() {
    let temp = tempfile::tempdir().unwrap();
    let (_env, policy) = isolated_home(temp.path());
    let (paths, expected) = stage_fixture(&temp.path().join("candidate"), "signed-registry-python");
    let installed = install_local_registry_pack(&expected, &paths).unwrap();
    let lock = store::load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).unwrap();
    let (_, verified) = store::open_installed_registry_pack(
        &mvm_core::config::registry_pack_cache_dir(),
        &lock,
        &policy,
        expected.reference(),
    )
    .unwrap();
    assert!(matches!(
        verified.manifest().image,
        Some(RegistryPackImage::Source(_))
    ));
    assert_eq!(expected.reference().to_string(), SOURCE);
    assert_eq!(lock.pins(), std::slice::from_ref(&expected));
    assert_eq!(
        install_local_registry_pack(&expected, &paths)
            .unwrap()
            .root(),
        installed.root()
    );
}

#[test]
fn expected_reference_digest_and_signature_refusals_precede_payload_access() {
    let temp = tempfile::tempdir().unwrap();
    let (_env, _) = isolated_home(temp.path());
    let (paths, expected) = stage_fixture(&temp.path().join("candidate"), "signed-registry-python");
    std::fs::remove_dir_all(temp.path().join("candidate/files")).unwrap();
    for wrong in [
        PackPin::new(
            "runtime/python@99.0.0".parse().unwrap(),
            expected.manifest_sha256().clone(),
        )
        .unwrap(),
        PackPin::new(
            expected.reference().clone(),
            Sha256Hex::from_bytes(b"wrong"),
        )
        .unwrap(),
    ] {
        let error = install_local_registry_pack(&wrong, &paths).unwrap_err();
        assert!(!format!("{error:#}").contains("No such file"), "{error:#}");
    }
    std::fs::write(temp.path().join("candidate/bundle.json"), b"bad signature").unwrap();
    assert!(install_local_registry_pack(&expected, &paths).is_err());
    assert!(!mvm_core::config::registry_pack_cache_dir().exists());
    assert!(!mvm_core::config::pack_lockfile_path().exists());
}

#[test]
fn configured_revocation_feed_is_required_before_payload_access() {
    let temp = tempfile::tempdir().unwrap();
    let (_env, _) = isolated_home(temp.path());
    let (paths, expected) = stage_fixture(&temp.path().join("candidate"), "signed-registry-python");
    std::fs::remove_dir_all(temp.path().join("candidate/files")).unwrap();
    let trust = mvm_core::config::registry_pack_revocation_trust_path();
    std::fs::create_dir_all(trust.parent().unwrap()).unwrap();
    mvm_core::private_fs::set_mode(trust.parent().unwrap(), 0o700).unwrap();
    std::fs::write(&trust,
        "schema_version = 1\nissuer = 'https://token.actions.githubusercontent.com'\naccepted_identities = ['https://github.com/tinylabscom/mvm/.github/workflows/revoke.yml@refs/heads/main']\n",
    ).unwrap();
    mvm_core::private_fs::set_mode(&trust, 0o600).unwrap();
    let error = install_local_registry_pack(&expected, &paths).unwrap_err();
    assert!(
        format!("{error:#}").contains("revocation cache is missing"),
        "{error:#}"
    );
    assert!(!mvm_core::config::registry_pack_cache_dir().exists());
    assert!(!mvm_core::config::pack_lockfile_path().exists());
}

#[test]
fn conflicting_pin_and_poisoned_cache_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let (_env, _) = isolated_home(temp.path());
    let (paths, expected) = stage_fixture(&temp.path().join("candidate"), "signed-registry-python");
    let lock_path = mvm_core::config::pack_lockfile_path();
    let conflicting = PackPin::new(
        "runtime/python@99.0.0".parse().unwrap(),
        Sha256Hex::from_bytes(b"other"),
    )
    .unwrap();
    store::save_pack_lockfile(
        &lock_path,
        &mvm_core::registry_pack::PackLockfile::new(vec![conflicting.clone()]).unwrap(),
    )
    .unwrap();
    assert!(install_local_registry_pack(&expected, &paths).is_err());
    assert_eq!(
        store::load_pack_lockfile(&lock_path).unwrap().pins(),
        &[conflicting]
    );
    store::save_pack_lockfile(
        &lock_path,
        &mvm_core::registry_pack::PackLockfile::new(vec![]).unwrap(),
    )
    .unwrap();
    let cache =
        mvm_core::config::registry_pack_cache_dir().join(expected.manifest_sha256().as_str());
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("keep"), b"existing invalid installation").unwrap();
    assert!(install_local_registry_pack(&expected, &paths).is_err());
    assert_eq!(
        std::fs::read(cache.join("keep")).unwrap(),
        b"existing invalid installation"
    );
    assert!(
        store::load_pack_lockfile(&lock_path)
            .unwrap()
            .pins()
            .is_empty()
    );
}

#[test]
fn unlisted_tampered_and_oversized_payloads_never_install() {
    for mutation in ["unlisted", "tampered", "oversized"] {
        let temp = tempfile::tempdir().unwrap();
        let (_env, _) = isolated_home(temp.path());
        let (paths, expected) =
            stage_fixture(&temp.path().join("candidate"), "signed-registry-python");
        let root = temp.path().join("candidate/files");
        match mutation {
            "unlisted" => std::fs::write(root.join("unlisted"), b"not signed").unwrap(),
            "tampered" => std::fs::write(root.join("pack/group.toml"), b"tampered").unwrap(),
            "oversized" => {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(root.join("pack/group.toml"))
                    .unwrap();
                file.set_len(32 * 1024 * 1024 * 1024).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            install_local_registry_pack(&expected, &paths).is_err(),
            "{mutation}"
        );
        assert!(!mvm_core::config::registry_pack_cache_dir().exists());
        assert!(!mvm_core::config::pack_lockfile_path().exists());
    }
}

#[test]
fn missing_dependency_is_refused_and_trusted_locked_local_dependency_is_accepted() {
    let temp = tempfile::tempdir().unwrap();
    let (_env, _) = isolated_home(temp.path());
    let (parent, parent_pin) = stage_fixture(&temp.path().join("parent"), "signed-registry-claude");
    let error = install_local_registry_pack(&parent_pin, &parent).unwrap_err();
    assert!(
        format!("{error:#}").contains("no fetch is performed"),
        "{error:#}"
    );
    assert!(!mvm_core::config::pack_lockfile_path().exists());
    let (dependency, dependency_pin) =
        stage_fixture(&temp.path().join("dependency"), "signed-registry-python");
    install_local_registry_pack(&dependency_pin, &dependency).unwrap();
    install_local_registry_pack(&parent_pin, &parent).unwrap();
    assert_eq!(
        store::load_pack_lockfile(&mvm_core::config::pack_lockfile_path())
            .unwrap()
            .pins()
            .len(),
        2
    );
}

#[test]
#[cfg(unix)]
fn symlink_hardlink_and_fifo_payloads_are_refused_without_installation() {
    use std::os::unix::fs::symlink;
    for mutation in ["symlink", "hardlink", "fifo", "parent-symlink"] {
        let temp = tempfile::tempdir().unwrap();
        let (_env, _) = isolated_home(temp.path());
        let (paths, expected) =
            stage_fixture(&temp.path().join("candidate"), "signed-registry-python");
        let root = temp.path().join("candidate/files");
        let group = root.join("pack/group.toml");
        let saved = temp.path().join("saved");
        std::fs::rename(&group, &saved).unwrap();
        match mutation {
            "symlink" => symlink(&saved, &group).unwrap(),
            "hardlink" => std::fs::hard_link(&saved, &group).unwrap(),
            "fifo" => assert!(
                std::process::Command::new("mkfifo")
                    .arg(&group)
                    .status()
                    .unwrap()
                    .success()
            ),
            "parent-symlink" => {
                std::fs::rename(root.join("pack"), temp.path().join("pack")).unwrap();
                symlink(temp.path().join("pack"), root.join("pack")).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            install_local_registry_pack(&expected, &paths).is_err(),
            "{mutation}"
        );
        assert!(!mvm_core::config::registry_pack_cache_dir().exists());
        assert!(!mvm_core::config::pack_lockfile_path().exists());
    }
}
