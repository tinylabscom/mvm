#![cfg(feature = "manifest-verify")]

use std::path::{Path, PathBuf};

use mvm_client::policy_profiles::{LayerOrigin, PolicyRef, PolicyStore};
use mvm_core::registry_pack::{
    LEGACY_PACK_SIGNING_CUTOFF, RegistryPackPublisher, RegistryPackPublisherPolicy,
};
use mvm_core::registry_pack_store::{
    load_pack_lockfile, open_installed_registry_pack, save_publisher_policy,
};
use mvm_core::util::test_env::TestEnv;
use tempfile::TempDir;

const MANIFEST: &[u8] = include_bytes!("fixtures/signed-registry-go/manifest.json");
const BUNDLE: &[u8] = include_bytes!("fixtures/signed-registry-go/manifest.sigstore.json");
const GROUP: &[u8] = include_bytes!("fixtures/signed-registry-go/pack/group.toml");
const MANIFEST_SHA256: &str = "ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50";
const HISTORICAL_PUBLISHER_IDENTITY: &str =
    "https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main";
const PYTHON_MANIFEST: &[u8] = include_bytes!("fixtures/signed-registry-python/manifest.json");
const PYTHON_BUNDLE: &[u8] =
    include_bytes!("fixtures/signed-registry-python/manifest.sigstore.json");
const PYTHON_FILES: [(&str, &[u8]); 4] = [
    (
        "pack/group.toml",
        include_bytes!("fixtures/signed-registry-python/files/pack/group.toml"),
    ),
    (
        "pack/image/mvm.toml",
        include_bytes!("fixtures/signed-registry-python/files/pack/image/mvm.toml"),
    ),
    (
        "pack/image/flake.nix",
        include_bytes!("fixtures/signed-registry-python/files/pack/image/flake.nix"),
    ),
    (
        "pack/image/flake.lock",
        include_bytes!("fixtures/signed-registry-python/files/pack/image/flake.lock"),
    ),
];

fn registry_files(root: &Path, manifest: &[u8], group: &[u8]) -> PathBuf {
    let registry = root.join("registry");
    let pack = registry.join("packs/runtime/go/1.0.0");
    std::fs::create_dir_all(pack.join("files/pack")).expect("pack fixture directory");
    std::fs::write(
        registry.join("packs/index.json"),
        br#"{"schema_version":1,"packs":[{"namespace":"runtime","name":"go","description":"Go runtime policy","versions":["1.0.0"]}]}"#,
    )
    .expect("registry index");
    std::fs::write(pack.join("manifest.json"), manifest).expect("signed manifest");
    std::fs::write(pack.join("manifest.sigstore.json"), BUNDLE).expect("Sigstore bundle");
    std::fs::write(pack.join("files/pack/group.toml"), group).expect("signed payload");
    registry
}

fn isolated_registry(temp: &TempDir, manifest: &[u8], group: &[u8]) -> TestEnv {
    let registry = registry_files(temp.path(), manifest, group);
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    env.set(
        "MVM_PACK_REGISTRY",
        format!("file://{}", registry.display()),
    );
    let publisher = RegistryPackPublisher::new(
        "runtime",
        "https://token.actions.githubusercontent.com",
        vec![HISTORICAL_PUBLISHER_IDENTITY.to_string()],
    )
    .expect("historical publisher identity");
    let policy = RegistryPackPublisherPolicy::new(vec![publisher]).expect("publisher policy");
    save_publisher_policy(
        &mvm_core::config::registry_pack_publisher_policy_path(),
        &policy,
    )
    .expect("save explicit historical fixture trust");
    env
}

#[test]
fn the_builtin_default_bounds_trust_in_the_historical_fixture_identity() {
    let temp = TempDir::new().expect("tempdir");
    let _env = isolated_registry(&temp, MANIFEST, GROUP);
    std::fs::remove_file(mvm_core::config::registry_pack_publisher_policy_path())
        .expect("remove explicit fixture trust");

    let cutoff = chrono::DateTime::parse_from_rfc3339(LEGACY_PACK_SIGNING_CUTOFF)
        .expect("built-in cutoff is RFC 3339")
        .with_timezone(&chrono::Utc);
    let result = mvm_cli::pack_registry::pull("runtime/go");
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).expect("lockfile");
    if chrono::Utc::now() < cutoff {
        let summary = result.expect("former publisher is trusted before the cutoff");
        assert_eq!(summary.manifest_sha256, MANIFEST_SHA256);
        assert_eq!(lock.pins().len(), 1);
    } else {
        let error = result.expect_err("former publisher must be refused after the cutoff");
        assert!(format!("{error:#}").contains("signature"));
        assert!(lock.pins().is_empty());
    }
}

#[test]
fn published_signed_pack_pulls_pins_and_loads_without_network() {
    let temp = TempDir::new().expect("tempdir");
    let _env = isolated_registry(&temp, MANIFEST, GROUP);
    let summary = mvm_cli::pack_registry::pull("runtime/go").expect("signed pull");
    assert_eq!(summary.reference.to_string(), "runtime/go@1.0.0");
    assert_eq!(summary.manifest_sha256, MANIFEST_SHA256);
    assert_eq!(summary.files, 1);

    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).expect("lockfile");
    assert_eq!(lock.pins().len(), 1);
    assert_eq!(lock.pins()[0].manifest_sha256().as_str(), MANIFEST_SHA256);

    let store = PolicyStore::at(temp.path().join("policy"));
    let reference = PolicyRef::parse("runtime/go").expect("policy reference");
    let loaded = store
        .load_group(&reference, None, LayerOrigin::User, "test")
        .expect("load the signed pack policy through the consumer path");
    assert_eq!(loaded.origin, LayerOrigin::Pack);
    assert!(
        loaded
            .doc
            .network
            .allow
            .contains(&"proxy.golang.org:443".to_string())
    );
}

#[test]
fn a_tampered_signed_manifest_is_refused_before_a_pin_is_written() {
    let temp = TempDir::new().expect("tempdir");
    let mut manifest = MANIFEST.to_vec();
    let offset = manifest
        .windows(2)
        .position(|bytes| bytes == b"Go")
        .expect("description present");
    manifest[offset] = b'N';
    let _env = isolated_registry(&temp, &manifest, GROUP);
    let error = mvm_cli::pack_registry::pull("runtime/go").expect_err("tamper refused");
    assert!(format!("{error:#}").contains("signature"));
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).expect("lockfile");
    assert!(lock.pins().is_empty());
}

#[test]
fn a_tampered_signed_payload_is_refused_before_a_pin_is_written() {
    let temp = TempDir::new().expect("tempdir");
    let mut group = GROUP.to_vec();
    group[0] = b'X';
    let _env = isolated_registry(&temp, MANIFEST, &group);
    let error = mvm_cli::pack_registry::pull("runtime/go").expect_err("tamper refused");
    assert!(format!("{error:#}").contains("digest mismatch"));
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).expect("lockfile");
    assert!(lock.pins().is_empty());
}

#[test]
fn a_pinned_pack_refuses_manifest_drift_on_the_next_pull() {
    let temp = TempDir::new().expect("tempdir");
    let _env = isolated_registry(&temp, MANIFEST, GROUP);
    mvm_cli::pack_registry::pull("runtime/go").expect("initial signed pull");
    let manifest_path = temp
        .path()
        .join("registry/packs/runtime/go/1.0.0/manifest.json");
    let mut manifest = MANIFEST.to_vec();
    let offset = manifest
        .windows(2)
        .position(|bytes| bytes == b"Go")
        .expect("description present");
    manifest[offset] = b'N';
    std::fs::write(manifest_path, manifest).expect("modify registry copy");

    let error = mvm_cli::pack_registry::pull("runtime/go").expect_err("drift refused");
    assert!(format!("{error:#}").contains("digest drift"));
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).expect("lockfile");
    assert_eq!(lock.pins()[0].manifest_sha256().as_str(), MANIFEST_SHA256);
}

#[test]
fn a_different_publisher_identity_cannot_adopt_the_signed_pack() {
    let temp = TempDir::new().expect("tempdir");
    let _env = isolated_registry(&temp, MANIFEST, GROUP);
    let publisher = RegistryPackPublisher::new(
        "runtime",
        "https://token.actions.githubusercontent.com",
        vec![
            "https://github.com/example/other/.github/workflows/publish.yml@refs/heads/main"
                .to_string(),
        ],
    )
    .expect("publisher policy");
    let policy = RegistryPackPublisherPolicy::new(vec![publisher]).expect("publisher policy");
    save_publisher_policy(
        &mvm_core::config::registry_pack_publisher_policy_path(),
        &policy,
    )
    .expect("save publisher policy");
    let error = mvm_cli::pack_registry::pull("runtime/go").expect_err("wrong publisher refused");
    assert!(format!("{error:#}").contains("signature"));
}

#[test]
fn a_real_signed_image_pack_pulls_with_its_image_and_reopens_under_the_pin() {
    let temp = TempDir::new().expect("tempdir");
    let registry = temp.path().join("registry");
    let pack = registry.join("packs/runtime/python/1.1.0");
    std::fs::create_dir_all(pack.join("files/pack/image")).expect("image payload directory");
    std::fs::write(
        registry.join("packs/index.json"),
        br#"{"schema_version":1,"packs":[{"namespace":"runtime","name":"python","description":"Python runtime","versions":["1.1.0"]}]}"#,
    )
    .expect("registry index");
    std::fs::write(pack.join("manifest.json"), PYTHON_MANIFEST).expect("signed manifest");
    std::fs::write(pack.join("manifest.sigstore.json"), PYTHON_BUNDLE).expect("signature bundle");
    for (path, bytes) in PYTHON_FILES {
        std::fs::write(pack.join("files").join(path), bytes).expect("signed payload");
    }
    let mut env = TestEnv::new();
    env.isolate_mvm_home(temp.path().join("home"));
    env.set(
        "MVM_PACK_REGISTRY",
        format!("file://{}", registry.display()),
    );
    let publisher = RegistryPackPublisher::new(
        "runtime",
        "https://token.actions.githubusercontent.com",
        vec!["https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/feat/3716-python-image-pack".to_string()],
    )
    .expect("branch publisher identity");
    let policy = RegistryPackPublisherPolicy::new(vec![publisher]).expect("publisher trust");
    save_publisher_policy(
        &mvm_core::config::registry_pack_publisher_policy_path(),
        &policy,
    )
    .expect("save publisher trust");

    let summary = mvm_cli::pack_registry::pull("runtime/python@1.1.0")
        .expect("pull a real signed image pack");
    assert_eq!(summary.files, 4);
    let lock = load_pack_lockfile(&mvm_core::config::pack_lockfile_path()).expect("lockfile");
    let (_, verified) = open_installed_registry_pack(
        &mvm_core::config::registry_pack_cache_dir(),
        &lock,
        &policy,
        &summary.reference,
    )
    .expect("reopen signed pack");
    assert_eq!(
        verified.manifest().image.as_ref().expect("image").manifest,
        "pack/image/mvm.toml"
    );
    assert_eq!(verified.manifest_sha256().as_str(), summary.manifest_sha256);
}
