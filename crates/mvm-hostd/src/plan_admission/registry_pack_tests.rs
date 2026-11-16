#![cfg(test)]

use super::test_support::*;
use super::*;

#[cfg(feature = "manifest-verify")]
const PYTHON_MANIFEST: &[u8] =
    include_bytes!("../../../mvm-cli/tests/fixtures/signed-registry-python/manifest.json");
#[cfg(feature = "manifest-verify")]
const PYTHON_BUNDLE: &[u8] =
    include_bytes!("../../../mvm-cli/tests/fixtures/signed-registry-python/manifest.sigstore.json");

#[cfg(feature = "manifest-verify")]
fn install_signed_python_pack(
    home: &std::path::Path,
) -> mvm_core::registry_pack::InstalledRegistryPack {
    use mvm_core::registry_pack::{
        PackAdoption, RegistryPackPublisher, RegistryPackPublisherPolicy,
    };
    use mvm_core::registry_pack_store::{adopt_install_and_pin, save_publisher_policy};

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
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../mvm-cli/tests/fixtures/signed-registry-python/files");
    let staged = home.join("staged-pack");
    std::fs::create_dir_all(staged.join("pack/image")).expect("staged image directory");
    for relative in [
        "pack/group.toml",
        "pack/image/mvm.toml",
        "pack/image/flake.nix",
        "pack/image/flake.lock",
    ] {
        std::fs::copy(fixture.join(relative), staged.join(relative))
            .expect("stage signed payload bytes");
    }
    let reference = "runtime/python@1.1.0".parse().expect("pack reference");
    adopt_install_and_pin(
        &PackAdoption {
            requested: &reference,
            manifest_bytes: PYTHON_MANIFEST,
            signature_bundle: PYTHON_BUNDLE,
            publisher_policy: &policy,
        },
        &staged,
        &mvm_core::config::registry_pack_cache_dir(),
        &mvm_core::config::pack_lockfile_path(),
    )
    .expect("adopt signed image pack")
}

#[test]
fn registry_pack_asset_requires_an_exact_version_and_a_verified_installation() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let mut plan = plan_binding(&[]);
    plan.asset_identities.push(
        mvm_core::plan::AssetIdentity::new(
            mvm_core::plan::AssetKind::RegistryPack,
            "runtime/python",
            FIXTURE_SHA,
        )
        .expect("valid digest"),
    );
    let error = verify_registry_pack_assets(&plan).expect_err("version required");
    assert!(error.to_string().contains("exact version"), "{error}");
    assert!(
        registry_pack::verify_registry_pack_boot(
            &plan,
            &mut VmStartConfig::default(),
            BackendKind::Firecracker,
        )
        .is_err(),
        "backend handoff must also refuse a non-versioned pack pin"
    );

    plan.asset_identities
        .last_mut()
        .expect("pack identity was appended")
        .name = "runtime/python@1.0.0".to_string();
    let error = verify_registry_pack_assets(&plan).expect_err("uninstalled pack refused");
    assert!(
        error.to_string().contains("verifying registry pack"),
        "{error}"
    );

    plan.asset_identities
        .last_mut()
        .expect("pack identity was appended")
        .name = "../../outside@1.0.0".to_string();
    let error = verify_registry_pack_assets(&plan).expect_err("unsafe reference refused");
    assert!(
        error
            .to_string()
            .contains("invalid registry pack reference"),
        "{error}"
    );
}

#[test]
fn admission_without_registry_pack_assets_needs_no_pack_store() {
    let (_env, _home) = host_with_ceiling(Default::default());
    let plan = plan_binding(&[]);
    verify_registry_pack_assets(&plan).expect("ordinary plan has no pack lookup");
    registry_pack::verify_registry_pack_boot(
        &plan,
        &mut VmStartConfig::default(),
        BackendKind::Mock,
    )
    .expect("ordinary workloads need no built-pack boot contract");
}

#[cfg(feature = "manifest-verify")]
#[test]
fn real_signed_pack_identity_is_reverified_at_host_admission() {
    let (_env, home) = host_with_ceiling(Default::default());
    let installed = install_signed_python_pack(home.path());
    let digest = mvm_core::packs::Sha256Hex::from_bytes(PYTHON_MANIFEST);
    let mut plan = plan_binding(&[]);
    plan.asset_identities.push(
        mvm_core::plan::AssetIdentity::new(
            mvm_core::plan::AssetKind::RegistryPack,
            "runtime/python@1.1.0",
            digest.as_str(),
        )
        .expect("pack asset identity"),
    );
    verify_registry_pack_assets(&plan).expect("signed pack admits");
    registry_pack::verify_registry_pack_boot(
        &plan,
        &mut VmStartConfig::default(),
        BackendKind::Mock,
    )
    .expect("source packs do not acquire built-image boot authority");

    let ledger = InMemoryNonceLedger::new();
    let admitted = admit_plan_for_run(
        &plan,
        &SystemClock,
        &ledger,
        None,
        None,
        None,
        RunPosture::on_backend(Variant::Dev, BackendKind::Firecracker),
    )
    .expect("real source pack plan is admitted");
    let mut config = VmStartConfig {
        tenant_id: Some(admitted.plan().tenant.0.clone()),
        plan_json: Some(serde_json::to_string(admitted.signed()).unwrap()),
        ..Default::default()
    };
    assert!(
        admitted
            .built_pack_boot_check()
            .unwrap()
            .unwrap()
            .prepare(&mut config, BackendKind::Firecracker)
            .unwrap()
            .is_none(),
        "a source pack keeps its existing non-built launch path"
    );
    assert!(
        admitted
            .built_pack_boot_check()
            .unwrap()
            .unwrap()
            .prepare(&mut config, BackendKind::Hvf)
            .unwrap_err()
            .to_string()
            .contains("backend differs")
    );
    config.plan_json = Some("{}".into());
    assert!(
        admitted
            .built_pack_boot_check()
            .unwrap()
            .unwrap()
            .prepare(&mut config, BackendKind::Firecracker)
            .unwrap_err()
            .to_string()
            .contains("admitted plan")
    );

    plan.asset_identities
        .last_mut()
        .expect("pack identity")
        .digest = FIXTURE_SHA.to_string();
    let error = verify_registry_pack_assets(&plan).expect_err("wrong plan digest refused");
    assert!(error.to_string().contains("signed-plan digest"), "{error}");

    plan.asset_identities
        .last_mut()
        .expect("pack identity")
        .digest = digest.as_str().to_string();
    let path = installed.payload_root().join("pack/image/mvm.toml");
    let mut bytes = std::fs::read(&path).expect("read signed image manifest");
    bytes[0] ^= 1;
    std::fs::write(path, bytes).expect("tamper cached payload without changing length");
    let error = verify_registry_pack_assets(&plan).expect_err("tampered pack refused");
    assert!(
        format!("{error:#}").contains("digest mismatch"),
        "{error:#}"
    );
}
