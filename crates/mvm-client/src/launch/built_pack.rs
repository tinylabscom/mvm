//! Fresh resolution of a pinned built pack's image, never a persisted host path.

use anyhow::{Context, Result, ensure};
use mvm_core::arch::GuestArch;
use mvm_core::registry_pack::PackPin;
use mvm_core::registry_pack_boot::BuiltPackBootContract;
use mvm_core::vm_backend::{BackendKind, VmStartConfig};

/// Resolve the pack/base-owned image fields through the authenticated contract.
/// This does not authorize a boot: runtime preparation, signed-plan admission
/// and the final host `prepare_built_pack_start` gate remain mandatory.
pub fn resolve_built_pack_image(
    pin: &PackPin,
    backend: &str,
    profile: &str,
) -> Result<VmStartConfig> {
    validate_built_pack_profile(profile)?;
    ensure!(
        std::env::var("MVM_DIRECT_BOOT").as_deref() != Ok("1"),
        "a built pack cannot substitute a direct-boot image"
    );
    let backend_kind = BackendKind::from_label(backend).context("unknown built-pack backend")?;
    let contract = BuiltPackBootContract::open_for_admission(
        pin,
        &mvm_build::stage0_kernel::current_image_set_protocol_support(),
    )?;
    // Validate architecture/backend before resolving any host kernel input.
    contract.kernel(GuestArch::host(), backend_kind)?;
    let kernel = super::machine_start::cached_workload_kernel(backend)?
        .context("built packs require the signed workload kernel to be prepared")?;
    contract.image_config(
        std::path::Path::new(&kernel),
        GuestArch::host(),
        backend_kind,
    )
}

pub(super) fn validate_built_pack_profile(profile: &str) -> Result<()> {
    ensure!(
        matches!(
            crate::profile::RunProfile::from_name(profile),
            Some(crate::profile::RunProfile::Restrictive | crate::profile::RunProfile::Standard)
        ),
        "built registry images require a restrictive or standard workload profile"
    );
    Ok(())
}

/// A legacy manifest marker must name the image declared by that exact signed
/// Source pack. Neither a Built nor a policy-only pack can enter this path.
pub(super) fn validate_source_pack_slot(pin: &PackPin, selected: &str) -> Result<()> {
    use mvm_core::registry_pack::RegistryPackImage;

    let lock =
        mvm_core::registry_pack_store::load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?
    .policy;
    let (installed, verified) = mvm_core::registry_pack_store::open_installed_registry_pack(
        &mvm_core::config::registry_pack_cache_dir(),
        &lock,
        &publisher,
        pin.reference(),
    )?;
    ensure!(
        verified.manifest_sha256() == pin.manifest_sha256(),
        "source registry image no longer matches its persisted pin"
    );
    let Some(RegistryPackImage::Source(image)) = &verified.manifest().image else {
        anyhow::bail!(
            "a manifest source requires a signed Source pack image, not Built or policy-only"
        );
    };
    let manifest = installed.payload_root().join(&image.manifest);
    validate_source_slot_identity(&manifest, selected)
}

fn validate_source_slot_identity(manifest: &std::path::Path, selected: &str) -> Result<()> {
    use mvm_core::domain::manifest::{
        Manifest, PersistedManifest, flake_manifest_identity, key_for_manifest_identity,
        resolve_flake_ref,
    };

    let declared = Manifest::read_file(manifest)?;
    let directory = manifest.parent().context("source manifest has no parent")?;
    let resolved = resolve_flake_ref(
        directory
            .to_str()
            .context("source pack directory is not UTF-8")?,
    )?;
    let identity = flake_manifest_identity(&resolved);
    let expected_slot = key_for_manifest_identity(&identity);
    ensure!(
        selected == expected_slot,
        "persistent manifest slot differs from the signed Source pack descriptor"
    );
    let actual = PersistedManifest::read_from_slot(std::path::Path::new(
        &mvm_core::manifest::slot_dir(selected),
    ))?;
    ensure!(
        actual.manifest_hash == expected_slot
            && actual.manifest_path == identity
            && actual.flake_ref == resolved
            && actual.profile == declared.profile,
        "persistent Source slot identity or profile differs from its signed descriptor"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_profiles_never_enable_developer_or_permissive_guests() {
        for profile in ["restrictive", "standard"] {
            validate_built_pack_profile(profile).unwrap();
        }
        for profile in ["dev", "permissive", "unknown", ""] {
            assert!(validate_built_pack_profile(profile).is_err(), "{profile}");
        }
    }

    #[test]
    fn built_resolution_requires_the_applied_revocation_list() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.remove("MVM_DIRECT_BOOT");
        let pin = PackPin::new(
            "runtime/python@1.1.0".parse().unwrap(),
            mvm_core::packs::Sha256Hex::from_bytes(b"uninstalled fixture"),
        )
        .unwrap();
        let error = resolve_built_pack_image(&pin, "firecracker", "standard").unwrap_err();
        assert!(
            format!("{error:#}").contains("image-set revocation"),
            "{error:#}"
        );
    }

    #[test]
    fn durable_built_source_round_trips_only_its_pin() {
        use super::super::{LaunchRequest, LaunchSource, LifecycleMode};
        let pin = PackPin::new(
            "runtime/python@1.1.0".parse().unwrap(),
            mvm_core::packs::Sha256Hex::from_bytes(b"declared fixture"),
        )
        .unwrap();
        let request = LaunchRequest::builder_for(
            LifecycleMode::Persistent,
            LaunchSource::RegistryPack { pin: pin.clone() },
        )
        .name("built-definition")
        .profile("standard")
        .build()
        .unwrap();
        let spec = super::super::persisted_spec_from_request(&request, "built-definition");
        assert!(spec.image.is_none() && spec.manifest.is_none() && spec.deployment.is_none());
        let restored: mvm_runtime::machine::persist::MachineSpec =
            serde_json::from_slice(&serde_json::to_vec(&spec).unwrap()).unwrap();
        assert_eq!(restored.registry_pack_image, Some(pin));
        assert!(!restored.runtime_pack);
    }

    #[test]
    fn built_request_rejects_a_developer_profile_before_preparation() {
        use super::super::{LaunchRequest, LaunchSource, LifecycleMode};
        let pin = PackPin::new(
            "runtime/python@1.1.0".parse().unwrap(),
            mvm_core::packs::Sha256Hex::from_bytes(b"declared fixture"),
        )
        .unwrap();
        let request = LaunchRequest::builder_for(
            LifecycleMode::Transient,
            LaunchSource::RegistryPack { pin },
        )
        .profile("dev")
        .build();
        assert!(
            request
                .unwrap_err()
                .to_string()
                .contains("workload profile")
        );
    }

    #[test]
    fn source_slot_uses_the_compilers_flake_identity_and_profile() {
        use mvm_core::domain::manifest::{PersistedManifest, resolve_flake_ref};
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let source = home.path().join("signed-source");
        std::fs::create_dir(&source).unwrap();
        let manifest = source.join("mvm.toml");
        std::fs::write(&manifest, "flake = \".\"\nprofile = \"minimal\"\n").unwrap();
        let resolved = resolve_flake_ref(source.to_str().unwrap()).unwrap();
        let mut record = PersistedManifest::from_flake_identity(&resolved, Some("minimal"), "mock");
        let slot = std::path::PathBuf::from(mvm_core::manifest::slot_dir(&record.manifest_hash));
        record.write_to_slot(&slot).unwrap();
        validate_source_slot_identity(&manifest, &record.manifest_hash).unwrap();
        assert!(
            validate_source_slot_identity(
                &manifest,
                &mvm_core::domain::manifest::canonical_key_for_path(&manifest).unwrap(),
            )
            .is_err(),
            "canonical manifest and flake identities must not be confused"
        );
        record.profile = "different".into();
        record.write_to_slot(&slot).unwrap();
        assert!(validate_source_slot_identity(&manifest, &record.manifest_hash).is_err());
    }

    #[cfg(feature = "test-support")]
    #[tokio::test]
    async fn public_persistent_start_accepts_pin_shape_but_refuses_missing_authentication() {
        use super::super::{LaunchRequest, LaunchSource, LifecycleMode};
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        env.remove("MVM_DIRECT_BOOT");
        let client = crate::local::LocalBackend::with_hypervisor("mock");
        let pin = PackPin::new(
            "runtime/python@1.1.0".parse().unwrap(),
            mvm_core::packs::Sha256Hex::from_bytes(b"missing signed fixture"),
        )
        .unwrap();
        let request = LaunchRequest::builder_for(
            LifecycleMode::Persistent,
            LaunchSource::RegistryPack { pin },
        )
        .name("built-persistent")
        .profile("standard")
        .build()
        .unwrap();
        client.create_from_request(&request).unwrap();
        let error = client
            .start_persistent("built-persistent")
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("image-set revocation"),
            "{error:#}"
        );
        let mut spec =
            mvm_runtime::machine::persist::load_machine_spec("built-persistent").unwrap();
        assert!(spec.last_started_at.is_none());
        for conflict in ["image", "deployment", "runtime_pack"] {
            spec.image = None;
            spec.deployment = None;
            spec.runtime_pack = false;
            match conflict {
                "image" => spec.image = Some("alpine:3.20".into()),
                "deployment" => spec.deployment = Some("conflicting-deployment".into()),
                "runtime_pack" => spec.runtime_pack = true,
                _ => unreachable!(),
            }
            mvm_runtime::machine::persist::overwrite_machine_spec(&spec).unwrap();
            let error = client
                .start_persistent("built-persistent")
                .await
                .unwrap_err();
            let expected = if conflict == "runtime_pack" {
                "runtime-pack source"
            } else {
                "cannot be combined"
            };
            assert!(
                format!("{error:#}").contains(expected),
                "{conflict}: {error:#}"
            );
            let persisted =
                mvm_runtime::machine::persist::load_machine_spec("built-persistent").unwrap();
            assert!(persisted.last_started_at.is_none(), "{conflict}");
            assert_eq!(persisted.registry_pack_image, spec.registry_pack_image);
        }
    }

    #[cfg(feature = "manifest-verify")]
    #[test]
    fn signed_source_fixture_binds_the_production_flake_slot() {
        use mvm_core::domain::manifest::{Manifest, PersistedManifest, resolve_flake_ref};
        use mvm_core::registry_pack::{
            PackAdoption, RegistryPackPublisher, RegistryPackPublisherPolicy,
        };
        use mvm_core::registry_pack_store::{adopt_install_and_pin, save_publisher_policy};

        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/signed-registry-python");
        let manifest_bytes = std::fs::read(fixture.join("manifest.json")).unwrap();
        let signature = std::fs::read(fixture.join("manifest.sigstore.json")).unwrap();
        let policy = RegistryPackPublisherPolicy::new(vec![
            RegistryPackPublisher::new(
                "runtime",
                "https://token.actions.githubusercontent.com",
                vec!["https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/feat/3716-python-image-pack".into()],
            )
            .unwrap(),
        ])
        .unwrap();
        save_publisher_policy(
            &mvm_core::config::registry_pack_publisher_policy_path(),
            &policy,
        )
        .unwrap();
        let staged = home.path().join("staged");
        for relative in [
            "pack/group.toml",
            "pack/image/mvm.toml",
            "pack/image/flake.nix",
            "pack/image/flake.lock",
        ] {
            let path = staged.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::copy(fixture.join("files").join(relative), path).unwrap();
        }
        let reference = "runtime/python@1.1.0".parse().unwrap();
        let installed = adopt_install_and_pin(
            &PackAdoption {
                requested: &reference,
                manifest_bytes: &manifest_bytes,
                signature_bundle: &signature,
                publisher_policy: &policy,
            },
            &staged,
            &mvm_core::config::registry_pack_cache_dir(),
            &mvm_core::config::pack_lockfile_path(),
        )
        .unwrap();
        let pin = PackPin::new(
            reference,
            mvm_core::packs::Sha256Hex::from_bytes(&manifest_bytes),
        )
        .unwrap();
        let source = installed.payload_root().join("pack/image");
        let declared = Manifest::read_file(&source.join("mvm.toml")).unwrap();
        let resolved = resolve_flake_ref(source.to_str().unwrap()).unwrap();
        // This is the same record constructor used by production CLI builds;
        // registering metadata does not claim an actual Nix build or VM boot.
        let mut record =
            PersistedManifest::from_flake_identity(&resolved, Some(&declared.profile), "mock");
        let slot = std::path::PathBuf::from(mvm_core::manifest::slot_dir(&record.manifest_hash));
        record.write_to_slot(&slot).unwrap();
        validate_source_pack_slot(&pin, &record.manifest_hash).unwrap();
        assert!(validate_source_pack_slot(&pin, &"0".repeat(64)).is_err());
        let wrong_pin = PackPin::new(
            pin.reference().clone(),
            mvm_core::packs::Sha256Hex::from_bytes(b"replaced pin"),
        )
        .unwrap();
        assert!(validate_source_pack_slot(&wrong_pin, &record.manifest_hash).is_err());
        record.profile = "different".into();
        record.write_to_slot(&slot).unwrap();
        assert!(validate_source_pack_slot(&pin, &record.manifest_hash).is_err());
        record.profile = declared.profile;
        record.flake_ref = "/unrelated/source".into();
        record.write_to_slot(&slot).unwrap();
        assert!(validate_source_pack_slot(&pin, &record.manifest_hash).is_err());
        record.flake_ref = resolved;
        record.manifest_path = "/unrelated/identity".into();
        record.write_to_slot(&slot).unwrap();
        assert!(validate_source_pack_slot(&pin, &record.manifest_hash).is_err());
        record.manifest_path =
            mvm_core::domain::manifest::flake_manifest_identity(&record.flake_ref);
        let original_hash = record.manifest_hash.clone();
        record.manifest_hash = "f".repeat(64);
        record.write_to_slot(&slot).unwrap();
        assert!(validate_source_pack_slot(&pin, &original_hash).is_err());
    }
}
