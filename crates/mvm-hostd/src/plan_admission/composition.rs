//! Recheck a composition's original publisher evidence on every run.
//!
//! The plan pins the signed bundle and measures its rootfs; the bundle
//! retains only small signed inputs, never a second copy of the layer archives.

use anyhow::{Context, Result, ensure};
use mvm_build::runtime_layer::ResolvedComposableLock;
use mvm_contract::pack_spec::PackTarget;
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_ORIGIN_LABEL, BundleMember, FsTrustStore, LOCAL_BUILD_ORIGIN, TrustStore,
    VerifiedBundle, key_id_from_pubkey,
};
use mvm_core::plan::{AssetKind, ExecutionPlan};
use mvm_core::registry_pack::runtime_layer::{
    require_offline_runtime_group_at_admission, resolve_runtime_layers,
};
use mvm_core::registry_pack::{
    AuthenticatedRegistryManifest, OFFICIAL_PACK_SIGNING_IDENTITY, OFFICIAL_PACK_SIGNING_ISSUER,
    PackLockfile, PackReference, RegistryPackVerification, VerifiedRegistryManifest,
    is_official_python_bundle_author_key, verify_registry_manifest,
};

pub(super) fn verify(plan: &ExecutionPlan, bundle: &VerifiedBundle) -> Result<()> {
    let local = bundle
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::LocalComposition(composition) => Some(composition),
            _ => None,
        });
    let production = bundle
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::ProductionComposition(composition) => Some(composition),
            _ => None,
        });
    ensure!(
        local.is_none() || production.is_none(),
        "local and production composition cannot be combined"
    );
    let (lock_artifact, layers) = if let Some(composition) = local {
        let enrolled = FsTrustStore::default_path()?.lookup(&bundle.key_id);
        ensure!(
            bundle
                .manifest
                .labels
                .get(BUNDLE_ORIGIN_LABEL)
                .map(String::as_str)
                == Some(LOCAL_BUILD_ORIGIN)
                && enrolled
                    .as_ref()
                    .is_some_and(|key| key_id_from_pubkey(key) == bundle.key_id),
            "composition must be signed as a local build by an explicitly enrolled key"
        );
        (&composition.lock_artifact, composition.layers.as_slice())
    } else if let Some(composition) = production {
        verify_official_publisher(plan, bundle)?;
        (&composition.lock_artifact, composition.layers.as_slice())
    } else {
        return Ok(());
    };
    let rootfs = bundle
        .manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == ArtifactRole::Rootfs)
        .collect::<Vec<_>>();
    let [rootfs] = rootfs.as_slice() else {
        anyhow::bail!("composition requires exactly one measured rootfs");
    };
    ensure!(
        rootfs.sha256 == plan.image.sha256 && bundle.manifest.verity.is_some(),
        "composition output differs from the signed plan or has no verity binding"
    );
    let base = bundle
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::CanonicalLinuxProof(proof) => Some(proof.manifest_artifact.as_str()),
            _ => None,
        })
        .context("composition lacks original signed Linux root")?;
    let evidence = |name: &str| -> Result<&[u8]> {
        let artifact = bundle
            .manifest
            .find_by_name(name)
            .context("composition evidence artifact missing")?;
        let limit = if name == base {
            4 * 1024 * 1024
        } else {
            1024 * 1024
        };
        ensure!(
            artifact.role == ArtifactRole::Other && artifact.size_bytes <= limit,
            "composition evidence artifact has an invalid role or size"
        );
        Ok(bundle
            .artifacts
            .get(&artifact.path)
            .context("composition evidence bytes missing")?
            .as_slice())
    };
    let lock_bytes = evidence(lock_artifact)?;
    let lock_digest = Sha256Hex::from_bytes(lock_bytes);
    ensure!(
        bundle
            .manifest
            .build_provenance()
            .and_then(|provenance| provenance.lock_digest.as_deref())
            == Some(lock_digest.as_str()),
        "composition lock differs from signed build provenance"
    );
    let lock: ResolvedComposableLock =
        serde_json::from_slice(lock_bytes).context("invalid signed composition lock")?;
    ensure!(
        Sha256Hex::from_bytes(evidence(base)?) == *lock.base_manifest_sha256()
            && match lock.target() {
                PackTarget::X86_64Linux => bundle.manifest.arch == "x86_64",
                PackTarget::Aarch64Linux => bundle.manifest.arch == "aarch64",
            }
            && lock.runtime_pins().len() == layers.len(),
        "composition input lock differs from the selected Linux root, architecture or layers"
    );
    let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?
    .policy;
    let mut verified_layers = Vec::with_capacity(layers.len());
    for (pin, artifacts) in lock.runtime_pins().iter().zip(layers) {
        let one = PackLockfile::new(vec![pin.clone()])?;
        let verified = verify_registry_manifest(&RegistryPackVerification::new(
            pin.reference(),
            evidence(&artifacts.manifest_artifact)?,
            evidence(&artifacts.signature_artifact)?,
            &one,
            &publisher,
        ))?;
        let VerifiedRegistryManifest::RuntimeLayer(layer) = verified else {
            anyhow::bail!("composition input is not a runtime layer");
        };
        require_offline_runtime_group_at_admission(&layer, evidence(&artifacts.group_artifact)?)?;
        verified_layers.push(layer);
    }
    let order =
        resolve_runtime_layers(lock.runtime_pins(), &verified_layers, &bundle.manifest.arch)?;
    ensure!(
        order
            .iter()
            .zip(lock.runtime_pins())
            .all(|(layer, pin)| layer.reference() == pin.reference()
                && layer.manifest_sha256() == pin.manifest_sha256()),
        "composition dependency order differs from the signed input lock"
    );
    Ok(())
}

fn verify_official_publisher(plan: &ExecutionPlan, bundle: &VerifiedBundle) -> Result<()> {
    ensure!(
        !bundle.manifest.labels.contains_key(BUNDLE_ORIGIN_LABEL),
        "production composition cannot claim a local build origin"
    );
    ensure!(
        is_official_python_bundle_author_key(&bundle.key_id),
        "production composition is not signed by the current official Python author"
    );
    if let Some(host_key) = mvm_core::plan::bundle::existing_local_build_key()? {
        ensure!(
            key_id_from_pubkey(&host_key) != bundle.key_id,
            "the local host key cannot be the production composition author"
        );
    }
    let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?;
    ensure!(
        publisher.is_official_default(),
        "production composition requires official registry publisher trust"
    );
    let lock =
        mvm_core::registry_pack_store::load_pack_lockfile(&mvm_core::config::pack_lockfile_path())?;
    let cache = mvm_core::config::registry_pack_cache_dir();
    let bundle_sha256 = &plan
        .bundle
        .as_ref()
        .context("production composition has no bundle pin")?
        .bundle_sha256;
    let mut matched = 0;
    for identity in plan
        .asset_identities
        .iter()
        .filter(|identity| identity.kind == AssetKind::RegistryPack)
    {
        let reference: PackReference = identity.name.parse()?;
        ensure!(
            reference.version().is_some(),
            "production application descriptor must have an exact version"
        );
        let (_, verified) = mvm_core::registry_pack_store::open_installed_registry_manifest(
            &cache,
            &lock,
            &publisher.policy,
            &reference,
        )?;
        let VerifiedRegistryManifest::Application(application) = verified else {
            continue;
        };
        let descriptor = application.manifest();
        if application.manifest_sha256().as_str() == identity.digest
            && application.signer().identity == OFFICIAL_PACK_SIGNING_IDENTITY
            && application.signer().issuer == OFFICIAL_PACK_SIGNING_ISSUER
            && descriptor.application.bundle.archive_sha256.as_str() == bundle_sha256
            && descriptor.application.bundle.key_id == bundle.key_id
            && descriptor.application.guest_arch == bundle.manifest.arch
        {
            matched += 1;
        }
    }
    ensure!(
        matched == 1,
        "production composition requires one current official application descriptor bound to the signed plan and archive"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::bundle::{
        BundleArtifact, BundleManifest, CanonicalLinuxProof, LocalComposition,
        ProductionComposition, VerityInfo,
    };
    use mvm_core::plan::types::{ArtifactDigests, BuildProvenance, InputKind};

    #[test]
    fn composition_requires_enrolled_local_signer_and_bound_input_lock() {
        let home = tempfile::tempdir().unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let signer = crate::audit::host_keypair::load_or_init().unwrap();
        let key_id = key_id_from_pubkey(&signer.verifying);
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.image.sha256 = "a".repeat(64);
        let manifest = BundleManifest {
            schema_version: 8,
            publisher: "local".into(),
            key_id: key_id.clone(),
            arch: "x86_64".into(),
            kernel_version: None,
            profile: None,
            workload_label: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            labels: [(BUNDLE_ORIGIN_LABEL.into(), LOCAL_BUILD_ORIGIN.into())]
                .into_iter()
                .collect(),
            artifacts: vec![BundleArtifact {
                name: "rootfs.ext4".into(),
                role: ArtifactRole::Rootfs,
                path: "artifacts/rootfs.ext4".into(),
                sha256: plan.image.sha256.clone(),
                size_bytes: 4096,
            }],
            members: vec![
                BundleMember::CanonicalLinuxProof(CanonicalLinuxProof {
                    manifest_artifact: "boot-image-set.json".into(),
                    signature_bundle_artifact: "linux.bundle".into(),
                    revocation_document_artifact: "revocations.json".into(),
                    revocation_signature_bundle_artifact: "revocations.bundle".into(),
                }),
                BundleMember::LocalComposition(LocalComposition {
                    lock_artifact: "composition-lock.json".into(),
                    layers: Vec::new(),
                }),
            ],
            verity: Some(VerityInfo {
                roothash: "b".repeat(64),
                sidecar_artifact: "rootfs.verity".into(),
            }),
            resources: None,
        };
        let mut bundle = VerifiedBundle {
            manifest,
            artifacts: Default::default(),
            key_id,
            embedded_image_sets: Vec::new(),
            boot_assets: None,
        };
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            error.to_string().contains("explicitly enrolled"),
            "{error:#}"
        );
        let enrollment = home
            .path()
            .join("trusted-publishers")
            .join(format!("{}.pub", bundle.key_id.0));
        std::fs::create_dir_all(enrollment.parent().unwrap()).unwrap();
        std::fs::write(&enrollment, signer.verifying.to_bytes()).unwrap();
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            format!("{error:#}").contains("evidence artifact missing"),
            "{error:#}"
        );
        let foreign = ed25519_dalek::SigningKey::from_bytes(&[3; 32]).verifying_key();
        let foreign_id = key_id_from_pubkey(&foreign);
        bundle.key_id = foreign_id.clone();
        bundle.manifest.key_id = foreign_id.clone();
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            error.to_string().contains("explicitly enrolled"),
            "{error:#}"
        );
        std::fs::write(
            home.path()
                .join("trusted-publishers")
                .join(format!("{}.pub", foreign_id.0)),
            foreign.to_bytes(),
        )
        .unwrap();
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            format!("{error:#}").contains("evidence artifact missing"),
            "{error:#}"
        );
        bundle.manifest.labels.clear();
        assert!(
            verify(&plan, &bundle)
                .unwrap_err()
                .to_string()
                .contains("local build")
        );
        bundle
            .manifest
            .labels
            .insert(BUNDLE_ORIGIN_LABEL.into(), LOCAL_BUILD_ORIGIN.into());
        bundle.manifest.artifacts[0].sha256 = "c".repeat(64);
        assert!(
            verify(&plan, &bundle)
                .unwrap_err()
                .to_string()
                .contains("output differs")
        );
        bundle.manifest.artifacts[0].sha256 = plan.image.sha256.clone();
        let lock = b"{}";
        bundle.manifest.artifacts.push(BundleArtifact {
            name: "composition-lock.json".into(),
            role: ArtifactRole::Other,
            path: "artifacts/composition-lock.json".into(),
            sha256: Sha256Hex::from_bytes(lock).as_str().to_owned(),
            size_bytes: lock.len() as u64,
        });
        bundle.manifest.artifacts.push(BundleArtifact {
            name: "boot-image-set.json".into(),
            role: ArtifactRole::Other,
            path: "artifacts/boot-image-set.json".into(),
            sha256: Sha256Hex::from_bytes(b"base").as_str().to_owned(),
            size_bytes: 4,
        });
        bundle
            .artifacts
            .insert("artifacts/composition-lock.json".into(), lock.to_vec());
        bundle
            .artifacts
            .insert("artifacts/boot-image-set.json".into(), b"base".to_vec());
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            error.to_string().contains("signed build provenance"),
            "{error:#}"
        );
        bundle
            .manifest
            .members
            .push(BundleMember::BuildProvenance(BuildProvenance {
                input_kind: InputKind::LocalProject,
                input_ref: "python".into(),
                lock_digest: Some("0".repeat(64)),
                builder_id: None,
                artifacts: ArtifactDigests::default(),
            }));
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            error.to_string().contains("signed build provenance"),
            "{error:#}"
        );
        let BundleMember::BuildProvenance(provenance) = bundle.manifest.members.last_mut().unwrap()
        else {
            unreachable!("test just appended build provenance");
        };
        provenance.lock_digest = Some(Sha256Hex::from_bytes(lock).as_str().to_owned());
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            format!("{error:#}").contains("invalid signed composition lock"),
            "{error:#}"
        );
        bundle.manifest.members[1] = BundleMember::ProductionComposition(ProductionComposition {
            lock_artifact: "composition-lock.json".into(),
            layers: Vec::new(),
        });
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            error.to_string().contains("local build origin"),
            "{error:#}"
        );
        bundle.manifest.labels.clear();
        let error = verify(&plan, &bundle).unwrap_err();
        assert!(
            error.to_string().contains("current official Python author"),
            "{error:#}"
        );
    }
}
