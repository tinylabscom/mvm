//! Recheck a host-local composition's original publisher evidence on every run.
//!
//! The plan pins the host-signed bundle and measures its rootfs; the bundle
//! retains only small signed inputs, never a second copy of the layer archives.

use anyhow::{Context, Result, ensure};
use mvm_build::runtime_layer::ResolvedComposableLock;
use mvm_contract::pack_spec::PackTarget;
use mvm_core::packs::Sha256Hex;
use mvm_core::plan::ExecutionPlan;
use mvm_core::plan::bundle::{
    ArtifactRole, BUNDLE_ORIGIN_LABEL, BundleMember, LOCAL_BUILD_ORIGIN, VerifiedBundle,
    key_id_from_pubkey,
};
use mvm_core::registry_pack::runtime_layer::{
    require_offline_runtime_group_at_admission, resolve_runtime_layers,
};
use mvm_core::registry_pack::{
    AuthenticatedRegistryManifest, PackLockfile, RegistryPackVerification,
    VerifiedRegistryManifest, verify_registry_manifest,
};

pub(super) fn verify(plan: &ExecutionPlan, bundle: &VerifiedBundle) -> Result<()> {
    let Some(composition) = bundle
        .manifest
        .members
        .iter()
        .find_map(|member| match member {
            BundleMember::LocalComposition(composition) => Some(composition),
            _ => None,
        })
    else {
        return Ok(());
    };
    let signer = crate::audit::host_keypair::load_or_init()?;
    ensure!(
        bundle
            .manifest
            .labels
            .get(BUNDLE_ORIGIN_LABEL)
            .map(String::as_str)
            == Some(LOCAL_BUILD_ORIGIN)
            && bundle.key_id == key_id_from_pubkey(&signer.verifying),
        "composition must be signed as a local build by this host"
    );
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
            BundleMember::LocalDevelopmentBaseProof(proof) => {
                Some(proof.manifest_artifact.as_str())
            }
            _ => None,
        })
        .context("composition lacks selected Linux base evidence")?;
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
    let lock: ResolvedComposableLock =
        serde_json::from_slice(evidence(&composition.lock_artifact)?)
            .context("invalid signed composition lock")?;
    ensure!(
        Sha256Hex::from_bytes(evidence(base)?) == *lock.base_manifest_sha256()
            && match lock.target() {
                PackTarget::X86_64Linux => bundle.manifest.arch == "x86_64",
                PackTarget::Aarch64Linux => bundle.manifest.arch == "aarch64",
            }
            && lock.runtime_pins().len() == composition.layers.len(),
        "composition input lock differs from the selected Linux root, architecture or layers"
    );
    let publisher = mvm_core::registry_pack_store::load_publisher_policy_or_official_default(
        &mvm_core::config::registry_pack_publisher_policy_path(),
    )?
    .policy;
    let mut layers = Vec::with_capacity(composition.layers.len());
    for (pin, artifacts) in lock.runtime_pins().iter().zip(&composition.layers) {
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
        layers.push(layer);
    }
    let order = resolve_runtime_layers(lock.runtime_pins(), &layers, &bundle.manifest.arch)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::plan::bundle::{
        BundleArtifact, BundleManifest, CanonicalLinuxProof, LocalComposition, VerityInfo,
    };

    #[test]
    fn an_unbound_or_foreign_local_composition_cannot_reach_input_resolution() {
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
    }
}
