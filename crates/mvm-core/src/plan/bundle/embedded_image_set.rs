//! Bind embedded image-set declarations to verified bundle artifacts.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    ArtifactRole, BundleManifest, BundleMember, BundleVerifyError, GuestArch, ImageSetManifest,
    ImageSetRequirement, LocalDevelopmentBaseProof, Sha256Hex, VerifiedBootAssets,
    VerifiedEmbeddedImageSet, require_complete, select_boot_asset_members, select_cli_boot_kernel,
    select_local_development_base, stream, validate_structure,
};

/// Bind each embedded image-set declaration to the already verified bundle
/// artifacts. The image-set module owns structure, completeness and backend
/// compatibility; this adapter owns only the cross-manifest name/hash binding.
pub(super) fn verify_embedded_image_sets(
    bundle: &BundleManifest,
    artifacts: &dyn stream::ArtifactSource,
) -> Result<Vec<VerifiedEmbeddedImageSet>, BundleVerifyError> {
    let mut names = BTreeSet::new();
    for artifact in &bundle.artifacts {
        if !names.insert(artifact.name.as_str()) {
            return Err(BundleVerifyError::DuplicateArtifactName {
                name: artifact.name.clone(),
            });
        }
    }

    bundle
        .members
        .iter()
        .filter_map(|member| match member {
            BundleMember::EmbeddedImageSet { manifest_artifact } => Some(manifest_artifact),
            BundleMember::KernelCmdline { .. }
            | BundleMember::EmbeddedBootAssets { .. }
            | BundleMember::EmbeddedCliBootAssets(_)
            | BundleMember::CanonicalLinuxProof(_)
            | BundleMember::LocalDevelopmentBaseProof(_)
            | BundleMember::LocalComposition(_)
            | BundleMember::SecurityPosture(_)
            | BundleMember::BuildProvenance(_)
            | BundleMember::Environment(_) => None,
        })
        .map(|manifest_artifact| {
            verify_embedded_image_set(
                bundle,
                artifacts,
                manifest_artifact,
                ImageSetSelection::Full,
            )
        })
        .collect()
}

pub(super) fn verify_boot_assets(
    bundle: &BundleManifest,
    artifacts: &dyn stream::ArtifactSource,
) -> Result<Option<VerifiedBootAssets>, BundleVerifyError> {
    let Some((manifest_artifact, cli_runtime)) =
        bundle.members.iter().find_map(|member| match member {
            BundleMember::EmbeddedBootAssets { manifest_artifact } => {
                Some((manifest_artifact, None))
            }
            BundleMember::EmbeddedCliBootAssets(runtime) => {
                Some((&runtime.manifest_artifact, Some(runtime)))
            }
            BundleMember::EmbeddedImageSet { .. }
            | BundleMember::CanonicalLinuxProof(_)
            | BundleMember::LocalDevelopmentBaseProof(_)
            | BundleMember::LocalComposition(_)
            | BundleMember::KernelCmdline { .. }
            | BundleMember::SecurityPosture(_)
            | BundleMember::BuildProvenance(_)
            | BundleMember::Environment(_) => None,
        })
    else {
        return Ok(None);
    };
    let arch = match bundle.arch.as_str() {
        "x86_64" => GuestArch::X86_64,
        "aarch64" => GuestArch::Aarch64,
        other => {
            return Err(BundleVerifyError::ManifestParse(format!(
                "unknown boot-assets architecture {other}"
            )));
        }
    };
    let local = bundle.members.iter().find_map(|member| match member {
        BundleMember::LocalDevelopmentBaseProof(proof) => Some(proof),
        _ => None,
    });
    let selection = if let Some(proof) = local {
        ImageSetSelection::LocalKernel(arch, proof)
    } else if cli_runtime.is_some() {
        ImageSetSelection::CliKernel(arch)
    } else {
        ImageSetSelection::LegacyRuntime(arch)
    };
    let image_set = verify_embedded_image_set(bundle, artifacts, manifest_artifact, selection)?;
    Ok(Some(VerifiedBootAssets {
        arch,
        image_set,
        cli_runtime: cli_runtime.cloned(),
        local_development_base: local.cloned(),
    }))
}

enum ImageSetSelection<'a> {
    Full,
    LegacyRuntime(GuestArch),
    CliKernel(GuestArch),
    LocalKernel(GuestArch, &'a LocalDevelopmentBaseProof),
}

fn verify_embedded_image_set(
    bundle: &BundleManifest,
    artifacts: &dyn stream::ArtifactSource,
    manifest_artifact: &str,
    selection: ImageSetSelection<'_>,
) -> Result<VerifiedEmbeddedImageSet, BundleVerifyError> {
    let declaration = bundle
        .artifacts
        .iter()
        .find(|artifact| artifact.name == manifest_artifact)
        .ok_or_else(|| BundleVerifyError::ImageSetManifestArtifactMissing {
            name: manifest_artifact.to_string(),
        })?;
    let manifest_bytes = artifacts
        .read_image_set_manifest(&declaration.path)
        .map_err(|reason| BundleVerifyError::ImageSetManifestParse {
            name: manifest_artifact.to_string(),
            reason,
        })?;
    let manifest: ImageSetManifest = serde_json::from_slice(&manifest_bytes).map_err(|error| {
        BundleVerifyError::ImageSetManifestParse {
            name: manifest_artifact.to_string(),
            reason: error.to_string(),
        }
    })?;
    validate_structure(&manifest).map_err(|reason| BundleVerifyError::ImageSetRefused {
        name: manifest_artifact.to_string(),
        reason,
    })?;
    if !matches!(&selection, ImageSetSelection::LocalKernel(_, _)) {
        require_complete(&manifest, &ImageSetRequirement::current_train()).map_err(|reason| {
            BundleVerifyError::ImageSetRefused {
                name: manifest_artifact.to_string(),
                reason,
            }
        })?;
    }

    let selected = match &selection {
        ImageSetSelection::Full => Ok(manifest.members.iter().collect()),
        ImageSetSelection::LegacyRuntime(arch) => {
            select_boot_asset_members(&manifest, *arch).map(|members| members.to_vec())
        }
        ImageSetSelection::CliKernel(arch) => {
            select_cli_boot_kernel(&manifest, *arch).map(|member| vec![member])
        }
        ImageSetSelection::LocalKernel(arch, proof) => {
            let kernel = bundle.find_by_role(&ArtifactRole::Kernel).ok_or_else(|| {
                BundleVerifyError::ManifestParse("local kernel artifact missing".into())
            })?;
            let (selected, _) = select_local_development_base(
                &manifest,
                *arch,
                &kernel.sha256,
                kernel.size_bytes,
                proof,
            )?;
            Ok(vec![selected])
        }
    };
    let members = selected.map_err(|reason| BundleVerifyError::ImageSetRefused {
        name: manifest_artifact.to_string(),
        reason,
    })?;
    let mut artifact_paths = BTreeMap::new();
    for image_artifact in members
        .into_iter()
        .flat_map(|member| member.artifacts.iter())
    {
        let name = image_artifact.name.as_str();
        let bundle_artifact = bundle
            .artifacts
            .iter()
            .find(|artifact| match &selection {
                ImageSetSelection::CliKernel(_) | ImageSetSelection::LocalKernel(_, _) => {
                    artifact.role == ArtifactRole::Kernel
                }
                ImageSetSelection::Full | ImageSetSelection::LegacyRuntime(_) => {
                    artifact.name == name
                }
            })
            .ok_or_else(|| BundleVerifyError::ImageSetArtifactMissing {
                name: name.to_string(),
            })?;
        if image_artifact.sha256.as_str() != bundle_artifact.sha256 {
            return Err(BundleVerifyError::ImageSetArtifactDigestMismatch {
                name: name.to_string(),
                image_set: image_artifact.sha256.as_str().to_string(),
                bundle: bundle_artifact.sha256.clone(),
            });
        }
        if image_artifact.size != bundle_artifact.size_bytes {
            return Err(BundleVerifyError::ImageSetArtifactSizeMismatch {
                name: name.to_string(),
                image_set: image_artifact.size,
                bundle: bundle_artifact.size_bytes,
            });
        }
        artifact_paths.insert(name.to_string(), bundle_artifact.path.clone());
    }

    Ok(VerifiedEmbeddedImageSet {
        manifest_artifact: manifest_artifact.to_string(),
        manifest_sha256: Sha256Hex::from_bytes(&manifest_bytes),
        manifest,
        artifact_paths,
    })
}
