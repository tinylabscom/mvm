//! Built-image authentication shared by installation and installed-pack reopen.

use super::*;
use crate::registry_pack_image::{BuiltImageAsset, MAX_BUILT_IMAGE_METADATA_BYTES};
use std::io::Read;

/// Authenticate a built image's statement against its verified pack publisher.
pub fn verify_built_image_provenance(
    verified: &VerifiedRegistryPack,
    root: &Path,
) -> Result<Sha256Hex, RegistryPackVerificationError> {
    let Some(RegistryPackImage::Built(image)) = &verified.manifest().image else {
        return Err(RegistryPackVerificationError::InvalidImageDeclaration {
            reason: "pack has no built image provenance to verify".to_string(),
        });
    };
    let statement = read_image_attestation(root, &image.assets.provenance_statement)?;
    let bundle = read_image_attestation(root, &image.assets.provenance_signature_bundle)?;
    image
        .verify_signed_provenance(
            &verified.manifest().reference,
            &crate::image_set::image_train_lock().image_set,
            verified.signer(),
            &statement,
            &bundle,
        )
        .map_err(
            |error| RegistryPackVerificationError::InvalidImageDeclaration {
                reason: format!("built image provenance refused: {error}"),
            },
        )
}

fn read_image_attestation(
    root: &Path,
    asset: &BuiltImageAsset,
) -> Result<Vec<u8>, RegistryPackVerificationError> {
    let read = || -> std::io::Result<Vec<u8>> {
        let path = root.join(asset.name.as_str());
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || asset.size > MAX_BUILT_IMAGE_METADATA_BYTES {
            return Err(std::io::Error::other(
                "non-regular or oversized image attestation",
            ));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(asset.size + 1)
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).ok() != Some(asset.size)
            || Sha256Hex::from_bytes(&bytes) != asset.sha256
        {
            return Err(std::io::Error::other(
                "image attestation digest or size differs",
            ));
        }
        Ok(bytes)
    };
    read().map_err(|error| RegistryPackVerificationError::PayloadFileRead {
        path: asset.name.as_str().to_string(),
        reason: error.to_string(),
    })
}

pub(super) fn verify_built_image_authenticity(
    verified: &VerifiedRegistryPack,
    root: &Path,
) -> Result<(), RegistryPackVerificationError> {
    verify_built_image_provenance(verified, root)?;
    let Some(RegistryPackImage::Built(image)) = &verified.manifest().image else {
        return Err(RegistryPackVerificationError::InvalidImageDeclaration {
            reason: "pack has no built image signature to verify".to_string(),
        });
    };
    let bundle = read_image_attestation(root, &image.assets.rootfs_signature_bundle)?;
    crate::crypto::image_verify::verify_signed_sha256(
        image.assets.rootfs.sha256.as_str(),
        &bundle,
        &verified.signer().identity,
        &verified.signer().issuer,
    )
    .map_err(
        |error| RegistryPackVerificationError::InvalidImageDeclaration {
            reason: format!("built image signature refused: {error}"),
        },
    )
}

#[cfg(test)]
#[path = "../registry_pack_built_tests.rs"]
mod tests;
