//! Built-image assembly tests use a private structural verifier; these are not publisher
//! OIDC evidence. The public verifier must reject this unsigned fixture.

use super::*;
use crate::registry_pack_image::tests::{descriptor, provenance};

fn fixture() -> (tempfile::TempDir, VerifiedRegistryPack) {
    let root = tempfile::tempdir().unwrap();
    let mut image = serde_json::to_value(descriptor()).unwrap();
    let statement = serde_json::to_vec(&provenance()).unwrap();
    for asset in image["assets"].as_object_mut().unwrap().values_mut() {
        let name = asset["name"].as_str().unwrap().to_string();
        let bytes = if name == "provenance.json" {
            statement.as_slice()
        } else {
            b"test asset"
        };
        asset["sha256"] = serde_json::json!(Sha256Hex::from_bytes(bytes));
        asset["size"] = serde_json::json!(bytes.len());
        std::fs::write(root.path().join(name), bytes).unwrap();
    }
    std::fs::create_dir(root.path().join("pack")).unwrap();
    std::fs::write(root.path().join("pack/profile.toml"), b"profile").unwrap();
    let manifest = RegistryPackManifest {
        schema_version: 1,
        reference: "runtime/python@1.0.0".parse().unwrap(),
        description: "split registry and release fixture".to_string(),
        files: vec![RegistryPackFile {
            path: "pack/profile.toml".to_string(),
            sha256: Sha256Hex::from_bytes(b"profile"),
            size: 7,
        }],
        image: Some(RegistryPackImage::Built(Box::new(
            serde_json::from_value(image).unwrap(),
        ))),
    };
    validate_registry_pack_manifest(&manifest).unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let verified = VerifiedRegistryPack {
        manifest_sha256: Sha256Hex::from_bytes(&manifest_bytes),
        manifest_bytes,
        manifest,
        signature_bundle: b"unsigned assembly fixture".to_vec(),
        signer: VerifiedSigner {
            identity: OFFICIAL_PACK_SIGNING_IDENTITY.to_string(),
            issuer: OFFICIAL_PACK_SIGNING_ISSUER.to_string(),
        },
    };
    (root, verified)
}

#[test]
fn provenance_verifier_must_match_the_approved_released_binary() {
    let trusted = Sha256Hex::new(TRUSTED_IMAGE_VERIFIER_SHA256.to_string()).unwrap();
    verify_trusted_image_verifier(&trusted).expect("approved release verifier");

    let untrusted = Sha256Hex::from_bytes(b"another verifier");
    assert!(
        verify_trusted_image_verifier(&untrusted).is_err(),
        "a publisher-signed but unapproved verifier digest must be refused"
    );
}

fn structural_only(
    verified: &VerifiedRegistryPack,
    root: &Path,
) -> Result<(), RegistryPackVerificationError> {
    let Some(RegistryPackImage::Built(image)) = &verified.manifest.image else {
        panic!("built fixture required");
    };
    let statement = read_image_attestation(root, &image.assets.provenance_statement)?;
    image
        .validate_pin(
            &verified.manifest.reference,
            &crate::image_set::image_train_lock().image_set,
        )
        .and_then(|()| {
            image.validate_provenance_payload(
                &verified.manifest.reference,
                &verified.signer.identity,
                &statement,
            )
        })
        .map(|_| ())
        .map_err(
            |error| RegistryPackVerificationError::InvalidImageDeclaration {
                reason: error.to_string(),
            },
        )
}

#[test]
fn split_inventory_is_complete_and_production_refuses_unsigned_evidence() {
    let (root, verified) = fixture();
    assert_eq!(verified.manifest.files.len(), 1);
    assert_eq!(verified.payload_files().len(), 8);
    verify_registry_pack_contents_with(&verified, root.path(), structural_only).unwrap();
    assert!(verify_registry_pack_contents(&verified, root.path()).is_err());
    let cache = tempfile::tempdir().unwrap();
    assert!(install_registry_pack_at(cache.path(), root.path(), &verified).is_err());
    assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
}

#[test]
fn descriptor_inventory_refuses_duplicates_prefixes_unsafe_paths_and_limits() {
    let (_, verified) = fixture();
    for path in [
        "rootfs.ext4",
        "rootfs.ext4/child",
        "pack",
        "../escape",
        "/absolute",
    ] {
        let mut manifest = verified.manifest.clone();
        manifest.files.push(RegistryPackFile {
            path: path.to_string(),
            sha256: Sha256Hex::from_bytes(b"x"),
            size: 1,
        });
        assert!(
            validate_registry_pack_manifest(&manifest).is_err(),
            "{path}"
        );
    }
    let mut manifest = verified.manifest.clone();
    manifest.files[0].size = u64::MAX;
    assert!(validate_registry_pack_manifest(&manifest).is_err());
    let mut manifest = verified.manifest.clone();
    manifest.files = (0..MAX_REGISTRY_PAYLOAD_FILES)
        .map(|i| RegistryPackFile {
            path: format!("pack/{i}"),
            sha256: Sha256Hex::from_bytes(b""),
            size: 0,
        })
        .collect();
    assert!(validate_registry_pack_manifest(&manifest).is_err());
}

#[test]
fn every_release_asset_is_reopened_at_verification() {
    for name in [
        "rootfs.ext4",
        "rootfs.verity",
        "rootfs.roothash",
        "mvm-meta.json",
        "rootfs.signature.json",
        "provenance.json",
        "provenance.signature.json",
    ] {
        for mutation in ["missing", "same-size", "oversized"] {
            let (root, verified) = fixture();
            let target = root.path().join(name);
            match mutation {
                "missing" => std::fs::remove_file(&target).unwrap(),
                "same-size" => {
                    let mut bytes = std::fs::read(&target).unwrap();
                    bytes[0] ^= 1;
                    std::fs::write(&target, bytes).unwrap();
                }
                "oversized" => {
                    use std::io::Write;
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&target)
                        .unwrap()
                        .write_all(b"x")
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                verify_registry_pack_contents_with(&verified, root.path(), structural_only)
                    .is_err(),
                "{name}: {mutation}"
            );
        }
    }
}

#[test]
fn unsigned_files_and_parent_symlinks_are_refused_before_payload_reads() {
    let (root, verified) = fixture();
    std::fs::write(root.path().join("unlisted"), b"not signed").unwrap();
    assert!(verify_registry_pack_contents_with(&verified, root.path(), structural_only).is_err());
    #[cfg(unix)]
    {
        std::fs::remove_file(root.path().join("unlisted")).unwrap();
        let target = tempfile::tempdir().unwrap();
        std::fs::write(target.path().join("profile.toml"), b"profile").unwrap();
        std::fs::remove_dir_all(root.path().join("pack")).unwrap();
        std::os::unix::fs::symlink(target.path(), root.path().join("pack")).unwrap();
        assert!(
            verify_registry_pack_contents_with(&verified, root.path(), structural_only).is_err()
        );
    }
}

#[test]
fn activation_copies_the_full_inventory_and_reverifies_cache_mutations() {
    let (root, verified) = fixture();
    let cache = tempfile::tempdir().unwrap();
    let installed =
        install_registry_pack_at_with(cache.path(), root.path(), &verified, structural_only)
            .unwrap();
    for file in verified.payload_files() {
        assert_eq!(
            std::fs::read(installed.payload_root().join(&file.path)).unwrap(),
            std::fs::read(root.path().join(&file.path)).unwrap(),
        );
    }
    std::fs::write(installed.payload_root().join("rootfs.ext4"), b"wrong root").unwrap();
    assert!(
        verify_registry_pack_contents_with(&verified, &installed.payload_root(), structural_only)
            .is_err()
    );
    install_registry_pack_at_with(cache.path(), root.path(), &verified, structural_only).unwrap();
    verify_registry_pack_contents_with(&verified, &installed.payload_root(), structural_only)
        .unwrap();
    assert!(verify_registry_pack_contents(&verified, &installed.payload_root()).is_err());
}

#[test]
fn failure_after_copy_never_exposes_a_partial_cache_entry() {
    fn interrupted(
        verified: &VerifiedRegistryPack,
        root: &Path,
    ) -> Result<(), RegistryPackVerificationError> {
        structural_only(verified, root)?;
        if root
            .file_name()
            .is_some_and(|name| name == REGISTRY_PAYLOAD_DIR_NAME)
        {
            return Err(RegistryPackVerificationError::InvalidImageDeclaration {
                reason: "injected interruption after copy".to_string(),
            });
        }
        Ok(())
    }
    let (root, verified) = fixture();
    let cache = tempfile::tempdir().unwrap();
    assert!(
        install_registry_pack_at_with(cache.path(), root.path(), &verified, interrupted).is_err()
    );
    assert!(
        !cache
            .path()
            .join(verified.manifest_sha256().as_str())
            .exists()
    );
    let entries = std::fs::read_dir(cache.path())
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_name(), ".incoming");
    assert_eq!(std::fs::read_dir(entries[0].path()).unwrap().count(), 0);
}
