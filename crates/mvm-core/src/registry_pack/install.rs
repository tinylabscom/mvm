//! Content-addressed registry-pack cache installation and local snapshots.

use super::*;

/// Whether installation may repair an invalid existing cache entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryPackInstallPolicy {
    Repair,
    RefuseExisting,
}

/// Verify and atomically publish a registry pack beneath its exact manifest digest.
pub fn install_registry_pack_at(
    cache_root: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    install_registry_pack_at_with(
        cache_root,
        staged_root,
        verified,
        verify_built_image_authenticity,
    )
}

/// Install an explicitly acquired local pack under a no-repair cache policy.
pub(crate) fn install_local_registry_pack_at(
    cache_root: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
    policy: RegistryPackInstallPolicy,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    install_registry_pack_with_policy(
        cache_root,
        staged_root,
        verified,
        verify_built_image_authenticity,
        policy,
    )
}

/// Snapshot exactly the signed inventory with the installer's bounded copier.
/// Authenticate metadata before calling this operation.
pub fn snapshot_registry_pack_payload(
    root: &Path,
    verified: &VerifiedRegistryPack,
) -> Result<tempfile::TempDir, RegistryPackInstallError> {
    let files = verified.payload_files();
    let declared = files
        .iter()
        .map(|file| file.path.as_str())
        .collect::<BTreeSet<_>>();
    refuse_undeclared_payload_paths(root, root, &declared)?;
    let snapshot = tempfile::tempdir().map_err(install_io_at(root))?;
    populate_registry_quarantine(
        snapshot.path(),
        root,
        verified,
        verify_built_image_authenticity,
    )?;
    refuse_undeclared_payload_paths(root, root, &declared)?;
    Ok(snapshot)
}

pub(super) fn install_registry_pack_at_with(
    cache_root: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
    check_built: BuiltImageChecker,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    install_registry_pack_with_policy(
        cache_root,
        staged_root,
        verified,
        check_built,
        RegistryPackInstallPolicy::Repair,
    )
}

fn install_registry_pack_with_policy(
    cache_root: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
    check_built: BuiltImageChecker,
    policy: RegistryPackInstallPolicy,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    verify_registry_pack_contents_with(verified, staged_root, check_built)?;
    let final_dir = cache_root.join(verified.manifest_sha256().as_str());
    if std::fs::symlink_metadata(&final_dir).is_ok() {
        if cached_registry_pack_is_valid(&final_dir, verified, check_built) {
            return Ok(InstalledRegistryPack { root: final_dir });
        }
        if policy == RegistryPackInstallPolicy::RefuseExisting {
            return Err(RegistryPackInstallError::Io {
                path: final_dir.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "local acquisition refuses an invalid existing cache entry",
                ),
            });
        }
        remove_registry_cache_entry(&final_dir)?;
    }

    let populate = |quarantine: &Path| {
        populate_registry_quarantine(quarantine, staged_root, verified, check_built)
    };
    let publish = match policy {
        RegistryPackInstallPolicy::Repair => {
            crate::pack_cache::atomically_populate_dir_at(cache_root, &final_dir, populate)
        }
        RegistryPackInstallPolicy::RefuseExisting => {
            crate::pack_cache::atomically_populate_dir_at_no_replace(
                cache_root, &final_dir, populate,
            )
        }
    };
    match publish {
        Ok(()) => Ok(InstalledRegistryPack { root: final_dir }),
        Err(_) if cached_registry_pack_is_valid(&final_dir, verified, check_built) => {
            Ok(InstalledRegistryPack { root: final_dir })
        }
        Err(error) => Err(error),
    }
}

/// Verify and atomically publish a registry pack in the configured MVM cache.
pub fn install_registry_pack(
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
) -> Result<InstalledRegistryPack, RegistryPackInstallError> {
    install_registry_pack_at(
        &crate::config::registry_pack_cache_dir(),
        staged_root,
        verified,
    )
}

fn populate_registry_quarantine(
    quarantine: &Path,
    staged_root: &Path,
    verified: &VerifiedRegistryPack,
    check_built: BuiltImageChecker,
) -> Result<(), RegistryPackInstallError> {
    use std::io::Read;
    let payload_root = quarantine.join(REGISTRY_PAYLOAD_DIR_NAME);
    std::fs::create_dir_all(&payload_root).map_err(install_io_at(&payload_root))?;
    for file in verified.payload_files() {
        let source = staged_root.join(&file.path);
        let destination = payload_root.join(&file.path);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent).map_err(install_io_at(parent))?;
        }
        let file_input = local_input::open_payload(staged_root, &file.path, file.size)
            .map_err(install_io_at(&source))?;
        let before = file_input.metadata().map_err(install_io_at(&source))?;
        let mut input = file_input.take(file.size + 1);
        let mut output = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination)
            .map_err(install_io_at(&destination))?;
        std::io::copy(&mut input, &mut output).map_err(install_io_at(&source))?;
        local_input::ensure_unchanged(input.get_ref(), &before, staged_root, &file.path, file.size)
            .map_err(install_io_at(&source))?;
    }
    let manifest_path = quarantine.join(REGISTRY_MANIFEST_FILE_NAME);
    std::fs::write(&manifest_path, verified.manifest_bytes())
        .map_err(install_io_at(&manifest_path))?;
    let signature_path = quarantine.join(REGISTRY_SIGNATURE_FILE_NAME);
    std::fs::write(&signature_path, verified.signature_bundle())
        .map_err(install_io_at(&signature_path))?;
    verify_registry_pack_contents_with(verified, &payload_root, check_built)?;
    Ok(())
}
