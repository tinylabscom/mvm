//! Install complete bundle content before committing its descriptor reference.

use std::path::{Path, PathBuf};

use super::{ApplicationBundleError, VerifiedApplicationBundle};
use crate::plan::bundle::{BundleRegistry, InstalledBundle, TrustStore};
use crate::registry_pack::{
    AuthenticatedRegistryManifest, PackAdoption, REGISTRY_MANIFEST_FILE_NAME,
    REGISTRY_SIGNATURE_FILE_NAME, RegistryPackPublisherPolicy, RegistryPackSignatureChecker,
    RegistryPackVerification, VerifiedRegistryApplication, VerifiedRegistryManifest,
    default_signature_checker,
};
use crate::registry_pack_store::{
    RegistryPackStoreError, RegistryPackStoreLease, load_pack_lockfile, lock_registry_pack_store,
};

/// The existing bundle registry, descriptor cache and shared pack lock.
#[derive(Debug)]
pub struct ApplicationInstallStore {
    pub(super) descriptor_cache_root: PathBuf,
    pub(super) lock_path: PathBuf,
    pub(super) bundle_root: PathBuf,
}

impl ApplicationInstallStore {
    pub fn new(
        descriptor_cache_root: impl Into<PathBuf>,
        lock_path: impl Into<PathBuf>,
        bundle_root: impl Into<PathBuf>,
    ) -> Self {
        Self {
            descriptor_cache_root: descriptor_cache_root.into(),
            lock_path: lock_path.into(),
            bundle_root: bundle_root.into(),
        }
    }
}

/// A committed descriptor-to-bundle identity, not launch authorization.
#[derive(Debug)]
pub struct InstalledRegistryApplication {
    application: VerifiedRegistryApplication,
    bundle: InstalledBundle,
    descriptor_root: PathBuf,
}

impl InstalledRegistryApplication {
    pub fn application(&self) -> &VerifiedRegistryApplication {
        &self.application
    }
    pub fn bundle(&self) -> &InstalledBundle {
        &self.bundle
    }
    pub fn descriptor_root(&self) -> &Path {
        &self.descriptor_root
    }
}

/// Recheck current trust, install complete content, and atomically commit its pin.
///
/// A failure before the pin commit may leave complete unreferenced bundle and
/// descriptor content. It never reports that content as a committed application.
pub fn install_application_bundle(
    candidate: &VerifiedApplicationBundle,
    store: &ApplicationInstallStore,
    publisher_policy_path: &Path,
    trust: &dyn TrustStore,
) -> Result<InstalledRegistryApplication, ApplicationBundleError> {
    install_with_loader(
        candidate,
        store,
        || {
            crate::registry_pack_store::load_publisher_policy_or_official_default(
                publisher_policy_path,
            )
            .map(|loaded| loaded.policy)
        },
        trust,
        default_signature_checker(),
        VerifiedRegistryApplication::check_current_revocations,
        RegistryPackStoreLease::commit_application_pin,
    )
}

#[cfg(test)]
pub(super) fn install_with(
    candidate: &VerifiedApplicationBundle,
    store: &ApplicationInstallStore,
    policy: &RegistryPackPublisherPolicy,
    trust: &dyn TrustStore,
    check_signature: RegistryPackSignatureChecker,
    commit: impl FnOnce(
        &RegistryPackStoreLease,
        &VerifiedRegistryApplication,
    ) -> Result<(), RegistryPackStoreError>,
) -> Result<InstalledRegistryApplication, ApplicationBundleError> {
    install_with_loader(
        candidate,
        store,
        || Ok(policy.clone()),
        trust,
        check_signature,
        crate::registry_pack_store::application_test_feed::check,
        commit,
    )
}

pub(super) fn install_with_loader(
    candidate: &VerifiedApplicationBundle,
    store: &ApplicationInstallStore,
    mut load_policy: impl FnMut() -> Result<RegistryPackPublisherPolicy, RegistryPackStoreError>,
    trust: &dyn TrustStore,
    check_signature: RegistryPackSignatureChecker,
    mut check_revocations: impl FnMut(
        &VerifiedRegistryApplication,
    ) -> Result<(), RegistryPackStoreError>,
    commit: impl FnOnce(
        &RegistryPackStoreLease,
        &VerifiedRegistryApplication,
    ) -> Result<(), RegistryPackStoreError>,
) -> Result<InstalledRegistryApplication, ApplicationBundleError> {
    let lease = lock_registry_pack_store(&store.lock_path)?;
    let application = candidate.application();
    let lock = load_pack_lockfile(&store.lock_path)?;
    authenticate(application, &lock, &load_policy()?, check_signature)?;
    check_revocations(application)?;
    candidate.reverify(trust)?;
    let registry = BundleRegistry::new(&store.bundle_root);
    // Retain bundle exclusion through the reference commit, not just extraction.
    // Every cooperating installer and remover takes this same entry lease.
    let installed = registry.install_leased_file(candidate.archive_path(), trust, true)?;
    sync_bundle_content(&registry, &installed.bundle, application)?;
    let descriptor_root = publish_descriptor(&store.descriptor_cache_root, application)?;
    authenticate(application, &lock, &load_policy()?, check_signature)?;
    check_revocations(application)?;
    candidate.reverify(trust)?;
    commit(&lease, application)?;
    Ok(InstalledRegistryApplication {
        application: application.clone(),
        bundle: installed.bundle,
        descriptor_root,
    })
}

fn authenticate(
    application: &VerifiedRegistryApplication,
    lock: &crate::registry_pack::PackLockfile,
    policy: &RegistryPackPublisherPolicy,
    check_signature: RegistryPackSignatureChecker,
) -> Result<(), ApplicationBundleError> {
    let adoption = PackAdoption {
        requested: application.reference(),
        manifest_bytes: application.manifest_bytes(),
        signature_bundle: application.signature_bundle(),
        publisher_policy: policy,
    };
    let authenticated = if lock
        .pins()
        .iter()
        .any(|pin| pin.reference() == application.reference())
    {
        super::super::dispatch::verify_with(
            &RegistryPackVerification::new(
                adoption.requested,
                adoption.manifest_bytes,
                adoption.signature_bundle,
                lock,
                policy,
            ),
            check_signature,
        )?
    } else {
        super::super::dispatch::adopt_with(&adoption, check_signature)?
    };
    let VerifiedRegistryManifest::Application(current) = authenticated else {
        return Err(ApplicationBundleError::Digest);
    };
    if &current != application {
        return Err(ApplicationBundleError::Digest);
    }
    Ok(())
}

fn sync_bundle_content(
    registry: &BundleRegistry,
    bundle: &InstalledBundle,
    application: &VerifiedRegistryApplication,
) -> Result<(), ApplicationBundleError> {
    let mut directories = std::collections::BTreeSet::new();
    for artifact in &bundle.manifest.artifacts {
        super::super::local_input::open_payload(&bundle.root, &artifact.path, artifact.size_bytes)?
            .sync_all()?;
        let path = bundle.root.join(&artifact.path);
        for parent in path
            .ancestors()
            .skip(1)
            .take_while(|parent| parent.starts_with(&bundle.root))
        {
            directories.insert(parent.to_path_buf());
        }
    }
    for name in [
        crate::plan::bundle::MANIFEST_FILENAME,
        crate::plan::bundle::SIGNATURE_FILENAME,
    ] {
        let path = bundle.root.join(name);
        let size = std::fs::symlink_metadata(&path)?.len();
        super::super::local_input::open_sized_regular(&path, size)?.sync_all()?;
    }
    for directory in directories.iter().rev() {
        super::super::local_input::sync_directory(directory)?;
    }
    super::super::local_input::sync_directory(&bundle.root)?;
    super::super::local_input::open_sized_regular(
        &registry.archive_path(&bundle.sha256),
        application.manifest().application.bundle.archive_size,
    )?
    .sync_all()?;
    crate::private_fs::sync_managed_directory_chain(registry.root(), registry.root())?;
    Ok(())
}

fn publish_descriptor(
    cache_root: &Path,
    application: &VerifiedRegistryApplication,
) -> Result<PathBuf, ApplicationBundleError> {
    if let Ok(metadata) = std::fs::symlink_metadata(cache_root)
        && (!metadata.is_dir() || metadata.file_type().is_symlink())
    {
        return Err(std::io::Error::other("descriptor cache root must be a real directory").into());
    }
    crate::config::create_private_dir(cache_root)?;
    let destination = cache_root.join(application.manifest_sha256().as_str());
    if std::fs::symlink_metadata(&destination).is_ok() {
        let valid = std::fs::symlink_metadata(&destination)?.is_dir()
            && !std::fs::symlink_metadata(&destination)?
                .file_type()
                .is_symlink()
            && super::super::local_input::read_metadata(
                &destination.join(REGISTRY_MANIFEST_FILE_NAME),
            )
            .is_ok_and(|bytes| bytes == application.manifest_bytes())
            && super::super::local_input::read_metadata(
                &destination.join(REGISTRY_SIGNATURE_FILE_NAME),
            )
            .is_ok_and(|bytes| bytes == application.signature_bundle())
            && std::fs::read_dir(&destination)?.take(3).count() == 2;
        if valid {
            super::super::local_input::open_sized_regular(
                &destination.join(REGISTRY_MANIFEST_FILE_NAME),
                application.manifest_bytes().len() as u64,
            )?
            .sync_all()?;
            super::super::local_input::open_sized_regular(
                &destination.join(REGISTRY_SIGNATURE_FILE_NAME),
                application.signature_bundle().len() as u64,
            )?
            .sync_all()?;
            crate::private_fs::sync_managed_directory_chain(cache_root, &destination)?;
            return Ok(destination);
        }
        super::super::remove_registry_cache_entry(&destination)?;
    }
    crate::pack_cache::atomically_populate_dir_at(
        cache_root,
        &destination,
        |staging| -> Result<(), ApplicationBundleError> {
            write_synced(
                staging.join(REGISTRY_MANIFEST_FILE_NAME),
                application.manifest_bytes(),
            )?;
            write_synced(
                staging.join(REGISTRY_SIGNATURE_FILE_NAME),
                application.signature_bundle(),
            )?;
            Ok(())
        },
    )?;
    crate::private_fs::sync_managed_directory_chain(cache_root, &destination)?;
    Ok(destination)
}

fn write_synced(path: impl AsRef<Path>, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
