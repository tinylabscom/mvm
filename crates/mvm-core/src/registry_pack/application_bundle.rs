//! Descriptor-bound verification through the existing independent bundle trust.

use std::io::Read;
use std::path::Path;

use thiserror::Error;

use super::VerifiedRegistryApplication;
use crate::plan::bundle::{
    BundleVerifyError, HashingWriter, TrustStore, VerifiedBundleFile, verify_bundle_file,
};

mod install;
mod launch;
#[cfg(test)]
use install::install_with;
pub use install::{
    ApplicationInstallStore, InstalledRegistryApplication, install_application_bundle,
};
pub use launch::{
    ApplicationLaunchError, ResolvedApplication, names_installed_application,
    names_installed_policy_pack, resolve_installed_application,
    resolve_installed_application_bundle,
};

/// Resource ceiling shared with the bundle OCI transport.
pub const MAX_APPLICATION_ARCHIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ApplicationBundleError {
    #[error("application archive I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("application archive must be a regular file matching its signed size (at most 4 GiB)")]
    Size,
    #[error("application archive digest differs from its descriptor")]
    Digest,
    #[error("application bundle signing key differs from its descriptor")]
    Key,
    #[error("application bundle architecture differs from its descriptor")]
    Architecture,
    #[error(transparent)]
    Verification(#[from] BundleVerifyError),
    #[error(transparent)]
    Store(#[from] crate::registry_pack_store::RegistryPackStoreError),
    #[error(transparent)]
    Manifest(#[from] super::RegistryPackVerificationError),
    #[error(transparent)]
    BundleInstall(#[from] crate::plan::bundle::BundleInstallError),
    #[error(transparent)]
    Cache(#[from] crate::pack_cache::PackCacheError),
    #[error(transparent)]
    DescriptorCache(#[from] super::RegistryPackInstallError),
}

/// An independent bundle verification bound to immutable descriptor evidence.
///
/// This owns a private snapshot, not an installation or execution grant. Current
/// publisher policy and revocations must be checked again before committing it.
#[derive(Debug)]
pub struct VerifiedApplicationBundle {
    application: VerifiedRegistryApplication,
    snapshot: tempfile::NamedTempFile,
    bundle: VerifiedBundleFile,
}

impl VerifiedApplicationBundle {
    /// Read only the producer's bounded, declared root-hash member. No caller
    /// reader, manifest, callback or snapshot pathname crosses this boundary.
    pub(crate) fn application_root_hash_member(&self) -> Result<Vec<u8>, BundleVerifyError> {
        use crate::plan::bundle::ArtifactRole;
        let name = crate::registry_pack_boot::APPLICATION_ROOT_HASH_MEMBER_NAME;
        let mut members = self
            .bundle
            .manifest
            .artifacts
            .iter()
            .filter(|member| member.name == name);
        let member = members
            .next()
            .ok_or_else(|| BundleVerifyError::ArtifactMissing {
                name: name.to_owned(),
            })?;
        if members.next().is_some() || member.role != ArtifactRole::Other {
            return Err(BundleVerifyError::ManifestParse(
                "application root hash member is ambiguous or has the wrong role".into(),
            ));
        }
        if member.size_bytes != 65 {
            return Err(BundleVerifyError::ManifestParse(
                "application root hash member must declare exactly 65 bytes".into(),
            ));
        }
        // Reopen checks identity and obtains an independent cursor. Cloning a
        // File and seeking would race other readers behind this shared borrow.
        let archive = self.snapshot.reopen().map_err(|error| {
            BundleVerifyError::ManifestParse(format!("reopening retained snapshot: {error}"))
        })?;
        if archive
            .metadata()
            .map_err(|error| {
                BundleVerifyError::ManifestParse(format!("retained snapshot metadata: {error}"))
            })?
            .len()
            != self.application.manifest().application.bundle.archive_size
        {
            return Err(BundleVerifyError::ManifestParse(
                "retained snapshot size changed".into(),
            ));
        }
        self.bundle.read_small_verified_member(archive, name, 65)
    }

    pub fn application(&self) -> &VerifiedRegistryApplication {
        &self.application
    }

    pub fn bundle(&self) -> &VerifiedBundleFile {
        &self.bundle
    }

    /// Recheck independently enrolled keys and the held snapshot before use.
    /// Descriptor publisher policy and current revocations are separate checks.
    pub fn reverify(&self, trust: &dyn TrustStore) -> Result<(), ApplicationBundleError> {
        let verified = verify_bundle_file(self.archive_path(), trust)?;
        match_descriptor(&self.application, &verified)
    }

    pub(super) fn archive_path(&self) -> &Path {
        self.snapshot.path()
    }
}

/// Snapshot a bounded archive, check its signed byte identity, then invoke the
/// existing bundle verifier with independently enrolled consumer keys.
///
/// No key is added to `trust`. Architecture is bound between the two signed
/// manifests; backend/host compatibility remains the existing admission check.
pub fn verify_application_bundle(
    application: &VerifiedRegistryApplication,
    archive: &Path,
    trust: &dyn TrustStore,
) -> Result<VerifiedApplicationBundle, ApplicationBundleError> {
    let expected = &application.manifest().application;
    if expected.bundle.archive_size > MAX_APPLICATION_ARCHIVE_BYTES {
        return Err(ApplicationBundleError::Size);
    }
    let input = super::local_input::open_sized_regular(archive, expected.bundle.archive_size)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::Other {
                ApplicationBundleError::Size
            } else {
                ApplicationBundleError::Io(error)
            }
        })?;
    let mut snapshot = tempfile::NamedTempFile::new()?;
    let mut writer = HashingWriter::new(snapshot.as_file_mut());
    std::io::copy(
        &mut input.take(expected.bundle.archive_size + 1),
        &mut writer,
    )?;
    let (size, digest) = writer.finish();
    if size != expected.bundle.archive_size {
        return Err(ApplicationBundleError::Size);
    }
    if digest != expected.bundle.archive_sha256.as_str() {
        return Err(ApplicationBundleError::Digest);
    }
    snapshot.as_file().sync_all()?;
    let bundle = verify_bundle_file(snapshot.path(), trust)?;
    match_descriptor(application, &bundle)?;
    Ok(VerifiedApplicationBundle {
        application: application.clone(),
        snapshot,
        bundle,
    })
}

fn match_descriptor(
    application: &VerifiedRegistryApplication,
    bundle: &VerifiedBundleFile,
) -> Result<(), ApplicationBundleError> {
    let expected = &application.manifest().application;
    if bundle.bundle_sha256 != expected.bundle.archive_sha256.as_str() {
        return Err(ApplicationBundleError::Digest);
    }
    if bundle.key_id != expected.bundle.key_id {
        return Err(ApplicationBundleError::Key);
    }
    if bundle.manifest.arch != expected.guest_arch {
        return Err(ApplicationBundleError::Architecture);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
