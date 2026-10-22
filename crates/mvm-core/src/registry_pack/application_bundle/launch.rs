//! Resolve an installed application reference to the bundle a launch boots.
//!
//! Resolution authenticates again rather than trusting what install left on
//! disk: the cached descriptor must still match its pin and publisher policy,
//! must not be revoked, and the cached archive must still verify under the
//! consumer's independently enrolled keys. The result names a bundle for the
//! existing bundle admission path; it is not itself launch authorization.

use std::path::Path;

use thiserror::Error;

use super::{
    ApplicationBundleError, ApplicationInstallStore, VerifiedApplicationBundle,
    verify_application_bundle,
};
use crate::plan::bundle::{
    BundleManifest, BundleRegistry, BundleVerifyError, MANIFEST_FILENAME, SIGNATURE_FILENAME,
    TrustStore,
};
use crate::registry_pack::{
    AuthenticatedRegistryManifest, PackReference, REGISTRY_MANIFEST_FILE_NAME,
    REGISTRY_SIGNATURE_FILE_NAME, RegistryPackPublisherPolicy, RegistryPackSignatureChecker,
    RegistryPackVerification, VerifiedRegistryManifest, check_registry_pack_signature,
};
use crate::registry_pack_store::load_pack_lockfile;

#[derive(Debug, Error)]
pub enum ApplicationLaunchError {
    #[error("application {reference} is not installed; run `mvmctl pack pull {reference}`")]
    NotInstalled { reference: String },
    #[error(
        "application {coordinate} is installed at {installed}, not {requested}; \
         run `mvmctl pack pull {coordinate}@{requested}`"
    )]
    VersionNotInstalled {
        coordinate: String,
        requested: String,
        installed: String,
    },
    #[error("{reference} is installed as a policy pack, not an application")]
    NotAnApplication { reference: String },
    #[error(
        "installed bundle {bundle_sha256} of {reference} is missing; \
         run `mvmctl pack pull {reference}`"
    )]
    BundleMissing {
        reference: String,
        bundle_sha256: String,
    },
    #[error(transparent)]
    Bundle(#[from] ApplicationBundleError),
    #[error(transparent)]
    Store(#[from] crate::registry_pack_store::RegistryPackStoreError),
    #[error(transparent)]
    Manifest(#[from] crate::registry_pack::RegistryPackVerificationError),
    #[error("reading the installed descriptor failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Metadata from a just-verified installed application, not retained custody.
///
/// Runtime preparation must retain the value returned by
/// [`resolve_installed_application_bundle`], not reconstruct authority from
/// these public fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApplication {
    pub reference: PackReference,
    pub descriptor_sha256: String,
    pub bundle_sha256: String,
}

/// The kind of the descriptor cached for `reference`'s pin, if one is cached.
/// Nothing is authenticated; use [`resolve_installed_application_bundle`]
/// before preparing a runtime.
fn cached_kind_is_application(
    reference: &PackReference,
    store: &ApplicationInstallStore,
) -> Option<bool> {
    let lock = load_pack_lockfile(&store.lock_path).ok()?;
    let pin = pinned(&lock, reference)?;
    let path = store
        .descriptor_cache_root
        .join(pin.manifest_sha256().as_str())
        .join(REGISTRY_MANIFEST_FILE_NAME);
    let bytes = super::super::local_input::read_metadata(&path).ok()?;
    Some(is_application(&bytes))
}

/// Whether `reference` names an installed application, by its pin and cached
/// descriptor kind alone.
pub fn names_installed_application(
    reference: &PackReference,
    store: &ApplicationInstallStore,
) -> bool {
    cached_kind_is_application(reference, store) == Some(true)
}

/// Whether `reference` names an installed pack that is not an application, so
/// `run` can refuse it by name instead of treating it as an OCI image.
pub fn names_installed_policy_pack(
    reference: &PackReference,
    store: &ApplicationInstallStore,
) -> bool {
    cached_kind_is_application(reference, store) == Some(false)
}

fn is_application(manifest: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(manifest)
        .is_ok_and(|value| value.get("kind").and_then(|kind| kind.as_str()) == Some("application"))
}

fn pinned<'a>(
    lock: &'a crate::registry_pack::PackLockfile,
    reference: &PackReference,
) -> Option<&'a crate::registry_pack::PackPin> {
    lock.pins()
        .iter()
        .find(|pin| pin.reference().coordinate_string() == reference.coordinate_string())
}

/// Resolve metadata against the current publisher policy and real verifier.
///
/// This compatibility interface does not retain the verified archive snapshot.
pub fn resolve_installed_application(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    publisher_policy_path: &Path,
    trust: &dyn TrustStore,
) -> Result<ResolvedApplication, ApplicationLaunchError> {
    let held =
        resolve_installed_application_bundle(reference, store, publisher_policy_path, trust)?;
    Ok(resolution_metadata(&held))
}

/// Reauthenticate an installed application and retain its original evidence.
///
/// This requires the current pin, publisher policy, independent revocation feed
/// and bundle-author trust in the same call. The returned opaque value owns
/// the verified descriptor and private archive snapshot, not an execution
/// grant. Canonical preparation, admission and lifecycle custody remain required.
/// No download, installation, key enrollment or pin advancement occurs.
pub fn resolve_installed_application_bundle(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    publisher_policy_path: &Path,
    trust: &dyn TrustStore,
) -> Result<VerifiedApplicationBundle, ApplicationLaunchError> {
    let policy = crate::registry_pack_store::load_publisher_policy_or_official_default(
        publisher_policy_path,
    )?
    .policy;
    resolve_bundle_with(
        reference,
        store,
        &policy,
        trust,
        check_registry_pack_signature,
    )
}

pub(super) fn resolve_bundle_with(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    policy: &RegistryPackPublisherPolicy,
    trust: &dyn TrustStore,
    check_signature: RegistryPackSignatureChecker,
) -> Result<VerifiedApplicationBundle, ApplicationLaunchError> {
    resolve_bundle_with_checks(
        reference,
        store,
        policy,
        trust,
        check_signature,
        crate::registry_pack::VerifiedRegistryApplication::check_current_revocations,
    )
}

#[cfg(test)]
pub(super) fn resolve_with_checks(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    policy: &RegistryPackPublisherPolicy,
    trust: &dyn TrustStore,
    check_signature: RegistryPackSignatureChecker,
    check_revocations: impl FnOnce(
        &crate::registry_pack::VerifiedRegistryApplication,
    )
        -> Result<(), crate::registry_pack_store::RegistryPackStoreError>,
) -> Result<ResolvedApplication, ApplicationLaunchError> {
    let held = resolve_bundle_with_checks(
        reference,
        store,
        policy,
        trust,
        check_signature,
        check_revocations,
    )?;
    Ok(resolution_metadata(&held))
}

fn resolution_metadata(held: &VerifiedApplicationBundle) -> ResolvedApplication {
    ResolvedApplication {
        reference: held.application().reference().clone(),
        descriptor_sha256: held.application().manifest_sha256().as_str().to_string(),
        bundle_sha256: held.bundle().bundle_sha256.clone(),
    }
}

pub(super) fn resolve_bundle_with_checks(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    policy: &RegistryPackPublisherPolicy,
    trust: &dyn TrustStore,
    check_signature: RegistryPackSignatureChecker,
    check_revocations: impl FnOnce(
        &crate::registry_pack::VerifiedRegistryApplication,
    )
        -> Result<(), crate::registry_pack_store::RegistryPackStoreError>,
) -> Result<VerifiedApplicationBundle, ApplicationLaunchError> {
    let lock = load_pack_lockfile(&store.lock_path)?;
    let not_installed = || ApplicationLaunchError::NotInstalled {
        reference: reference.to_string(),
    };
    let pin = pinned(&lock, reference).ok_or_else(not_installed)?;
    let installed = pin.reference();
    if let Some(requested) = reference.version()
        && Some(requested) != installed.version()
    {
        return Err(ApplicationLaunchError::VersionNotInstalled {
            coordinate: reference.coordinate_string(),
            requested: requested.to_string(),
            installed: installed.to_string(),
        });
    }
    let descriptor = store
        .descriptor_cache_root
        .join(pin.manifest_sha256().as_str());
    let manifest =
        super::super::local_input::read_metadata(&descriptor.join(REGISTRY_MANIFEST_FILE_NAME))?;
    let signature =
        super::super::local_input::read_metadata(&descriptor.join(REGISTRY_SIGNATURE_FILE_NAME))?;
    let verified = super::super::dispatch::verify_with(
        &RegistryPackVerification::new(installed, &manifest, &signature, &lock, policy),
        check_signature,
    )?;
    let VerifiedRegistryManifest::Application(application) = verified else {
        return Err(ApplicationLaunchError::NotAnApplication {
            reference: installed.to_string(),
        });
    };
    check_revocations(&application)?;
    let registry = BundleRegistry::new(&store.bundle_root);
    let archive = registry.archive_path(
        application
            .manifest()
            .application
            .bundle
            .archive_sha256
            .as_str(),
    );
    let bundle = verify_application_bundle(&application, &archive, trust)?;
    require_installed_metadata(&registry, &bundle)?;
    Ok(bundle)
}

fn require_installed_metadata(
    registry: &BundleRegistry,
    bundle: &VerifiedApplicationBundle,
) -> Result<(), ApplicationLaunchError> {
    let bundle_sha256 = &bundle.bundle().bundle_sha256;
    let root = registry.install_dir(bundle_sha256);
    let mismatch = || {
        ApplicationLaunchError::Bundle(ApplicationBundleError::Verification(
            BundleVerifyError::ManifestParse(
                "installed application metadata differs from its verified archive".into(),
            ),
        ))
    };
    let metadata = match std::fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ApplicationLaunchError::BundleMissing {
                reference: bundle.application().reference().to_string(),
                bundle_sha256: bundle_sha256.clone(),
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() {
        return Err(mismatch());
    }
    let manifest = super::super::local_input::read_metadata(&root.join(MANIFEST_FILENAME))?;
    let installed: BundleManifest = serde_json::from_slice(&manifest).map_err(|_| mismatch())?;
    if installed != bundle.bundle().manifest {
        return Err(mismatch());
    }
    let signature = super::super::local_input::read_metadata(&root.join(SIGNATURE_FILENAME))?;
    let expected = bundle
        .bundle()
        .plan_artifact()
        .signature_bytes()
        .ok_or_else(mismatch)?;
    if signature.as_slice() != expected.as_slice() {
        return Err(mismatch());
    }
    Ok(())
}
