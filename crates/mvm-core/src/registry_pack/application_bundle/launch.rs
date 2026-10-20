//! Resolve an installed application reference to the bundle a launch boots.
//!
//! Resolution authenticates again rather than trusting what install left on
//! disk: the cached descriptor must still match its pin and publisher policy,
//! must not be revoked, and the cached archive must still verify under the
//! consumer's independently enrolled keys. The result names a bundle for the
//! existing bundle admission path; it is not itself launch authorization.

use std::path::Path;

use thiserror::Error;

use super::{ApplicationBundleError, ApplicationInstallStore, verify_application_bundle};
use crate::plan::bundle::{BundleRegistry, TrustStore};
use crate::registry_pack::{
    AuthenticatedRegistryManifest, PackReference, REGISTRY_MANIFEST_FILE_NAME,
    REGISTRY_SIGNATURE_FILE_NAME, RegistryPackPublisherPolicy, RegistryPackSignatureChecker,
    RegistryPackVerification, VerifiedRegistryManifest, check_registry_pack_signature,
};
use crate::registry_pack_store::{
    check_registry_pack_revocations_if_configured, load_pack_lockfile,
};

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

/// An installed application whose descriptor and bundle were just re-verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedApplication {
    pub reference: PackReference,
    pub descriptor_sha256: String,
    pub bundle_sha256: String,
}

/// Whether `reference` names an installed application, by its pin and cached
/// descriptor kind alone. Nothing is authenticated; use [`resolve_installed_application`].
pub fn names_installed_application(
    reference: &PackReference,
    store: &ApplicationInstallStore,
) -> bool {
    let Ok(lock) = load_pack_lockfile(&store.lock_path) else {
        return false;
    };
    let Some(pin) = pinned(&lock, reference) else {
        return false;
    };
    let path = store
        .descriptor_cache_root
        .join(pin.manifest_sha256().as_str())
        .join(REGISTRY_MANIFEST_FILE_NAME);
    super::super::local_input::read_metadata(&path).is_ok_and(|bytes| is_application(&bytes))
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

/// Resolve against the current publisher policy and real signature verifier.
pub fn resolve_installed_application(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    publisher_policy_path: &Path,
    trust: &dyn TrustStore,
) -> Result<ResolvedApplication, ApplicationLaunchError> {
    let policy = crate::registry_pack_store::load_publisher_policy_or_official_default(
        publisher_policy_path,
    )?
    .policy;
    resolve_with(
        reference,
        store,
        &policy,
        trust,
        check_registry_pack_signature,
    )
}

pub(super) fn resolve_with(
    reference: &PackReference,
    store: &ApplicationInstallStore,
    policy: &RegistryPackPublisherPolicy,
    trust: &dyn TrustStore,
    check_signature: RegistryPackSignatureChecker,
) -> Result<ResolvedApplication, ApplicationLaunchError> {
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
    check_registry_pack_revocations_if_configured(&application)?;
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
    let bundle_sha256 = bundle.bundle().bundle_sha256.clone();
    if registry.find(&bundle_sha256).ok().flatten().is_none() {
        return Err(ApplicationLaunchError::BundleMissing {
            reference: installed.to_string(),
            bundle_sha256,
        });
    }
    Ok(ResolvedApplication {
        reference: application.reference().clone(),
        descriptor_sha256: application.manifest_sha256().as_str().to_string(),
        bundle_sha256,
    })
}
