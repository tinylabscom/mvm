//! Lockfile and installation-directory facade for registry packs.
//!
//! [`registry_pack`] verifies and installs; this module owns the durable
//! state around that: the lockfile pinning one exact signed manifest per
//! pack, the publisher trust policy, and the correlation between pins and
//! content-addressed cache entries. Every path is explicit so tests drive
//! the facade through temp directories.

use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::registry_pack::{
    InstalledRegistryPack, PackAdoption, PackLockfile, PackPin, PackReference, RegistryPackError,
    RegistryPackInstallError, RegistryPackPublisherPolicy, RegistryPackSignatureChecker,
    RegistryPackVerification, RegistryPackVerificationError, VerifiedRegistryPack,
    adopt_registry_pack_with, default_signature_checker, install_registry_pack_at,
    verify_registry_pack_contents, verify_registry_pack_with,
};

#[derive(Debug, Error)]
pub enum RegistryPackStoreError {
    #[error("registry-pack state i/o error at {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("could not parse {path}: {reason}")]
    Parse { path: String, reason: String },
    #[error(
        "no publisher trust policy at {path}; create it with the namespaces and \
         workflow identities packs may come from"
    )]
    MissingPublisherPolicy { path: String },
    #[error(transparent)]
    Lock(#[from] RegistryPackError),
    #[error(transparent)]
    Verification(#[from] RegistryPackVerificationError),
    #[error(transparent)]
    Install(#[from] RegistryPackInstallError),
}

fn io_at(path: &Path) -> impl Fn(std::io::Error) -> RegistryPackStoreError + '_ {
    let shown = path.display().to_string();
    move |source| RegistryPackStoreError::Io {
        path: shown.clone(),
        source,
    }
}

fn parse_at(path: &Path, reason: impl fmt::Display) -> RegistryPackStoreError {
    RegistryPackStoreError::Parse {
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

/// Read the lockfile, treating a missing file as an empty lock.
pub fn load_pack_lockfile(path: &Path) -> Result<PackLockfile, RegistryPackStoreError> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|error| parse_at(path, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            PackLockfile::new(Vec::new()).map_err(RegistryPackStoreError::Lock)
        }
        Err(error) => Err(io_at(path)(error)),
    }
}

/// Atomically replace the lockfile (temp file + rename on one filesystem).
pub fn save_pack_lockfile(path: &Path, lock: &PackLockfile) -> Result<(), RegistryPackStoreError> {
    let text = toml::to_string_pretty(lock)
        .map_err(|error| parse_at(path, format!("serialize lockfile: {error}")))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_at(parent))?;
    }
    let temp = path.with_extension("lock.tmp");
    std::fs::write(&temp, text).map_err(io_at(&temp))?;
    std::fs::rename(&temp, path).map_err(io_at(path))?;
    Ok(())
}

/// Record `pin`, replacing any pin for the same namespace/name.
pub fn upsert_pack_pin(
    lock: PackLockfile,
    pin: PackPin,
) -> Result<PackLockfile, RegistryPackStoreError> {
    let mut packs: Vec<PackPin> = lock
        .pins()
        .iter()
        .filter(|existing| {
            existing.reference().namespace() != pin.reference().namespace()
                || existing.reference().name() != pin.reference().name()
        })
        .cloned()
        .collect();
    packs.push(pin);
    PackLockfile::new(packs).map_err(RegistryPackStoreError::Lock)
}

/// Drop the pin for `requested`'s namespace/name, if present.
///
/// Returns the new lock and whether a pin was removed. The cache entry is
/// left in place; [`remove_installed_registry_pack`] removes both.
pub fn remove_pack_pin(lock: PackLockfile, requested: &PackReference) -> (PackLockfile, bool) {
    let mut removed = false;
    let packs: Vec<PackPin> = lock
        .pins()
        .iter()
        .filter(|pin| {
            let matches = pin.reference().namespace() == requested.namespace()
                && pin.reference().name() == requested.name();
            if matches {
                removed = true;
            }
            !matches
        })
        .cloned()
        .collect();
    let new_lock = PackLockfile::new(packs).unwrap_or_else(|_| {
        PackLockfile::new(Vec::new()).expect("an empty lockfile is always valid")
    });
    (new_lock, removed)
}

/// Read the namespace-scoped publisher trust policy. Fail-closed: a missing
/// or malformed policy refuses every pack rather than admitting one.
pub fn load_publisher_policy(
    path: &Path,
) -> Result<RegistryPackPublisherPolicy, RegistryPackStoreError> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RegistryPackStoreError::MissingPublisherPolicy {
                path: path.display().to_string(),
            }
        } else {
            io_at(path)(error)
        }
    })?;
    toml::from_str(&text).map_err(|error| parse_at(path, error))
}

/// Serialize a publisher policy for bootstrap commands and tests.
pub fn save_publisher_policy(
    path: &Path,
    policy: &RegistryPackPublisherPolicy,
) -> Result<(), RegistryPackStoreError> {
    let text = toml::to_string_pretty(policy)
        .map_err(|error| parse_at(path, format!("serialize publisher policy: {error}")))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_at(parent))?;
    }
    let temp = path.with_extension("policy.tmp");
    std::fs::write(&temp, text).map_err(io_at(&temp))?;
    std::fs::rename(&temp, path).map_err(io_at(path))?;
    Ok(())
}

/// Where a publisher policy came from: the operator's file, or the built-in
/// official-registry default because no file exists yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherPolicySource {
    /// The operator's policy file at the configured path.
    OperatorFile,
    /// No policy file exists; the built-in official policy applies.
    OfficialDefault,
}

/// A loaded publisher policy together with where it came from.
#[derive(Debug, Clone)]
pub struct LoadedPublisherPolicy {
    pub policy: RegistryPackPublisherPolicy,
    pub source: PublisherPolicySource,
}

impl LoadedPublisherPolicy {
    /// Whether the built-in official default is in effect. Callers announce
    /// this so an operator who wants a different trust decision knows the
    /// file to write.
    #[must_use]
    pub fn is_official_default(&self) -> bool {
        self.source == PublisherPolicySource::OfficialDefault
    }
}

/// Load the operator publisher policy, falling back to the official
/// registry's built-in trust when no policy file exists.
///
/// A missing file means the operator has not made a trust decision yet, so
/// the official policy applies. A malformed file fails closed: a broken
/// operator policy is an error, never a silent widening to the official
/// default.
pub fn load_publisher_policy_or_official_default(
    path: &Path,
) -> Result<LoadedPublisherPolicy, RegistryPackStoreError> {
    match load_publisher_policy(path) {
        Ok(policy) => Ok(LoadedPublisherPolicy {
            policy,
            source: PublisherPolicySource::OperatorFile,
        }),
        Err(RegistryPackStoreError::MissingPublisherPolicy { .. }) => Ok(LoadedPublisherPolicy {
            policy: crate::registry_pack::official_publisher_policy(),
            source: PublisherPolicySource::OfficialDefault,
        }),
        Err(error) => Err(error),
    }
}

/// Adopt a freshly fetched pack: signature-first verification, content
/// verification, atomic installation, and a recorded pin.
///
/// This is the composition `mvmctl pull` runs; keeping it here lets the
/// happy path be tested without a network or a verification bypass.
pub fn adopt_install_and_pin(
    adoption: &PackAdoption<'_>,
    staged_root: &Path,
    cache_root: &Path,
    lock_path: &Path,
) -> Result<InstalledRegistryPack, RegistryPackStoreError> {
    adopt_install_and_pin_with(
        adoption,
        staged_root,
        cache_root,
        lock_path,
        default_signature_checker(),
    )
}

pub(crate) fn adopt_install_and_pin_with(
    adoption: &PackAdoption<'_>,
    staged_root: &Path,
    cache_root: &Path,
    lock_path: &Path,
    check_signature: RegistryPackSignatureChecker,
) -> Result<InstalledRegistryPack, RegistryPackStoreError> {
    let lock = load_pack_lockfile(lock_path)?;
    let verified = adopt_registry_pack_with(adoption, check_signature)?;
    let installed = install_registry_pack_at(cache_root, staged_root, &verified)?;
    let pin = PackPin::new(
        verified.manifest().reference.clone(),
        verified.manifest_sha256().clone(),
    )?;
    let lock = upsert_pack_pin(lock, pin)?;
    save_pack_lockfile(lock_path, &lock)?;
    crate::policy::audit::event(crate::policy::audit::LocalAuditKind::RegistryPackPin)
        .detail(format!(
            "pack={} manifest_sha256={}",
            verified.manifest().reference,
            verified.manifest_sha256().as_str()
        ))
        .emit();
    Ok(installed)
}

/// Re-open an installed pack: lock-first verification of the recorded
/// sidecars and exact payload, refusing every drift or tamper.
pub fn open_installed_registry_pack(
    cache_root: &Path,
    lock: &PackLockfile,
    publisher_policy: &RegistryPackPublisherPolicy,
    requested: &PackReference,
) -> Result<(InstalledRegistryPack, VerifiedRegistryPack), RegistryPackStoreError> {
    open_installed_registry_pack_with(
        &OpenInstalledRequest {
            cache_root,
            lock,
            publisher_policy,
            requested,
        },
        default_signature_checker(),
    )
}

/// Everything needed to re-open one installed pack.
pub(crate) struct OpenInstalledRequest<'a> {
    pub cache_root: &'a Path,
    pub lock: &'a PackLockfile,
    pub publisher_policy: &'a RegistryPackPublisherPolicy,
    pub requested: &'a PackReference,
}

pub(crate) fn open_installed_registry_pack_with(
    request: &OpenInstalledRequest<'_>,
    check_signature: RegistryPackSignatureChecker,
) -> Result<(InstalledRegistryPack, VerifiedRegistryPack), RegistryPackStoreError> {
    let OpenInstalledRequest {
        cache_root,
        lock,
        publisher_policy,
        requested,
    } = request;
    let pin = lock
        .pins()
        .iter()
        .find(|pin| {
            pin.reference().namespace() == requested.namespace()
                && pin.reference().name() == requested.name()
        })
        .ok_or(RegistryPackVerificationError::Lock(
            RegistryPackError::UnpinnedPack {
                reference: requested.to_string(),
            },
        ))?;
    if let Some(requested_version) = requested.version() {
        let pinned = pin
            .reference()
            .version()
            .expect("PackPin construction requires a version");
        if requested_version != pinned {
            return Err(RegistryPackStoreError::Verification(
                RegistryPackVerificationError::Lock(RegistryPackError::RequestedVersionMismatch {
                    coordinate: format!("{}/{}", requested.namespace(), requested.name()),
                    requested: requested_version.to_string(),
                    pinned: pinned.to_string(),
                }),
            ));
        }
    }
    let root = cache_root.join(pin.manifest_sha256().as_str());
    let installed = InstalledRegistryPack::from_root(root);
    let manifest_path = installed.manifest_path();
    let manifest_bytes = std::fs::read(&manifest_path).map_err(io_at(&manifest_path))?;
    let signature_path = installed.signature_path();
    let signature_bytes = std::fs::read(&signature_path).map_err(io_at(&signature_path))?;
    let verification = RegistryPackVerification::new(
        pin.reference(),
        &manifest_bytes,
        &signature_bytes,
        lock,
        publisher_policy,
    );
    let verified = verify_registry_pack_with(&verification, check_signature)?;
    verify_registry_pack_contents(&verified, &installed.payload_root())?;
    Ok((installed, verified))
}

/// Remove the installed cache entry and lock pin for a pack.
///
/// Returns whether anything was recorded. A missing cache entry is not an
/// error once the pin is gone.
pub fn remove_installed_registry_pack(
    cache_root: &Path,
    lock_path: &Path,
    requested: &PackReference,
) -> Result<bool, RegistryPackStoreError> {
    let lock = load_pack_lockfile(lock_path)?;
    let pin = lock.pins().iter().find(|pin| {
        pin.reference().namespace() == requested.namespace()
            && pin.reference().name() == requested.name()
    });
    let Some(pin) = pin else {
        return Ok(false);
    };
    let pin_reference = pin.reference().to_string();
    let pin_digest = pin.manifest_sha256().as_str().to_string();
    let entry = cache_root.join(&pin_digest);
    if std::fs::symlink_metadata(&entry).is_ok() {
        let metadata = std::fs::symlink_metadata(&entry).map_err(io_at(&entry))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            std::fs::remove_dir_all(&entry).map_err(io_at(&entry))?;
        } else {
            std::fs::remove_file(&entry).map_err(io_at(&entry))?;
        }
    }
    let (lock, removed) = remove_pack_pin(lock, requested);
    if removed {
        save_pack_lockfile(lock_path, &lock)?;
        crate::policy::audit::event(crate::policy::audit::LocalAuditKind::RegistryPackRemove)
            .detail(format!("pack={pin_reference} manifest_sha256={pin_digest}"))
            .emit();
    }
    Ok(true)
}

/// One row of `mvmctl pack registry ls`: a pin and whether its exact
/// content-addressed entry is present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryPackListing {
    pub pin: PackPin,
    pub installed: bool,
}

/// Correlate lock pins with cache entries, sorted by reference.
pub fn list_installed_registry_packs(
    cache_root: &Path,
    lock: &PackLockfile,
) -> Vec<RegistryPackListing> {
    let mut rows: Vec<RegistryPackListing> = lock
        .pins()
        .iter()
        .map(|pin| {
            let entry = cache_root.join(pin.manifest_sha256().as_str());
            RegistryPackListing {
                pin: pin.clone(),
                installed: std::fs::symlink_metadata(&entry)
                    .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                    .unwrap_or(false),
            }
        })
        .collect();
    rows.sort_by(|a, b| a.pin.reference().cmp(b.pin.reference()));
    rows
}

/// The policy document a pack may declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackPolicyDocument {
    Profile,
    Group,
}

impl PackPolicyDocument {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Profile => "pack/profile.toml",
            Self::Group => "pack/group.toml",
        }
    }
}

/// Read a pack's declared policy document from an already-verified
/// installation, refusing a pack that does not declare it.
pub fn read_pack_policy_document(
    installed: &InstalledRegistryPack,
    verified: &VerifiedRegistryPack,
    document: PackPolicyDocument,
) -> Result<(PathBuf, String), RegistryPackStoreError> {
    let declared = verified
        .manifest()
        .files
        .iter()
        .any(|file| file.path == document.file_name());
    if !declared {
        return Err(RegistryPackStoreError::Parse {
            path: installed.root().display().to_string(),
            reason: format!("the pack does not declare `{}`", document.file_name()),
        });
    }
    let path = installed.payload_root().join(document.file_name());
    let text = std::fs::read_to_string(&path).map_err(io_at(&path))?;
    Ok((path, text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packs::Sha256Hex;
    use crate::registry_pack::{
        PackAdoption, REGISTRY_PACK_MANIFEST_SCHEMA_VERSION, RegistryPackFile,
        RegistryPackManifest, RegistryPackPublisher,
    };

    const PROFILE: &[u8] = b"[tools]\nallow = [\"git\"]\n";
    const GROUP: &[u8] = b"[network]\nallow = [\"pypi.org:443\"]\n";

    fn reference(value: &str) -> PackReference {
        value
            .parse()
            .unwrap_or_else(|error| panic!("{value}: {error}"))
    }

    fn publisher_policy() -> RegistryPackPublisherPolicy {
        RegistryPackPublisherPolicy::new(vec![RegistryPackPublisher::new(
            "runtime",
            "https://token.actions.githubusercontent.com",
            vec!["https://github.com/tinylabscom/mvm-templates/.github/workflows/publish.yml@refs/heads/main".to_string()],
        )
        .unwrap()])
        .unwrap()
    }

    #[test]
    fn a_missing_policy_file_falls_back_to_the_official_default() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("config/policy/publishers.toml");
        let loaded = load_publisher_policy_or_official_default(&path).unwrap();
        assert!(loaded.is_official_default());
        let trust = loaded
            .policy
            .trust_for_namespace("anything")
            .expect("the wildcard default trusts official namespaces");
        assert_eq!(
            trust.issuer,
            crate::registry_pack::OFFICIAL_PACK_SIGNING_ISSUER
        );
        assert_eq!(
            trust.accepted_identities,
            [crate::registry_pack::OFFICIAL_PACK_SIGNING_IDENTITY.to_string()]
        );
    }

    #[test]
    fn an_operator_policy_file_replaces_the_default() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("publishers.toml");
        save_publisher_policy(&path, &publisher_policy()).unwrap();
        let loaded = load_publisher_policy_or_official_default(&path).unwrap();
        assert!(!loaded.is_official_default());
        assert!(loaded.policy.trust_for_namespace("runtime").is_ok());
        assert!(loaded.policy.trust_for_namespace("agent").is_err());
    }

    #[test]
    fn a_malformed_operator_policy_fails_closed() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("publishers.toml");
        std::fs::write(&path, "not = [valid toml\n").unwrap();
        assert!(load_publisher_policy_or_official_default(&path).is_err());
    }

    fn manifest_bytes(reference: &str) -> Vec<u8> {
        serde_json::to_vec(&RegistryPackManifest {
            schema_version: REGISTRY_PACK_MANIFEST_SCHEMA_VERSION,
            reference: self::reference(reference),
            description: "Python runtime".to_string(),
            files: vec![RegistryPackFile {
                path: "pack/profile.toml".to_string(),
                sha256: Sha256Hex::from_bytes(PROFILE),
                size: PROFILE.len() as u64,
            }],
        })
        .expect("serialize manifest")
    }

    fn accept(
        _payload: &[u8],
        _bundle: &[u8],
        _trust: &crate::packs::KeylessTrust,
    ) -> Result<(), RegistryPackVerificationError> {
        Ok(())
    }

    fn reject(
        _payload: &[u8],
        _bundle: &[u8],
        _trust: &crate::packs::KeylessTrust,
    ) -> Result<(), RegistryPackVerificationError> {
        Err(RegistryPackVerificationError::SignatureInvalid(
            "test refusal".to_string(),
        ))
    }

    fn stage_payload(staged: &Path) {
        let pack = staged.join("pack");
        std::fs::create_dir_all(&pack).expect("create staged pack dir");
        std::fs::write(pack.join("profile.toml"), PROFILE).expect("write staged profile");
        let _ = GROUP;
    }

    fn adoption<'a>(
        requested: &'a PackReference,
        manifest: &'a [u8],
        policy: &'a RegistryPackPublisherPolicy,
    ) -> PackAdoption<'a> {
        PackAdoption {
            requested,
            manifest_bytes: manifest,
            signature_bundle: b"test bundle",
            publisher_policy: policy,
        }
    }

    #[test]
    fn a_missing_lockfile_reads_as_an_empty_lock() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("packs.lock.toml");
        let lock = load_pack_lockfile(&path).expect("missing lock is empty");
        assert!(lock.pins().is_empty());
    }

    #[test]
    fn lockfile_round_trips_through_an_atomic_save() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("nested").join("packs.lock.toml");
        let pin = PackPin::new(
            reference("runtime/python@1.2.3"),
            Sha256Hex::from_bytes(b"manifest"),
        )
        .expect("versioned pin");
        let lock = upsert_pack_pin(load_pack_lockfile(&path).expect("empty lock"), pin.clone())
            .expect("upsert");
        save_pack_lockfile(&path, &lock).expect("save");
        let loaded = load_pack_lockfile(&path).expect("load");
        assert_eq!(loaded.pins(), &[pin]);
    }

    #[test]
    fn upsert_replaces_the_pin_for_one_coordinate_only() {
        let first = PackPin::new(
            reference("runtime/python@1.2.3"),
            Sha256Hex::from_bytes(b"one"),
        )
        .expect("pin");
        let other = PackPin::new(
            reference("runtime/node@2.0.0"),
            Sha256Hex::from_bytes(b"two"),
        )
        .expect("pin");
        let replacement = PackPin::new(
            reference("runtime/python@1.2.4"),
            Sha256Hex::from_bytes(b"three"),
        )
        .expect("pin");
        let lock = PackLockfile::new(vec![first, other.clone()]).expect("lock");
        let lock = upsert_pack_pin(lock, replacement.clone()).expect("upsert");
        assert_eq!(lock.pins(), &[other, replacement]);
    }

    #[test]
    fn remove_pack_pin_drops_only_the_named_coordinate() {
        let python = PackPin::new(
            reference("runtime/python@1.2.3"),
            Sha256Hex::from_bytes(b"one"),
        )
        .expect("pin");
        let node = PackPin::new(
            reference("runtime/node@2.0.0"),
            Sha256Hex::from_bytes(b"two"),
        )
        .expect("pin");
        let lock = PackLockfile::new(vec![python.clone(), node.clone()]).expect("lock");
        let (lock, removed) = remove_pack_pin(lock, &reference("runtime/python"));
        assert!(removed);
        assert_eq!(lock.pins(), &[node]);
        let (lock, removed) = remove_pack_pin(lock, &reference("runtime/python"));
        assert!(!removed);
        assert_eq!(lock.pins().len(), 1);
    }

    #[test]
    fn a_missing_publisher_policy_is_a_fail_closed_error() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("publishers.toml");
        let error = load_publisher_policy(&path).expect_err("missing policy refuses");
        assert!(matches!(
            error,
            RegistryPackStoreError::MissingPublisherPolicy { .. }
        ));
    }

    #[test]
    fn publisher_policy_round_trips() {
        let home = tempfile::tempdir().expect("tempdir");
        let path = home.path().join("publishers.toml");
        let policy = publisher_policy();
        save_publisher_policy(&path, &policy).expect("save policy");
        let loaded = load_publisher_policy(&path).expect("load policy");
        assert!(loaded.trust_for_namespace("runtime").is_ok());
        assert!(policy.trust_for_namespace("runtime").is_ok());
        assert!(loaded.trust_for_namespace("other").is_err());
    }

    #[test]
    fn adopt_install_and_pin_publishes_and_records_a_pack() {
        let home = tempfile::tempdir().expect("tempdir");
        let cache = home.path().join("registry-packs");
        let lock_path = home.path().join("packs.lock.toml");
        let policy = publisher_policy();
        let manifest = manifest_bytes("runtime/python@1.2.3");
        let staged = home.path().join("staged");
        stage_payload(&staged);
        let requested = reference("runtime/python@1.2.3");

        let installed = adopt_install_and_pin_with(
            &adoption(&requested, &manifest, &policy),
            &staged,
            &cache,
            &lock_path,
            accept,
        )
        .expect("adopt and install");

        assert!(installed.payload_root().join("pack/profile.toml").is_file());
        let lock = load_pack_lockfile(&lock_path).expect("load lock");
        assert_eq!(lock.pins().len(), 1);
        let rows = list_installed_registry_packs(&cache, &lock);
        assert!(rows.iter().all(|row| row.installed));
    }

    #[test]
    fn adopt_refuses_a_rejected_signature_without_recording_anything() {
        let home = tempfile::tempdir().expect("tempdir");
        let cache = home.path().join("registry-packs");
        let lock_path = home.path().join("packs.lock.toml");
        let policy = publisher_policy();
        let manifest = manifest_bytes("runtime/python@1.2.3");
        let staged = home.path().join("staged");
        stage_payload(&staged);
        let requested = reference("runtime/python@1.2.3");

        let error = adopt_install_and_pin_with(
            &adoption(&requested, &manifest, &policy),
            &staged,
            &cache,
            &lock_path,
            reject,
        )
        .expect_err("rejected signature refuses");
        assert!(matches!(
            error,
            RegistryPackStoreError::Verification(RegistryPackVerificationError::SignatureInvalid(
                _
            ))
        ));
        assert!(!lock_path.exists(), "no lockfile is written on refusal");
        assert!(!cache.exists(), "nothing is installed on refusal");
    }

    #[test]
    fn open_re_verifies_sidecars_and_payload_on_every_use() {
        let home = tempfile::tempdir().expect("tempdir");
        let cache = home.path().join("registry-packs");
        let lock_path = home.path().join("packs.lock.toml");
        let policy = publisher_policy();
        let manifest = manifest_bytes("runtime/python@1.2.3");
        let staged = home.path().join("staged");
        stage_payload(&staged);
        let requested = reference("runtime/python@1.2.3");
        adopt_install_and_pin_with(
            &adoption(&requested, &manifest, &policy),
            &staged,
            &cache,
            &lock_path,
            accept,
        )
        .expect("adopt and install");
        let lock = load_pack_lockfile(&lock_path).expect("load lock");

        let (installed, verified) = open_installed_registry_pack_with(
            &OpenInstalledRequest {
                cache_root: &cache,
                lock: &lock,
                publisher_policy: &policy,
                requested: &requested,
            },
            accept,
        )
        .expect("re-open");
        assert_eq!(
            verified.manifest().reference.to_string(),
            "runtime/python@1.2.3"
        );

        // A tampered payload is refused even though the sidecars match.
        let tampered = b"[tools]\nallow = [\"svn\"]\n";
        assert_eq!(tampered.len(), PROFILE.len());
        std::fs::write(installed.payload_root().join("pack/profile.toml"), tampered)
            .expect("tamper");
        let error = open_installed_registry_pack_with(
            &OpenInstalledRequest {
                cache_root: &cache,
                lock: &lock,
                publisher_policy: &policy,
                requested: &requested,
            },
            accept,
        )
        .expect_err("tampered payload refuses");
        assert!(matches!(
            error,
            RegistryPackStoreError::Verification(
                RegistryPackVerificationError::PayloadHashMismatch { .. }
            )
        ));
    }

    #[test]
    fn open_refuses_an_unpinned_or_version_drifted_request() {
        let home = tempfile::tempdir().expect("tempdir");
        let cache = home.path().join("registry-packs");
        let lock_path = home.path().join("packs.lock.toml");
        let policy = publisher_policy();
        let manifest = manifest_bytes("runtime/python@1.2.3");
        let staged = home.path().join("staged");
        stage_payload(&staged);
        let requested = reference("runtime/python@1.2.3");
        adopt_install_and_pin_with(
            &adoption(&requested, &manifest, &policy),
            &staged,
            &cache,
            &lock_path,
            accept,
        )
        .expect("adopt and install");
        let lock = load_pack_lockfile(&lock_path).expect("load lock");

        let unpinned = reference("runtime/rust@1.0.0");
        let error = open_installed_registry_pack_with(
            &OpenInstalledRequest {
                cache_root: &cache,
                lock: &lock,
                publisher_policy: &policy,
                requested: &unpinned,
            },
            accept,
        )
        .expect_err("unpinned pack refuses");
        assert!(matches!(
            error,
            RegistryPackStoreError::Verification(RegistryPackVerificationError::Lock(
                RegistryPackError::UnpinnedPack { .. }
            ))
        ));

        let drifted = reference("runtime/python@9.9.9");
        let error = open_installed_registry_pack_with(
            &OpenInstalledRequest {
                cache_root: &cache,
                lock: &lock,
                publisher_policy: &policy,
                requested: &drifted,
            },
            accept,
        )
        .expect_err("version drift refuses");
        assert!(matches!(
            error,
            RegistryPackStoreError::Verification(RegistryPackVerificationError::Lock(
                RegistryPackError::RequestedVersionMismatch { .. }
            ))
        ));
    }

    #[test]
    fn remove_installed_registry_pack_drops_entry_and_pin() {
        let home = tempfile::tempdir().expect("tempdir");
        let cache = home.path().join("registry-packs");
        let lock_path = home.path().join("packs.lock.toml");
        let policy = publisher_policy();
        let manifest = manifest_bytes("runtime/python@1.2.3");
        let staged = home.path().join("staged");
        stage_payload(&staged);
        let requested = reference("runtime/python@1.2.3");
        let installed = adopt_install_and_pin_with(
            &adoption(&requested, &manifest, &policy),
            &staged,
            &cache,
            &lock_path,
            accept,
        )
        .expect("adopt and install");

        assert!(
            remove_installed_registry_pack(&cache, &lock_path, &requested)
                .expect("remove installed")
        );
        assert!(!installed.root().exists());
        let lock = load_pack_lockfile(&lock_path).expect("load lock");
        assert!(lock.pins().is_empty());
        assert!(
            !remove_installed_registry_pack(&cache, &lock_path, &requested)
                .expect("second remove is a no-op")
        );
    }

    #[test]
    fn read_pack_policy_document_returns_declared_files_only() {
        let home = tempfile::tempdir().expect("tempdir");
        let cache = home.path().join("registry-packs");
        let lock_path = home.path().join("packs.lock.toml");
        let policy = publisher_policy();
        let manifest = manifest_bytes("runtime/python@1.2.3");
        let staged = home.path().join("staged");
        stage_payload(&staged);
        let requested = reference("runtime/python@1.2.3");
        let installed = adopt_install_and_pin_with(
            &adoption(&requested, &manifest, &policy),
            &staged,
            &cache,
            &lock_path,
            accept,
        )
        .expect("adopt and install");
        let lock = load_pack_lockfile(&lock_path).expect("load lock");
        let (_, verified) = open_installed_registry_pack_with(
            &OpenInstalledRequest {
                cache_root: &cache,
                lock: &lock,
                publisher_policy: &policy,
                requested: &requested,
            },
            accept,
        )
        .expect("re-open");

        let (path, text) =
            read_pack_policy_document(&installed, &verified, PackPolicyDocument::Profile)
                .expect("read declared profile");
        assert!(path.ends_with("payload/pack/profile.toml"));
        assert_eq!(text.as_bytes(), PROFILE);

        let error = read_pack_policy_document(&installed, &verified, PackPolicyDocument::Group)
            .expect_err("this pack does not declare group.toml");
        assert!(matches!(error, RegistryPackStoreError::Parse { .. }));
    }
}
