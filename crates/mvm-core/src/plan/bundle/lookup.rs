//! Admit-time lookups: where a pinned bundle's archive bytes and its
//! publisher's verifying key come from.
//!
//! Both are traits so the verifier and the supervisor stay free of a
//! filesystem dependency; the `Fs*` implementations are the production
//! stores under `~/.mvm`.

use std::path::{Path, PathBuf};

use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use thiserror::Error;

use super::KeyId;

/// Look up bundle archive bytes by SHA-256 at admit time.
///
/// The supervisor calls this on every admission whose `ExecutionPlan`
/// carries a `PlanArtifact`. Production impls read from
/// `~/.mvm/bundles/<bundle_sha256>.mvmpkg.gz` (or legacy `.mvmpkg`); tests inject in-memory
/// resolvers. The trait stays in `mvm_plan` rather than alongside
/// `FsTrustStore` so the supervisor doesn't need a filesystem dep
/// to consume admissions.
pub trait BundleResolver: Send + Sync {
    /// Fetch the archive bytes for `bundle_sha256`. Returns
    /// `Err(MissingBundle)` when the bundle isn't cached locally;
    /// `Err(Io(_))` when it's there but unreadable.
    fn resolve(&self, bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError>;
}

/// Errors specific to bundle resolution at admit time. Distinct
/// from [`BundleVerifyError`](super::BundleVerifyError) so the supervisor can surface
/// "we don't have the bundle locally" differently from "we have
/// it but the bytes don't verify."
#[derive(Debug, Error)]
pub enum BundleResolveError {
    #[error("no cached bundle for sha256 {bundle_sha256}")]
    MissingBundle { bundle_sha256: String },

    #[error("reading cached bundle {bundle_sha256}: {reason}")]
    Io {
        bundle_sha256: String,
        reason: String,
    },
}

/// Filesystem-backed resolver rooted at `~/.mvm/bundles/`.
/// `<bundle_sha256>.mvmpkg.gz` is the on-disk filename — content-
/// addressed so two bundles with the same bytes share a cache
/// entry. The cache is populated by `mvmctl bundle fetch` once
/// the registry-replacement follow-up lands; until then,
/// publishers write the file by hand.
pub struct FsBundleResolver {
    root: PathBuf,
}

impl FsBundleResolver {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Default path: `~/.mvm/bundles/`. Same shape as
    /// `FsTrustStore::default_path` so admission code can resolve
    /// both with no extra plumbing.
    pub fn default_path() -> anyhow::Result<Self> {
        let p = crate::config::mvm_home_strict()?.join("bundles");
        Ok(Self::new(p))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl BundleResolver for FsBundleResolver {
    fn resolve(&self, bundle_sha256: &str) -> Result<Vec<u8>, BundleResolveError> {
        let path = super::BundleRegistry::new(&self.root).archive_path(bundle_sha256);
        if std::fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return Err(BundleResolveError::MissingBundle {
                bundle_sha256: bundle_sha256.to_string(),
            });
        }
        #[cfg(feature = "host-state")]
        let read = super::stream::read_bundle_archive(&path)
            .map_err(|error| std::io::Error::other(error.to_string()));
        #[cfg(not(feature = "host-state"))]
        let read = if path.extension().is_some_and(|ext| ext == "gz") {
            Err(std::io::Error::other(
                "compressed bundle resolution requires host-state",
            ))
        } else {
            std::fs::read(&path)
        };
        match read {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(BundleResolveError::MissingBundle {
                    bundle_sha256: bundle_sha256.to_string(),
                })
            }
            Err(e) => Err(BundleResolveError::Io {
                bundle_sha256: bundle_sha256.to_string(),
                reason: e.to_string(),
            }),
        }
    }
}

/// Lookup interface for finding a publisher's verifying key by `key_id`.
///
/// Production impl reads `~/.mvm/trusted-publishers/<key_id>.pub`;
/// tests inject an in-memory map. Kept narrow so the verifier
/// doesn't grow a filesystem dependency.
pub trait TrustStore {
    /// Return the verifying key for `key_id`, or `None` if the
    /// consumer has not enrolled this publisher.
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey>;
}

/// Read this host's existing public signing key without creating new trust.
///
/// # Errors
///
/// Refuses a malformed or linked public key instead of treating it as a publisher.
#[cfg(feature = "host-state")]
pub fn existing_local_build_key() -> anyhow::Result<Option<VerifyingKey>> {
    let path = crate::config::mvm_keys_dir().join("host-signer.pub");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.len() == 32,
        "local build public key is not a regular 32-byte key"
    );
    let key: [u8; 32] = std::fs::read(path)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("local build public key changed during read"))?;
    Ok(Some(VerifyingKey::from_bytes(&key)?))
}

/// Release trust extended with exactly this host's signing key.
///
/// This store is for the local-build execution path only. Callers must still
/// classify the verified manifest with `bundle_origin`: a host signature
/// alone does not make a bundle admissible without the signed local-build
/// label, and a label alone does not grant trust.
pub struct LocalBundleTrustStore<T> {
    release: T,
    host_key_id: KeyId,
    host_key: VerifyingKey,
}

impl<T> LocalBundleTrustStore<T> {
    pub fn new(release: T, host_key_id: KeyId, host_key: VerifyingKey) -> Self {
        Self {
            release,
            host_key_id,
            host_key,
        }
    }

    pub fn release(&self) -> &T {
        &self.release
    }
}

impl<T: TrustStore> TrustStore for LocalBundleTrustStore<T> {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        if key_id == &self.host_key_id {
            Some(self.host_key)
        } else {
            self.release.lookup(key_id)
        }
    }
}

/// Filesystem-backed trust store rooted at `~/.mvm/trusted-publishers/`
/// (or any directory). Pubkey files are named `<key_id>.pub` and
/// hold the 32 raw Ed25519 public-key bytes (no PEM, no headers).
///
/// Production consumers populate this via `mvmctl trust add`
/// (shipped in a follow-up). For now the format is documented here
/// so out-of-band enrolment via plain file copy works too.
pub struct FsTrustStore {
    root: PathBuf,
}

impl FsTrustStore {
    /// Construct rooted at `dir`.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { root: dir.into() }
    }

    /// Default path: `~/.mvm/trusted-publishers/`. Errors when
    /// `$HOME` is unset.
    pub fn default_path() -> Result<Self> {
        let p = crate::config::mvm_home_strict()?.join("trusted-publishers");
        Ok(Self::new(p))
    }

    /// Underlying directory.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl TrustStore for FsTrustStore {
    fn lookup(&self, key_id: &KeyId) -> Option<VerifyingKey> {
        if !key_id.is_well_formed() {
            return None;
        }
        let path = self.root.join(format!("{}.pub", key_id.0));
        let bytes = std::fs::read(&path).ok()?;
        let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
        VerifyingKey::from_bytes(&arr).ok()
    }
}
