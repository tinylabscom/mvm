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
/// `~/.mvm/bundles/<bundle_sha256>.mvmpkg`; tests inject in-memory
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
/// `<bundle_sha256>.mvmpkg` is the on-disk filename — content-
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
        let path = self.root.join(format!("{bundle_sha256}.mvmpkg"));
        match std::fs::read(&path) {
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
