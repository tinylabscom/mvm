//! `mvm addon verify <ref>` reproducible-build verification.
//!
//! Rebuild the addon locally from source, archive it deterministically,
//! and assert the resulting sha256 matches the registry-published
//! artifact. Mismatch → `E_ADDON_REPRODUCIBILITY_FAILED`.
//!
//! v1 scope: skeleton entry point. The end-to-end implementation
//! depends on (a) `pack_addon_dir` reaching feature parity with the
//! compile pipeline's `archive_dir`, (b) the registry client gaining a
//! real `tarball()` implementation. Both land in a follow-up phase.

use crate::addon::registry::ResolvedVersion;

/// Verify that a local source tree reproduces the registry's
/// canonical-form sha256 byte-for-byte.
pub fn verify_local_against_registry(
    _local_dir: &std::path::Path,
    _registry_version: &ResolvedVersion,
) -> Result<(), VerifyError> {
    Err(VerifyError::NotYetImplemented)
}

#[derive(Debug)]
pub enum VerifyError {
    /// Local rebuild produced a different sha256 than the registry.
    /// Maps to `E_ADDON_REPRODUCIBILITY_FAILED`.
    ShaMismatch {
        local_sha256: String,
        registry_sha256: String,
    },
    /// Registry artifact bytes are corrupt or could not be parsed.
    Malformed { detail: String },
    /// I/O error reading the local tree.
    Io(std::io::Error),
    /// Implementation pending follow-up.
    NotYetImplemented,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShaMismatch {
                local_sha256,
                registry_sha256,
            } => {
                write!(
                    f,
                    "local rebuild sha256 {local_sha256} does not match registry {registry_sha256}"
                )
            }
            Self::Malformed { detail } => write!(f, "registry artifact malformed: {detail}"),
            Self::Io(e) => write!(f, "I/O error during verify: {e}"),
            Self::NotYetImplemented => write!(f, "verify is not yet implemented"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<std::io::Error> for VerifyError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
