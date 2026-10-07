//! The ways a bundle archive can fail verification, and the archive-path
//! rule every reader and validator applies.

use std::path::PathBuf;

use thiserror::Error;

use crate::image_set::ImageSetError;

/// Errors that can fall out of bundle verification.
///
/// Each variant carries enough detail to debug a specific failure
/// without exposing artifact bytes to log sinks.
#[derive(Debug, Error)]
pub enum BundleVerifyError {
    #[error("trust store has no entry for key_id {key_id}")]
    UnknownKey { key_id: String },

    #[error("publisher key file at {path} is malformed: {reason}")]
    MalformedPubkey { path: PathBuf, reason: String },

    #[error("signature does not verify under trusted key {key_id}: {reason}")]
    SignatureInvalid { key_id: String, reason: String },

    #[error("schema version {found} is newer than this build supports ({supported})")]
    UnsupportedSchema { found: u32, supported: u32 },

    #[error("manifest JSON parse failed: {0}")]
    ManifestParse(String),

    #[error("manifest declares key_id {declared} but trust store entry is for {actual}")]
    KeyIdMismatch { declared: String, actual: String },

    #[error("artifact {name} sha256 mismatch: manifest says {declared}, actual {actual}")]
    ArtifactSha256Mismatch {
        name: String,
        declared: String,
        actual: String,
    },

    #[error("artifact {name} size mismatch: manifest says {declared}, actual {actual}")]
    ArtifactSizeMismatch {
        name: String,
        declared: u64,
        actual: u64,
    },

    #[error(
        "archive entry path is unsafe: {path:?} (absolute paths, `..` traversal, and \
         backslash separators are rejected)"
    )]
    UnsafePath { path: String },

    #[error("manifest references artifact {name} but it is missing from the archive")]
    ArtifactMissing { name: String },

    #[error("signature blob is the wrong size: expected 64 bytes, got {got}")]
    MalformedSignature { got: usize },

    #[error("bundle member references image-set manifest artifact {name}, but it is not declared")]
    ImageSetManifestArtifactMissing { name: String },

    #[error("embedded image-set manifest {name} is not valid JSON: {reason}")]
    ImageSetManifestParse { name: String, reason: String },

    #[error("embedded image-set manifest {name} was refused: {reason}")]
    ImageSetRefused {
        name: String,
        #[source]
        reason: ImageSetError,
    },

    #[error("embedded image set names artifact {name}, but the bundle does not declare it")]
    ImageSetArtifactMissing { name: String },

    #[error(
        "embedded image-set artifact {name} digest differs from its bundle artifact: image set {image_set}, bundle {bundle}"
    )]
    ImageSetArtifactDigestMismatch {
        name: String,
        image_set: String,
        bundle: String,
    },

    #[error(
        "embedded image-set artifact {name} size differs from its bundle artifact: image set {image_set}, bundle {bundle}"
    )]
    ImageSetArtifactSizeMismatch {
        name: String,
        image_set: u64,
        bundle: u64,
    },

    #[error("bundle declares artifact name {name} more than once")]
    DuplicateArtifactName { name: String },

    #[error("bundle schema v{found} cannot declare typed members; members require schema v3")]
    MembersRequireSchemaV3 { found: u32 },

    #[error("bundle entry {path} is {size} bytes, over the {limit}-byte per-entry limit")]
    EntryTooLarge { path: String, size: u64, limit: u64 },

    #[error("bundle payload reaches {total} bytes, over the {limit}-byte total limit")]
    BundleTooLarge { total: u64, limit: u64 },

    #[error("bundle declares more than one {class} member")]
    DuplicateMember { class: &'static str },

    #[error("bundle kernel command line is malformed: {reason}")]
    MalformedCmdline { reason: String },

    #[error("bundle security posture is malformed: {reason}")]
    MalformedPosture { reason: String },

    #[error("bundle build provenance does not match its {artifact}: {reason}")]
    ProvenanceMismatch { artifact: String, reason: String },
}

/// Validate that an archive-relative path is safe to extract: no
/// absolute roots, no `..` traversal, no backslash separators.
///
/// Returns `Ok(())` if safe; `BundleVerifyError::UnsafePath`
/// otherwise. Surfaced as a free function so the archive reader and
/// the manifest validator both apply the same rule.
pub fn ensure_safe_path(path: &str) -> Result<(), BundleVerifyError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').any(|seg| seg == ".." || seg == ".")
    {
        return Err(BundleVerifyError::UnsafePath {
            path: path.to_string(),
        });
    }
    Ok(())
}
