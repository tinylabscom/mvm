//! Content-addressed build-action cache records.
//!
//! A dev build cache entry used to be a bare `<revision>` marker: its presence
//! meant "trust whatever is on disk under this name." `ActionCacheRecord`
//! replaces that with a typed record naming the action's fingerprint and the
//! recorded digest + size of every artifact it produced, so a cache hit can be
//! verified against the actual bytes on disk before reuse rather than assumed.

use std::path::{Component, Path};

use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::packs::{Sha256Hex, is_sha256_hex, stream_sha256};

/// Identifies a build action by its fingerprint (sha256 over the action's
/// inputs — flake ref, profile, role, and so on). Bare 64-hex, no prefix: the
/// same shape as [`Sha256Hex`], but kept as a distinct type since an action
/// fingerprint and an artifact's content hash are never interchangeable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct ActionDigest(String);

impl ActionDigest {
    pub fn from_fingerprint_hex(value: &str) -> Result<Self, ActionError> {
        if is_sha256_hex(value) {
            Ok(Self(value.to_string()))
        } else {
            Err(ActionError::InvalidFingerprint(value.to_string()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ActionDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        ActionDigest::from_fingerprint_hex(&value).map_err(serde::de::Error::custom)
    }
}

/// One cached artifact's recorded identity: its path relative to the
/// revision directory (e.g. `rootfs.ext4`, `vmlinux`), content hash, and byte
/// size.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub path: String,
    pub sha256: Sha256Hex,
    pub size_bytes: u64,
}

/// The typed record for one build action's output set — what a cache entry
/// stores in place of the old plaintext `<revision>` marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionCacheRecord {
    pub action_digest: ActionDigest,
    pub revision: String,
    pub artifacts: Vec<ArtifactDigest>,
}

/// Recompute each recorded artifact's on-disk digest and size and compare
/// against `record`, returning the first mismatch encountered.
///
/// Each file is streamed through a fixed buffer rather than read whole into
/// memory — a cached `rootfs.ext4` runs to hundreds of megabytes. An empty
/// `artifacts` list is refused rather than treated as vacuously verified: the
/// absence of recorded digests must never read back as "verified." Every
/// `artifact.path` is checked for an escape (absolute, or carrying a `..`,
/// root, or prefix component) before it is joined onto `dir`, so a record
/// naming a path outside the revision directory is refused before any file
/// is touched.
pub fn verify_artifacts_on_disk(dir: &Path, record: &ActionCacheRecord) -> Result<(), VerifyError> {
    if record.artifacts.is_empty() {
        return Err(VerifyError::EmptyRecord);
    }
    for artifact in &record.artifacts {
        if !artifact_path_is_safe(&artifact.path) {
            return Err(VerifyError::UnsafePath {
                path: artifact.path.clone(),
            });
        }
        let path = dir.join(&artifact.path);
        let (got_hash, got_size) = hash_file_streaming(&path, &artifact.path)?;
        if got_size != artifact.size_bytes {
            return Err(VerifyError::SizeMismatch {
                path: artifact.path.clone(),
                expected: artifact.size_bytes,
                got: got_size,
            });
        }
        if got_hash != artifact.sha256.as_str() {
            return Err(VerifyError::Mismatch {
                path: artifact.path.clone(),
                expected: artifact.sha256.as_str().to_string(),
                got: got_hash,
            });
        }
    }
    Ok(())
}

/// Build an [`ActionCacheRecord`] for a freshly produced action output set:
/// stream each of `rel_paths` under `dir` through the same sha256 primitive
/// [`verify_artifacts_on_disk`] re-checks against later, and pack the
/// results into the typed record. Reuses [`hash_file_streaming`] so the
/// write side and the verify side can never disagree about how a digest is
/// computed.
///
/// Errors identically to [`verify_artifacts_on_disk`]'s per-artifact
/// failures (`UnsafePath`, `Missing`, `Io`) — a path that couldn't be
/// hashed on the way in could never have verified on the way out either.
pub fn build_record(
    action_digest: ActionDigest,
    revision: String,
    dir: &Path,
    rel_paths: &[&str],
) -> Result<ActionCacheRecord, VerifyError> {
    let mut artifacts = Vec::with_capacity(rel_paths.len());
    for rel_path in rel_paths {
        if !artifact_path_is_safe(rel_path) {
            return Err(VerifyError::UnsafePath {
                path: (*rel_path).to_string(),
            });
        }
        let path = dir.join(rel_path);
        let (sha256_hex, size_bytes) = hash_file_streaming(&path, rel_path)?;
        artifacts.push(ArtifactDigest {
            path: (*rel_path).to_string(),
            sha256: Sha256Hex::new(sha256_hex)
                .expect("stream_sha256 always returns a valid 64-hex digest"),
            size_bytes,
        });
    }
    Ok(ActionCacheRecord {
        action_digest,
        revision,
        artifacts,
    })
}

/// True when `path` cannot escape the directory it will be joined onto:
/// non-empty, relative, and every component a plain path segment (no `..`,
/// no root, no Windows-style prefix). An empty path's `Component` iterator
/// is also empty, so the "every component is `Normal`" check holds
/// vacuously for it; without an explicit check it would join onto `dir`
/// itself instead of naming a real artifact, so it's rejected up front.
fn artifact_path_is_safe(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    let path = Path::new(path);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Hash `path` on disk via [`stream_sha256`], mapping the raw `io::Error`
/// onto `VerifyError::Missing` or `VerifyError::Io`. `record_path` is the
/// artifact's recorded relative path, used for error reporting instead of
/// the joined absolute path.
fn hash_file_streaming(path: &Path, record_path: &str) -> Result<(String, u64), VerifyError> {
    stream_sha256(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            VerifyError::Missing {
                path: record_path.to_string(),
            }
        } else {
            VerifyError::Io {
                path: record_path.to_string(),
                source,
            }
        }
    })
}

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("invalid action fingerprint {0:?}: expected 64 lowercase hex characters")]
    InvalidFingerprint(String),
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("artifact {path} content mismatch: expected {expected}, got {got}")]
    Mismatch {
        path: String,
        expected: String,
        got: String,
    },
    #[error("artifact {path} size mismatch: expected {expected}, got {got}")]
    SizeMismatch {
        path: String,
        expected: u64,
        got: u64,
    },
    #[error("artifact {path} is missing on disk")]
    Missing { path: String },
    #[error("artifact path {path:?} is unsafe: must be relative with no parent-dir component")]
    UnsafePath { path: String },
    #[error("artifact {path} could not be read: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("action cache record has no recorded artifacts")]
    EmptyRecord,
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn valid_hex() -> String {
        "a".repeat(64)
    }

    #[test]
    fn action_digest_accepts_64_lower_hex() {
        let digest = ActionDigest::from_fingerprint_hex(&valid_hex()).expect("valid fingerprint");
        assert_eq!(digest.as_str(), valid_hex());
    }

    #[test]
    fn action_digest_rejects_non_hex() {
        let value = "g".repeat(64);
        let error = ActionDigest::from_fingerprint_hex(&value).unwrap_err();
        assert!(matches!(error, ActionError::InvalidFingerprint(v) if v == value));
    }

    #[test]
    fn action_digest_rejects_wrong_length() {
        let value = "a".repeat(63);
        let error = ActionDigest::from_fingerprint_hex(&value).unwrap_err();
        assert!(matches!(error, ActionError::InvalidFingerprint(v) if v == value));
    }

    #[test]
    fn action_digest_serde_roundtrip() {
        let digest = ActionDigest::from_fingerprint_hex(&valid_hex()).expect("valid fingerprint");
        let json = serde_json::to_string(&digest).expect("serialize");
        assert_eq!(json, format!("\"{}\"", valid_hex()));
        let back: ActionDigest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, digest);
    }

    #[test]
    fn action_digest_deserialize_rejects_bad_shape() {
        let bad = serde_json::to_string("not-a-digest").expect("serialize string");
        let result: Result<ActionDigest, _> = serde_json::from_str(&bad);
        assert!(result.is_err());
    }

    fn sample_record() -> ActionCacheRecord {
        ActionCacheRecord {
            action_digest: ActionDigest::from_fingerprint_hex(&valid_hex())
                .expect("valid fingerprint"),
            revision: "rev-1".to_string(),
            artifacts: vec![ArtifactDigest {
                path: "rootfs.ext4".to_string(),
                sha256: Sha256Hex::from_bytes(b"rootfs bytes"),
                size_bytes: 12,
            }],
        }
    }

    #[test]
    fn record_serde_roundtrip() {
        let record = sample_record();
        let json = serde_json::to_string(&record).expect("serialize");
        let back: ActionCacheRecord = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, record);
    }

    #[test]
    fn record_rejects_unknown_field() {
        let record = sample_record();
        let mut value = serde_json::to_value(&record).expect("to_value");
        value
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_string(), serde_json::json!("surprise"));
        let result: Result<ActionCacheRecord, _> = serde_json::from_value(value);
        assert!(result.is_err());
    }

    /// Write two temp files under `dir`, returning an `ActionCacheRecord`
    /// whose `artifacts` carry their real on-disk digests and sizes.
    fn write_matching_fixture(dir: &Path) -> ActionCacheRecord {
        let first = b"kernel image bytes".to_vec();
        let second = b"rootfs image bytes, somewhat longer".to_vec();
        fs::write(dir.join("vmlinux"), &first).expect("write vmlinux");
        fs::write(dir.join("rootfs.ext4"), &second).expect("write rootfs.ext4");
        ActionCacheRecord {
            action_digest: ActionDigest::from_fingerprint_hex(&valid_hex())
                .expect("valid fingerprint"),
            revision: "rev-1".to_string(),
            artifacts: vec![
                ArtifactDigest {
                    path: "vmlinux".to_string(),
                    sha256: Sha256Hex::from_bytes(&first),
                    size_bytes: first.len() as u64,
                },
                ArtifactDigest {
                    path: "rootfs.ext4".to_string(),
                    sha256: Sha256Hex::from_bytes(&second),
                    size_bytes: second.len() as u64,
                },
            ],
        }
    }

    #[test]
    fn verify_passes_on_matching_artifacts() {
        let dir = TempDir::new().expect("tempdir");
        let record = write_matching_fixture(dir.path());
        verify_artifacts_on_disk(dir.path(), &record).expect("verification should pass");
    }

    #[test]
    fn verify_fails_on_tampered_artifact() {
        let dir = TempDir::new().expect("tempdir");
        let record = write_matching_fixture(dir.path());
        let path = dir.path().join("rootfs.ext4");
        let mut bytes = fs::read(&path).expect("read rootfs.ext4");
        bytes[0] ^= 0xFF;
        fs::write(&path, &bytes).expect("rewrite rootfs.ext4");

        let error = verify_artifacts_on_disk(dir.path(), &record).unwrap_err();
        match error {
            VerifyError::Mismatch { path, .. } => assert_eq!(path, "rootfs.ext4"),
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_fails_on_missing_artifact() {
        let dir = TempDir::new().expect("tempdir");
        let record = write_matching_fixture(dir.path());
        fs::remove_file(dir.path().join("vmlinux")).expect("remove vmlinux");

        let error = verify_artifacts_on_disk(dir.path(), &record).unwrap_err();
        match error {
            VerifyError::Missing { path } => assert_eq!(path, "vmlinux"),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn verify_fails_on_size_mismatch() {
        let dir = TempDir::new().expect("tempdir");
        let mut record = write_matching_fixture(dir.path());
        record.artifacts[0].size_bytes += 1;

        let error = verify_artifacts_on_disk(dir.path(), &record).unwrap_err();
        match error {
            VerifyError::SizeMismatch { path, .. } => assert_eq!(path, "vmlinux"),
            other => panic!("expected SizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_fails_on_unsafe_path() {
        let dir = TempDir::new().expect("tempdir");
        let unsafe_record = |path: &str| ActionCacheRecord {
            action_digest: ActionDigest::from_fingerprint_hex(&valid_hex())
                .expect("valid fingerprint"),
            revision: "rev-1".to_string(),
            artifacts: vec![ArtifactDigest {
                path: path.to_string(),
                sha256: Sha256Hex::from_bytes(b"irrelevant"),
                size_bytes: 0,
            }],
        };

        let absolute = unsafe_record("/etc/passwd");
        let error = verify_artifacts_on_disk(dir.path(), &absolute).unwrap_err();
        match error {
            VerifyError::UnsafePath { path } => assert_eq!(path, "/etc/passwd"),
            other => panic!("expected UnsafePath, got {other:?}"),
        }

        let escaping = unsafe_record("../escape");
        let error = verify_artifacts_on_disk(dir.path(), &escaping).unwrap_err();
        match error {
            VerifyError::UnsafePath { path } => assert_eq!(path, "../escape"),
            other => panic!("expected UnsafePath, got {other:?}"),
        }

        // An empty path's `Component` iterator is itself empty, so without
        // an explicit check it would vacuously pass the "every component is
        // Normal" test and join onto `dir` itself instead of naming a file.
        let empty = unsafe_record("");
        let error = verify_artifacts_on_disk(dir.path(), &empty).unwrap_err();
        match error {
            VerifyError::UnsafePath { path } => assert_eq!(path, ""),
            other => panic!("expected UnsafePath, got {other:?}"),
        }
    }

    #[test]
    fn build_record_produces_a_record_verify_accepts() {
        let dir = TempDir::new().expect("tempdir");
        let matching = write_matching_fixture(dir.path());
        let digest = ActionDigest::from_fingerprint_hex(&valid_hex()).expect("valid fingerprint");

        let built = build_record(
            digest,
            "rev-1".to_string(),
            dir.path(),
            &["vmlinux", "rootfs.ext4"],
        )
        .expect("build_record should succeed on real files");

        // Same digests/sizes the fixture recorded by hand.
        assert_eq!(built.artifacts, matching.artifacts);
        verify_artifacts_on_disk(dir.path(), &built).expect("built record should verify");
    }

    #[test]
    fn build_record_fails_on_missing_artifact() {
        let dir = TempDir::new().expect("tempdir");
        let digest = ActionDigest::from_fingerprint_hex(&valid_hex()).expect("valid fingerprint");

        let error =
            build_record(digest, "rev-1".to_string(), dir.path(), &["rootfs.ext4"]).unwrap_err();
        match error {
            VerifyError::Missing { path } => assert_eq!(path, "rootfs.ext4"),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn build_record_rejects_unsafe_rel_path() {
        let dir = TempDir::new().expect("tempdir");
        let digest = ActionDigest::from_fingerprint_hex(&valid_hex()).expect("valid fingerprint");

        let error =
            build_record(digest, "rev-1".to_string(), dir.path(), &["../escape"]).unwrap_err();
        match error {
            VerifyError::UnsafePath { path } => assert_eq!(path, "../escape"),
            other => panic!("expected UnsafePath, got {other:?}"),
        }
    }

    #[test]
    fn verify_fails_on_empty_record() {
        let dir = TempDir::new().expect("tempdir");
        let record = ActionCacheRecord {
            action_digest: ActionDigest::from_fingerprint_hex(&valid_hex())
                .expect("valid fingerprint"),
            revision: "rev-1".to_string(),
            artifacts: Vec::new(),
        };

        let error = verify_artifacts_on_disk(dir.path(), &record).unwrap_err();
        assert!(matches!(error, VerifyError::EmptyRecord));
    }
}
