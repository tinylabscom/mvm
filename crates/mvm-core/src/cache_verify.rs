//! Verify-on-read for path-keyed artifact caches.
//!
//! A cache that serves an entry because a file *exists* at the expected path
//! answers "is something here?" when the question is "are these the bytes we
//! built?". Those differ in three ways that all show up in practice:
//!
//! - **Corruption.** Silent data corruption is measured, not hypothetical, and
//!   it does not move a file's size or mtime — so a size/mtime-keyed digest
//!   sidecar (`crypto::image_verify::sha256_file_cached`) cannot see it. That is
//!   why everything here streams the file through [`sha256_file`] on every read
//!   rather than consulting that sidecar.
//! - **Identity discrepancy.** An intact artifact that is the *wrong* artifact —
//!   the whole file is readable and self-consistent, it just belongs to a
//!   different build. A path-trusting cache cannot detect this at all, and it is
//!   the shape of the cache-skew that otherwise mimics a real bug.
//! - **Partial writes.** An entry whose producer died mid-write leaves a file
//!   that exists and is short.
//!
//! ## What this is not
//!
//! This is a cache-trust check, not an admission decision, and not a defence
//! against a host-level attacker: whoever can rewrite a cached artifact can
//! usually rewrite the record that describes it. Workload admission stays with
//! the signed execution plan. The value here is that a cache stops *silently*
//! serving bytes it never checked.
//!
//! ## Fail-closed
//!
//! An entry with no recorded digests is [`CacheVerdict::Unrecorded`] and callers
//! must treat it as a miss. Falling back to "the file is there, serve it" would
//! reintroduce exactly the path-trust this module exists to remove.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::crypto::image_verify::sha256_file;

/// Recorded digests for one cache entry: artifact name → lowercase SHA-256 hex.
///
/// Names are single path components relative to the entry's directory, so a
/// record can never redirect a read outside the entry it describes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigests {
    #[serde(default)]
    artifacts: BTreeMap<String, String>,
}

/// The outcome of verifying a cache entry against its recorded digests.
///
/// Only [`CacheVerdict::Verified`] permits serving the entry. Every other
/// variant is a miss; [`CacheVerdict::Mismatch`] and [`CacheVerdict::Missing`]
/// additionally mean the entry should be evicted rather than left to be
/// re-consulted on the next read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Every recorded artifact is present and hashes to its recorded digest.
    Verified,
    /// The entry carries no recorded digests. Treated as a miss, never trusted.
    Unrecorded,
    /// A recorded artifact is absent from the entry directory.
    Missing { artifact: String },
    /// A recorded artifact hashes to something other than what was recorded.
    Mismatch {
        artifact: String,
        expected: String,
        actual: String,
    },
    /// A recorded artifact could not be read to be hashed.
    Unreadable { artifact: String, error: String },
}

impl CacheVerdict {
    /// Whether the entry may be served. Only `Verified` qualifies.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Whether the entry should be evicted. `Unrecorded` is a miss but not
    /// evidence of damage, so it is not an eviction trigger on its own.
    pub fn should_evict(&self) -> bool {
        matches!(
            self,
            Self::Missing { .. } | Self::Mismatch { .. } | Self::Unreadable { .. }
        )
    }

    /// A one-line operator-facing reason, for the log line that explains why a
    /// cache hit turned into a rebuild.
    pub fn reason(&self) -> String {
        match self {
            Self::Verified => "verified".to_string(),
            Self::Unrecorded => "no recorded digests (entry predates verify-on-read)".to_string(),
            Self::Missing { artifact } => format!("{artifact} is missing"),
            Self::Mismatch {
                artifact,
                expected,
                actual,
            } => format!(
                "{artifact} hashes to {} but {} was recorded",
                short(actual),
                short(expected)
            ),
            Self::Unreadable { artifact, error } => {
                format!("{artifact} could not be read: {error}")
            }
        }
    }
}

/// First 12 hex chars, enough to identify a digest in a log line.
fn short(hex: &str) -> &str {
    hex.get(..12).unwrap_or(hex)
}

impl ArtifactDigests {
    /// An empty record. Verifying against it yields [`CacheVerdict::Unrecorded`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether anything was recorded.
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// Recorded artifact names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.artifacts.keys().map(String::as_str)
    }

    /// Look up one recorded digest.
    pub fn get(&self, artifact: &str) -> Option<&str> {
        self.artifacts.get(artifact).map(String::as_str)
    }

    /// Hash `dir/artifact` and record it. A name that is not a single safe path
    /// component is refused, so a record can never point outside its entry.
    /// A missing file is skipped — callers record the artifacts a build
    /// actually produced, and an optional artifact that was not produced must
    /// not become a permanent `Missing` verdict.
    pub fn record(&mut self, dir: &Path, artifact: &str) -> std::io::Result<bool> {
        if !is_safe_artifact_name(artifact) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("unsafe cache artifact name {artifact:?}"),
            ));
        }
        let path = dir.join(artifact);
        if !path.is_file() {
            return Ok(false);
        }
        let digest = sha256_file(&path)?;
        self.artifacts.insert(artifact.to_string(), digest);
        Ok(true)
    }

    /// Record every name in `artifacts` that exists under `dir`, returning how
    /// many were recorded.
    pub fn record_all(&mut self, dir: &Path, artifacts: &[&str]) -> std::io::Result<usize> {
        let mut n = 0;
        for artifact in artifacts {
            if self.record(dir, artifact)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Re-hash every recorded artifact under `dir` and compare.
    ///
    /// Streams each file fresh — deliberately not via the size/mtime digest
    /// sidecar, which by construction cannot observe a change that leaves both
    /// unchanged.
    pub fn verify(&self, dir: &Path) -> CacheVerdict {
        if self.artifacts.is_empty() {
            return CacheVerdict::Unrecorded;
        }
        for (artifact, expected) in &self.artifacts {
            if !is_safe_artifact_name(artifact) {
                return CacheVerdict::Mismatch {
                    artifact: artifact.clone(),
                    expected: expected.clone(),
                    actual: "<unsafe artifact name in record>".to_string(),
                };
            }
            let path = dir.join(artifact);
            if !path.is_file() {
                return CacheVerdict::Missing {
                    artifact: artifact.clone(),
                };
            }
            match sha256_file(&path) {
                Ok(actual) if actual.eq_ignore_ascii_case(expected) => {}
                Ok(actual) => {
                    return CacheVerdict::Mismatch {
                        artifact: artifact.clone(),
                        expected: expected.clone(),
                        actual,
                    };
                }
                Err(e) => {
                    return CacheVerdict::Unreadable {
                        artifact: artifact.clone(),
                        error: e.to_string(),
                    };
                }
            }
        }
        CacheVerdict::Verified
    }
}

/// A single safe path component: non-empty, no separators, no traversal.
fn is_safe_artifact_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, contents: &[u8]) {
        std::fs::write(dir.join(name), contents).unwrap();
    }

    #[test]
    fn empty_record_is_unrecorded_not_verified() {
        // The fail-closed contract: nothing recorded must never read as "fine".
        let dir = tempfile::tempdir().unwrap();
        let digests = ArtifactDigests::new();
        assert_eq!(digests.verify(dir.path()), CacheVerdict::Unrecorded);
        assert!(!digests.verify(dir.path()).is_verified());
        assert!(!digests.verify(dir.path()).should_evict());
    }

    #[test]
    fn recorded_then_unchanged_verifies() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4", b"root filesystem bytes");
        write(dir.path(), "vmlinux", b"kernel bytes");

        let mut digests = ArtifactDigests::new();
        let n = digests
            .record_all(dir.path(), &["rootfs.ext4", "vmlinux"])
            .unwrap();
        assert_eq!(n, 2);
        assert!(digests.verify(dir.path()).is_verified());
    }

    #[test]
    fn absent_optional_artifact_is_not_recorded() {
        // initrd is optional; a build that produced none must not leave a
        // record that permanently fails as Missing.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4", b"root");

        let mut digests = ArtifactDigests::new();
        let n = digests
            .record_all(dir.path(), &["rootfs.ext4", "initrd"])
            .unwrap();
        assert_eq!(n, 1);
        assert_eq!(digests.get("initrd"), None);
        assert!(digests.verify(dir.path()).is_verified());
    }

    #[test]
    fn flipped_byte_is_a_mismatch_and_evicts() {
        // The corruption class. Same length, so a size check would pass.
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4", b"aaaaaaaa");
        let mut digests = ArtifactDigests::new();
        digests.record(dir.path(), "rootfs.ext4").unwrap();

        write(dir.path(), "rootfs.ext4", b"aaaaaaab");
        let verdict = digests.verify(dir.path());
        assert!(matches!(verdict, CacheVerdict::Mismatch { .. }));
        assert!(!verdict.is_verified());
        assert!(verdict.should_evict());
    }

    #[test]
    fn intact_but_wrong_artifact_is_detected() {
        // The identity-discrepancy class: swap two entries' kernels. Both files
        // are complete and readable; each is simply the other build's. A
        // path-trusting cache sees nothing wrong.
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        write(a.path(), "vmlinux", b"kernel from build A");
        write(b.path(), "vmlinux", b"kernel from build B");

        let mut da = ArtifactDigests::new();
        da.record(a.path(), "vmlinux").unwrap();
        let mut db = ArtifactDigests::new();
        db.record(b.path(), "vmlinux").unwrap();

        // Swap the two intact kernels.
        let ka = std::fs::read(a.path().join("vmlinux")).unwrap();
        let kb = std::fs::read(b.path().join("vmlinux")).unwrap();
        std::fs::write(a.path().join("vmlinux"), &kb).unwrap();
        std::fs::write(b.path().join("vmlinux"), &ka).unwrap();

        assert!(a.path().join("vmlinux").is_file(), "still intact");
        assert!(da.verify(a.path()).should_evict());
        assert!(db.verify(b.path()).should_evict());
    }

    #[test]
    fn truncated_artifact_is_a_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4", b"the whole thing");
        let mut digests = ArtifactDigests::new();
        digests.record(dir.path(), "rootfs.ext4").unwrap();

        write(dir.path(), "rootfs.ext4", b"the whole");
        assert!(digests.verify(dir.path()).should_evict());
    }

    #[test]
    fn deleted_artifact_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4", b"root");
        let mut digests = ArtifactDigests::new();
        digests.record(dir.path(), "rootfs.ext4").unwrap();

        std::fs::remove_file(dir.path().join("rootfs.ext4")).unwrap();
        assert_eq!(
            digests.verify(dir.path()),
            CacheVerdict::Missing {
                artifact: "rootfs.ext4".to_string()
            }
        );
        assert!(digests.verify(dir.path()).should_evict());
    }

    #[test]
    fn unsafe_artifact_name_is_refused_on_record() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["../escape", "a/b", "..", "", "nul\0byte"] {
            assert!(
                digests_record(dir.path(), name).is_err(),
                "{name:?} must be refused"
            );
        }
    }

    fn digests_record(dir: &Path, name: &str) -> std::io::Result<bool> {
        ArtifactDigests::new().record(dir, name)
    }

    #[test]
    fn unsafe_artifact_name_in_a_tampered_record_cannot_escape() {
        // A record is on-disk data; a hand-edited one must not turn into a read
        // outside the entry directory.
        let dir = tempfile::tempdir().unwrap();
        let json = r#"{"artifacts":{"../../etc/passwd":"00"}}"#;
        let digests: ArtifactDigests = serde_json::from_str(json).unwrap();
        assert!(matches!(
            digests.verify(dir.path()),
            CacheVerdict::Mismatch { .. }
        ));
    }

    #[test]
    fn record_round_trips_through_json() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "rootfs.ext4", b"root");
        let mut digests = ArtifactDigests::new();
        digests.record(dir.path(), "rootfs.ext4").unwrap();

        let json = serde_json::to_string(&digests).unwrap();
        let back: ArtifactDigests = serde_json::from_str(&json).unwrap();
        assert_eq!(digests, back);
        assert!(back.verify(dir.path()).is_verified());
    }

    #[test]
    fn verify_does_not_consult_the_size_mtime_sidecar() {
        // Bit-rot leaves size and mtime untouched, so a sidecar-backed digest
        // would report the stale value. Prove verification reads the bytes: seed
        // a sidecar that claims the ORIGINAL digest, then change the content and
        // restore size+mtime. If verify consulted the sidecar it would pass.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootfs.ext4");
        std::fs::write(&path, b"original").unwrap();
        let original_meta = std::fs::metadata(&path).unwrap();
        let original_mtime = original_meta.modified().unwrap();

        let mut digests = ArtifactDigests::new();
        digests.record(dir.path(), "rootfs.ext4").unwrap();
        // Populate the sidecar with the pre-rot digest.
        let _ = crate::crypto::image_verify::sha256_file_cached(&path).unwrap();

        // Same length, restored mtime — the sidecar still "matches".
        std::fs::write(&path, b"rottened").unwrap();
        filetime_set(&path, original_mtime);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), original_meta.len());

        assert!(
            digests.verify(dir.path()).should_evict(),
            "verify must re-read the bytes, not trust size+mtime"
        );
    }

    fn filetime_set(path: &Path, mtime: std::time::SystemTime) {
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.set_modified(mtime).unwrap();
        f.sync_all().unwrap();
    }
}
