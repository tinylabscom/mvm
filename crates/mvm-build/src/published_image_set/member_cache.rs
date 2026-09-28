//! Where members acquired from the locked image set are cached, and how an
//! installed one is recognised on a later boot.
//!
//! A member's identity is the signed root it was delivered under, not the
//! version of the CLI that happens to pin that root. The image set is built by
//! a separate repository at whatever workspace version it was cut from, so a
//! member's `VERSION` is routinely not the running CLI's, and a CLI version bump
//! must not invalidate a member that is still the one the lock pins. Whether a
//! host can run a set is answered by the root's declared compatibility, which
//! acquisition checks before any member is requested.
//!
//! So a member is filed under the root's digest: an artifact's ordinary cache
//! layout is placed beneath `<cache_root>/image-set/<root-sha256>/`, and a
//! provenance record beside it names the root, the role, the target and the
//! member's own `VERSION` as read from its digest-verified bytes. A later
//! resolve reads that record and hands its `VERSION` to the artifact's
//! resolver as the version to expect, so every check the resolver makes still
//! runs; only the source of the expected value differs. An entry installed
//! from any other root sits under another directory and is never consulted.

use std::path::{Path, PathBuf};

use mvm_core::image_set::{ImageSetRole, MemberTarget};
use mvm_core::packs::Sha256Hex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Directory, under an artifact's cache root, holding one subdirectory per
/// image-set root members were installed from.
pub const IMAGE_SET_MEMBER_CACHE_DIR: &str = "image-set";

/// Why a cached image-set member cannot be used.
#[derive(Debug, Error)]
pub enum SetMemberCacheError {
    /// Nothing from this root is recorded for the member: it was never
    /// installed, or its install did not complete.
    #[error(
        "no {role}/{target} member of image set {root} is installed under {}",
        set_root.display()
    )]
    NotInstalled {
        root: String,
        role: ImageSetRole,
        target: MemberTarget,
        set_root: PathBuf,
    },
    /// The provenance record exists but does not describe this member of this
    /// root, or cannot be parsed.
    #[error("image-set install record {} is not usable: {reason}", path.display())]
    InvalidRecord { path: PathBuf, reason: String },
    /// A member's `VERSION` cannot name a cache entry.
    #[error("image-set member VERSION {found:?} is not usable: {reason}")]
    InvalidVersion { found: String, reason: &'static str },
    #[error("io error on {}: {reason}", path.display())]
    Io { path: PathBuf, reason: String },
}

/// A member's own `VERSION`, as read from its verified bytes.
///
/// It becomes a directory segment of the cache entry, and the publisher chose
/// it, so it is held to a conservative alphabet rather than trusted as a path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MemberVersion(String);

impl MemberVersion {
    /// Parse a `VERSION` file body. Surrounding whitespace is tolerated, as
    /// every artifact resolver tolerates it; anything else a version string
    /// never needs is refused.
    pub fn parse(raw: &str) -> Result<Self, SetMemberCacheError> {
        let trimmed = raw.trim();
        let refuse = |reason| SetMemberCacheError::InvalidVersion {
            found: trimmed.to_string(),
            reason,
        };
        if trimmed.is_empty() {
            return Err(refuse("VERSION is empty"));
        }
        if trimmed == "." || trimmed == ".." {
            return Err(refuse("VERSION names a directory"));
        }
        if !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
        {
            return Err(refuse(
                "VERSION may only contain ASCII letters, digits, '.', '-', '+' and '_'",
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    /// Read and parse the `VERSION` file at `path`.
    pub fn read(path: &Path) -> Result<Self, SetMemberCacheError> {
        let raw = std::fs::read_to_string(path).map_err(|e| SetMemberCacheError::Io {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })?;
        Self::parse(&raw)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for MemberVersion {
    type Error = SetMemberCacheError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<MemberVersion> for String {
    fn from(value: MemberVersion) -> Self {
        value.0
    }
}

/// What was installed, and from which root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberProvenance {
    root_sha256: Sha256Hex,
    role: ImageSetRole,
    target: MemberTarget,
    version: MemberVersion,
}

/// The cache of members installed from one signed root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetMemberCache {
    root: Sha256Hex,
}

impl SetMemberCache {
    /// Members of the root this build's lock pins. A pure read of the
    /// compiled-in lock: answering whether a member is cached never needs the
    /// network.
    pub fn locked() -> Self {
        Self::for_root(
            mvm_core::image_set::image_train_lock()
                .image_set
                .manifest_sha256
                .clone(),
        )
    }

    /// Members of the root whose manifest hashes to `root`.
    pub fn for_root(root: Sha256Hex) -> Self {
        Self { root }
    }

    /// Digest of the signed root these members were delivered under.
    pub fn root(&self) -> &Sha256Hex {
        &self.root
    }

    /// The cache root an artifact's ordinary layout is placed under for this
    /// set: `<cache_root>/image-set/<root-sha256>`.
    pub fn cache_root(&self, cache_root: &Path) -> PathBuf {
        cache_root
            .join(IMAGE_SET_MEMBER_CACHE_DIR)
            .join(self.root.as_str())
    }

    fn record_path(&self, cache_root: &Path, role: ImageSetRole, target: MemberTarget) -> PathBuf {
        self.cache_root(cache_root)
            .join(format!("{role}-{target}.json"))
    }

    /// Record that `version` of the `role` member for `target` is installed
    /// under [`Self::cache_root`]. Written after the artifact itself, so an
    /// install interrupted in between reads as not installed and is acquired
    /// again rather than trusted.
    pub fn record(
        &self,
        cache_root: &Path,
        role: ImageSetRole,
        target: MemberTarget,
        version: &MemberVersion,
    ) -> Result<(), SetMemberCacheError> {
        let path = self.record_path(cache_root, role, target);
        let record = MemberProvenance {
            root_sha256: self.root.clone(),
            role,
            target,
            version: version.clone(),
        };
        let body = serde_json::to_string_pretty(&record).map_err(|e| SetMemberCacheError::Io {
            path: path.clone(),
            reason: e.to_string(),
        })?;
        mvm_core::util::atomic_io::atomic_write_str(&path, &body).map_err(|e| {
            SetMemberCacheError::Io {
                path: path.clone(),
                reason: format!("{e:#}"),
            }
        })
    }

    /// The `VERSION` of the `role` member for `target` installed from this
    /// root, which is what that entry's resolver must expect.
    pub fn installed_version(
        &self,
        cache_root: &Path,
        role: ImageSetRole,
        target: MemberTarget,
    ) -> Result<MemberVersion, SetMemberCacheError> {
        let path = self.record_path(cache_root, role, target);
        let body = match std::fs::read_to_string(&path) {
            Ok(body) => body,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SetMemberCacheError::NotInstalled {
                    root: self.root.as_str().to_string(),
                    role,
                    target,
                    set_root: self.cache_root(cache_root),
                });
            }
            Err(e) => {
                return Err(SetMemberCacheError::Io {
                    path,
                    reason: e.to_string(),
                });
            }
        };
        let record: MemberProvenance =
            serde_json::from_str(&body).map_err(|e| SetMemberCacheError::InvalidRecord {
                path: path.clone(),
                reason: e.to_string(),
            })?;
        let invalid = |reason: String| SetMemberCacheError::InvalidRecord {
            path: path.clone(),
            reason,
        };
        if record.root_sha256 != self.root {
            return Err(invalid(format!(
                "it names image set {}, not {}",
                record.root_sha256.as_str(),
                self.root.as_str()
            )));
        }
        if record.role != role || record.target != target {
            return Err(invalid(format!(
                "it describes {}/{}, not {role}/{target}",
                record.role, record.target
            )));
        }
        Ok(record.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::arch::GuestArch;

    const OVERLAY: ImageSetRole = ImageSetRole::RuntimeOverlay;
    const AARCH64: MemberTarget = MemberTarget::Arch(GuestArch::Aarch64);

    fn root(fill: &[u8]) -> SetMemberCache {
        SetMemberCache::for_root(Sha256Hex::from_bytes(fill))
    }

    #[test]
    fn a_member_version_is_trimmed_and_kept_verbatim() {
        let version = MemberVersion::parse("0.18.0-rc.2+build_7\n").unwrap();
        assert_eq!(version.as_str(), "0.18.0-rc.2+build_7");
    }

    #[test]
    fn a_member_version_that_cannot_name_a_directory_is_refused() {
        for raw in ["", "  \n", ".", "..", "../x", "a/b", "0.18 rc", "0.18\\x"] {
            assert!(
                matches!(
                    MemberVersion::parse(raw),
                    Err(SetMemberCacheError::InvalidVersion { .. })
                ),
                "{raw:?} must be refused"
            );
        }
    }

    #[test]
    fn members_of_a_root_live_under_that_roots_digest() {
        let set = root(b"root");
        let dir = set.cache_root(Path::new("/cache"));
        assert_eq!(
            dir,
            Path::new("/cache/image-set").join(set.root().as_str()),
            "the directory key is the root, so another root is another directory"
        );
    }

    #[test]
    fn the_locked_set_is_the_root_the_lock_pins() {
        assert_eq!(
            SetMemberCache::locked().root(),
            &mvm_core::image_set::image_train_lock()
                .image_set
                .manifest_sha256
        );
    }

    #[test]
    fn a_recorded_install_reads_back_its_member_version() {
        let cache = tempfile::tempdir().unwrap();
        let set = root(b"root");
        let version = MemberVersion::parse("0.17.4").unwrap();
        set.record(cache.path(), OVERLAY, AARCH64, &version)
            .unwrap();

        assert_eq!(
            set.installed_version(cache.path(), OVERLAY, AARCH64)
                .unwrap(),
            version
        );
    }

    #[test]
    fn an_unrecorded_member_is_not_installed() {
        let cache = tempfile::tempdir().unwrap();
        let err = root(b"root")
            .installed_version(cache.path(), OVERLAY, AARCH64)
            .unwrap_err();
        assert!(
            matches!(err, SetMemberCacheError::NotInstalled { .. }),
            "{err}"
        );
    }

    #[test]
    fn another_roots_install_is_not_this_roots() {
        let cache = tempfile::tempdir().unwrap();
        let version = MemberVersion::parse("0.17.4").unwrap();
        root(b"old")
            .record(cache.path(), OVERLAY, AARCH64, &version)
            .unwrap();

        let err = root(b"new")
            .installed_version(cache.path(), OVERLAY, AARCH64)
            .unwrap_err();
        assert!(
            matches!(err, SetMemberCacheError::NotInstalled { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_record_that_names_another_root_is_refused() {
        let cache = tempfile::tempdir().unwrap();
        let version = MemberVersion::parse("0.17.4").unwrap();
        let old = root(b"old");
        let new = root(b"new");
        old.record(cache.path(), OVERLAY, AARCH64, &version)
            .unwrap();
        // A record copied into another root's directory still names its own.
        std::fs::create_dir_all(new.cache_root(cache.path())).unwrap();
        std::fs::copy(
            old.record_path(cache.path(), OVERLAY, AARCH64),
            new.record_path(cache.path(), OVERLAY, AARCH64),
        )
        .unwrap();

        let err = new
            .installed_version(cache.path(), OVERLAY, AARCH64)
            .unwrap_err();
        assert!(
            matches!(err, SetMemberCacheError::InvalidRecord { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_record_for_another_member_is_refused() {
        let cache = tempfile::tempdir().unwrap();
        let set = root(b"root");
        let version = MemberVersion::parse("0.17.4").unwrap();
        set.record(cache.path(), OVERLAY, AARCH64, &version)
            .unwrap();
        std::fs::copy(
            set.record_path(cache.path(), OVERLAY, AARCH64),
            set.record_path(cache.path(), ImageSetRole::Initramfs, AARCH64),
        )
        .unwrap();

        let err = set
            .installed_version(cache.path(), ImageSetRole::Initramfs, AARCH64)
            .unwrap_err();
        assert!(
            matches!(err, SetMemberCacheError::InvalidRecord { .. }),
            "{err}"
        );
    }

    #[test]
    fn a_record_carrying_an_unusable_version_is_refused() {
        let cache = tempfile::tempdir().unwrap();
        let set = root(b"root");
        let path = set.record_path(cache.path(), OVERLAY, AARCH64);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::json!({
                "root_sha256": set.root().as_str(),
                "role": "runtime_overlay",
                "target": {"arch": "aarch64"},
                "version": "../escape",
            })
            .to_string(),
        )
        .unwrap();

        let err = set
            .installed_version(cache.path(), OVERLAY, AARCH64)
            .unwrap_err();
        assert!(
            matches!(err, SetMemberCacheError::InvalidRecord { .. }),
            "{err}"
        );
    }
}
