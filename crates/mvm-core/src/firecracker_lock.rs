//! The checked-in lock over the Firecracker VMM mvm ships and boots.
//!
//! Firecracker runs every Linux guest, so its bytes are named by this tree and
//! not by whatever a download served last. Each architecture pins the digest of
//! the upstream release tarball (what a fetch is checked against) and of the
//! `firecracker` binary inside it (what a launch is checked against).
//!
//! The pins are read from `mvm-core`'s own `firecracker.lock`, parsed once, and
//! shared. `include_str!` rather than a build script, for the reason the image
//! lock gives: the file is checked in, a build script would be a second thing to
//! keep working, and a parse failure here is a bug in the tree rather than a
//! condition a caller can handle.
//!
//! Host-only: guest binaries never carry `toml`, and only the host downloads or
//! runs a Firecracker binary.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::arch::GuestArch;
use crate::packs::Sha256Hex;

/// The schema this build understands. Bumped when the file's shape changes in a
/// way an older reader would misread rather than refuse.
pub const FIRECRACKER_LOCK_SCHEMA_VERSION: u32 = 1;

/// The only place the lock may name as the source of a Firecracker release.
pub const FIRECRACKER_UPSTREAM_REPOSITORY: &str = "firecracker-microvm/firecracker";

/// `mvm-core`'s `firecracker.lock`, compiled in so a binary carries its pin
/// wherever it runs.
const FIRECRACKER_LOCK_TOML: &str = include_str!("../firecracker.lock");

/// Why the checked-in lock was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FirecrackerLockError {
    #[error("the Firecracker lock is not valid TOML: {0}")]
    Malformed(String),
    #[error("Firecracker lock schema version {found} is not supported (expected {supported})")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("the Firecracker lock is internally inconsistent: {detail}")]
    Inconsistent { detail: String },
}

/// One architecture's pinned artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerArchPin {
    /// The upstream release tarball's file name.
    pub tarball: String,
    /// Digest of the tarball, copied from the checksum the release publishes.
    pub tarball_sha256: Sha256Hex,
    /// The `firecracker` binary's path inside the tarball.
    pub binary: String,
    /// Digest of that binary once extracted.
    pub binary_sha256: Sha256Hex,
    /// Size of that binary in bytes.
    pub binary_size: u64,
}

/// The pinned Firecracker release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerLock {
    pub schema_version: u32,
    /// Where the release is published.
    pub repository: String,
    /// The release tag, `vMAJOR.MINOR.PATCH`.
    pub version: String,
    pub x86_64: FirecrackerArchPin,
    pub aarch64: FirecrackerArchPin,
}

impl FirecrackerLock {
    /// Parse and validate a lock file's text.
    pub fn parse(toml_text: &str) -> Result<Self, FirecrackerLockError> {
        let lock: Self = toml::from_str(toml_text)
            .map_err(|error| FirecrackerLockError::Malformed(error.to_string()))?;
        if lock.schema_version != FIRECRACKER_LOCK_SCHEMA_VERSION {
            return Err(FirecrackerLockError::UnsupportedSchemaVersion {
                found: lock.schema_version,
                supported: FIRECRACKER_LOCK_SCHEMA_VERSION,
            });
        }
        if lock.repository != FIRECRACKER_UPSTREAM_REPOSITORY {
            return Err(inconsistent(format!(
                "the repository is {}, not {FIRECRACKER_UPSTREAM_REPOSITORY}",
                lock.repository
            )));
        }
        if !is_release_tag(&lock.version) {
            return Err(inconsistent(format!(
                "{} is not a vMAJOR.MINOR.PATCH release tag",
                lock.version
            )));
        }
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            lock.check_arch(arch)?;
        }
        Ok(lock)
    }

    fn check_arch(&self, arch: GuestArch) -> Result<(), FirecrackerLockError> {
        let pin = self.pin(arch);
        let expected_tarball = format!("firecracker-{}-{arch}.tgz", self.version);
        if pin.tarball != expected_tarball {
            return Err(inconsistent(format!(
                "the {arch} tarball is {}, not {expected_tarball}",
                pin.tarball
            )));
        }
        let expected_binary = format!(
            "release-{version}-{arch}/firecracker-{version}-{arch}",
            version = self.version
        );
        if pin.binary != expected_binary {
            return Err(inconsistent(format!(
                "the {arch} binary is {}, not {expected_binary}",
                pin.binary
            )));
        }
        if pin.binary_size == 0 {
            return Err(inconsistent(format!("the {arch} binary has no size")));
        }
        Ok(())
    }

    /// The pinned artifacts for `arch`.
    pub fn pin(&self, arch: GuestArch) -> &FirecrackerArchPin {
        match arch {
            GuestArch::X86_64 => &self.x86_64,
            GuestArch::Aarch64 => &self.aarch64,
        }
    }

    /// The download URL of `arch`'s release tarball.
    ///
    /// Composed here rather than pinned per artifact, so the repository appears
    /// once and a URL cannot name a different host from the one the pin trusts.
    pub fn tarball_url(&self, arch: GuestArch) -> String {
        format!(
            "https://github.com/{}/releases/download/{}/{}",
            self.repository,
            self.version,
            self.pin(arch).tarball
        )
    }
}

fn inconsistent(detail: String) -> FirecrackerLockError {
    FirecrackerLockError::Inconsistent { detail }
}

/// `vMAJOR.MINOR.PATCH`, all three numeric.
fn is_release_tag(tag: &str) -> bool {
    let Some(numbers) = tag.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = numbers.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The compiled-in lock, parsed once.
///
/// Panics on a malformed file, which is the honest outcome: the file is checked
/// in beside the code that reads it, every caller wants a pin rather than an
/// error path, and `the_shipped_lock_parses` fails the build before anyone
/// reaches this.
pub fn firecracker_lock() -> &'static FirecrackerLock {
    static LOCK: LazyLock<FirecrackerLock> = LazyLock::new(|| {
        FirecrackerLock::parse(FIRECRACKER_LOCK_TOML).expect(
            "the checked-in firecracker.lock must parse; xtask check-firecracker-pin gates it",
        )
    });
    &LOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped() -> FirecrackerLock {
        FirecrackerLock::parse(FIRECRACKER_LOCK_TOML).expect("the shipped lock parses")
    }

    fn with(replace: &str, with: &str) -> String {
        assert!(
            FIRECRACKER_LOCK_TOML.contains(replace),
            "the shipped lock no longer contains {replace:?}"
        );
        FIRECRACKER_LOCK_TOML.replacen(replace, with, 1)
    }

    #[test]
    fn the_shipped_lock_parses() {
        let lock = shipped();
        assert_eq!(lock.schema_version, FIRECRACKER_LOCK_SCHEMA_VERSION);
        assert_eq!(lock.repository, FIRECRACKER_UPSTREAM_REPOSITORY);
        assert!(is_release_tag(&lock.version));
        assert_eq!(firecracker_lock(), &lock);
    }

    #[test]
    fn both_architectures_name_their_artifacts_from_the_version() {
        let lock = shipped();
        for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
            let pin = lock.pin(arch);
            assert_eq!(
                pin.tarball,
                format!("firecracker-{}-{arch}.tgz", lock.version)
            );
            assert!(
                pin.binary
                    .ends_with(&format!("firecracker-{}-{arch}", lock.version))
            );
            assert!(pin.binary_size > 0);
        }
    }

    #[test]
    fn the_two_architectures_pin_different_bytes() {
        let lock = shipped();
        assert_ne!(lock.x86_64.tarball_sha256, lock.aarch64.tarball_sha256);
        assert_ne!(lock.x86_64.binary_sha256, lock.aarch64.binary_sha256);
    }

    #[test]
    fn a_tarball_url_is_composed_from_the_one_repository() {
        let lock = shipped();
        assert_eq!(
            lock.tarball_url(GuestArch::Aarch64),
            format!(
                "https://github.com/{FIRECRACKER_UPSTREAM_REPOSITORY}/releases/download/{0}/firecracker-{0}-aarch64.tgz",
                lock.version
            )
        );
    }

    #[test]
    fn the_default_firecracker_version_is_the_locked_one() {
        // A build can override the default to try an unpublished release; the
        // lock is what every build without that override gets.
        if option_env!("MVM_FC_VERSION").is_none() {
            assert_eq!(crate::config::FC_VERSION_DEFAULT, shipped().version);
        }
    }

    #[test]
    fn a_schema_it_does_not_know_is_refused() {
        let text = with("schema_version = 1", "schema_version = 2");
        assert_eq!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::UnsupportedSchemaVersion {
                found: 2,
                supported: FIRECRACKER_LOCK_SCHEMA_VERSION
            })
        );
    }

    #[test]
    fn a_repository_other_than_upstream_is_refused() {
        let text = with(FIRECRACKER_UPSTREAM_REPOSITORY, "someone/else");
        assert!(matches!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::Inconsistent { .. })
        ));
    }

    #[test]
    fn a_version_that_is_not_a_release_tag_is_refused() {
        for bad in ["1.17.0", "v1.17", "v1.17.x", "v1.17.0-rc1", "main"] {
            let text = FIRECRACKER_LOCK_TOML.replacen("v1.17.0", bad, usize::MAX);
            assert!(
                FirecrackerLock::parse(&text).is_err(),
                "{bad} must not be accepted as the pinned version"
            );
        }
    }

    #[test]
    fn a_tarball_that_does_not_belong_to_the_version_is_refused() {
        let text = with(
            "firecracker-v1.17.0-x86_64.tgz",
            "firecracker-v1.16.0-x86_64.tgz",
        );
        assert!(matches!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::Inconsistent { .. })
        ));
    }

    #[test]
    fn a_binary_path_that_does_not_belong_to_the_version_is_refused() {
        let text = with(
            "release-v1.17.0-aarch64/firecracker-v1.17.0-aarch64",
            "release-v1.17.0-aarch64/firecracker-v1.17.0-x86_64",
        );
        assert!(matches!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::Inconsistent { .. })
        ));
    }

    #[test]
    fn a_malformed_digest_is_refused() {
        let text = with(
            "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
            "06094a11",
        );
        assert!(matches!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::Malformed(_))
        ));
    }

    #[test]
    fn a_zero_size_binary_is_refused() {
        let text = with("binary_size = 3676680", "binary_size = 0");
        assert!(matches!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::Inconsistent { .. })
        ));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let text = format!("{FIRECRACKER_LOCK_TOML}\nextra = \"x\"\n");
        assert!(matches!(
            FirecrackerLock::parse(&text),
            Err(FirecrackerLockError::Malformed(_))
        ));
    }

    #[test]
    fn an_architecture_with_no_pin_is_refused() {
        let cut = FIRECRACKER_LOCK_TOML
            .find("[aarch64]")
            .expect("aarch64 table");
        assert!(matches!(
            FirecrackerLock::parse(&FIRECRACKER_LOCK_TOML[..cut]),
            Err(FirecrackerLockError::Malformed(_))
        ));
    }
}
