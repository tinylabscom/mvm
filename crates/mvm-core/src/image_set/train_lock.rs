//! The checked-in lock over the published image set and compatibility window.
//!
//! [`ImageLock`](super::ImageLock) pins the signed root manifest. The small
//! train-shaped fields remain because Stage 0 needs a compile-time seed digest
//! before it can build anything, while the legacy entry deliberately preserves
//! the previous producer through the compatibility window. New consumers use
//! `image_set`; the legacy entry is evidence of accepted historical trust, not
//! a fallback that may be selected implicitly.
//!
//! The pins are read from `mvm-core`'s own `images.lock`, parsed once, and
//! shared. `include_str!` rather than a build script: the file is checked in, a
//! build script would be a second thing to keep working, and a parse failure
//! here is a bug in the tree rather than a condition a caller can handle.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::identity::{ArtifactName, ReleaseTag, RepositorySlug};
use super::{ImageLock, ImageSetCompatibility, SigningIdentity};
use crate::arch::GuestArch;
use crate::packs::Sha256Hex;

/// The schema this build understands. Bumped when the file's shape changes in
/// a way an older reader would misread rather than refuse.
pub const IMAGE_TRAIN_LOCK_SCHEMA_VERSION: u32 = 2;

/// `mvm-core`'s `images.lock`, compiled in so a binary carries its pins
/// wherever it runs.
const IMAGE_TRAIN_LOCK_TOML: &str = include_str!("../../images.lock");

/// Why the checked-in lock was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ImageTrainLockError {
    #[error("the image lock is not valid TOML: {0}")]
    Malformed(String),
    #[error("image lock schema version {found} is not supported (expected {supported})")]
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    #[error("the image lock pins no Stage 0 bootstrap kernel for {arch}")]
    NoStage0Kernel { arch: GuestArch },
    #[error("the image lock is internally inconsistent: {detail}")]
    Inconsistent { detail: String },
}

/// Every published pin mvm fetches, keyed by what it is rather than by who
/// consumes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageTrainLock {
    pub schema_version: u32,
    /// Where the current signed image-set artifacts are published.
    pub repository: RepositorySlug,
    /// The signed root manifest all current consumers are bound to.
    pub image_set: ImageLock,
    /// Compatibility copied from the verified root so every path can refuse
    /// before it starts an artifact download.
    pub compatibility: ImageSetCompatibility,
    pub boot_image: BootImagePin,
    pub stage0_kernel: Stage0KernelPin,
    /// The previous producer retained only for the declared support window.
    pub legacy: LegacyImageTrain,
}

/// Previous image producer accepted during the old-plus-new trust window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyImageTrain {
    pub repository: RepositorySlug,
    pub release_tag: ReleaseTag,
    pub signing_identity: SigningIdentity,
}

/// The boot image release the CLI expects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootImagePin {
    pub release_tag: ReleaseTag,
}

/// The Stage 0 bootstrap kernel's release, and the per-arch artifact it is
/// taken from. The digests are here because nothing derives them: they are
/// copied out of a signature-verified checksum manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stage0KernelPin {
    pub release_tag: ReleaseTag,
    pub artifact: BTreeMap<GuestArch, PinnedArtifact>,
}

impl Stage0KernelPin {
    /// The artifact pinned for `arch`, or a refusal naming the architecture.
    pub fn for_arch(&self, arch: GuestArch) -> Result<&PinnedArtifact, ImageTrainLockError> {
        self.artifact
            .get(&arch)
            .ok_or(ImageTrainLockError::NoStage0Kernel { arch })
    }
}

/// One release asset and the bytes it must hash to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedArtifact {
    pub name: ArtifactName,
    pub sha256: Sha256Hex,
}

impl ImageTrainLock {
    /// Parse and validate a lock file's text.
    pub fn parse(toml_text: &str) -> Result<Self, ImageTrainLockError> {
        let lock: Self =
            toml::from_str(toml_text).map_err(|e| ImageTrainLockError::Malformed(e.to_string()))?;
        if lock.schema_version != IMAGE_TRAIN_LOCK_SCHEMA_VERSION {
            return Err(ImageTrainLockError::UnsupportedSchemaVersion {
                found: lock.schema_version,
                supported: IMAGE_TRAIN_LOCK_SCHEMA_VERSION,
            });
        }
        if lock.repository != lock.image_set.repository {
            return Err(ImageTrainLockError::Inconsistent {
                detail: "the train repository and image_set repository differ".to_string(),
            });
        }
        for (consumer, tag) in [
            ("boot_image", &lock.boot_image.release_tag),
            ("stage0_kernel", &lock.stage0_kernel.release_tag),
        ] {
            if tag != &lock.image_set.release_tag {
                return Err(ImageTrainLockError::Inconsistent {
                    detail: format!(
                        "{consumer} pins {tag}, not the root {}",
                        lock.image_set.release_tag
                    ),
                });
            }
        }
        let expected_ref = format!("refs/tags/{}", lock.image_set.release_tag);
        if lock.image_set.signing_identity.tag_ref.as_str() != expected_ref {
            return Err(ImageTrainLockError::Inconsistent {
                detail: format!(
                    "the signing tag ref {} does not bind {}",
                    lock.image_set.signing_identity.tag_ref, lock.image_set.release_tag
                ),
            });
        }
        Ok(lock)
    }

    /// The download URL for `asset` published under `release_tag`.
    ///
    /// Composed here rather than pinned per artifact, so the repository appears
    /// once and a URL cannot name a different host from the one the pin trusts.
    pub fn asset_url(&self, release_tag: &ReleaseTag, asset: &ArtifactName) -> String {
        format!(
            "https://github.com/{}/releases/download/{release_tag}/{asset}",
            self.repository
        )
    }

    /// URL of the locked root manifest.
    pub fn manifest_url(&self) -> String {
        self.asset_url(&self.image_set.release_tag, &self.image_set.manifest_asset)
    }

    /// URL of the detached Sigstore bundle over the locked root manifest.
    pub fn manifest_bundle_url(&self) -> String {
        format!("{}.bundle", self.manifest_url())
    }

    /// The URL of the Stage 0 bootstrap kernel for `arch`.
    pub fn stage0_kernel_url(&self, arch: GuestArch) -> Result<String, ImageTrainLockError> {
        let artifact = self.stage0_kernel.for_arch(arch)?;
        Ok(self.asset_url(&self.stage0_kernel.release_tag, &artifact.name))
    }
}

/// The compiled-in lock, parsed once.
///
/// Panics on a malformed file, which is the honest outcome: the file is checked
/// in beside the code that reads it, every caller wants a pin rather than an
/// error path, and `the_shipped_lock_parses` fails the build before anyone
/// reaches this.
pub fn image_train_lock() -> &'static ImageTrainLock {
    static LOCK: LazyLock<ImageTrainLock> = LazyLock::new(|| {
        ImageTrainLock::parse(IMAGE_TRAIN_LOCK_TOML)
            .expect("the checked-in images.lock must parse; xtask check-image-lock gates it")
    });
    &LOCK
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version = 2
repository = "tinylabscom/mvm-images"

[image_set]
schema_version = 1
repository = "tinylabscom/mvm-images"
release_tag = "image-set/v1.2.3"
manifest_asset = "image-set.json"
manifest_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

[image_set.signing_identity]
workflow = ".github/workflows/release.yml"
tag_ref = "refs/tags/image-set/v1.2.3"

[compatibility]
guest_agent_protocol = { min = 2, max = 2 }
builder_cache_contract = 4

[boot_image]
release_tag = "image-set/v1.2.3"

[stage0_kernel]
release_tag = "image-set/v1.2.3"

[stage0_kernel.artifact.aarch64]
name = "stage0-vmlinux-aarch64"
sha256 = "b53be06555a144433369708a57e9e1d278dbad7d26cb31a5fe9167eb7a90f6c1"

[legacy]
repository = "tinylabscom/mvm"
release_tag = "boot-image/v1.2.0"

[legacy.signing_identity]
workflow = ".github/workflows/release-boot-image.yml"
tag_ref = "refs/tags/boot-image/v1.2.0"
"#;

    #[test]
    fn the_shipped_lock_parses() {
        let lock = image_train_lock();
        assert_eq!(lock.schema_version, IMAGE_TRAIN_LOCK_SCHEMA_VERSION);
        assert_eq!(lock.repository.as_str(), "tinylabscom/mvm-images");
        assert_eq!(lock.image_set.repository, lock.repository);
        assert!(
            lock.boot_image
                .release_tag
                .as_str()
                .starts_with("image-set/v")
        );
    }

    /// Stage 0 runs on both architectures mvm supports, and a missing pin is a
    /// backend that cannot bootstrap at all.
    #[test]
    fn the_shipped_lock_pins_a_stage0_kernel_for_both_architectures() {
        let lock = image_train_lock();
        for arch in [GuestArch::Aarch64, GuestArch::X86_64] {
            let artifact = lock.stage0_kernel.for_arch(arch).expect("a pin per arch");
            assert!(
                artifact.name.as_str().ends_with(&arch.to_string()),
                "{arch}: the pinned asset names another architecture: {}",
                artifact.name
            );
            assert_eq!(artifact.sha256.as_str().len(), 64);
        }
    }

    #[test]
    fn the_shipped_lock_composes_the_stage0_download_url() {
        let lock = image_train_lock();
        assert_eq!(
            lock.stage0_kernel_url(GuestArch::X86_64).unwrap(),
            format!(
                "https://github.com/tinylabscom/mvm-images/releases/download/{}/stage0-vmlinux-x86_64",
                lock.stage0_kernel.release_tag
            )
        );
    }

    #[test]
    fn the_current_and_legacy_trains_are_pinned_separately() {
        let lock = ImageTrainLock::parse(MINIMAL).expect("the fixture parses");
        assert_eq!(lock.boot_image.release_tag.as_str(), "image-set/v1.2.3");
        assert_eq!(lock.stage0_kernel.release_tag.as_str(), "image-set/v1.2.3");
        assert_eq!(lock.legacy.repository.as_str(), "tinylabscom/mvm");
        assert_eq!(lock.legacy.release_tag.as_str(), "boot-image/v1.2.0");
    }

    #[test]
    fn every_current_consumer_must_route_to_the_same_release() {
        for text in [
            MINIMAL.replacen(
                "repository = \"tinylabscom/mvm-images\"",
                "repository = \"tinylabscom/not-images\"",
                1,
            ),
            MINIMAL.replace(
                "[boot_image]\nrelease_tag = \"image-set/v1.2.3\"",
                "[boot_image]\nrelease_tag = \"image-set/v1.2.4\"",
            ),
            MINIMAL.replace(
                "[stage0_kernel]\nrelease_tag = \"image-set/v1.2.3\"",
                "[stage0_kernel]\nrelease_tag = \"image-set/v1.2.4\"",
            ),
        ] {
            assert!(matches!(
                ImageTrainLock::parse(&text),
                Err(ImageTrainLockError::Inconsistent { .. })
            ));
        }
    }

    #[test]
    fn a_future_schema_version_is_refused_by_number() {
        let text = MINIMAL.replacen("schema_version = 2", "schema_version = 3", 1);
        assert_eq!(
            ImageTrainLock::parse(&text),
            Err(ImageTrainLockError::UnsupportedSchemaVersion {
                found: 3,
                supported: 2,
            })
        );
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let text = format!("{MINIMAL}\n[unexpected]\nkey = 1\n");
        assert!(matches!(
            ImageTrainLock::parse(&text),
            Err(ImageTrainLockError::Malformed(_))
        ));
    }

    #[test]
    fn a_mutable_reference_is_not_a_release_tag() {
        let text = MINIMAL.replace("\"image-set/v1.2.3\"", "\"image-set/latest\"");
        assert!(matches!(
            ImageTrainLock::parse(&text),
            Err(ImageTrainLockError::Malformed(_))
        ));
    }

    #[test]
    fn a_digest_that_is_not_sha256_hex_is_refused() {
        let text = MINIMAL.replace(
            "b53be06555a144433369708a57e9e1d278dbad7d26cb31a5fe9167eb7a90f6c1",
            "not-a-digest",
        );
        assert!(matches!(
            ImageTrainLock::parse(&text),
            Err(ImageTrainLockError::Malformed(_))
        ));
    }

    /// A path separator in an asset name would address something outside the
    /// release it is downloaded into.
    #[test]
    fn an_artifact_name_with_a_path_separator_is_refused() {
        let text = MINIMAL.replace("stage0-vmlinux-aarch64", "../stage0-vmlinux-aarch64");
        assert!(matches!(
            ImageTrainLock::parse(&text),
            Err(ImageTrainLockError::Malformed(_))
        ));
    }

    #[test]
    fn an_unpinned_architecture_is_refused_by_name() {
        let lock = ImageTrainLock::parse(MINIMAL).expect("the fixture parses");
        assert_eq!(
            lock.stage0_kernel.for_arch(GuestArch::X86_64),
            Err(ImageTrainLockError::NoStage0Kernel {
                arch: GuestArch::X86_64
            })
        );
    }

    #[test]
    fn the_lock_round_trips_through_toml() {
        let lock = ImageTrainLock::parse(MINIMAL).expect("the fixture parses");
        let rendered = toml::to_string(&lock).expect("serialize");
        assert_eq!(ImageTrainLock::parse(&rendered), Ok(lock));
    }
}
