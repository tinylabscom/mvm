//! Which builder images this payload can boot.
//!
//! The image says what it is in [`IMAGE_ABI_MARKER`]; the payload's stage 1
//! reads it off the mounted root and refuses outside [`payload_supported_abis`]
//! rather than guess. A missing marker is ABI 0, the legacy image that bakes
//! its own copies of the builder binaries.

use mvm_core::image_set::{BuilderBootAbi, BuilderBootAbiRange};
use thiserror::Error;

/// Where a builder image declares its boot ABI, as an absolute guest path.
pub const IMAGE_ABI_MARKER: &str = "/etc/mvm/builder-boot-abi";

/// Every builder boot ABI this build of the payload can boot.
pub fn payload_supported_abis() -> BuilderBootAbiRange {
    BuilderBootAbiRange::new(BuilderBootAbi::LEGACY, BuilderBootAbi::PAYLOAD)
        .expect("the legacy ABI precedes the payload ABI")
}

/// The ABIs a host can boot without a payload: only images that carry their
/// own builder binaries.
pub fn baked_only_abis() -> BuilderBootAbiRange {
    BuilderBootAbiRange::new(BuilderBootAbi::LEGACY, BuilderBootAbi::LEGACY)
        .expect("a single ABI is a range")
}

/// Why a builder image's boot ABI was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BootAbiError {
    #[error(
        "builder image declares boot ABI {contents:?} in {IMAGE_ABI_MARKER}, which is not a number"
    )]
    Malformed { contents: String },
    #[error(
        "builder image declares boot ABI {image}, but this mvmctl boots {supported}; \
         rebuild or refetch the builder image, or use an mvmctl that supports ABI {image}"
    )]
    Unsupported {
        image: BuilderBootAbi,
        supported: BuilderBootAbiRange,
    },
}

/// The ABI an image declares, given the contents of its marker file.
/// `None` — no marker — is the legacy image.
pub fn parse_image_abi_marker(contents: Option<&str>) -> Result<BuilderBootAbi, BootAbiError> {
    let Some(contents) = contents else {
        return Ok(BuilderBootAbi::LEGACY);
    };
    contents
        .trim()
        .parse::<u32>()
        .map(BuilderBootAbi::new)
        .map_err(|_| BootAbiError::Malformed {
            contents: contents.to_string(),
        })
}

/// Refuse an image whose ABI falls outside `supported`, naming both.
pub fn check_image_abi(
    image: BuilderBootAbi,
    supported: BuilderBootAbiRange,
) -> Result<(), BootAbiError> {
    if supported.contains(image) {
        Ok(())
    } else {
        Err(BootAbiError::Unsupported { image, supported })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide(marker: Option<&str>) -> Result<BuilderBootAbi, BootAbiError> {
        let abi = parse_image_abi_marker(marker)?;
        check_image_abi(abi, payload_supported_abis()).map(|()| abi)
    }

    #[test]
    fn a_missing_marker_is_the_legacy_image() {
        assert_eq!(decide(None).unwrap(), BuilderBootAbi::LEGACY);
    }

    #[test]
    fn a_marker_inside_the_range_is_accepted() {
        assert_eq!(decide(Some("0\n")).unwrap(), BuilderBootAbi::LEGACY);
        assert_eq!(decide(Some("1\n")).unwrap(), BuilderBootAbi::PAYLOAD);
    }

    #[test]
    fn a_marker_above_the_range_is_refused_naming_both_numbers() {
        let err = decide(Some("2")).unwrap_err();
        assert_eq!(
            err,
            BootAbiError::Unsupported {
                image: BuilderBootAbi::new(2),
                supported: payload_supported_abis(),
            }
        );
        let message = err.to_string();
        assert!(
            message.contains("ABI 2") && message.contains("0..=1"),
            "{message}"
        );
    }

    #[test]
    fn a_payload_image_is_refused_below_its_range() {
        let err = check_image_abi(BuilderBootAbi::PAYLOAD, baked_only_abis()).unwrap_err();
        assert!(err.to_string().contains("boots 0..=0"), "{err}");
    }

    #[test]
    fn a_marker_that_is_not_a_number_is_refused() {
        for bad in ["", "one", "-1", "1.0"] {
            assert!(
                matches!(decide(Some(bad)), Err(BootAbiError::Malformed { .. })),
                "{bad:?}"
            );
        }
    }
}
