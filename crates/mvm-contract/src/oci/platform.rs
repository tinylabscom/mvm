//! Platform selection for OCI image indexes and Docker manifest lists.
//!
//! The selector and the matching rule are pure comparisons over strings the
//! manifest already carries, so they belong on the browser side of the
//! split. Deciding *which* platform the caller wants is a different question:
//! on a host it is that host's architecture, which is a host fact and stays
//! in `mvm-fs`. A browser has no such answer and must say what it wants.

use alloc::string::String;

use super::manifest_types::PlatformDescriptor;

/// Linux platform selector for OCI image indexes / Docker manifest lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPlatform {
    /// OCI architecture string (`amd64`, `arm64`, ...).
    pub architecture: String,
    /// Optional architecture variant (`v8` for linux/arm64/v8).
    pub variant: Option<String>,
}

/// Whether `candidate` satisfies `requested`.
///
/// The `linux` OS check is not a parameter: this selector exists to pick a
/// Linux guest image, and matching a non-Linux descriptor would hand back an
/// image the guest cannot boot.
pub fn matches_linux_platform(candidate: &PlatformDescriptor, requested: &LinuxPlatform) -> bool {
    if candidate.os != "linux" || candidate.architecture != requested.architecture {
        return false;
    }
    match (
        candidate.variant.as_deref(),
        requested.variant.as_deref(),
        requested.architecture.as_str(),
    ) {
        (actual, wanted, _) if actual == wanted => true,
        // Registries routinely publish `linux/arm64` with no variant for what
        // is in practice v8; treating the absent variant as satisfying a v8
        // request is what makes ordinary arm64 images selectable.
        (None, Some("v8"), "arm64") => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn descriptor(os: &str, arch: &str, variant: Option<&str>) -> PlatformDescriptor {
        PlatformDescriptor {
            os: os.to_string(),
            architecture: arch.to_string(),
            variant: variant.map(|v| v.to_string()),
        }
    }

    fn want(arch: &str, variant: Option<&str>) -> LinuxPlatform {
        LinuxPlatform {
            architecture: arch.to_string(),
            variant: variant.map(|v| v.to_string()),
        }
    }

    #[test]
    fn an_exact_match_is_selected() {
        assert!(matches_linux_platform(
            &descriptor("linux", "amd64", None),
            &want("amd64", None)
        ));
    }

    #[test]
    fn a_non_linux_descriptor_is_never_selected() {
        assert!(!matches_linux_platform(
            &descriptor("windows", "amd64", None),
            &want("amd64", None)
        ));
    }

    #[test]
    fn a_different_architecture_is_never_selected() {
        assert!(!matches_linux_platform(
            &descriptor("linux", "arm64", None),
            &want("amd64", None)
        ));
    }

    #[test]
    fn a_variantless_arm64_descriptor_satisfies_a_v8_request() {
        assert!(matches_linux_platform(
            &descriptor("linux", "arm64", None),
            &want("arm64", Some("v8"))
        ));
    }

    #[test]
    fn the_variantless_arm64_rule_does_not_generalise_to_other_arches() {
        assert!(!matches_linux_platform(
            &descriptor("linux", "amd64", None),
            &want("amd64", Some("v8"))
        ));
    }

    #[test]
    fn a_mismatched_variant_is_never_selected() {
        assert!(!matches_linux_platform(
            &descriptor("linux", "arm64", Some("v7")),
            &want("arm64", Some("v8"))
        ));
    }
}
