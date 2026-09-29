//! Fetch-when-unchanged: adopt published set members when this tree's sources
//! are exactly what those members were built from.
//!
//! The documented-surface e2e (and, behind the same knob, any caller) builds
//! the SDK sidecars and the dev default image from a source checkout on every
//! run. Since the image-set schema carries a member's `source_fingerprint`
//! and dev build variants, a tree whose fingerprint matches the published
//! sidecars can adopt those verified bytes instead of rebuilding them — and
//! the same predicate covers the dev image, whose inputs over-approximate to
//! the host-services C ABI on purpose (a broader guest change rebuilds;
//! that is the accepted v1 behavior). A mismatch or an absent field never
//! fails here: it names the reason and the caller builds locally, which is
//! the safe direction.

use std::path::Path;

use mvm_contract::guest_libc::GuestLibc;
use mvm_core::arch::GuestArch;
use mvm_core::image_set::{ImageSetRole, MemberTarget};

use crate::guest_agent_build;
use crate::published_image_set::PublishedImageSet;

/// The opt-in knob. Production resolvers never read it; the documented-surface
/// e2e sets it to adopt unchanged members instead of pair-building them.
pub const FETCH_UNCHANGED_ENV: &str = "MVM_FETCH_UNCHANGED_IMAGES";

/// Whether the caller asked for the fetch-when-unchanged arm.
pub fn fetch_unchanged_enabled() -> bool {
    std::env::var(FETCH_UNCHANGED_ENV)
        .map(|value| value == "1")
        .unwrap_or(false)
}

/// Which arm supplied the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnchangedArm {
    /// The published, digest-verified members were adopted.
    Fetched,
    /// Build locally; the reason says why the published members were not
    /// adopted.
    BuildLocally(&'static str),
}

/// This tree's cdylib source fingerprint — the same function the producer ran
/// at the pinned commit.
pub fn tree_sdk_fingerprint(
    workspace_root: &Path,
) -> Result<String, guest_agent_build::GuestAgentBuildError> {
    guest_agent_build::sdk_cdylib_source_fingerprint(workspace_root)
}

/// Both SDK sidecar members of the set (glibc and musl, this architecture,
/// production build) declare `source_fingerprint` equal to `fingerprint`.
pub fn set_sidecars_match_tree(
    set: &PublishedImageSet,
    arch: GuestArch,
    fingerprint: &str,
) -> bool {
    [GuestLibc::Glibc, GuestLibc::Musl].iter().all(|libc| {
        set.manifest().members.iter().any(|member| {
            member.role == ImageSetRole::SdkSidecar(*libc)
                && member.target == MemberTarget::Arch(arch)
                && member.build_mode.is_none()
                && member
                    .source_fingerprint
                    .as_ref()
                    .is_some_and(|fp| fp.as_str() == fingerprint)
        })
    })
}

/// Fetch both sidecars from an already-acquired, verified set into
/// `cache_root` — the same install the release-channel download arm performs.
pub fn fetch_sidecars_from_set(
    set: &PublishedImageSet,
    arch: GuestArch,
    cache_root: &Path,
) -> Result<(), crate::sdk_sidecar::SdkSidecarBuildError> {
    for libc in [GuestLibc::Glibc, GuestLibc::Musl] {
        crate::sdk_sidecar::download_sdk_sidecar_from(set, arch, libc, cache_root)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published_image_set::fixture::ImageSetFixture;
    use mvm_core::util::test_env::TestEnv;

    const ARCH: GuestArch = GuestArch::Aarch64;

    fn fingerprint(fill: &str) -> String {
        fill.repeat(32)
    }

    fn unsigned_env() -> TestEnv {
        let mut env = TestEnv::new();
        env.set(crate::release_signature::SKIP_COSIGN_VERIFY_ENV, "1");
        env
    }

    fn set_with_sidecar_fingerprints(fingerprint: Option<String>) -> PublishedImageSet {
        let _env = unsigned_env();
        let fixture = ImageSetFixture::complete().with_sidecar_fingerprints(ARCH, fingerprint);
        let served = tempfile::tempdir().unwrap();
        PublishedImageSet::acquire_from(fixture.serve_from(served.path()))
            .expect("the fixture set acquires")
    }

    #[test]
    fn matching_fingerprints_on_both_libcs_adopt_the_set() {
        let fp = fingerprint("ab");
        let set = set_with_sidecar_fingerprints(Some(fp.clone()));
        assert!(set_sidecars_match_tree(&set, ARCH, &fp));
    }

    #[test]
    fn a_mismatched_or_absent_fingerprint_builds_locally() {
        let set = set_with_sidecar_fingerprints(Some(fingerprint("cd")));
        assert!(
            !set_sidecars_match_tree(&set, ARCH, &fingerprint("ab")),
            "a differing fingerprint must not adopt the published bytes"
        );
        let set = set_with_sidecar_fingerprints(None);
        assert!(
            !set_sidecars_match_tree(&set, ARCH, &fingerprint("ab")),
            "a set published before the fingerprint field must not adopt"
        );
    }

    #[test]
    fn the_knob_defaults_off() {
        let mut env = TestEnv::new();
        assert!(!fetch_unchanged_enabled());
        env.set(FETCH_UNCHANGED_ENV, "1");
        assert!(fetch_unchanged_enabled());
    }
}
