//! Release signature verification, guest-runtime acquisition and the
//! release-side helpers `mvmctl env update` and `bootstrap` call.
//!
//! Each function runs the build layer's own logic unchanged and returns its
//! typed result; none adds authority, widens an accepted identity, or reads
//! an environment variable the build layer does not. The skip hatch
//! ([`SKIP_COSIGN_VERIFY_ENV`]) keeps exactly the meaning it has there.

use std::path::{Path, PathBuf};

use mvm_core::arch::GuestArch;

pub use mvm_build::artifact_acquisition::{
    DistributionChannel, RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, compiled_channel,
};
pub use mvm_build::guest_bins::release::{
    AuthenticatedReleaseArchive, ReleaseGuestRuntime, ReleaseGuestRuntimeError,
    ReleaseGuestRuntimeOrigin, ReleaseGuestRuntimeRequest,
};
pub use mvm_build::guest_runtime::GuestRuntime;
pub use mvm_build::published_image_set::{
    Download, ImageSetSource, PublishedImageSet, github_download_base,
};
pub use mvm_build::release_signature::{
    ReleaseSignatureRequest, ReleaseTrain, SKIP_COSIGN_VERIFY_ENV, bundle_asset_name,
};

/// Verify a downloaded release asset against its signature bundle, in
/// process, under the workflow identity of the request's train and version.
/// `Ok(None)` is the explicit [`SKIP_COSIGN_VERIFY_ENV`] bypass; otherwise
/// the verified bundle bytes come back.
pub fn verify_archive_signature(
    request: &ReleaseSignatureRequest<'_>,
) -> Result<Option<Vec<u8>>, mvm_build::runtime_overlay::RuntimeOverlayError> {
    mvm_build::release_signature::verify_release_archive_signature(request)
}

/// Verify archive bytes against bundle bytes for one of `identities`.
pub fn verify_archive_bytes(
    archive: &[u8],
    bundle: &[u8],
    asset: &str,
    identities: &[String],
    issuer: &str,
) -> Result<(), mvm_build::runtime_overlay::RuntimeOverlayError> {
    mvm_build::release_signature::verify_release_archive_bytes(
        archive, bundle, asset, identities, issuer,
    )
}

/// Acquire the image set this build pins, fetching members through `download`.
pub fn acquire_locked_image_set(download: Download) -> anyhow::Result<PublishedImageSet> {
    PublishedImageSet::acquire_from(ImageSetSource::locked().with_download(download))
}

/// Record the digest sidecar beside a downloaded kernel.
pub fn record_kernel_digest(
    kernel: &Path,
) -> Result<(), mvm_build::kernel_fetch::KernelFetchError> {
    mvm_build::kernel_fetch::record_kernel_digest(kernel)
}

/// The digest sidecar's path for `kernel`.
#[must_use]
pub fn kernel_digest_sidecar(kernel: &Path) -> PathBuf {
    mvm_build::kernel_fetch::kernel_digest_sidecar(kernel)
}

/// The guest-runtime archive name a release of `version` publishes.
#[must_use]
pub fn guest_runtime_archive_name(version: &str) -> String {
    mvm_build::guest_bins::guest_bins_archive_name(version)
}

/// The directories beside `exe` an installed guest runtime may sit in.
#[must_use]
pub fn installed_guest_runtime_dirs(exe: &Path) -> Vec<PathBuf> {
    mvm_build::guest_bins::release::installed_guest_runtime_dirs(exe)
}

/// Where a downloaded guest runtime of `version` is cached.
#[must_use]
pub fn guest_runtime_cache_dir(cache_root: &Path, version: &str) -> PathBuf {
    mvm_build::guest_bins::release::release_guest_runtime_cache_dir(cache_root, version)
}

/// Acquire the release guest runtime: installed copy, cache, or a download
/// held to its digest and then its signature.
pub fn acquire_release_guest_runtime(
    request: &ReleaseGuestRuntimeRequest<'_>,
) -> Result<ReleaseGuestRuntime, ReleaseGuestRuntimeError> {
    mvm_build::guest_bins::release::acquire_release_guest_runtime(request)
}

/// Install a release archive into the digest-keyed guest-runtime store.
pub fn install_guest_runtime(
    cache_root: &Path,
    archive: AuthenticatedReleaseArchive<'_>,
    version: &str,
    arch: GuestArch,
) -> Result<GuestRuntime, mvm_build::guest_runtime::GuestRuntimeError> {
    mvm_build::guest_runtime::install_release_guest_runtime(cache_root, archive, version, arch)
}

/// Install the OCI guest shims from an installed runtime.
pub fn install_oci_guest_runtime(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    runtime: &GuestRuntime,
) -> Result<(), mvm_build::guest_agent_build::GuestAgentBuildError> {
    mvm_build::runtime_pieces::install_oci_guest_runtime(cache_root, version, arch, runtime)
}

/// Assemble the version-locked launch pieces from a release archive.
pub fn assemble_release_pieces(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    archive: AuthenticatedReleaseArchive<'_>,
) -> Result<mvm_build::runtime_pieces::ReleaseAssembly, mvm_build::runtime_pieces::AssembleError> {
    mvm_build::runtime_pieces::assemble_release_runtime_pieces(cache_root, version, arch, archive)
}

/// Whether `version`'s pieces were assembled from a release archive, and
/// from which digest.
pub fn adopted_release_archive(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<Option<String>, mvm_build::runtime_pieces::PieceOriginError> {
    mvm_build::runtime_pieces::adopted_release_archive(cache_root, version, arch)
}

/// Whether the OCI guest binaries for `version` are cached complete.
#[must_use]
pub fn oci_guest_binaries_cached(oci_cache_root: &Path, version: &str, arch: GuestArch) -> bool {
    mvm_build::guest_agent_build::cached_guest_binaries(oci_cache_root, version, arch).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_archive_name_carries_the_version() {
        assert_eq!(
            guest_runtime_archive_name("1.2.3"),
            "mvm-guest-bins-v1.2.3.tar.gz"
        );
    }

    #[test]
    fn the_cache_dir_is_the_build_layers() {
        let root = Path::new("/c");
        assert_eq!(
            guest_runtime_cache_dir(root, "1.2.3"),
            mvm_build::guest_bins::release::release_guest_runtime_cache_dir(root, "1.2.3")
        );
    }

    #[test]
    fn the_kernel_sidecar_sits_beside_the_kernel() {
        let sidecar = kernel_digest_sidecar(Path::new("/k/vmlinux"));
        assert_eq!(sidecar.parent(), Some(Path::new("/k")));
    }

    #[test]
    fn installed_dirs_are_the_build_layers() {
        let exe = Path::new("/opt/mvm/bin/mvmctl");
        assert_eq!(
            installed_guest_runtime_dirs(exe),
            mvm_build::guest_bins::release::installed_guest_runtime_dirs(exe)
        );
    }

    #[test]
    fn nothing_is_adopted_in_an_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::host();
        assert_eq!(
            adopted_release_archive(dir.path(), "1.2.3", arch).unwrap(),
            None
        );
        assert!(!oci_guest_binaries_cached(dir.path(), "1.2.3", arch));
    }

    #[test]
    fn a_bundle_that_is_not_a_bundle_is_refused() {
        let identities = vec!["https://example.invalid/wf@refs/tags/v1".to_string()];
        let refused =
            verify_archive_bytes(b"archive", b"not a bundle", "a.tar.gz", &identities, "iss");
        assert!(refused.is_err());
    }

    #[test]
    fn the_bundle_asset_is_named_after_the_asset() {
        assert_eq!(bundle_asset_name("a.tar.gz"), "a.tar.gz.bundle");
    }
}
