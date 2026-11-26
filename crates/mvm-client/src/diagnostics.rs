//! The build-layer probes `mvmctl doctor` reports from. Each is a read: none
//! boots a VM or touches the network, and each runs the build layer's own
//! logic unchanged.

use std::path::{Path, PathBuf};
use std::time::Duration;

use mvm_core::arch::GuestArch;
use mvm_core::platform::Platform;

pub use mvm_build::artifact_acquisition::DistributionChannel;
pub use mvm_build::boot_image_select::{
    BootImageAcquisition, MVM_BOOT_IMAGE_ENV, ResolvedBootImage,
};
pub use mvm_build::builder_backend_select::{
    BuilderBackendChoice, MVM_BUILDER_BACKEND_ENV, MVM_LINUX_BUILDER_VM_ENV,
};
pub use mvm_build::builder_vm::BuilderCapabilities;
pub use mvm_build::guest_net::{BuilderNetBootstrap, classify_builder_net_bootstrap};
pub use mvm_build::guest_runtime::GuestRuntimeError;
pub use mvm_build::image_source::{
    IMAGES_CHECKOUT_MARKERS, ImageSource, ImageSourceError, MVM_IMAGES_DIR_ENV, RepoIdentity,
};
pub use mvm_build::runtime_pieces::{PieceOrigin, PieceOriginError, RuntimePiece, short_digest};
pub use mvm_hostd::topology_admission::exclusive_cores_held_on_host;

/// The distribution channel compiled into this binary.
#[must_use]
pub fn compiled_distribution_channel() -> DistributionChannel {
    mvm_build::artifact_acquisition::compiled_channel()
}

/// Bytes and path of the builder store, as a dry-run report. Removes nothing.
pub fn builder_store_footprint() -> std::io::Result<crate::maintenance::BuilderStoreRepair> {
    crate::maintenance::clear_builder_store(true)
}

/// The readiness summary of a builder daemon whose control socket exists
/// under `vm_state_dir`, or `None` when no candidate socket exists.
#[must_use]
pub fn builderd_readiness_summary(vm_state_dir: &Path, timeout: Duration) -> Option<String> {
    let socket = mvm_build::builderd_client::builderd_control_socket_candidates(vm_state_dir)
        .into_iter()
        .find(|path| path.exists())?;
    let readiness = mvm_build::builderd_client::probe_builderd_readiness(&socket, timeout);
    Some(mvm_build::builderd_client::readiness_summary(&readiness))
}

/// Whether a persistent builder session is recorded as active.
#[must_use]
pub fn builder_session_is_active() -> bool {
    mvm_build::persistent_builder::read_active_session().is_some()
}

/// The builder backend the environment resolves to.
#[must_use]
pub fn resolved_builder_backend() -> BuilderBackendChoice {
    mvm_build::builder_backend_select::resolve_choice(None)
}

/// The builder backend named by the environment, if any.
#[must_use]
pub fn builder_backend_env_override() -> Option<BuilderBackendChoice> {
    mvm_build::builder_backend_select::resolve_env_override()
}

/// The builder backend auto-detection picks for a described host.
#[must_use]
pub fn auto_detected_builder_backend(
    plat: Platform,
    is_hvf_default_tier: bool,
) -> BuilderBackendChoice {
    mvm_build::builder_backend_select::auto_detect_default_for(plat, is_hvf_default_tier)
}

/// Whether the Linux builder-VM rollout signal is set in the environment.
#[must_use]
pub fn linux_builder_vm_requested() -> bool {
    mvm_build::builder_backend_select::linux_builder_vm_requested()
}

/// What a builder backend declares it can do.
#[must_use]
pub fn declared_builder_capabilities(choice: BuilderBackendChoice) -> BuilderCapabilities {
    mvm_build::builder_backend_select::declared_capabilities(choice)
}

/// The boot-image acquisition arm the environment and host resolve to.
#[must_use]
pub fn resolved_boot_image(is_source_checkout: bool) -> ResolvedBootImage {
    mvm_build::boot_image_select::resolve(None, is_source_checkout)
}

/// Digest of the guest-runtime archive built from `workspace_root`, read from
/// the cache alone.
pub fn source_runtime_archive_digest(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    workspace_root: &Path,
) -> Result<Option<String>, GuestRuntimeError> {
    mvm_build::guest_runtime::source_guest_runtime_digest(cache_root, version, arch, workspace_root)
}

/// Digest of the release guest-runtime archive this version adopted.
pub fn adopted_release_runtime_digest(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
) -> Result<Option<String>, PieceOriginError> {
    mvm_build::runtime_pieces::adopted_release_archive(cache_root, version, arch)
}

/// File name of the release guest-runtime archive for `version`.
#[must_use]
pub fn release_runtime_archive_name(version: &str) -> String {
    mvm_build::guest_bins::guest_bins_archive_name(version)
}

/// Where `piece` would be attached from, read from the cache alone.
pub fn runtime_piece_origin(
    cache_root: &Path,
    version: &str,
    arch: GuestArch,
    piece: RuntimePiece,
) -> Result<PieceOrigin, PieceOriginError> {
    mvm_build::runtime_pieces::piece_origin(cache_root, version, arch, piece)
}

/// The mvm checkout this binary was built from, when its channel permits one.
#[must_use]
pub fn mvm_source_checkout(channel: DistributionChannel) -> Option<PathBuf> {
    mvm_build::image_source::mvm_source_checkout(channel)
}

/// Commit and working-tree state of the repository at `root`.
pub fn probe_repo_identity(root: &Path) -> Result<RepoIdentity, String> {
    mvm_build::image_source::probe_identity(root)
}

/// The image checkout directory the environment names, if any.
#[must_use]
pub fn configured_images_dir() -> Option<PathBuf> {
    mvm_build::image_source::configured_images_dir()
}

/// The image source the environment currently resolves to.
pub fn resolve_current_image_source() -> Result<ImageSource, ImageSourceError> {
    mvm_build::image_source::resolve_current_source()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::util::test_env::TestEnv;

    #[test]
    fn the_compiled_channel_is_the_build_layers() {
        assert_eq!(
            compiled_distribution_channel(),
            mvm_build::artifact_acquisition::compiled_channel()
        );
    }

    #[test]
    fn the_store_footprint_is_a_dry_run_report() {
        let _env = TestEnv::new();
        let report = builder_store_footprint().expect("report");
        assert!(report.dry_run);
        assert!(!report.existed);
    }

    #[test]
    fn no_socket_means_no_readiness_summary() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            builderd_readiness_summary(dir.path(), Duration::from_millis(50)),
            None
        );
    }

    #[test]
    fn an_empty_home_has_no_active_builder_session() {
        let _env = TestEnv::new();
        assert!(!builder_session_is_active());
    }

    #[test]
    fn the_env_names_the_builder_backend() {
        let mut env = TestEnv::new();
        env.set(MVM_BUILDER_BACKEND_ENV, "qemu");
        assert_eq!(
            builder_backend_env_override(),
            Some(BuilderBackendChoice::Qemu)
        );
        assert_eq!(resolved_builder_backend(), BuilderBackendChoice::Qemu);
        env.remove(MVM_BUILDER_BACKEND_ENV);
        assert_eq!(builder_backend_env_override(), None);
    }

    #[test]
    fn auto_detection_follows_the_described_host() {
        assert_eq!(
            auto_detected_builder_backend(Platform::LinuxNative, false),
            BuilderBackendChoice::Firecracker
        );
        assert_eq!(
            auto_detected_builder_backend(Platform::MacOS, true),
            BuilderBackendChoice::Hvf
        );
    }

    #[test]
    fn the_rollout_signal_is_read_from_the_environment() {
        let mut env = TestEnv::new();
        env.remove(MVM_LINUX_BUILDER_VM_ENV);
        assert!(!linux_builder_vm_requested());
    }

    #[test]
    fn capabilities_are_the_backends_declaration() {
        let choice = BuilderBackendChoice::Hvf;
        let declared = declared_builder_capabilities(choice);
        let direct = mvm_build::builder_backend_select::declared_capabilities(choice);
        assert_eq!(format!("{declared:?}"), format!("{direct:?}"));
    }

    #[test]
    fn the_boot_image_knob_names_the_arm() {
        let mut env = TestEnv::new();
        env.set(MVM_BOOT_IMAGE_ENV, "fetch");
        assert_eq!(
            resolved_boot_image(true).choice,
            BootImageAcquisition::Fetch
        );
    }

    #[test]
    fn an_empty_cache_has_no_archive_or_piece() {
        let dir = tempfile::tempdir().unwrap();
        let arch = GuestArch::X86_64;
        assert_eq!(
            adopted_release_runtime_digest(dir.path(), "1.2.3", arch).unwrap(),
            None
        );
        assert_eq!(
            source_runtime_archive_digest(dir.path(), "1.2.3", arch, dir.path()).unwrap(),
            None
        );
        assert_eq!(
            runtime_piece_origin(dir.path(), "1.2.3", arch, RuntimePiece::Initramfs).unwrap(),
            PieceOrigin::Missing
        );
        assert!(release_runtime_archive_name("1.2.3").contains("1.2.3"));
    }

    #[test]
    fn a_release_channel_has_no_source_checkout() {
        assert_eq!(mvm_source_checkout(DistributionChannel::Release), None);
    }

    #[test]
    fn a_directory_that_is_not_a_repo_has_no_identity() {
        let dir = tempfile::tempdir().unwrap();
        assert!(probe_repo_identity(dir.path()).is_err());
    }

    #[test]
    fn the_images_dir_knob_is_read_from_the_environment() {
        let mut env = TestEnv::new();
        env.set(MVM_IMAGES_DIR_ENV, "/nonexistent/images");
        assert_eq!(
            configured_images_dir(),
            Some(PathBuf::from("/nonexistent/images"))
        );
        env.remove(MVM_IMAGES_DIR_ENV);
        assert_eq!(configured_images_dir(), None);
    }
}
