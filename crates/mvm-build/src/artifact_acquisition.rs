//! Shared default policy for launch-critical artifact acquisition.
//!
//! Filesystem proximity is useful only inside contributor builds. An official
//! binary may be invoked from a cloned mvm checkout, so the compiled release
//! marker must win before any executable/CWD/manifest-path source detection.

/// How this binary was distributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DistributionChannel {
    /// Built by a contributor from the workspace.
    Source,
    /// Built by the official release pipeline.
    Release,
}

impl DistributionChannel {
    /// Whether automatic local source builds are permitted.
    #[must_use]
    pub const fn permits_automatic_builds(self) -> bool {
        matches!(self, Self::Source)
    }
}

/// The channel compiled into the running binary.
#[must_use]
pub const fn compiled_channel() -> DistributionChannel {
    if cfg!(feature = "release-channel") {
        DistributionChannel::Release
    } else {
        DistributionChannel::Source
    }
}

/// Default acquisition arm for an artifact whose local source is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultAcquisition {
    Build,
    Download,
}

/// Explicit opt-in for compiling the guest runtime from the current checkout.
pub const RUNTIME_OVERLAY_ACQUIRE_MODE_ENV: &str = "MVM_RUNTIME_OVERLAY_ACQUIRE_MODE";

/// Whether the operator explicitly selected local guest-runtime compilation.
#[must_use]
pub fn local_guest_runtime_build_requested() -> bool {
    std::env::var(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV).as_deref() == Ok("build")
}

/// Resolve the no-override default.
///
/// Launches never infer permission to compile from the presence of a source
/// checkout. Both distribution channels use published artifacts unless the
/// caller selects a build arm explicitly.
#[must_use]
pub const fn default_acquisition(
    _channel: DistributionChannel,
    _source_available: bool,
) -> DefaultAcquisition {
    DefaultAcquisition::Download
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_channel_never_automatically_builds() {
        assert_eq!(
            default_acquisition(DistributionChannel::Release, true),
            DefaultAcquisition::Download
        );
        assert_eq!(
            default_acquisition(DistributionChannel::Release, false),
            DefaultAcquisition::Download
        );
    }

    #[test]
    fn source_channel_never_infers_permission_to_build() {
        assert_eq!(
            default_acquisition(DistributionChannel::Source, true),
            DefaultAcquisition::Download
        );
        assert_eq!(
            default_acquisition(DistributionChannel::Source, false),
            DefaultAcquisition::Download
        );
    }

    #[test]
    fn guest_runtime_build_requires_the_explicit_build_value() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.remove(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV);
        assert!(!local_guest_runtime_build_requested());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "download");
        assert!(!local_guest_runtime_build_requested());
        env.set(RUNTIME_OVERLAY_ACQUIRE_MODE_ENV, "build");
        assert!(local_guest_runtime_build_requested());
    }

    #[test]
    fn compiled_channel_matches_the_distribution_feature() {
        #[cfg(feature = "release-channel")]
        assert_eq!(compiled_channel(), DistributionChannel::Release);
        #[cfg(not(feature = "release-channel"))]
        assert_eq!(compiled_channel(), DistributionChannel::Source);
    }
}
