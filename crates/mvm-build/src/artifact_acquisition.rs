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

/// Resolve the no-override default. Release distributions always download;
/// contributor distributions build only when that artifact's source exists.
#[must_use]
pub const fn default_acquisition(
    channel: DistributionChannel,
    source_available: bool,
) -> DefaultAcquisition {
    if channel.permits_automatic_builds() && source_available {
        DefaultAcquisition::Build
    } else {
        DefaultAcquisition::Download
    }
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
    fn source_channel_builds_only_when_source_is_available() {
        assert_eq!(
            default_acquisition(DistributionChannel::Source, true),
            DefaultAcquisition::Build
        );
        assert_eq!(
            default_acquisition(DistributionChannel::Source, false),
            DefaultAcquisition::Download
        );
    }

    #[test]
    fn compiled_channel_matches_the_distribution_feature() {
        #[cfg(feature = "release-channel")]
        assert_eq!(compiled_channel(), DistributionChannel::Release);
        #[cfg(not(feature = "release-channel"))]
        assert_eq!(compiled_channel(), DistributionChannel::Source);
    }
}
