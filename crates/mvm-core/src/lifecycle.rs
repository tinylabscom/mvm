//! Guest lifecycle markers and snapshot timing.
//!
//! `mvm-init` (the static guest PID-1 supervisor) emits a [`LifecycleMarker`]
//! over the vsock control channel at each boot milestone, so the host can
//! observe progress, decide *when* to capture a warm snapshot ([`SnapshotAt`]),
//! and tell a healthy-but-idle guest from one stuck in setup. On fatal setup
//! error the supervisor emits [`LifecycleMarker::FailedInspectable`] and stays
//! alive, so the VM can be inspected rather than vanishing.
//!
//! The tokens are a stable wire contract (host and guest must agree), so they
//! are matched exactly and round-trip through [`LifecycleMarker::as_str`] /
//! [`LifecycleMarker::parse`].

/// A guest boot milestone reported by `mvm-init` over the vsock control channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleMarker {
    /// PID 1 is running.
    Booted,
    /// Pseudo/early filesystems are mounted.
    MountsReady,
    /// Flat launch metadata has been read.
    MetadataReady,
    /// Policy-permitted secrets have been received over vsock.
    SecretsReady,
    /// About to exec the workload (snapshot point for the coldest warm tier).
    PreExec,
    /// The workload process has started.
    WorkloadStarted,
    /// The workload reports itself ready to serve.
    Ready,
    /// The workload process exited.
    WorkloadExited,
    /// Fatal setup error: the supervisor is holding the VM alive for inspection
    /// rather than exiting.
    FailedInspectable,
}

impl LifecycleMarker {
    /// Every marker, in boot order.
    pub const ALL: [LifecycleMarker; 9] = [
        Self::Booted,
        Self::MountsReady,
        Self::MetadataReady,
        Self::SecretsReady,
        Self::PreExec,
        Self::WorkloadStarted,
        Self::Ready,
        Self::WorkloadExited,
        Self::FailedInspectable,
    ];

    /// Stable wire token. Host and guest match on these exactly.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Booted => "BOOTED",
            Self::MountsReady => "MOUNTS_READY",
            Self::MetadataReady => "METADATA_READY",
            Self::SecretsReady => "SECRETS_READY",
            Self::PreExec => "PRE_EXEC",
            Self::WorkloadStarted => "WORKLOAD_STARTED",
            Self::Ready => "READY",
            Self::WorkloadExited => "WORKLOAD_EXITED",
            Self::FailedInspectable => "FAILED_INSPECTABLE",
        }
    }

    /// Parse a wire token. Unknown tokens are rejected (fail closed).
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == token)
    }

    /// A terminal state — no further normal progress. Either the workload
    /// exited or setup failed and the VM is held for inspection.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::WorkloadExited | Self::FailedInspectable)
    }
}

/// When to capture a warm snapshot of a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotAt {
    /// Before the workload entrypoint runs — fastest to capture, coldest cache.
    PreExec,
    /// Once the workload reports ready — the default warm point.
    #[default]
    Ready,
    /// After a declared warmup command has run, so the restored guest starts
    /// with a hot page cache. Gated on the host-driven warmup completing in
    /// addition to the guest reaching the trigger marker below.
    AfterWarmup,
}

impl SnapshotAt {
    /// The guest marker at or after which a snapshot for this policy is
    /// eligible. (`AfterWarmup` additionally waits for the host warmup command.)
    pub const fn trigger_marker(self) -> LifecycleMarker {
        match self {
            Self::PreExec => LifecycleMarker::PreExec,
            Self::Ready | Self::AfterWarmup => LifecycleMarker::Ready,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_string_round_trips() {
        for marker in LifecycleMarker::ALL {
            assert_eq!(LifecycleMarker::parse(marker.as_str()), Some(marker));
        }
    }

    #[test]
    fn parse_rejects_unknown_token() {
        assert_eq!(LifecycleMarker::parse("READYISH"), None);
        assert_eq!(LifecycleMarker::parse(""), None);
    }

    #[test]
    fn only_exit_and_failure_are_terminal() {
        assert!(LifecycleMarker::WorkloadExited.is_terminal());
        assert!(LifecycleMarker::FailedInspectable.is_terminal());
        assert!(!LifecycleMarker::Ready.is_terminal());
        assert!(!LifecycleMarker::Booted.is_terminal());
    }

    #[test]
    fn snapshot_at_defaults_to_ready() {
        assert_eq!(SnapshotAt::default(), SnapshotAt::Ready);
    }

    #[test]
    fn snapshot_at_maps_to_its_trigger_marker() {
        assert_eq!(
            SnapshotAt::PreExec.trigger_marker(),
            LifecycleMarker::PreExec
        );
        assert_eq!(SnapshotAt::Ready.trigger_marker(), LifecycleMarker::Ready);
        assert_eq!(
            SnapshotAt::AfterWarmup.trigger_marker(),
            LifecycleMarker::Ready
        );
    }
}
