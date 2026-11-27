//! Telling a snapshot this Firecracker cannot decode apart from any other
//! failed load.
//!
//! A snapshot is readable only by a Firecracker that writes the same snapshot
//! format, and the format moves with most releases — not only its version
//! number but the encoding of the header that carries it. v1.17.0 cannot read
//! so much as the header of a v1.14.1 snapshot: `--describe-snapshot` and
//! `PUT /snapshot/load` both fail with a bitcode error. So nothing can ask a
//! newer binary what an older one wrote, and upgrading a host's Firecracker
//! strands every snapshot the old one took.
//!
//! Firecracker refuses such a load before any guest code runs; this module
//! only names the refusal. Firecracker reports every failure to decode the
//! state file — foreign encoding, format version, magic, checksum, a short
//! read — under one message, distinct from failing to open the file. That is a
//! property of the snapshot, not of the attempt, so it is permanent for this
//! snapshot on this host whatever caused it.

use std::fmt;
use std::path::{Path, PathBuf};

/// The message Firecracker prefixes every state-decode failure with
/// (`SnapshotStateFromFileError::Load`, unchanged from v1.14.1 to v1.17.0).
/// Opening the file fails under a different message and is not matched.
const UNDECODABLE_STATE: &str = "Failed to load snapshot state from file";

/// A snapshot the running Firecracker cannot decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndecodableSnapshot {
    pub state_file: PathBuf,
    /// The version of the Firecracker that tried, when it could be read.
    pub firecracker: Option<String>,
}

impl fmt::Display for UndecodableSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let who = match &self.firecracker {
            Some(version) => format!("Firecracker {version}"),
            None => "the installed Firecracker".to_string(),
        };
        write!(
            f,
            "{who} cannot decode snapshot {}. A snapshot is readable only by a \
             Firecracker that writes the same snapshot format, and the format \
             changes between releases: if Firecracker was upgraded after this \
             snapshot was taken, it cannot be restored and must be captured again",
            self.state_file.display()
        )
    }
}

impl std::error::Error for UndecodableSnapshot {}

/// Whether a failed `PUT /snapshot/load` failed to decode the state file.
fn is_undecodable(load_error: &anyhow::Error) -> bool {
    format!("{load_error:#}").contains(UNDECODABLE_STATE)
}

/// Name a failed load, when the failure is that the state could not be
/// decoded. `socket` is the Firecracker that tried; its version goes in the
/// message. `None` for any other failure, whose own error then stands.
pub fn explain_load_failure(
    load_error: &anyhow::Error,
    socket: &Path,
    state_file: &Path,
) -> Option<UndecodableSnapshot> {
    is_undecodable(load_error).then(|| UndecodableSnapshot {
        state_file: state_file.to_path_buf(),
        firecracker: super::capabilities::running_version(socket).ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from Firecracker v1.17.0 loading a v1.14.1 snapshot.
    const FOREIGN_FORMAT: &str = r#"PUT /snapshot/load failed: HTTP 400 {"fault_message":"Load snapshot error: Failed to restore from snapshot: Failed to get snapshot state from file: Failed to load snapshot state from file: An error occurred during bitcode serialization: bitcode error"}"#;

    #[test]
    fn a_snapshot_from_another_firecracker_is_undecodable() {
        let error = anyhow::Error::msg(FOREIGN_FORMAT).context("PUT /snapshot/load");
        assert!(is_undecodable(&error));
    }

    #[test]
    fn a_file_that_will_not_open_is_not_blamed_on_its_format() {
        let error = anyhow::Error::msg(
            r#"PUT /snapshot/load failed: HTTP 400 {"fault_message":"Load snapshot error: Failed to restore from snapshot: Failed to get snapshot state from file: Failed to open snapshot file: No such file or directory (os error 2)"}"#,
        );
        assert!(!is_undecodable(&error));
    }

    #[test]
    fn a_failure_that_never_reached_firecracker_is_not_undecodable() {
        let error = anyhow::anyhow!("Firecracker socket /vms/w/fc.socket does not exist");
        assert!(!is_undecodable(&error));
    }

    #[test]
    fn the_explanation_names_the_file_the_binary_and_the_remedy() {
        let found = UndecodableSnapshot {
            state_file: "/vms/w/snapshot/vmstate.bin".into(),
            firecracker: Some("1.17.0".into()),
        };
        let message = found.to_string();
        assert!(
            message.starts_with("Firecracker 1.17.0 cannot decode"),
            "{message}"
        );
        assert!(message.contains("/vms/w/snapshot/vmstate.bin"), "{message}");
        assert!(message.contains("captured again"), "{message}");
    }

    #[test]
    fn an_unreadable_version_still_explains() {
        let found = UndecodableSnapshot {
            state_file: "/s/vmstate.bin".into(),
            firecracker: None,
        };
        assert!(
            found
                .to_string()
                .starts_with("the installed Firecracker cannot decode")
        );
    }
}
