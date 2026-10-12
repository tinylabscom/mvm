//! Provisioning the host snapshot key before a command that needs one.

use anyhow::{Context, Result};
use mvm_client::snapshot::{HostSnapshotKey, ensure_host_snapshot_key};

/// Make sure the host has a snapshot key, minting one under the mvm key
/// directory when no source holds any, and say so when one was minted: the
/// key is the only way back into every snapshot sealed under it.
pub(in crate::commands) fn ensure_snapshot_key() -> Result<HostSnapshotKey> {
    let outcome = ensure_host_snapshot_key().context("preparing the host snapshot key")?;
    if let Some(line) = provisioned_notice(&outcome) {
        crate::ui::notice(&line);
    }
    Ok(outcome)
}

/// The line announcing a newly minted key; nothing for one that existed.
fn provisioned_notice(outcome: &HostSnapshotKey) -> Option<String> {
    match outcome {
        HostSnapshotKey::Created(path) => Some(format!(
            "Created the host snapshot key at {} (mode 0600). Back it up: encrypted \
             snapshots and warm standbys cannot be resumed without it.",
            path.display()
        )),
        HostSnapshotKey::Existing(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::snapshot::SnapshotKeySource;

    #[test]
    fn only_a_minted_key_is_announced() {
        let created = HostSnapshotKey::Created("/h/keys/local.key".into());
        let line = provisioned_notice(&created).expect("announced");
        assert!(line.contains("/h/keys/local.key"), "{line}");
        assert!(line.contains("0600"), "{line}");
        assert_eq!(
            provisioned_notice(&HostSnapshotKey::Existing(SnapshotKeySource::Keystore)),
            None
        );
    }
}
