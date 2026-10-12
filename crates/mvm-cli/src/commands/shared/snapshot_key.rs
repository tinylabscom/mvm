//! Provisioning the host snapshot key before a command that needs one.

use anyhow::Result;
use mvm_client::snapshot::{HostSnapshotKey, ensure_host_snapshot_key_announced};

/// Make sure the host has a snapshot key, minting and announcing one when no
/// source holds any. The provisioning and its notice live in `mvm-client`, so
/// the host library and the CLI mint the same key the same way.
pub(in crate::commands) fn ensure_snapshot_key() -> Result<HostSnapshotKey> {
    ensure_host_snapshot_key_announced()
}

#[cfg(test)]
mod tests {
    use mvm_client::snapshot::{HostSnapshotKey, SnapshotKeySource, provisioned_notice};

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
