//! A machine's workspaces: the writable volumes that began as a snapshot of a
//! host directory.
//!
//! `machine volume mount <vm> <volume> --host DIR ... rw` gives the guest a
//! private copy of the directory's image to write in. The copy is the
//! workspace; the published image it was copied from is its baseline. Nothing
//! the guest does reaches the host directory — a diff compares the copy with
//! the baseline, and only a later reviewed apply may write the host tree.

#[cfg(test)]
use mvm_client::workspace_apply::workspaces_in;
pub(in crate::commands) use mvm_client::workspace_apply::{
    Workspace, baseline_image, workspaces_of,
};

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::volume::{AccessMode, AttachmentRecord, AttachmentSource, HostSnapshotRecord};
    use std::path::PathBuf;

    fn attachment(volume: &str, access: AccessMode, snapshot: bool) -> AttachmentRecord {
        AttachmentRecord {
            owner: "vm".into(),
            volume: volume.into(),
            guest_path: format!("/work/{volume}"),
            access,
            host_path: format!("/state/{volume}.ext4"),
            source: AttachmentSource::AdHocHost,
            host_snapshot: snapshot.then(|| HostSnapshotRecord {
                source_path: format!("/home/me/{volume}"),
                fingerprint: format!("key-{volume}"),
            }),
            attached_at: "2026-09-27T00:00:00Z".into(),
        }
    }

    #[test]
    fn only_a_writable_directory_snapshot_is_a_workspace() {
        let found = workspaces_in(vec![
            attachment("src", AccessMode::ReadWrite, true),
            attachment("docs", AccessMode::ReadOnly, true),
            attachment("data", AccessMode::ReadWrite, false),
            attachment("app", AccessMode::ReadWrite, true),
        ]);
        let names: Vec<&str> = found.iter().map(|w| w.volume.as_str()).collect();
        assert_eq!(names, ["app", "src"], "sorted, and only rw host snapshots");
        assert_eq!(found[1].source_dir, PathBuf::from("/home/me/src"));
        assert_eq!(found[1].baseline_key, "key-src");
        assert_eq!(found[1].image, PathBuf::from("/state/src.ext4"));
    }
}
