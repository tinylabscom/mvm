//! A machine's workspaces: the writable volumes that began as a snapshot of a
//! host directory.
//!
//! `machine volume mount <vm> <volume> --host DIR ... rw` gives the guest a
//! private copy of the directory's image to write in. The copy is the
//! workspace; the published image it was copied from is its baseline. Nothing
//! the guest does reaches the host directory — a diff compares the copy with
//! the baseline, and only a later reviewed apply may write the host tree.

use std::path::PathBuf;

use anyhow::{Context, Result};
use mvm_client::volume::{AccessMode, AttachmentRecord, LocalVolumeService, VolumeService};
use mvm_runtime::checkpoint::WorkspaceVolume;

/// One workspace volume attached to a machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct Workspace {
    /// The registered volume name.
    pub volume: String,
    /// Where the guest sees it.
    pub guest_path: String,
    /// The host directory it was snapshotted from.
    pub source_dir: PathBuf,
    /// The mount-cache key of the image the copy began as.
    pub baseline_key: String,
    /// The image the guest writes.
    pub image: PathBuf,
}

/// The workspaces among `attachments`: writable, and backed by a host
/// directory snapshot. A read-only snapshot cannot change, and a managed
/// volume has no host directory to compare against.
pub(in crate::commands) fn workspaces_in(attachments: Vec<AttachmentRecord>) -> Vec<Workspace> {
    let mut workspaces: Vec<Workspace> = attachments
        .into_iter()
        .filter(|attachment| attachment.access == AccessMode::ReadWrite)
        .filter_map(|attachment| {
            let snapshot = attachment.host_snapshot?;
            Some(Workspace {
                volume: attachment.volume,
                guest_path: attachment.guest_path,
                source_dir: PathBuf::from(snapshot.source_path),
                baseline_key: snapshot.fingerprint,
                image: PathBuf::from(attachment.host_path),
            })
        })
        .collect();
    workspaces.sort_by(|a, b| a.volume.cmp(&b.volume));
    workspaces
}

/// Every workspace registered for `vm`.
pub(in crate::commands) fn workspaces_of(vm: &str) -> Result<Vec<Workspace>> {
    let attachments = LocalVolumeService::new()
        .list_attachments(vm)
        .with_context(|| format!("listing the volumes registered for {vm:?}"))?;
    Ok(workspaces_in(attachments))
}

/// The capture set a checkpoint of `vm` freezes with the machine.
pub(in crate::commands) fn capture_set(workspaces: &[Workspace]) -> Vec<WorkspaceVolume> {
    workspaces
        .iter()
        .filter(|workspace| workspace.image.is_file())
        .map(|workspace| WorkspaceVolume {
            name: workspace.volume.clone(),
            image: workspace.image.clone(),
        })
        .collect()
}

/// The image `workspace` began as, verified against the digest it was
/// published with.
pub(in crate::commands) fn baseline_image(workspace: &Workspace) -> Result<PathBuf> {
    let cache = crate::mount_cache::MountImageCache::new()?;
    cache
        .published_image(&workspace.baseline_key)?
        .with_context(|| {
            format!(
                "the baseline image volume {:?} was copied from is no longer cached, or no \
                 longer matches its recorded digest; it cannot be compared against",
                workspace.volume
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_client::volume::{AttachmentSource, HostSnapshotRecord};

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
