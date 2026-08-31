use anyhow::{Context, Result};
use mvm_core::vm_backend::{VmVolume, VmVolumeKind};

use crate::commands::DirShareSpec;

/// Turn each `--mount` into a volume backed by a materialized ext4 image.
///
/// `host` stays the directory that was granted so the admission record names
/// it; `materialized_image` carries what the backend attaches.
pub(crate) fn materialize_mount_volumes(
    shares: &[DirShareSpec],
    vm_name: &str,
) -> Result<Vec<VmVolume>> {
    if shares.is_empty() {
        return Ok(Vec::new());
    }
    let state_dir = mvm_core::config::vm_state_dir(vm_name);
    std::fs::create_dir_all(&state_dir).with_context(|| {
        format!(
            "creating the VM state directory {} for --mount images",
            state_dir.display()
        )
    })?;
    shares
        .iter()
        .enumerate()
        .map(|(index, share)| {
            let image = materialize_mount_image(share, &state_dir, index)?;
            Ok(VmVolume {
                host: share.host_dir.clone(),
                guest: share.guest_mount.clone(),
                read_only: share.read_only,
                kind: VmVolumeKind::DirShare,
                materialized_image: Some(image.display().to_string()),
                ..Default::default()
            })
        })
        .collect()
}

/// Materialize a granted host directory into an ext4 image and return its path.
///
/// `--mount` used to attach the directory itself over virtio-fs. That put a
/// FUSE server on the host, parsing requests the guest composed, pointed at a
/// host directory — the one mechanism by which a guest addressed host
/// filesystem *structure* rather than opaque blocks. An image has no protocol
/// for a guest to drive.
///
/// The image is written by the same pure-Rust ext4 writer that materializes
/// every rootfs: no `mkfs`, no subprocess, and — the part that matters here —
/// it reads host bytes rather than guest requests, so it is not a surface the
/// guest can reach at all.
///
/// The directory is read as-is, unfiltered. The builder's own
/// dir-to-image packer excludes build outputs because it is packing *this*
/// workspace for a Nix build; a user who mounts a directory means the
/// directory.
///
/// # What a caller loses
///
/// The image is a snapshot taken now. Host edits during the run are not
/// visible to the guest. `--mount` was already read-only — the CLI refuses
/// `rw` with "transient live shares are read-only" — so mid-run visibility is
/// the only property that goes.
pub(crate) fn materialize_mount_image(
    share: &DirShareSpec,
    state_dir: &std::path::Path,
    index: usize,
) -> Result<std::path::PathBuf> {
    let host_dir = std::path::PathBuf::from(&share.host_dir);
    if !host_dir.is_dir() {
        anyhow::bail!(
            "--mount {}:{}: the host path is not a directory",
            share.host_dir,
            share.guest_mount
        );
    }
    let output = state_dir.join(format!("mount-{index}.ext4"));
    // Labelled so the guest mounts by identity rather than by enumeration
    // order, the same reason `stage0-init` reads its work disk by label.
    let label = format!("mvmmnt{index}");
    let input = mvm_build::rootfs::MaterializeExt4Input::builder()
        .unpacked_root(host_dir.clone())
        .output(output.clone())
        .uncompressed_size_bytes(tree_size_bytes(&host_dir))
        .volume_label(label)
        .emit_verity(false)
        // Only an OCI unpack on a case-folding host defers nodes; a host
        // directory is read as it is.
        .deferred_nodes(Vec::new())
        .build()
        .context("assembling the mount image inputs")?;
    mvm_build::rootfs::materialize_ext4_pure(&input).with_context(|| {
        format!(
            "materializing --mount {} into an ext4 image",
            share.host_dir
        )
    })?;
    Ok(output)
}

/// Sum of the regular-file bytes under `dir`, for sizing the image.
///
/// Best effort: an entry that cannot be read contributes nothing rather than
/// failing the launch, because this only feeds a size *estimate* and the
/// writer grows the image to fit what it actually writes. Symlinks are not
/// followed, so a link out of the tree is counted as the link it is.
fn tree_size_bytes(dir: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&next) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                pending.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_mounts_create_no_state_or_volumes() {
        assert!(materialize_mount_volumes(&[], "unused").unwrap().is_empty());
    }

    #[test]
    fn a_missing_host_directory_is_refused() {
        let scratch = tempfile::TempDir::new().unwrap();
        let share = DirShareSpec {
            host_dir: scratch.path().join("missing").display().to_string(),
            guest_mount: "/work".to_string(),
            read_only: true,
        };
        let err = materialize_mount_image(&share, scratch.path(), 0).unwrap_err();
        assert!(err.to_string().contains("not a directory"), "{err:#}");
        assert!(!scratch.path().join("mount-0.ext4").exists());
    }
}
