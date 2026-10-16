//! The host half of late volumes: the read-only slots a warm parent boots, and
//! the attachments a claim points them at.
//!
//! A parent boots its slots after every block its launch shape carries, each
//! backed by a small placeholder file in its own state directory, and its
//! cmdline declares how many there are. A restored child resolves the
//! parent's state-directory paths to its own, so it needs the same
//! placeholders there before its snapshot loads; the driver then points each
//! slot a claim uses at that claim's image before the child resumes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use mvm_core::vm_backend::VmStartConfig;

use crate::driver::spec::BlockDev;
use crate::driver::traits::LateVolumeAttach;

/// Size of each placeholder. The guest only sees it as an empty device until a
/// claim replaces it; it is never mounted.
pub const PLACEHOLDER_BYTES: u64 = 1024 * 1024;

/// Where slot `index`'s placeholder lives under `state_dir`.
pub fn placeholder_path(state_dir: &Path, index: u8) -> PathBuf {
    state_dir.join(format!("late-volume-{index}.img"))
}

/// Create `slots` sparse placeholders under `state_dir`, leaving any that
/// already exist alone.
pub fn ensure_placeholders(state_dir: &Path, slots: u8) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("creating {}", state_dir.display()))?;
    for index in 0..slots {
        let path = placeholder_path(state_dir, index);
        if path.exists() {
            continue;
        }
        let file = mvm_core::util::atomic_io::open_private_truncated(&path)
            .with_context(|| format!("creating late-volume placeholder {}", path.display()))?;
        file.set_len(PLACEHOLDER_BYTES)
            .with_context(|| format!("sizing late-volume placeholder {}", path.display()))?;
    }
    Ok(())
}

/// The read-only placeholder blocks a parent of `config` boots after every
/// block the launch shape carries.
pub fn parent_slot_blocks(config: &VmStartConfig, state_dir: &Path, slots: u8) -> Vec<BlockDev> {
    let first = super::spec_map::workload_blocks(config).len() as u8;
    (0..slots)
        .map(|index| BlockDev {
            source: placeholder_path(state_dir, index),
            read_only: true,
            ephemeral: false,
            slot: first + index,
        })
        .collect()
}

/// The slot attachments a claimed child of `config` needs: each of its
/// volumes, in order, behind the slot the parent booted at the same position.
///
/// The child's launch shape is the parent's plus its volumes, so the block the
/// workload mapper gives each volume is exactly the slot the parent booted
/// there. Refuses a volume the slots cannot hold, one that is not read-only,
/// and one with no materialized image to serve.
pub fn attachments(config: &VmStartConfig, slots: u8) -> Result<Vec<LateVolumeAttach>> {
    anyhow::ensure!(
        config.volumes.len() <= usize::from(slots),
        "{} volumes requested, but the parent booted {slots} late-volume slots",
        config.volumes.len()
    );
    let blocks = super::spec_map::workload_blocks(config);
    let first = blocks.len() - config.volumes.len();
    config
        .volumes
        .iter()
        .zip(&blocks[first..])
        .map(|(volume, block)| {
            anyhow::ensure!(
                volume.read_only && volume.materialized_image.is_some(),
                "volume {} is not a read-only materialized image, so it cannot be attached \
                 after restore",
                volume.guest
            );
            Ok(LateVolumeAttach {
                slot: block.slot,
                source: block.source.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::VmVolume;

    fn launch() -> VmStartConfig {
        VmStartConfig {
            rootfs_path: "/img/rootfs.ext4".into(),
            verity_path: Some("/img/rootfs.verity".into()),
            ..Default::default()
        }
    }

    fn mount(image: &str, guest: &str) -> VmVolume {
        VmVolume {
            host: "/host/dir".into(),
            guest: guest.into(),
            materialized_image: Some(image.into()),
            read_only: true,
            ..Default::default()
        }
    }

    #[test]
    fn a_parent_boots_its_slots_after_every_launch_block() {
        let state = Path::new("/state/standby");
        let blocks = parent_slot_blocks(&launch(), state, 2);
        assert_eq!(
            blocks.iter().map(|b| b.slot).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(blocks.iter().all(|b| b.read_only));
        assert_eq!(blocks[1].source, placeholder_path(state, 1));
    }

    #[test]
    fn a_childs_volumes_land_on_the_slots_the_parent_booted() {
        let state = Path::new("/state/standby");
        let mut child = launch();
        child.volumes = vec![
            mount("/cache/a.ext4", "/data"),
            mount("/cache/b.ext4", "/work"),
        ];
        let attached = attachments(&child, 4).unwrap();
        let parent = parent_slot_blocks(&launch(), state, 4);
        assert_eq!(attached[0].slot, parent[0].slot);
        assert_eq!(attached[1].slot, parent[1].slot);
        assert_eq!(attached[0].source, PathBuf::from("/cache/a.ext4"));
    }

    #[test]
    fn volumes_the_slots_cannot_serve_are_refused() {
        let mut too_many = launch();
        too_many.volumes = vec![mount("/a", "/data"), mount("/b", "/work")];
        assert!(attachments(&too_many, 1).is_err());

        let mut writable = launch();
        let mut volume = mount("/a", "/data");
        volume.read_only = false;
        writable.volumes = vec![volume];
        assert!(attachments(&writable, 4).is_err());

        let mut disk = launch();
        let mut volume = mount("/a", "/data");
        volume.materialized_image = None;
        disk.volumes = vec![volume];
        assert!(attachments(&disk, 4).is_err());
    }

    #[test]
    fn placeholders_are_created_once_and_sized() {
        let dir = tempfile::tempdir().unwrap();
        ensure_placeholders(dir.path(), 2).unwrap();
        ensure_placeholders(dir.path(), 2).unwrap();
        for index in 0..2 {
            let len = std::fs::metadata(placeholder_path(dir.path(), index))
                .unwrap()
                .len();
            assert_eq!(len, PLACEHOLDER_BYTES);
        }
        assert!(!placeholder_path(dir.path(), 2).exists());
    }
}
