//! Pure `VmStartConfig` → `VmmSpec` field mappings. Each function here is a
//! small, driver-independent unit so the workload role's translation of an
//! admitted launch config into a physical `VmmSpec` is testable without a VM.

use mvm_core::vm_backend::VmStartConfig;

use crate::driver::BlockDev;

/// The ordered virtio-blk list for a sealed workload: the read-only rootfs at
/// `/dev/vda` (slot 0), its dm-verity Merkle sidecar at `/dev/vdb` (slot 1) when
/// the image was built with verified boot, and — only when the full runtime
/// overlay triple (image + verity sidecar + roothash) is present — the overlay
/// at `/dev/vdc` (slot 2) and its verity sidecar at `/dev/vdd` (slot 3).
///
/// Every device is read-only: a workload rootfs is sealed, and the verity
/// sidecars are integrity data the guest only reads. The all-three-or-none
/// overlay rule mirrors `VmStartConfig`'s own contract — a partial overlay set
/// is treated as no overlay rather than a half-configured boot.
pub fn workload_blocks(config: &VmStartConfig) -> Vec<BlockDev> {
    let ro = |source: &str, slot: u8| BlockDev {
        source: source.into(),
        read_only: true,
        slot,
    };

    let mut blocks = vec![ro(&config.rootfs_path, 0)];

    if let Some(verity) = &config.verity_path {
        blocks.push(ro(verity, 1));
    }

    if let (Some(overlay), Some(overlay_verity), Some(_roothash)) = (
        &config.runtime_overlay_path,
        &config.runtime_overlay_verity_path,
        &config.runtime_overlay_roothash,
    ) {
        blocks.push(ro(overlay, 2));
        blocks.push(ro(overlay_verity, 3));
    }

    blocks
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn base() -> VmStartConfig {
        VmStartConfig {
            name: "w".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    fn nodes(blocks: &[BlockDev]) -> Vec<String> {
        blocks.iter().map(BlockDev::device_node).collect()
    }

    #[test]
    fn rootfs_only_maps_to_a_single_read_only_vda() {
        let blocks = workload_blocks(&base());
        assert_eq!(nodes(&blocks), vec!["/dev/vda"]);
        assert_eq!(blocks[0].source, PathBuf::from("/img/rootfs.ext4"));
        assert!(blocks[0].read_only);
    }

    #[test]
    fn verity_sidecar_lands_at_vdb() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(nodes(&blocks), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(blocks[1].source, PathBuf::from("/img/rootfs.verity"));
    }

    #[test]
    fn full_overlay_triple_adds_vdc_and_vdd() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(
            nodes(&blocks),
            vec!["/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd"]
        );
        assert!(blocks.iter().all(|b| b.read_only));
    }

    #[test]
    fn partial_overlay_set_is_treated_as_no_overlay() {
        // Overlay image + verity present but roothash missing: the all-three-or-none
        // rule drops the overlay rather than booting a half-configured second target.
        let cfg = VmStartConfig {
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: None,
            ..base()
        };
        assert_eq!(nodes(&workload_blocks(&cfg)), vec!["/dev/vda"]);
    }
}
