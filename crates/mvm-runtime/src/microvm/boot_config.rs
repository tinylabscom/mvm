//! dm-verity/runtime-overlay helpers and Firecracker API body builders.
//!
//! Backend-agnostic helpers now live in `mvm-vmm::host::boot_config` and are
//! re-exported here while callers migrate. This module retains only the
//! `FlakeRunConfig`-dependent helpers that still need `mvm-runtime` types.

use anyhow::Result;
use tracing::instrument;

pub use mvm_vmm::host::boot_config::*;

use super::flake_run::FlakeRunConfig;

/// Resolve whether the runtime-overlay drives should be attached
/// alongside the rootfs verity sidecar. Returns the
/// `(overlay_ext4_path, overlay_verity_sidecar_path,
/// overlay_roothash)` triple only when all three are present —
/// any missing field disables the overlay attachment so a
/// half-configured workload boots through the legacy
/// rootfs-verity-only path instead of failing with a partial
/// drive map.
pub fn resolved_runtime_overlay(config: &FlakeRunConfig) -> Option<(&str, &str, &str)> {
    Some((
        config.runtime_overlay_path.as_deref()?,
        config.runtime_overlay_verity_path.as_deref()?,
        config.runtime_overlay_roothash.as_deref()?,
    ))
}

/// Configure a flake-built microVM via the Firecracker API (multi-VM).
#[instrument(skip_all, fields(name = %config.name))]
pub fn configure_flake_microvm(config: &FlakeRunConfig, abs_dir: &str, socket: &str) -> Result<()> {
    let _ = (config, abs_dir, socket);
    anyhow::bail!("raw Firecracker flake configuration is disabled; use the vsock workload runner")
}

/// Configure a flake-built microVM with custom config/secrets drive location.
#[instrument(skip_all, fields(name = %config.name))]
pub fn configure_flake_microvm_with_drives_dir(
    config: &FlakeRunConfig,
    abs_dir: &str,
    socket: &str,
    drives_dir: &str,
) -> Result<()> {
    let _ = (config, abs_dir, socket, drives_dir);
    anyhow::bail!("raw Firecracker flake configuration is disabled; use the vsock workload runner")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::VmSlot;

    fn baseline_run_config(mem_initial: Option<u32>) -> FlakeRunConfig {
        FlakeRunConfig {
            name: "v".to_string(),
            slot: VmSlot::new("v", 0),
            vmlinux_path: "/k/vmlinux".to_string(),
            initrd_path: None,
            rootfs_path: "/k/rootfs.ext4".to_string(),
            verity_path: None,
            roothash: None,
            runtime_overlay_path: None,
            runtime_overlay_verity_path: None,
            runtime_overlay_roothash: None,
            revision_hash: "abc".to_string(),
            flake_ref: "/p".to_string(),
            profile: None,
            cpus: 2,
            memory: 1024,
            mem_initial,
            volumes: Vec::new(),
            config_files: Vec::new(),
            secret_files: Vec::new(),
            ports: Vec::new(),
        }
    }

    const OVERLAY_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    #[test]
    fn resolved_runtime_overlay_requires_all_three_fields() {
        let mut cfg = baseline_run_config(None);
        const ROOTFS_HASH: &str =
            "0000000000000000000000000000000000000000000000000000000000000001";
        cfg.roothash = Some(ROOTFS_HASH.into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        cfg.runtime_overlay_path = Some("/k/rootfs.runtime.ext4".into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        cfg.runtime_overlay_verity_path = Some("/k/rootfs.runtime.verity".into());
        assert!(resolved_runtime_overlay(&cfg).is_none());

        cfg.runtime_overlay_roothash = Some(OVERLAY_HASH.into());
        let (p, vp, h) = resolved_runtime_overlay(&cfg).expect("complete triple resolves");
        assert_eq!(p, "/k/rootfs.runtime.ext4");
        assert_eq!(vp, "/k/rootfs.runtime.verity");
        assert_eq!(h, OVERLAY_HASH);
    }

    #[test]
    fn resolved_runtime_overlay_can_feed_non_verity_oci_mount_path() {
        let mut cfg = baseline_run_config(None);
        cfg.roothash = None;
        cfg.runtime_overlay_path = Some("/k/rootfs.runtime.ext4".into());
        cfg.runtime_overlay_verity_path = Some("/k/rootfs.runtime.verity".into());
        cfg.runtime_overlay_roothash = Some(OVERLAY_HASH.into());
        assert!(resolved_runtime_overlay(&cfg).is_some());
        assert_eq!(build_verity_cmdline_args(None, Some(OVERLAY_HASH)), None);
        assert_eq!(
            build_runtime_overlay_cmdline_args(None, true).as_deref(),
            Some("mvm.runtime_data=/dev/vdb")
        );
    }
}
