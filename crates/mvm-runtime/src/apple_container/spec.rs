//! The boot spec the backend hands the container shim (`--spec <path>`).
//!
//! Mirrors the Swift `ShimSpec` in `swift/mvm-container-shim` field for
//! field (snake_case JSON): kernel + initfs for the framework's
//! Virtualization.framework manager, the container rootfs, extra blocks,
//! virtio-fs shares, the control socket, the guest-agent vsock port, and
//! the boot-log directory. The mapping from an admitted `VmStartConfig` is
//! pure so every shape (sealed, plain, volumes, refusals) is unit-testable
//! without a hypervisor.
//!
//! Block order is load-bearing: the framework hands out virtio-blk device
//! letters in attach order, so the layout matches every other backend —
//! rootfs `/dev/vda`, rootfs verity `/dev/vdb`, runtime overlay
//! `/dev/vdc`, overlay verity `/dev/vdd`. Verity sidecars are marked
//! `device_only`: they are not filesystems and must never become an OCI
//! runtime mount.

use std::path::{Path, PathBuf};

use mvm_core::vm_backend::{VmStartConfig, VmVolumeKind};
use serde::{Deserialize, Serialize};

use crate::apple_container_backend::AppleContainerError;

/// The container's root filesystem (mounted at the guest root).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootfsSpec {
    pub path: PathBuf,
    pub read_only: bool,
}

/// One extra virtio-blk device, in attach order (`/dev/vdb` onward).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockSpec {
    pub path: PathBuf,
    pub read_only: bool,
    /// True for blocks that are not mountable filesystems (dm-verity hash
    /// sidecars): the shim defers their attach rather than letting the OCI
    /// runtime try — and fail — to mount them.
    pub device_only: bool,
}

/// One virtio-fs share. `tag` is mvm's activation-contract tag
/// (`uvol{idx}`); `guest_path` is where the framework mounts the share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareSpec {
    pub tag: String,
    pub host_path: PathBuf,
    pub guest_path: String,
    pub read_only: bool,
}

/// The shim's boot description, serialized as snake_case JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppleContainerSpec {
    pub vm_name: String,
    pub kernel_path: PathBuf,
    pub initfs_path: PathBuf,
    pub cpus: u32,
    pub memory_mib: u64,
    pub rootfs: RootfsSpec,
    #[serde(default)]
    pub blocks: Vec<BlockSpec>,
    #[serde(default)]
    pub virtiofs_shares: Vec<ShareSpec>,
    pub control_socket: PathBuf,
    pub agent_port: u32,
    pub boot_log_dir: PathBuf,
}

/// Everything the spec mapping needs that does not come from the launch
/// config: the resolved artifact paths (framework kernel + initfs) and the
/// host paths the shim binds (control socket, boot-log dir). Grouped so
/// the mapping takes one value instead of a positional list.
#[derive(Debug, Clone)]
pub struct SpecInputs<'a> {
    pub kernel_path: &'a Path,
    pub initfs_path: &'a Path,
    pub control_socket: &'a Path,
    pub boot_log_dir: &'a Path,
    /// The guest-agent vsock port the shim reports and the backend dials.
    pub agent_port: u32,
}

/// Refuse every launch shape this backend cannot honestly boot, before
/// any artifact resolution or side effect. Mirrors the wasm/docker tiers'
/// reject-then-build discipline: each check names the limitation.
pub fn reject_unsupported_start_config(
    config: &VmStartConfig,
) -> std::result::Result<(), AppleContainerError> {
    if config.initrd_path.is_some() {
        return Err(AppleContainerError::NotImplemented {
            operation: "boot a caller-supplied initramfs (the framework initfs is fixed)",
            milestone: "a custom-initfs artifact channel",
        });
    }
    if config.virtiofs_root.is_some() {
        return Err(AppleContainerError::VirtiofsRootNotSupported);
    }
    if let Some(volume) = config
        .volumes
        .iter()
        .find(|v| matches!(v.kind, VmVolumeKind::Disk))
    {
        return Err(AppleContainerError::DiskVolumeNotSupported {
            host: volume.host.clone(),
        });
    }
    if config.dev_console {
        return Err(AppleContainerError::NotImplemented {
            operation: "attach an interactive console",
            milestone: "a console transport through the shim",
        });
    }
    if config.rootfs_path.trim().is_empty() {
        return Err(AppleContainerError::NotImplemented {
            operation: "boot without a rootfs",
            milestone: "an initramfs-only boot path",
        });
    }
    Ok(())
}

/// Map an admitted launch config to the shim's boot spec. Pure — the
/// caller has already run [`reject_unsupported_start_config`] and resolved
/// the artifact paths in `inputs`.
pub fn build_apple_container_spec(
    config: &VmStartConfig,
    inputs: &SpecInputs<'_>,
) -> AppleContainerSpec {
    let rootfs = RootfsSpec {
        path: PathBuf::from(&config.rootfs_path),
        // A workload rootfs is sealed: always hypervisor-enforced read-only.
        read_only: true,
    };

    let mut blocks = Vec::new();
    if let Some(verity) = &config.verity_path {
        blocks.push(BlockSpec {
            path: PathBuf::from(verity),
            read_only: true,
            device_only: true,
        });
    }
    // The runtime overlay rides only as a complete triple — the same
    // all-three-or-none rule the other backends apply.
    if let (Some(overlay), Some(overlay_verity), Some(_)) = (
        &config.runtime_overlay_path,
        &config.runtime_overlay_verity_path,
        &config.runtime_overlay_roothash,
    ) {
        blocks.push(BlockSpec {
            path: PathBuf::from(overlay),
            read_only: true,
            device_only: false,
        });
        blocks.push(BlockSpec {
            path: PathBuf::from(overlay_verity),
            read_only: true,
            device_only: true,
        });
    }

    let virtiofs_shares = config
        .volumes
        .iter()
        .enumerate()
        .filter(|(_, v)| matches!(v.kind, VmVolumeKind::DirShare))
        .map(|(idx, v)| ShareSpec {
            tag: format!("uvol{idx}"),
            host_path: PathBuf::from(&v.host),
            guest_path: v.guest.clone(),
            read_only: v.read_only,
        })
        .collect();

    AppleContainerSpec {
        vm_name: config.name.clone(),
        kernel_path: inputs.kernel_path.to_path_buf(),
        initfs_path: inputs.initfs_path.to_path_buf(),
        cpus: config.cpus,
        memory_mib: u64::from(config.memory_mib),
        rootfs,
        blocks,
        virtiofs_shares,
        control_socket: inputs.control_socket.to_path_buf(),
        agent_port: inputs.agent_port,
        boot_log_dir: inputs.boot_log_dir.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_core::vm_backend::{RuntimeSourcePolicy, VmVolume};

    fn cfg(name: &str) -> VmStartConfig {
        VmStartConfig {
            name: name.to_string(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    fn inputs() -> SpecInputs<'static> {
        SpecInputs {
            kernel_path: Path::new("/cache/vmlinux"),
            initfs_path: Path::new("/cache/initfs.ext4"),
            control_socket: Path::new("/state/x/ac-shim.sock"),
            boot_log_dir: Path::new("/state/x/bootlog"),
            agent_port: 5252,
        }
    }

    fn dir_share(host: &str, guest: &str, read_only: bool) -> VmVolume {
        VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        }
    }

    fn disk_volume(host: &str) -> VmVolume {
        VmVolume {
            host: host.into(),
            guest: "/mnt/disk".into(),
            size: "1G".into(),
            read_only: false,
            kind: VmVolumeKind::Disk,
            encrypted: false,
        }
    }

    #[test]
    fn reject_initrd_and_virtiofs_root_and_disk_volumes_and_console_and_empty_rootfs() {
        let mut c = cfg("x");
        c.initrd_path = Some("/img/initrd".into());
        assert!(matches!(
            reject_unsupported_start_config(&c),
            Err(AppleContainerError::NotImplemented { .. })
        ));

        let mut c = cfg("x");
        c.virtiofs_root = Some("/host/oci".into());
        assert_eq!(
            reject_unsupported_start_config(&c),
            Err(AppleContainerError::VirtiofsRootNotSupported)
        );

        let mut c = cfg("x");
        c.volumes = vec![disk_volume("/host/disk.img")];
        assert_eq!(
            reject_unsupported_start_config(&c),
            Err(AppleContainerError::DiskVolumeNotSupported {
                host: "/host/disk.img".into()
            })
        );

        let mut c = cfg("x");
        c.dev_console = true;
        assert!(matches!(
            reject_unsupported_start_config(&c),
            Err(AppleContainerError::NotImplemented { .. })
        ));

        let mut c = cfg("x");
        c.rootfs_path = "  ".into();
        assert!(matches!(
            reject_unsupported_start_config(&c),
            Err(AppleContainerError::NotImplemented { .. })
        ));
    }

    #[test]
    fn plain_config_maps_to_rootfs_only() {
        let spec = build_apple_container_spec(&cfg("plain"), &inputs());
        assert_eq!(spec.vm_name, "plain");
        assert_eq!(spec.rootfs.path, PathBuf::from("/img/rootfs.ext4"));
        assert!(spec.rootfs.read_only, "workload rootfs is sealed ro");
        assert!(spec.blocks.is_empty());
        assert!(spec.virtiofs_shares.is_empty());
        assert_eq!(spec.kernel_path, PathBuf::from("/cache/vmlinux"));
        assert_eq!(spec.initfs_path, PathBuf::from("/cache/initfs.ext4"));
        assert_eq!(spec.control_socket, PathBuf::from("/state/x/ac-shim.sock"));
        assert_eq!(spec.agent_port, 5252);
    }

    #[test]
    fn sealed_config_orders_verity_then_overlay_then_overlay_verity() {
        let mut c = cfg("sealed");
        c.verity_path = Some("/img/rootfs.verity".into());
        c.roothash = Some("ab".repeat(32));
        c.runtime_overlay_path = Some("/img/runtime.ext4".into());
        c.runtime_overlay_verity_path = Some("/img/runtime.verity".into());
        c.runtime_overlay_roothash = Some("cd".repeat(32));
        c.runtime_source_policy = RuntimeSourcePolicy::RequiredOverlay;

        let spec = build_apple_container_spec(&c, &inputs());
        let paths: Vec<&Path> = spec.blocks.iter().map(|b| b.path.as_path()).collect();
        assert_eq!(
            paths,
            vec![
                Path::new("/img/rootfs.verity"),
                Path::new("/img/runtime.ext4"),
                Path::new("/img/runtime.verity"),
            ],
            "verity, overlay, overlay-verity = vdb, vdc, vdd in attach order"
        );
        assert!(spec.blocks[0].device_only);
        assert!(!spec.blocks[1].device_only, "the overlay is mountable ext4");
        assert!(spec.blocks[2].device_only);
        assert!(spec.blocks.iter().all(|b| b.read_only));
    }

    #[test]
    fn partial_overlay_triple_is_treated_as_no_overlay() {
        let mut c = cfg("partial");
        c.runtime_overlay_path = Some("/img/runtime.ext4".into());
        c.runtime_overlay_verity_path = Some("/img/runtime.verity".into());
        let spec = build_apple_container_spec(&c, &inputs());
        assert!(spec.blocks.is_empty());
    }

    #[test]
    fn dir_share_volumes_map_to_shares_with_tags_and_ro_honored() {
        let mut c = cfg("vols");
        c.volumes = vec![
            dir_share("/host/share", "/mnt/share", true),
            dir_share("/host/data", "/mnt/data", false),
        ];
        let spec = build_apple_container_spec(&c, &inputs());
        assert_eq!(spec.virtiofs_shares.len(), 2);
        assert_eq!(spec.virtiofs_shares[0].tag, "uvol0");
        assert_eq!(
            spec.virtiofs_shares[0].host_path,
            PathBuf::from("/host/share")
        );
        assert_eq!(spec.virtiofs_shares[0].guest_path, "/mnt/share");
        assert!(spec.virtiofs_shares[0].read_only);
        assert_eq!(spec.virtiofs_shares[1].tag, "uvol1");
        assert!(!spec.virtiofs_shares[1].read_only);
    }

    #[test]
    fn spec_json_uses_snake_case_keys_the_swift_side_decodes() {
        let mut c = cfg("wire");
        c.verity_path = Some("/img/rootfs.verity".into());
        c.volumes = vec![dir_share("/host/share", "/mnt/share", true)];
        let spec = build_apple_container_spec(&c, &inputs());
        let json = serde_json::to_string(&spec).unwrap();
        for key in [
            "vm_name",
            "kernel_path",
            "initfs_path",
            "memory_mib",
            "read_only",
            "device_only",
            "virtiofs_shares",
            "host_path",
            "guest_path",
            "control_socket",
            "agent_port",
            "boot_log_dir",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "missing key {key}: {json}"
            );
        }
    }
}
