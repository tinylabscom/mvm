//! Pure `VmStartConfig` → `VmmSpec` field mappings. Each function here is a
//! small, driver-independent unit so the workload role's translation of an
//! admitted launch config into a physical `VmmSpec` is testable without a VM.

use std::path::{Path, PathBuf};

use mvm_core::vm_backend::VmStartConfig;
use mvm_guest::vsock::{EGRESS_PORT, GUEST_AGENT_PORT, WORKLOAD_EXIT_PORT};

use crate::driver::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};

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

    // An empty rootfs_path means an initramfs-only guest (no sealed rootfs) —
    // skip the slot-0 disk rather than attach a bogus empty-source virtio-blk.
    let mut blocks = Vec::new();
    if !config.rootfs_path.is_empty() {
        blocks.push(ro(&config.rootfs_path, 0));
    }

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

/// The host-side unix sockets a workload's standing vsock channels bind to.
pub struct WorkloadSockets<'a> {
    /// Agent RPC: the host dials the guest agent listening on `GUEST_AGENT_PORT`.
    pub agent: &'a Path,
    /// Egress gateway: the guest dials `EGRESS_PORT`; the host-side bridge
    /// (claim-10 gate + substitution) listens here — the sole path off the box.
    pub egress_gateway: &'a Path,
    /// Workload exit: the guest dials `WORKLOAD_EXIT_PORT` to report its exit code.
    pub exit: &'a Path,
}

/// The standing vsock ports every workload VM carries: the agent RPC channel the
/// host dials, and the two channels the guest dials — egress (to the host
/// gateway) and exit (to report its status). Console data ports are dev-only and
/// attached separately when a session opens, so they are not part of the sealed
/// workload's fixed set.
pub fn workload_vsock_ports(socks: &WorkloadSockets) -> Vec<VsockPort> {
    vec![
        VsockPort {
            guest_port: GUEST_AGENT_PORT,
            host_uds: socks.agent.into(),
            direction: VsockDirection::HostDials,
        },
        VsockPort {
            guest_port: EGRESS_PORT,
            host_uds: socks.egress_gateway.into(),
            direction: VsockDirection::GuestDials,
        },
        VsockPort {
            guest_port: WORKLOAD_EXIT_PORT,
            host_uds: socks.exit.into(),
            direction: VsockDirection::GuestDials,
        },
    ]
}

/// Everything the workload role resolves before it can build a `VmmSpec`: the
/// admitted config, the host sockets its vsock channels bind to, the assembled
/// kernel cmdline, and the write-only console capture path.
pub struct WorkloadSpecInputs<'a> {
    pub config: &'a VmStartConfig,
    pub sockets: WorkloadSockets<'a>,
    /// The kernel cmdline the role assembled (roothash, overlay args, console).
    pub cmdline: String,
    /// Write-only host capture of the guest console.
    pub console_log: PathBuf,
}

/// Compose a `VmmSpec` from an admitted `VmStartConfig` and the runtime paths the
/// role resolved. The driver-agnostic translation: sealed rootfs + verity/overlay
/// disks, the three standing vsock channels, the kernel, and the write-only
/// console — no NIC, no policy (those live in the role above and the bridge it
/// spawns, never in the spec the driver boots).
pub fn workload_spec(inputs: &WorkloadSpecInputs) -> VmmSpec {
    let config = inputs.config;
    let kernel = match &config.kernel_path {
        Some(path) if !path.is_empty() => KernelImage::Path(path.into()),
        _ => KernelImage::Bundled,
    };
    VmmSpec {
        name: config.name.clone(),
        kernel,
        initramfs: config
            .initrd_path
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from),
        cmdline: inputs.cmdline.clone(),
        vcpus: config.cpus,
        memory_mib: config.memory_mib,
        mem_initial_mib: config.mem_initial_mib,
        blocks: workload_blocks(config),
        vsock: workload_vsock_ports(&inputs.sockets),
        console: ConsoleCapture {
            log_path: inputs.console_log.clone(),
        },
    }
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
    fn empty_rootfs_path_yields_no_blocks() {
        // An initramfs-only guest (e.g. the egress live-proof echo guest) carries no
        // sealed rootfs. An empty `rootfs_path` must not synthesize a bogus
        // empty-source virtio-blk — the legacy backend filtered this before the
        // WorkloadRunner path existed.
        let cfg = VmStartConfig {
            name: "w".into(),
            rootfs_path: String::new(),
            ..Default::default()
        };
        assert!(
            workload_blocks(&cfg).is_empty(),
            "empty rootfs_path must yield no disks"
        );
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

    #[test]
    fn workload_vsock_ports_wire_the_three_standing_channels_with_correct_direction() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
        };
        let ports = workload_vsock_ports(&socks);

        // Agent: host dials the guest; egress + exit: the guest dials the host.
        let by_port: std::collections::HashMap<u32, &VsockPort> =
            ports.iter().map(|p| (p.guest_port, p)).collect();

        let agent = by_port[&GUEST_AGENT_PORT];
        assert_eq!(agent.direction, VsockDirection::HostDials);
        assert_eq!(agent.host_uds, PathBuf::from("/run/agent.sock"));

        let egress = by_port[&EGRESS_PORT];
        assert_eq!(egress.direction, VsockDirection::GuestDials);
        assert_eq!(egress.host_uds, PathBuf::from("/run/egress.sock"));

        let exit = by_port[&WORKLOAD_EXIT_PORT];
        assert_eq!(exit.direction, VsockDirection::GuestDials);
        assert_eq!(exit.host_uds, PathBuf::from("/run/workload.exit"));
    }

    fn sample_sockets() -> WorkloadSockets<'static> {
        WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
        }
    }

    #[test]
    fn workload_spec_composes_kernel_blocks_vsock_and_console() {
        let cfg = VmStartConfig {
            kernel_path: Some("/img/Image".into()),
            verity_path: Some("/img/rootfs.verity".into()),
            cpus: 2,
            memory_mib: 512,
            ..base()
        };
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &cfg,
            sockets: sample_sockets(),
            cmdline: "console=ttyAMA0 root=/dev/vda".into(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.name, "w");
        assert_eq!(spec.kernel, KernelImage::Path(PathBuf::from("/img/Image")));
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.memory_mib, 512);
        assert_eq!(nodes(&spec.blocks), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(spec.vsock.len(), 3);
        assert_eq!(spec.console.log_path, PathBuf::from("/run/console.log"));
    }

    #[test]
    fn workload_spec_maps_initrd_path_to_initramfs() {
        let cfg = VmStartConfig {
            initrd_path: Some("/img/initrd.cpio".into()),
            ..base()
        };
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &cfg,
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.initramfs, Some(PathBuf::from("/img/initrd.cpio")));
    }

    #[test]
    fn workload_spec_without_initrd_has_no_initramfs() {
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.initramfs, None);
    }

    #[test]
    fn workload_spec_falls_back_to_bundled_kernel_without_a_path() {
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.kernel, KernelImage::Bundled);
    }
}
