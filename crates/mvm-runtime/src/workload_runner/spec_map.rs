//! Pure `VmStartConfig` → `VmmSpec` field mappings. Each function here is a
//! small, driver-independent unit so the workload role's translation of an
//! admitted launch config into a physical `VmmSpec` is testable without a VM.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use mvm_agentd::vsock::{
    BROKER_PORT, EGRESS_PORT, GUEST_AGENT_PORT, WORKLOAD_EXIT_PORT, dev_console_data_ports,
};
use mvm_core::config::vm_hvf_vsock_port_socket_at;
use mvm_core::vm_backend::{VmStartConfig, VmVolumeKind};

use crate::driver::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};

/// The ordered virtio-blk list for a sealed workload: the read-only rootfs at
/// `/dev/vda` (slot 0), its dm-verity Merkle sidecar at `/dev/vdb` (slot 1) when
/// the image was built with verified boot, and — only when the full runtime
/// overlay triple (image + verity sidecar + roothash) is present — the overlay
/// at `/dev/vdc` (slot 2) and its verity sidecar at `/dev/vdd` (slot 3). After
/// those, every `Disk`-kind entry in `config.volumes` (a sealed app-dep volume
/// or other `--volume` disk image) lands at the next free slot, in `volumes`
/// order — the same order `encode_user_volumes_cmdline` walks to number its
/// `uvol{idx}` tokens, so the Nth appended volume block matches the Nth
/// `mvm.uvols=` entry. A `DirShare` volume has no block-device representation
/// and is skipped here; callers must refuse it before reaching this function
/// (see `ensure_no_dir_share_volumes`) rather than relying on this silent skip.
///
/// The rootfs/verity/overlay devices are read-only: a workload rootfs is
/// sealed, and the verity sidecars are integrity data the guest only reads.
/// The all-three-or-none overlay rule mirrors `VmStartConfig`'s own contract —
/// a partial overlay set is treated as no overlay rather than a
/// half-configured boot. A volume's `read_only` flag is the caller's own
/// choice, carried through verbatim.
///
/// An empty `rootfs_path` yields no disks at all — an initramfs-only guest boots
/// entirely from RAM (matching `HvfBackend`'s own empty-path skip). The verity,
/// overlay, and user-volume disks all presuppose a rootfs, so they are dropped
/// with it.
pub fn workload_blocks(config: &VmStartConfig) -> Vec<BlockDev> {
    let ro = |source: &str, slot: u8| BlockDev {
        source: source.into(),
        read_only: true,
        // Read-only blocks are file-served (hypervisor-enforced RO), never RAM-backed.
        ephemeral: false,
        slot,
    };

    if config.rootfs_path.is_empty() {
        return Vec::new();
    }

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

    for volume in config
        .volumes
        .iter()
        .filter(|v| matches!(v.kind, VmVolumeKind::Disk))
    {
        let slot = blocks.len() as u8;
        blocks.push(BlockDev {
            source: volume.host.clone().into(),
            read_only: volume.read_only,
            // A sealed app-dep / user-supplied disk persists to the host file
            // like the rootfs — never RAM-backed, so a writable volume's
            // mutations actually land on disk instead of vanishing on exit.
            ephemeral: false,
            slot,
        });
    }

    blocks
}

/// Resolve the guest block device for each configured volume.
///
/// The returned entries preserve `config.volumes` order. Directory shares have
/// no block device and therefore produce `None`; disk volumes resolve to the
/// exact `/dev/vd*` node present in [`workload_blocks`]. Keeping this mapping
/// here makes callers use the same slot calculation as the VMM and the guest
/// activation path.
pub fn workload_volume_devices(config: &VmStartConfig) -> Vec<Option<String>> {
    let blocks = workload_blocks(config);
    let disk_count = config
        .volumes
        .iter()
        .filter(|volume| matches!(volume.kind, VmVolumeKind::Disk))
        .count();
    let first_user_block = blocks.len().saturating_sub(disk_count);
    let mut block_devices = blocks[first_user_block..]
        .iter()
        .map(crate::driver::BlockDev::device_node);

    config
        .volumes
        .iter()
        .map(|volume| match volume.kind {
            VmVolumeKind::DirShare => None,
            VmVolumeKind::Disk => block_devices.next(),
        })
        .collect()
}

/// The guest device node the SDK sidecar lands on for this launch config, or
/// `None` when no sidecar is attached.
///
/// Derived from [`workload_blocks`] rather than recomputed, so the device the
/// guest is told to mount is by construction the device the VMM attached. The
/// guest cannot derive this itself: the sidecar's slot depends on whether the
/// boot carries a verity sidecar, a runtime overlay, and how many user volumes
/// precede it.
pub fn sdk_sidecar_block_device(config: &VmStartConfig) -> Option<String> {
    let sidecar_index = config.volumes.iter().position(|v| {
        v.guest == mvm_core::plan::SDK_SIDECAR_GUEST_PATH && matches!(v.kind, VmVolumeKind::Disk)
    })?;
    workload_volume_devices(config)
        .get(sidecar_index)
        .cloned()
        .flatten()
}

/// Refuse a `DirShare` volume before a `VmmSpec` is assembled: the runner's
/// `VmmSpec` has no virtio-fs device, so a directory share can't be expressed
/// on this path (unlike a `Disk` volume, which becomes a `BlockDev`). Fails
/// closed with the offending volume named, rather than letting
/// `workload_blocks` silently drop it. `VmmSpec.shares` (virtio-fs) is a
/// deferred follow-up; the dev-tier `virtiofs_root` flat share is a separate,
/// unrelated field and out of scope here.
pub fn ensure_no_dir_share_volumes(config: &VmStartConfig) -> Result<()> {
    if let Some(v) = config
        .volumes
        .iter()
        .find(|v| matches!(v.kind, VmVolumeKind::DirShare))
    {
        bail!(
            "directory-share volume '{}' -> '{}' cannot be attached: the WorkloadRunner has no \
             virtio-fs device yet, so a live host-directory share can't be expressed. Use a \
             disk-image volume instead (host:/guest:SIZE), or run this workload on a backend \
             with virtio-fs support.",
            v.host,
            v.guest
        );
    }
    Ok(())
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
    /// Host-services broker: the guest dials `BROKER_PORT`; the per-VM broker (or
    /// the per-tenant host-agent daemon) binds here to serve `host.audit.v1` /
    /// `host.secrets.v1`. Present only for an **admitted** workload — an
    /// unadmitted VM carries no broker port, so a stray guest dial stays
    /// `ECONNREFUSED` (fail-closed).
    pub broker: Option<&'a Path>,
    /// Dev-only interactive console data ports: one host UDS per port in
    /// `dev_console_data_ports()`, pre-opened so a PTY can attach. Empty for
    /// sealed prod boots (`dev_console = false` in `VmStartConfig`).
    pub console_data: Vec<(u32, PathBuf)>,
}

/// The standing vsock ports every workload VM carries: the agent RPC channel the
/// host dials, the channels the guest dials (egress + exit, plus the broker when
/// admitted), and — only when `dev_console` is set — the pre-opened interactive
/// console data ports.
pub fn workload_vsock_ports(socks: &WorkloadSockets) -> Vec<VsockPort> {
    let mut ports = vec![
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
    ];
    // Only an admitted workload carries the broker channel; an unadmitted VM
    // gets none, so a stray guest dial to BROKER_PORT stays ECONNREFUSED.
    if let Some(broker) = socks.broker {
        ports.push(VsockPort {
            guest_port: BROKER_PORT,
            host_uds: broker.into(),
            direction: VsockDirection::GuestDials,
        });
    }
    // The guest agent allocates `CONSOLE_PORT_BASE + session_id` per ConsoleOpen
    // and listens there; the host dials in to fetch the PTY stream. Pre-open only
    // when `dev_console` is true — a sealed prod boot carries none (claim 15).
    for (port, path) in &socks.console_data {
        ports.push(VsockPort {
            guest_port: *port,
            host_uds: path.clone(),
            direction: VsockDirection::HostDials,
        });
    }
    ports
}

/// Build the per-port (port, host-UDS) list for the interactive console data
/// range, rooted under the shared HVF-style socket helper (`<socket-dir>/vsock/`).
/// Returns an empty vec when `dev_console` is false (claim 15: sealed prod boots
/// carry no console listeners).
pub fn console_data_sockets(state_dir: &Path, dev_console: bool) -> Vec<(u32, PathBuf)> {
    if !dev_console {
        return Vec::new();
    }
    dev_console_data_ports()
        .map(|port| (port, vm_hvf_vsock_port_socket_at(state_dir, port)))
        .collect()
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

/// Everything a guest can observe about how it was booted: its identity, the
/// kernel and initramfs, the assembled cmdline, the cpu/memory shape, and the
/// ordered disk stack. Host-side plumbing is deliberately absent — the returned
/// spec wires no vsock channels, and the caller adds the ones its role is
/// entitled to.
///
/// Split out from [`workload_spec`] because a warm-pool factory parent must
/// boot the identical device model and cmdline a workload does — every child
/// restored from that parent inherits both out of the saved memory image, so a
/// parent assembled by a second, hand-written recipe hands its divergence to
/// every child forever. There is exactly one mapping, and both callers use it.
pub fn workload_device_spec(config: &VmStartConfig, cmdline: &str, console_log: &Path) -> VmmSpec {
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
        cmdline: cmdline.to_string(),
        vcpus: config.cpus,
        memory_mib: config.memory_mib,
        mem_initial_mib: config.mem_initial_mib,
        blocks: workload_blocks(config),
        // The caller's role decides which host channels it may wire.
        vsock: Vec::new(),
        console: ConsoleCapture {
            log_path: console_log.to_path_buf(),
        },
        // A workload is untrusted: it must route egress through the gated endpoint.
        trusted_builder: false,
    }
}

/// Compose a `VmmSpec` from an admitted `VmStartConfig` and the runtime paths the
/// role resolved: the shared device model plus the standing vsock channels a
/// workload is entitled to (agent, egress, exit, and — when admitted — broker).
/// No NIC, no policy (those live in the role above and the bridge it spawns,
/// never in the spec the driver boots).
pub fn workload_spec(inputs: &WorkloadSpecInputs) -> VmmSpec {
    VmmSpec {
        vsock: workload_vsock_ports(&inputs.sockets),
        ..workload_device_spec(inputs.config, &inputs.cmdline, &inputs.console_log)
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
    fn rootfs_only_maps_to_a_single_read_only_vda() {
        let blocks = workload_blocks(&base());
        assert_eq!(nodes(&blocks), vec!["/dev/vda"]);
        assert_eq!(blocks[0].source, PathBuf::from("/img/rootfs.ext4"));
        assert!(blocks[0].read_only);
    }

    #[test]
    fn empty_rootfs_yields_no_blocks() {
        // An initramfs-only guest boots from RAM: no rootfs disk, and the verity /
        // overlay disks (which presuppose a rootfs) are dropped with it.
        let cfg = VmStartConfig {
            rootfs_path: String::new(),
            verity_path: Some("/img/rootfs.verity".into()),
            ..base()
        };
        assert!(workload_blocks(&cfg).is_empty());
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

    fn disk_volume(host: &str, guest: &str, read_only: bool) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only,
            kind: VmVolumeKind::Disk,
            encrypted: false,
        }
    }

    fn dir_share_volume(host: &str, guest: &str) -> mvm_core::vm_backend::VmVolume {
        mvm_core::vm_backend::VmVolume {
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only: false,
            kind: VmVolumeKind::DirShare,
            encrypted: false,
        }
    }

    #[test]
    fn a_disk_volume_lands_at_slot_4_after_the_full_base_stack() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            volumes: vec![disk_volume("/vol/data.img", "/data", true)],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(
            nodes(&blocks),
            vec!["/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vde"]
        );
        let vol_block = &blocks[4];
        assert_eq!(vol_block.source, PathBuf::from("/vol/data.img"));
        assert!(vol_block.read_only);
        assert!(!vol_block.ephemeral);
    }

    #[test]
    fn volume_devices_follow_the_attached_block_slots() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            volumes: vec![
                disk_volume("/vol/first.img", "/first", true),
                dir_share_volume("/host/share", "/share"),
                disk_volume("/vol/second.img", "/second", false),
            ],
            ..base()
        };
        assert_eq!(
            workload_volume_devices(&cfg),
            vec![Some("/dev/vde".into()), None, Some("/dev/vdf".into())]
        );
    }

    fn sdk_sidecar_volume(host: &str) -> mvm_core::vm_backend::VmVolume {
        disk_volume(host, mvm_core::plan::SDK_SIDECAR_GUEST_PATH, true)
    }

    #[test]
    fn no_sidecar_volume_resolves_no_sidecar_device() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            volumes: vec![disk_volume("/vol/data.img", "/data", true)],
            ..base()
        };
        assert_eq!(sdk_sidecar_block_device(&cfg), None);
    }

    #[test]
    fn a_sealed_boot_lands_the_sidecar_at_slot_4() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            volumes: vec![sdk_sidecar_volume("/cache/sdk.ext4")],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(
            nodes(&blocks),
            vec!["/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vde"]
        );
        assert!(blocks[4].read_only, "the sidecar attaches read-only");
        assert_eq!(sdk_sidecar_block_device(&cfg).as_deref(), Some("/dev/vde"));
    }

    /// A user volume ahead of the sidecar shifts the sidecar's device, and the
    /// resolved token follows it — this is exactly why the guest can't derive
    /// the slot on its own.
    #[test]
    fn a_preceding_user_volume_shifts_the_sidecar_device() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            volumes: vec![
                disk_volume("/vol/data.img", "/data", false),
                sdk_sidecar_volume("/cache/sdk.ext4"),
            ],
            ..base()
        };
        assert_eq!(
            nodes(&workload_blocks(&cfg)),
            vec![
                "/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vde", "/dev/vdf"
            ]
        );
        assert_eq!(sdk_sidecar_block_device(&cfg).as_deref(), Some("/dev/vdf"));
    }

    /// An unsealed boot has no verity or overlay pair, so the sidecar lands
    /// immediately after the rootfs. The device the guest is told to mount must
    /// track that, not a baked constant.
    #[test]
    fn an_unsealed_boot_lands_the_sidecar_right_after_the_rootfs() {
        let cfg = VmStartConfig {
            volumes: vec![sdk_sidecar_volume("/cache/sdk.ext4")],
            ..base()
        };
        assert_eq!(nodes(&workload_blocks(&cfg)), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(sdk_sidecar_block_device(&cfg).as_deref(), Some("/dev/vdb"));
    }

    /// A directory share at the sidecar mount point is not a sidecar
    /// attachment; the admission gate already refuses it, and this resolver
    /// must not paper over it by naming a block device that was never attached.
    #[test]
    fn a_dir_share_at_the_sidecar_path_resolves_no_device() {
        let cfg = VmStartConfig {
            volumes: vec![dir_share_volume(
                "/cache/sdk",
                mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
            )],
            ..base()
        };
        assert_eq!(sdk_sidecar_block_device(&cfg), None);
    }

    #[test]
    fn two_disk_volumes_preserve_order_at_slots_4_and_5() {
        let cfg = VmStartConfig {
            verity_path: Some("/img/rootfs.verity".into()),
            runtime_overlay_path: Some("/img/overlay.ext4".into()),
            runtime_overlay_verity_path: Some("/img/overlay.verity".into()),
            runtime_overlay_roothash: Some("ab".repeat(32)),
            volumes: vec![
                disk_volume("/vol/first.img", "/first", true),
                disk_volume("/vol/second.img", "/second", false),
            ],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(
            nodes(&blocks),
            vec![
                "/dev/vda", "/dev/vdb", "/dev/vdc", "/dev/vdd", "/dev/vde", "/dev/vdf"
            ]
        );
        assert_eq!(blocks[4].source, PathBuf::from("/vol/first.img"));
        assert!(blocks[4].read_only);
        assert_eq!(blocks[5].source, PathBuf::from("/vol/second.img"));
        assert!(!blocks[5].read_only);
    }

    #[test]
    fn a_disk_volume_with_no_verity_or_overlay_lands_right_after_the_rootfs() {
        let cfg = VmStartConfig {
            volumes: vec![disk_volume("/vol/data.img", "/data", false)],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert_eq!(nodes(&blocks), vec!["/dev/vda", "/dev/vdb"]);
        assert_eq!(blocks[1].source, PathBuf::from("/vol/data.img"));
    }

    #[test]
    fn a_dir_share_volume_is_skipped_by_workload_blocks() {
        // workload_blocks itself has no Result to refuse through; the fail-closed
        // guard lives in `ensure_no_dir_share_volumes`, which callers must run
        // first. This only proves the low-level mapper never fabricates a bogus
        // block device for a share it can't express.
        let cfg = VmStartConfig {
            volumes: vec![dir_share_volume("/host/dir", "/mnt")],
            ..base()
        };
        assert_eq!(nodes(&workload_blocks(&cfg)), vec!["/dev/vda"]);
    }

    #[test]
    fn ensure_no_dir_share_volumes_accepts_disk_only_configs() {
        let cfg = VmStartConfig {
            volumes: vec![disk_volume("/vol/data.img", "/data", true)],
            ..base()
        };
        assert!(ensure_no_dir_share_volumes(&cfg).is_ok());
    }

    #[test]
    fn ensure_no_dir_share_volumes_refuses_and_names_the_volume() {
        let cfg = VmStartConfig {
            volumes: vec![
                disk_volume("/vol/data.img", "/data", true),
                dir_share_volume("/host/dir", "/mnt/share"),
            ],
            ..base()
        };
        let err = ensure_no_dir_share_volumes(&cfg)
            .expect_err("a DirShare volume must be refused, not silently dropped");
        let message = err.to_string();
        assert!(message.contains("/host/dir"), "message: {message}");
        assert!(message.contains("/mnt/share"), "message: {message}");
    }

    #[test]
    fn workload_vsock_ports_wire_the_three_standing_channels_with_correct_direction() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            broker: None,
            console_data: Vec::new(),
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
            broker: None,
            console_data: Vec::new(),
        }
    }

    #[test]
    fn workload_vsock_ports_emit_the_broker_channel_only_when_admitted() {
        // Admitted (broker socket present) ⇒ a BROKER_PORT GuestDials channel.
        let admitted = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            broker: Some(Path::new("/run/broker.sock")),
            console_data: Vec::new(),
        };
        let broker = workload_vsock_ports(&admitted)
            .into_iter()
            .find(|p| p.guest_port == BROKER_PORT)
            .expect("admitted VM carries the broker channel");
        assert_eq!(broker.direction, VsockDirection::GuestDials);
        assert_eq!(broker.host_uds, PathBuf::from("/run/broker.sock"));

        // Unadmitted (broker None) ⇒ no BROKER_PORT channel, so a stray guest
        // dial stays ECONNREFUSED.
        let unadmitted = WorkloadSockets {
            broker: None,
            ..sample_sockets()
        };
        assert!(
            workload_vsock_ports(&unadmitted)
                .iter()
                .all(|p| p.guest_port != BROKER_PORT),
            "unadmitted VM must carry no broker port"
        );
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

    // --- console_data_sockets / dev_console gating ---

    #[test]
    fn console_data_sockets_returns_empty_when_dev_console_is_false() {
        let sockets = console_data_sockets(Path::new("/state/w"), false);
        assert!(
            sockets.is_empty(),
            "sealed prod boot must carry no console listeners"
        );
    }

    #[test]
    fn console_data_sockets_returns_128_entries_when_dev_console_is_true() {
        let sockets = console_data_sockets(Path::new("/state/w"), true);
        assert_eq!(
            sockets.len(),
            128,
            "pre-open all 128 console data ports when dev_console is set"
        );
    }

    #[test]
    fn console_data_sockets_paths_follow_hvf_convention() {
        use mvm_agentd::vsock::CONSOLE_PORT_BASE;
        let state_dir = Path::new("/state/myvm");
        let sockets = console_data_sockets(state_dir, true);

        // First port: CONSOLE_PORT_BASE + 1 = 20001
        let (port, path) = &sockets[0];
        assert_eq!(*port, CONSOLE_PORT_BASE + 1);
        assert_eq!(
            path,
            &mvm_core::config::vm_hvf_vsock_port_socket_at(state_dir, *port),
            "path must follow the shared HVF-socket helper"
        );

        // Last port: CONSOLE_PORT_BASE + 128 = 20128
        let (last_port, last_path) = &sockets[127];
        assert_eq!(*last_port, CONSOLE_PORT_BASE + 128);
        assert_eq!(
            last_path,
            &mvm_core::config::vm_hvf_vsock_port_socket_at(state_dir, *last_port)
        );
    }

    #[test]
    fn workload_vsock_ports_with_dev_console_carries_128_console_ports() {
        use mvm_agentd::vsock::CONSOLE_PORT_BASE;
        let state_dir = Path::new("/state/w");
        let console_data = console_data_sockets(state_dir, true);
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            broker: None,
            console_data,
        };
        let ports = workload_vsock_ports(&socks);

        // 3 standing + 128 console = 131
        assert_eq!(ports.len(), 131);

        // All console ports are HostDials and land in the expected range.
        let console_ports: Vec<_> = ports
            .iter()
            .filter(|p| p.guest_port > CONSOLE_PORT_BASE)
            .collect();
        assert_eq!(console_ports.len(), 128);
        assert!(
            console_ports
                .iter()
                .all(|p| p.direction == VsockDirection::HostDials),
            "host dials the guest-side console listener"
        );
    }

    #[test]
    fn workload_vsock_ports_without_dev_console_carries_only_three_ports() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Path::new("/run/egress.sock"),
            exit: Path::new("/run/workload.exit"),
            broker: None,
            console_data: Vec::new(),
        };
        let ports = workload_vsock_ports(&socks);
        assert_eq!(ports.len(), 3, "no console ports on a sealed prod boot");
    }

    #[test]
    fn workload_spec_with_dev_console_carries_131_vsock_entries() {
        let state_dir = Path::new("/state/w");
        let console_data = console_data_sockets(state_dir, true);
        let cfg = VmStartConfig {
            dev_console: true,
            ..base()
        };
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &cfg,
            sockets: WorkloadSockets {
                agent: Path::new("/run/agent.sock"),
                egress_gateway: Path::new("/run/egress.sock"),
                exit: Path::new("/run/workload.exit"),
                broker: None,
                console_data,
            },
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.vsock.len(), 131);
    }

    #[test]
    fn workload_spec_without_dev_console_carries_three_vsock_entries() {
        let spec = workload_spec(&WorkloadSpecInputs {
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.vsock.len(), 3);
    }
}
