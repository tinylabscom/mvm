//! Pure `VmStartConfig` → `VmmSpec` field mappings. Each function here is a
//! small, driver-independent unit so the workload role's translation of an
//! admitted launch config into a physical `VmmSpec` is testable without a VM.

use std::path::{Path, PathBuf};

use mvm_agentd::vsock::dev_console_data_ports;
use mvm_core::config::vm_hvf_vsock_port_socket_at;
use mvm_core::vm_backend::VmStartConfig;
use mvm_net::channel::GuestService;

use crate::driver::spec::{
    BlockDev, ConsoleCapture, KernelImage, PlanBinding, VmmSpec, VsockDirection, VsockPort,
};

/// The ordered virtio-blk list for a sealed workload: the read-only rootfs at
/// `/dev/vda` (slot 0), its dm-verity Merkle sidecar at `/dev/vdb` (slot 1) when
/// the image was built with verified boot, and — only when the full runtime
/// overlay triple (image + verity sidecar + roothash) is present — the overlay
/// at `/dev/vdc` (slot 2) and its verity sidecar at `/dev/vdd` (slot 3). After
/// those, every `Disk`-kind entry in `config.volumes` (a sealed app-dep volume
/// or other `--volume` disk image) lands at the next free slot, in `volumes`
/// order — the same order `encode_user_volumes_cmdline` walks to number its
/// `uvol{idx}` tokens, so the Nth appended volume block matches the Nth
/// `mvm.uvols=` entry. Every volume has a block-device representation.
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
        blocks.push(ro(verity, blocks.len() as u8));
    }

    if let (Some(overlay), Some(overlay_verity), Some(_roothash)) = (
        &config.runtime_overlay_path,
        &config.runtime_overlay_verity_path,
        &config.runtime_overlay_roothash,
    ) {
        blocks.push(ro(overlay, blocks.len() as u8));
        blocks.push(ro(overlay_verity, blocks.len() as u8));
    }

    for volume in &config.volumes {
        let slot = blocks.len() as u8;
        blocks.push(BlockDev {
            source: volume.block_source().to_string().into(),
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
/// The returned entries preserve `config.volumes` order. Every user volume is
/// a block image and resolves to the exact `/dev/vd*` node present in
/// [`workload_blocks`]. Keeping this mapping here makes callers use the same
/// slot calculation as the VMM and the guest activation path.
pub fn workload_volume_devices(config: &VmStartConfig) -> Vec<Option<String>> {
    let blocks = workload_blocks(config);
    let disk_count = config.volumes.len();
    let first_user_block = blocks.len().saturating_sub(disk_count);
    let mut block_devices = blocks[first_user_block..].iter().map(BlockDev::device_node);

    config
        .volumes
        .iter()
        .map(|_| block_devices.next())
        .collect()
}

/// Return whether a configured volume is the reserved SDK sidecar.
///
/// The sidecar is physically a disk, but it is not a user volume: the guest
/// mounts it through the dedicated `mvm.sdk_dev` contract at `/mvm/sdk`.
pub fn is_sdk_sidecar_volume(volume: &mvm_core::vm_backend::VmVolume) -> bool {
    volume.guest == mvm_core::plan::SDK_SIDECAR_GUEST_PATH && volume.materialized_image.is_none()
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
    let sidecar_index = config.volumes.iter().position(is_sdk_sidecar_volume)?;
    workload_volume_devices(config)
        .get(sidecar_index)
        .cloned()
        .flatten()
}

/// The host-side unix sockets a workload's standing vsock channels bind to.
pub struct WorkloadSockets<'a> {
    /// Agent RPC: the host dials the guest agent listening on `GUEST_AGENT_PORT`.
    pub agent: &'a Path,
    /// Egress gateway: the guest dials `EGRESS_PORT`; the host-side bridge
    /// (claim-10 gate + substitution) listens here — the sole path off the box.
    /// `None` means the admitted policy grants no egress and the guest carries
    /// no host egress channel, which is fail-closed.
    pub egress_gateway: Option<&'a Path>,
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
            service: GuestService::MachineControl,
            host_uds: socks.agent.into(),
            direction: VsockDirection::HostDials,
        },
        VsockPort {
            service: GuestService::WorkloadExit,
            host_uds: socks.exit.into(),
            direction: VsockDirection::GuestDials,
        },
    ];
    if let Some(egress_gateway) = socks.egress_gateway {
        ports.push(VsockPort {
            service: GuestService::NetworkFlow,
            host_uds: egress_gateway.into(),
            direction: VsockDirection::GuestDials,
        });
    }
    // Only an admitted workload carries the broker channel; an unadmitted VM
    // gets none, so a stray guest dial to BROKER_PORT stays ECONNREFUSED.
    if let Some(broker) = socks.broker {
        ports.push(VsockPort {
            service: GuestService::Broker,
            host_uds: broker.into(),
            direction: VsockDirection::GuestDials,
        });
    }
    // The guest agent allocates `CONSOLE_PORT_BASE + session_id` per ConsoleOpen
    // and listens there; the host dials in to fetch the PTY stream. Pre-open only
    // when `dev_console` is true — a sealed prod boot carries none (claim 15).
    for (port, path) in &socks.console_data {
        ports.push(VsockPort {
            service: GuestService::ConsoleData { port: *port },
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

/// Build the per-port (port, host-UDS) list for a persistent builder VM's
/// control plane: job dispatch and the resident daemon's typed channel. Same
/// shape and socket convention as [`console_data_sockets`], and the same
/// fail-closed default — a non-builder VM gets an empty list, so no workload
/// can be handed a listener on the build engine's ports.
///
/// The guest end of both exists only while `mvm-host-vm-init` is running its
/// dispatch loop, which happens only for a builder VM started as a long-lived
/// session.
pub fn builder_control_sockets(state_dir: &Path, builder_tier: bool) -> Vec<(u32, PathBuf)> {
    if !builder_tier {
        return Vec::new();
    }
    [
        GuestService::BuilderDispatch.port(),
        GuestService::BuilderdControl.port(),
    ]
    .into_iter()
    .map(|port| (port, vm_hvf_vsock_port_socket_at(state_dir, port)))
    .collect()
}

/// Everything the workload role resolves before it can build a `VmmSpec`: the
/// admitted config, the host sockets its vsock channels bind to, the assembled
/// kernel cmdline, and the write-only console capture path.
pub struct WorkloadSpecInputs<'a> {
    pub config: &'a VmStartConfig,
    /// This boot's FlowMux identity drive, when it minted one. Appended after
    /// every other block and found in the guest by ext4 label, so the volumes
    /// above cannot shift it out from under the guest.
    pub identity_drive: Option<&'a Path>,
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
        cpu_grant: config.cpu_grant,
        memory_mib: config.memory_mib,
        mem_initial_mib: config.mem_initial_mib,
        blocks: workload_blocks(config),
        // The caller's role decides which host channels it may wire.
        vsock: Vec::new(),
        console: ConsoleCapture {
            log_path: console_log.to_path_buf(),
        },
        // A workload carries no virtio-fs device. A granted directory is
        // materialized into a block image, and the dev-tier virtiofs root is
        // gone, so nothing is left to put in this list. `VmmSpec.shares` stays
        // on the type because the builder VM still uses it.
        shares: Vec::new(),
        trusted_builder: false,
        // Workload launches spawn their own endpoint and stay alive for the
        // VM's whole life, so there is no supervisor-owned one to ask for.
        builder_egress_endpoint: None,
        plan_binding: workload_plan_binding(config),
    }
}

/// The plan plus the audit paths a supervisor needs to enforce that plan's
/// wall-clock bound and record the kill, or `None` when the launch carries no
/// admitted plan.
///
/// Malformed `plan_json` yields `None` rather than an error: this mapping is
/// infallible by construction, and a plan the supervisor cannot parse would
/// fail its own re-verification regardless. Whether a bound actually exists is
/// the supervisor's read of `resources.timeouts.exec_secs`; this only makes one
/// enforceable.
fn workload_plan_binding(config: &VmStartConfig) -> Option<PlanBinding> {
    let plan_json = serde_json::from_str(config.plan_json.as_deref()?).ok()?;
    Some(PlanBinding {
        plan_json,
        audit_dir: mvm_core::config::mvm_audit_dir(),
        signing_key_path: mvm_core::config::mvm_keys_dir().join(HOST_SIGNER_KEY_FILE),
    })
}

/// File name of the host signing key inside [`mvm_core::config::mvm_keys_dir`].
const HOST_SIGNER_KEY_FILE: &str = "host-signer.ed25519";

/// Compose a `VmmSpec` from an admitted `VmStartConfig` and the runtime paths the
/// role resolved: the shared device model plus the standing vsock channels a
/// workload is entitled to (agent, egress, exit, and — when admitted — broker).
/// No NIC, no policy (those live in the role above and the bridge it spawns,
/// never in the spec the driver boots).
pub fn workload_spec(inputs: &WorkloadSpecInputs) -> VmmSpec {
    let mut spec = VmmSpec {
        vsock: workload_vsock_ports(&inputs.sockets),
        ..workload_device_spec(inputs.config, &inputs.cmdline, &inputs.console_log)
    };
    if let Some(drive) = inputs.identity_drive {
        let slot = spec.blocks.len() as u8;
        spec.blocks.push(BlockDev {
            source: drive.to_path_buf(),
            read_only: true,
            ephemeral: false,
            slot,
        });
    }
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use mvm_agentd::vsock::{EGRESS_PORT, GUEST_AGENT_PORT, WORKLOAD_EXIT_PORT};
    use mvm_core::vm_backend::{VmVolume, VmVolumeKind};
    use std::path::PathBuf;

    fn base() -> VmStartConfig {
        VmStartConfig {
            name: "w".into(),
            rootfs_path: "/img/rootfs.ext4".into(),
            ..Default::default()
        }
    }

    fn granted_dir(host: &str, guest: &str, image: &str) -> VmVolume {
        VmVolume {
            host: host.into(),
            guest: guest.into(),
            read_only: true,
            kind: VmVolumeKind::Disk,
            materialized_image: Some(image.to_string()),
            volume_label: None,
            ..Default::default()
        }
    }

    fn disk(host: &str, guest: &str) -> VmVolume {
        VmVolume {
            host: host.into(),
            guest: guest.into(),
            kind: VmVolumeKind::Disk,
            ..Default::default()
        }
    }

    #[test]
    fn a_materialized_grant_is_attached_as_a_block_device_and_not_as_a_share() {
        // The point of the whole change: no virtio-fs device is asked for.
        let cfg = VmStartConfig {
            volumes: vec![granted_dir("/home/me/src", "/work", "/state/mount-0.ext4")],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert!(
            blocks
                .iter()
                .any(|b| b.source.as_path() == Path::new("/state/mount-0.ext4")),
            "the image must be attached as a block device: {blocks:?}"
        );
        assert!(
            !blocks
                .iter()
                .any(|b| b.source.as_path() == Path::new("/home/me/src")),
            "the granted directory itself must never be attached"
        );
    }

    #[test]
    fn a_materialized_grant_resolves_to_the_block_node_the_vmm_created() {
        // The three sites — block list, slot arithmetic, device mapping — have
        // to agree. If they drift, the guest mounts a real device that holds
        // someone else's data, which no error surfaces.
        let cfg = VmStartConfig {
            volumes: vec![
                granted_dir("/src", "/work", "/state/mount-0.ext4"),
                disk("/state/data.ext4", "/data"),
            ],
            ..base()
        };
        let devices = workload_volume_devices(&cfg);
        assert_eq!(devices.len(), 2);
        assert!(
            devices.iter().all(Option::is_some),
            "every attached volume resolves to a node: {devices:?}"
        );
        assert_ne!(
            devices[0], devices[1],
            "two volumes must not resolve to the same guest device"
        );

        let blocks = workload_blocks(&cfg);
        let node_of = |src: &str| {
            blocks
                .iter()
                .find(|b| b.source.as_path() == Path::new(src))
                .map(BlockDev::device_node)
        };
        assert_eq!(devices[0], node_of("/state/mount-0.ext4"));
        assert_eq!(devices[1], node_of("/state/data.ext4"));
    }

    #[test]
    fn a_launch_carrying_an_admitted_plan_gets_a_plan_binding() {
        let cfg = VmStartConfig {
            plan_json: Some(r#"{"resources":{"timeouts":{"exec_secs":30}}}"#.into()),
            ..base()
        };
        let spec = workload_device_spec(&cfg, "console=ttyS0", Path::new("/state/console.log"));
        let binding = spec
            .plan_binding
            .expect("a launch with an admitted plan must carry the bound the supervisor enforces");
        assert_eq!(binding.plan_json["resources"]["timeouts"]["exec_secs"], 30);
        assert_eq!(
            binding
                .signing_key_path
                .file_name()
                .and_then(|n| n.to_str()),
            Some("host-signer.ed25519"),
            "the kill is signed under the host signer"
        );
        assert_eq!(
            binding.audit_dir.file_name().and_then(|n| n.to_str()),
            Some("audit"),
            "the kill lands in the audit chain dir"
        );
    }

    #[test]
    fn a_launch_without_a_plan_has_no_binding() {
        let spec = workload_device_spec(&base(), "console=ttyS0", Path::new("/state/console.log"));
        assert!(
            spec.plan_binding.is_none(),
            "Stage 0 and the builder VM carry no plan, so they have no bound to enforce"
        );
    }

    #[test]
    fn an_unparseable_plan_yields_no_binding_rather_than_panicking() {
        let cfg = VmStartConfig {
            plan_json: Some("{not json".into()),
            ..base()
        };
        let spec = workload_device_spec(&cfg, "console=ttyS0", Path::new("/state/console.log"));
        assert!(
            spec.plan_binding.is_none(),
            "the mapping is infallible; a plan the supervisor cannot parse fails its own verify"
        );
    }

    fn nodes(blocks: &[BlockDev]) -> Vec<String> {
        blocks.iter().map(BlockDev::device_node).collect()
    }

    /// Neither access mode turns a materialized directory grant back into a
    /// live share.
    #[test]
    fn materialized_directory_grants_are_blocks_whatever_their_mode() {
        let cfg = VmStartConfig {
            volumes: vec![
                VmVolume {
                    materialized_image: Some("/state/rw.ext4".to_string()),
                    volume_label: None,
                    host: "/host/rw".into(),
                    guest: "/guest/rw".into(),
                    size: String::new(),
                    read_only: false,
                    kind: VmVolumeKind::Disk,
                    encrypted: false,
                },
                VmVolume {
                    materialized_image: Some("/state/ro.ext4".to_string()),
                    volume_label: None,
                    host: "/host/ro".into(),
                    guest: "/guest/ro".into(),
                    size: String::new(),
                    read_only: true,
                    kind: VmVolumeKind::Disk,
                    encrypted: false,
                },
            ],
            ..base()
        };
        let blocks = workload_blocks(&cfg);
        assert!(
            blocks
                .iter()
                .any(|block| block.source == Path::new("/state/rw.ext4"))
        );
        assert!(
            blocks
                .iter()
                .any(|block| block.source == Path::new("/state/ro.ext4"))
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
            materialized_image: None,
            volume_label: None,
            host: host.into(),
            guest: guest.into(),
            size: String::new(),
            read_only,
            kind: VmVolumeKind::Disk,
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
                granted_dir("/host/share", "/share", "/state/share.ext4"),
                disk_volume("/vol/second.img", "/second", false),
            ],
            ..base()
        };
        assert_eq!(
            workload_volume_devices(&cfg),
            vec![
                Some("/dev/vde".into()),
                Some("/dev/vdf".into()),
                Some("/dev/vdg".into())
            ]
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

    /// A materialized directory grant at the sidecar mount point is not the
    /// reserved SDK sidecar attachment.
    #[test]
    fn a_materialized_directory_at_the_sidecar_path_is_not_the_sidecar() {
        let cfg = VmStartConfig {
            volumes: vec![granted_dir(
                "/cache/sdk",
                mvm_core::plan::SDK_SIDECAR_GUEST_PATH,
                "/state/sdk-shaped-mount.ext4",
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

    /// The inverse of what this used to assert, and the property that matters
    /// now: a user volume never becomes a virtio-fs share. A granted directory
    /// is materialized into an image and attached as virtio-blk, so the only
    /// share a workload spec can carry is the dev-tier root.
    #[test]
    fn a_user_volume_never_becomes_a_virtiofs_share() {
        let cfg = VmStartConfig {
            volumes: vec![
                disk_volume("/vol/data.img", "/data", true),
                granted_dir("/host/dir", "/mnt/share", "/state/share.ext4"),
            ],
            ..base()
        };
        let spec = workload_device_spec(&cfg, "init=/init", Path::new("/tmp/console.log"));
        assert!(
            spec.shares.is_empty(),
            "no volume may produce a virtio-fs share: {:?}",
            spec.shares
        );
    }

    #[test]
    fn workload_vsock_ports_wire_the_three_standing_channels_with_correct_direction() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Some(Path::new("/run/egress.sock")),
            exit: Path::new("/run/workload.exit"),
            broker: None,
            console_data: Vec::new(),
        };
        let ports = workload_vsock_ports(&socks);

        // Agent: host dials the guest; egress + exit: the guest dials the host.
        let by_port: std::collections::HashMap<u32, &VsockPort> =
            ports.iter().map(|p| (p.port(), p)).collect();

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

    #[test]
    fn workload_vsock_ports_omit_egress_when_the_policy_grants_none() {
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: None,
            exit: Path::new("/run/workload.exit"),
            broker: None,
            console_data: Vec::new(),
        };
        let ports = workload_vsock_ports(&socks);
        assert_eq!(ports.len(), 2);
        assert!(
            ports
                .iter()
                .all(|port| port.service != GuestService::NetworkFlow)
        );
        assert!(
            ports
                .iter()
                .any(|port| port.service == GuestService::MachineControl)
        );
        assert!(
            ports
                .iter()
                .any(|port| port.service == GuestService::WorkloadExit)
        );
    }

    fn sample_sockets() -> WorkloadSockets<'static> {
        WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Some(Path::new("/run/egress.sock")),
            exit: Path::new("/run/workload.exit"),
            broker: None,
            console_data: Vec::new(),
        }
    }

    #[test]
    fn workload_vsock_ports_converged_path_has_exactly_one_network_flow() {
        let ports = workload_vsock_ports(&sample_sockets());

        let network_flow: Vec<_> = ports
            .iter()
            .filter(|p| p.service == GuestService::NetworkFlow)
            .collect();
        assert_eq!(
            network_flow.len(),
            1,
            "exactly one NetworkFlow channel on the converged path"
        );
        assert_eq!(network_flow[0].direction, VsockDirection::GuestDials);
    }

    #[test]
    fn workload_vsock_ports_emit_the_broker_channel_only_when_admitted() {
        // Admitted (broker socket present) ⇒ a BROKER_PORT GuestDials channel.
        let admitted = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Some(Path::new("/run/egress.sock")),
            exit: Path::new("/run/workload.exit"),
            broker: Some(Path::new("/run/broker.sock")),
            console_data: Vec::new(),
        };
        let broker = workload_vsock_ports(&admitted)
            .into_iter()
            .find(|p| p.service == GuestService::Broker)
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
                .all(|p| p.service != GuestService::Broker),
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
            identity_drive: None,
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
            identity_drive: None,
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
            identity_drive: None,
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
            identity_drive: None,
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.kernel, KernelImage::Bundled);
    }

    // --- console_data_sockets / dev_console gating ---

    #[test]
    fn builder_control_sockets_are_empty_for_a_non_builder_vm() {
        // Fail closed: only the build engine gets listeners on its control
        // ports. A workload is handed none, sealed or not.
        assert!(builder_control_sockets(Path::new("/state/w"), false).is_empty());
    }

    #[test]
    fn builder_control_sockets_cover_dispatch_and_daemon_control() {
        let state_dir = Path::new("/state/builder");
        let sockets = builder_control_sockets(state_dir, true);

        let ports: Vec<u32> = sockets.iter().map(|(port, _)| *port).collect();
        assert_eq!(
            ports,
            vec![
                GuestService::BuilderDispatch.port(),
                GuestService::BuilderdControl.port()
            ]
        );
        for (port, path) in &sockets {
            assert_eq!(
                path,
                &mvm_core::config::vm_hvf_vsock_port_socket_at(state_dir, *port),
                "path must follow the shared HVF-socket helper"
            );
        }
    }

    #[test]
    fn builder_control_sockets_never_collide_with_console_ports() {
        // Both lists feed one bridge keyed by guest port, so an overlap would
        // have one silently displace the other.
        let builder = builder_control_sockets(Path::new("/state/b"), true);
        let console = console_data_sockets(Path::new("/state/b"), true);
        for (port, _) in &builder {
            assert!(
                !console.iter().any(|(c, _)| c == port),
                "builder port {port} overlaps the console data range"
            );
        }
    }

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
        let state_dir = Path::new("/state/w");
        let console_data = console_data_sockets(state_dir, true);
        let socks = WorkloadSockets {
            agent: Path::new("/run/agent.sock"),
            egress_gateway: Some(Path::new("/run/egress.sock")),
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
            .filter(|p| matches!(p.service, GuestService::ConsoleData { .. }))
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
            egress_gateway: Some(Path::new("/run/egress.sock")),
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
            identity_drive: None,
            config: &cfg,
            sockets: WorkloadSockets {
                agent: Path::new("/run/agent.sock"),
                egress_gateway: Some(Path::new("/run/egress.sock")),
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
            identity_drive: None,
            config: &base(),
            sockets: sample_sockets(),
            cmdline: String::new(),
            console_log: PathBuf::from("/run/console.log"),
        });
        assert_eq!(spec.vsock.len(), 3);
    }
}
