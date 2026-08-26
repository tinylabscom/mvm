//! Maps a builder VM's resolved host artifacts onto the backend-agnostic
//! `VmmSpec` a `VmmDriver` boots. The builder is the disk-only, trusted sibling
//! of the workload path: four virtio-blk disks (no virtio-fs), booting the
//! builder's PID 1 with no claim-10 egress gate.

use std::path::{Path, PathBuf};

use crate::driver::{
    BlockDev, ConsoleCapture, KernelImage, VirtioFsShare, VmmSpec, VsockDirection, VsockPort,
};
use mvm_net::channel::GuestService;

/// Kernel cmdline for the disk-transport builder on the HVF VMM. Mirrors
/// the console args the workload default uses (PL011 earlycon + `ttyAMA0`), but
/// boots the builder's PID 1 (`/sbin/mvm-host-vm-init`, not the workload
/// `/init`), mounts the rootfs read-only, and selects the disk transport with its
/// input/output block devices. The device names match `mvm-host-vm-init`'s
/// defaults (`/dev/vdc` in, `/dev/vdd` out) and the slot order below.
pub const BUILDER_CMDLINE: &str = "earlycon=pl011,0x9000000 console=ttyAMA0 panic=-1 nokaslr \
     loglevel=8 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-host-vm-init \
     mvm.builder_transport=disk mvm.builder_input=/dev/vdc mvm.builder_output=/dev/vdd \
     mvm.vsock_egress=1";
const BUILDER_RUNTIME_DEVICE: &str = "/dev/vde";

/// Kernel cmdline for a **persistent** builder: the same boot contract as
/// [`BUILDER_CMDLINE`], minus the disk-transport selection.
///
/// Omitting `mvm.builder_transport=disk` is the whole switch. `mvm-host-vm-init`
/// reads that token and, when it is absent, mounts `/job`, `/work`, `/out` and
/// `/mvm-bins` from virtio-fs instead of unpacking them off a block device. A
/// long-lived session needs exactly that: the input disk is packed once, before
/// boot, so a second dispatch would have nowhere to put its inputs.
pub const PERSISTENT_BUILDER_CMDLINE: &str = "earlycon=pl011,0x9000000 console=ttyAMA0 panic=-1 nokaslr \
     loglevel=8 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-host-vm-init \
     mvm.vsock_egress=1";

/// Runtime-overlay device for the persistent layout. With no input/output
/// disks the overlay is the third block, not the fifth.
const PERSISTENT_BUILDER_RUNTIME_DEVICE: &str = "/dev/vdc";

/// The resolved host artifacts a builder VM boots with. Disk slots are fixed:
/// `vda` rootfs (RO), `vdb` nix-store (RW, persistent), `vdc` input (RO), `vdd`
/// output (RW, persistent) — matching [`BUILDER_CMDLINE`] and the guest init.
pub struct BuilderSpecInputs<'a> {
    pub name: &'a str,
    /// arm64 boot `Image` for the builder VM.
    pub kernel: &'a Path,
    /// Builder rootfs (mounted read-only; its baked Nix store is the seed).
    pub rootfs: &'a Path,
    /// Persistent nix-store disk (writable; survives across builds).
    pub nix_store: &'a Path,
    /// Input disk: the packed `{job, work, mvm-bins}` tar (read-only).
    pub input_disk: &'a Path,
    /// Output disk: the guest writes the artifact tar here (writable).
    pub output_disk: &'a Path,
    /// Optional read-only runtime overlay ext4 for the builder guest.
    pub runtime_overlay: Option<&'a Path>,
    /// Write-only console capture path.
    pub console_log: PathBuf,
    /// Optional host→guest agent RPC socket (the host dials the guest agent).
    pub agent_socket: Option<PathBuf>,
    /// Host-side egress relay UDS wired to `EGRESS_PORT`.
    pub egress_socket: PathBuf,
    /// This boot's FlowMux identity drive (read-only). The guest reads its
    /// signing key and the host anchor off it before starting the egress
    /// client, which will not bind without them.
    pub identity_drive: &'a Path,
    pub vcpus: u32,
    pub memory_mib: u32,
}

/// Compose the builder `VmmSpec`. Trusted-builder: no egress gate, no
/// `EGRESS_PORT` is still wired because builder egress now rides the same
/// vsock relay path as workloads; the host-side endpoint enforces the trusted
/// builder policy. Every disk is file-served; the writable ones (`vdb`/`vdd`)
/// persist to their host file (`ephemeral = false`).
pub fn builder_spec(inputs: &BuilderSpecInputs<'_>) -> VmmSpec {
    let block = |source: &Path, slot: u8, read_only: bool| BlockDev {
        source: source.to_path_buf(),
        read_only,
        // Builder disks are file-served and (when writable) persistent — never
        // RAM-backed, so a large nix-store costs no guest RAM and the output
        // survives for the host to read back.
        ephemeral: false,
        slot,
    };

    let mut vsock = Vec::new();
    if let Some(sock) = &inputs.agent_socket {
        vsock.push(VsockPort {
            service: GuestService::MachineControl,
            host_uds: sock.clone(),
            direction: VsockDirection::HostDials,
        });
    }
    vsock.push(VsockPort {
        service: GuestService::NetworkFlow,
        host_uds: inputs.egress_socket.clone(),
        direction: VsockDirection::HostDials,
    });

    let cmdline = if inputs.runtime_overlay.is_some() {
        format!("{BUILDER_CMDLINE} mvm.runtime_data={BUILDER_RUNTIME_DEVICE}")
    } else {
        BUILDER_CMDLINE.to_string()
    };
    // Seed the RTC-less HVF builder guest's wall clock from the host: PID 1
    // (mvm-host-vm-init) reads this token and calls settimeofday, so a cold Nix
    // store's HTTPS fetch doesn't fail cert validation against a ~1970 clock.
    let cmdline = format!(
        "{cmdline} {}",
        mvm_build::builder_vm::builder_hostepoch_cmdline_token()
    );

    let mut blocks = vec![
        block(inputs.rootfs, 0, true),       // vda: rootfs, RO
        block(inputs.nix_store, 1, false),   // vdb: nix-store, RW persist
        block(inputs.input_disk, 2, true),   // vdc: input tar, RO
        block(inputs.output_disk, 3, false), // vdd: output tar, RW persist
    ];
    if let Some(runtime_overlay) = inputs.runtime_overlay {
        blocks.push(block(runtime_overlay, 4, true)); // vde: runtime overlay, RO
    }
    // Appended last, and found in the guest by ext4 label rather than by slot,
    // so the optional overlay above cannot shift it out from under the guest.
    let identity_slot = blocks.len() as u8;
    blocks.push(block(inputs.identity_drive, identity_slot, true));

    VmmSpec {
        name: inputs.name.to_string(),
        kernel: KernelImage::Path(inputs.kernel.to_path_buf()),
        initramfs: None,
        cmdline,
        vcpus: inputs.vcpus,
        // The builder VM is the trusted build engine, not a workload. Nothing
        // admits it under a grant, so there is no bound to carry here.
        cpu_grant: None,
        memory_mib: inputs.memory_mib,
        mem_initial_mib: None,
        blocks,
        vsock,
        console: ConsoleCapture {
            log_path: inputs.console_log.clone(),
        },
        shares: Vec::new(),
        trusted_builder: true,
        // The builder VM boots from no admitted plan, so it carries no
        // wall-clock bound to enforce.
        plan_binding: None,
    }
}

/// The resolved host artifacts a **persistent** builder VM boots with. No
/// input/output disks: per-dispatch payloads ride live virtio-fs shares, so the
/// block layout is `vda` rootfs (RO), `vdb` nix-store (RW), and — when present —
/// `vdc` runtime overlay (RO).
pub struct PersistentBuilderSpecInputs<'a> {
    pub name: &'a str,
    /// arm64 boot `Image` for the builder VM.
    pub kernel: &'a Path,
    /// Builder rootfs (mounted read-only; its baked Nix store is the seed).
    pub rootfs: &'a Path,
    /// Persistent nix-store disk (writable; survives across builds *and*
    /// across dispatches, which is the point of the session).
    pub nix_store: &'a Path,
    /// Host dir served at `/job` — where the host stages each dispatch and
    /// reads its artifacts back.
    pub job_dir: &'a Path,
    /// Host dir served at `/work` — the live source tree, reflecting host
    /// edits for the session's lifetime.
    pub workspace_root: &'a Path,
    /// Host dir served at `/mvm-bins` — the extracted host binaries.
    pub host_bin_dir: &'a Path,
    /// Optional read-only runtime overlay ext4 for the builder guest.
    pub runtime_overlay: Option<&'a Path>,
    /// Write-only console capture path.
    pub console_log: PathBuf,
    /// Host-side egress relay UDS wired to `EGRESS_PORT`.
    pub egress_socket: PathBuf,
    /// Host UDS for the guest's job-dispatch listener (the host dials).
    pub dispatch_socket: PathBuf,
    /// Host UDS for the resident builder daemon's typed control plane.
    pub builderd_socket: PathBuf,
    pub vcpus: u32,
    pub memory_mib: u32,
}

/// Compose the persistent builder `VmmSpec`.
///
/// Two differences from [`builder_spec`], and both are what make a session
/// possible rather than a single run:
///
/// 1. The cmdline omits `mvm.builder_transport=disk`, so the guest mounts its
///    job directories from virtio-fs and each dispatch can stage fresh inputs
///    into a running VM.
/// 2. The spec names the builder control ports, so the backend binds host
///    sockets the dispatch client can dial.
pub fn persistent_builder_spec(inputs: &PersistentBuilderSpecInputs<'_>) -> VmmSpec {
    let block = |source: &Path, slot: u8, read_only: bool| BlockDev {
        source: source.to_path_buf(),
        read_only,
        ephemeral: false,
        slot,
    };

    let mut blocks = vec![
        block(inputs.rootfs, 0, true),     // vda: rootfs, RO
        block(inputs.nix_store, 1, false), // vdb: nix-store, RW persist
    ];
    let cmdline = if let Some(runtime_overlay) = inputs.runtime_overlay {
        blocks.push(block(runtime_overlay, 2, true)); // vdc: runtime overlay, RO
        format!(
            "{PERSISTENT_BUILDER_CMDLINE} \
             mvm.runtime_data={PERSISTENT_BUILDER_RUNTIME_DEVICE}"
        )
    } else {
        PERSISTENT_BUILDER_CMDLINE.to_string()
    };
    // Same RTC-less clock seed the one-shot builder takes: a cold store's HTTPS
    // fetch fails cert validation against a ~1970 clock.
    let cmdline = format!(
        "{cmdline} {}",
        mvm_build::builder_vm::builder_hostepoch_cmdline_token()
    );

    let share = |tag: &str, host_path: &Path, read_only: bool| VirtioFsShare {
        tag: tag.to_string(),
        host_path: host_path.to_path_buf(),
        read_only,
        dax: false,
    };
    // The read-only split mirrors `mvm-host-vm-init`'s
    // `virtiofs_tag_is_read_only`: `work` and `mvm-bins` are inputs the guest
    // must not write back, while `job` and `out` carry per-dispatch payloads
    // and artifacts in the other direction. Marking one wrongly fails the
    // dispatch inside the guest, so a test pins the exact split.
    let shares = vec![
        share("work", inputs.workspace_root, true),
        share("mvm-bins", inputs.host_bin_dir, true),
        share("job", inputs.job_dir, false),
        // `/out` is the same host directory as `/job`: the guest writes each
        // dispatch's artifacts into the job dir the host is already watching,
        // which is the arrangement the libkrun persistent VM uses.
        share("out", inputs.job_dir, false),
    ];

    let host_dials = |service: GuestService, host_uds: &PathBuf| VsockPort {
        service,
        host_uds: host_uds.clone(),
        direction: VsockDirection::HostDials,
    };
    let vsock = vec![
        host_dials(GuestService::NetworkFlow, &inputs.egress_socket),
        host_dials(GuestService::BuilderDispatch, &inputs.dispatch_socket),
        host_dials(GuestService::BuilderdControl, &inputs.builderd_socket),
    ];

    VmmSpec {
        name: inputs.name.to_string(),
        kernel: KernelImage::Path(inputs.kernel.to_path_buf()),
        initramfs: None,
        cmdline,
        vcpus: inputs.vcpus,
        cpu_grant: None,
        memory_mib: inputs.memory_mib,
        mem_initial_mib: None,
        blocks,
        vsock,
        console: ConsoleCapture {
            log_path: inputs.console_log.clone(),
        },
        shares,
        trusted_builder: true,
        // The builder VM boots from no admitted plan, so it carries no
        // wall-clock bound to enforce.
        plan_binding: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persistent_inputs() -> PersistentBuilderSpecInputs<'static> {
        PersistentBuilderSpecInputs {
            name: "bld-persistent",
            kernel: Path::new("/img/Image"),
            rootfs: Path::new("/img/builder-rootfs.ext4"),
            nix_store: Path::new("/cache/nix-store.img"),
            job_dir: Path::new("/cache/jobs/s1"),
            workspace_root: Path::new("/src/repo"),
            host_bin_dir: Path::new("/cache/host-bins"),
            runtime_overlay: None,
            console_log: PathBuf::from("/state/console.log"),
            egress_socket: PathBuf::from("/state/vsock-5253.sock"),
            dispatch_socket: PathBuf::from("/state/vsock-21471.sock"),
            builderd_socket: PathBuf::from("/state/vsock-21473.sock"),
            vcpus: 4,
            memory_mib: 8192,
        }
    }

    #[test]
    fn a_persistent_builder_does_not_select_the_disk_transport() {
        // The one token that decides it: with `mvm.builder_transport=disk` the
        // guest unpacks a block device staged before boot, and a second
        // dispatch has nowhere to put its inputs.
        let spec = persistent_builder_spec(&persistent_inputs());
        assert!(!spec.cmdline.contains("mvm.builder_transport"));
        assert!(!spec.cmdline.contains("mvm.builder_input"));
        assert!(!spec.cmdline.contains("mvm.builder_output"));
        // Still the builder's PID 1 and the same egress posture.
        assert!(spec.cmdline.contains("init=/sbin/mvm-host-vm-init"));
        assert!(spec.cmdline.contains("mvm.vsock_egress=1"));
    }

    #[test]
    fn a_persistent_builder_carries_live_shares_instead_of_transport_disks() {
        let spec = persistent_builder_spec(&persistent_inputs());

        // Only rootfs + nix-store: no input/output disks to go stale.
        assert_eq!(spec.blocks.len(), 2);
        assert_eq!(spec.blocks[0].device_node(), "/dev/vda");
        assert!(spec.blocks[0].read_only);
        assert_eq!(spec.blocks[1].device_node(), "/dev/vdb");
        assert!(!spec.blocks[1].read_only, "the store must stay writable");

        let tags: Vec<&str> = spec.shares.iter().map(|s| s.tag.as_str()).collect();
        assert_eq!(tags, vec!["work", "mvm-bins", "job", "out"]);

        // The read-only split must match what the guest init expects, or a
        // dispatch write into /job fails inside the VM.
        for share in &spec.shares {
            let expect_ro = matches!(share.tag.as_str(), "work" | "mvm-bins");
            assert_eq!(share.read_only, expect_ro, "tag {}", share.tag);
        }
    }

    #[test]
    fn a_persistent_builder_names_its_control_ports() {
        let spec = persistent_builder_spec(&persistent_inputs());
        let services: Vec<GuestService> = spec.vsock.iter().map(|p| p.service).collect();

        assert!(services.contains(&GuestService::BuilderDispatch));
        assert!(services.contains(&GuestService::BuilderdControl));
        assert!(services.contains(&GuestService::NetworkFlow));
        // Every one is host-dials: the guest listens, the host connects.
        assert!(
            spec.vsock
                .iter()
                .all(|p| p.direction == VsockDirection::HostDials)
        );
    }

    #[test]
    fn the_persistent_runtime_overlay_lands_where_its_cmdline_says() {
        // With no input/output disks the overlay is the third block, so the
        // cmdline device must move with it — a stale /dev/vde would mount
        // nothing and fail the required-overlay policy.
        let mut inputs = persistent_inputs();
        let overlay = Path::new("/img/runtime-overlay.ext4");
        inputs.runtime_overlay = Some(overlay);
        let spec = persistent_builder_spec(&inputs);

        assert_eq!(spec.blocks.len(), 3);
        assert_eq!(
            spec.blocks[2].device_node(),
            PERSISTENT_BUILDER_RUNTIME_DEVICE
        );
        assert!(spec.blocks[2].read_only);
        assert!(spec.cmdline.contains(&format!(
            "mvm.runtime_data={PERSISTENT_BUILDER_RUNTIME_DEVICE}"
        )));
    }

    fn inputs() -> BuilderSpecInputs<'static> {
        BuilderSpecInputs {
            identity_drive: Path::new("/state/flowmux-identity.ext4"),
            name: "bld",
            kernel: Path::new("/img/Image"),
            rootfs: Path::new("/img/builder-rootfs.ext4"),
            nix_store: Path::new("/cache/nix-store.img"),
            input_disk: Path::new("/state/input.img"),
            output_disk: Path::new("/state/output.img"),
            runtime_overlay: None,
            console_log: PathBuf::from("/state/console.log"),
            agent_socket: Some(PathBuf::from("/state/agent.sock")),
            egress_socket: PathBuf::from("/state/vsock-21002.sock"),
            vcpus: 4,
            memory_mib: 4096,
        }
    }

    #[test]
    fn builder_spec_lays_out_four_disks_in_vda_vdd_order() {
        let spec = builder_spec(&inputs());
        // Four job disks plus this boot's FlowMux identity drive, appended
        // last so the optional overlay cannot shift it.
        assert_eq!(spec.blocks.len(), 5);
        // vda rootfs RO (file-served, not ephemeral).
        assert_eq!(spec.blocks[0].device_node(), "/dev/vda");
        assert_eq!(
            spec.blocks[0].source,
            PathBuf::from("/img/builder-rootfs.ext4")
        );
        assert!(spec.blocks[0].read_only);
        // vdb nix-store: writable + persistent.
        assert_eq!(spec.blocks[1].device_node(), "/dev/vdb");
        assert!(!spec.blocks[1].read_only);
        // vdc input RO, vdd output writable — both persistent, none ephemeral.
        assert_eq!(spec.blocks[2].device_node(), "/dev/vdc");
        assert!(spec.blocks[2].read_only);
        assert_eq!(spec.blocks[3].device_node(), "/dev/vdd");
        assert!(!spec.blocks[3].read_only);
        // The identity drive: read-only, and last.
        assert_eq!(spec.blocks[4].device_node(), "/dev/vde");
        assert_eq!(
            spec.blocks[4].source,
            PathBuf::from("/state/flowmux-identity.ext4")
        );
        assert!(spec.blocks[4].read_only);
        assert!(spec.blocks.iter().all(|b| !b.ephemeral));
    }

    #[test]
    fn builder_spec_carries_the_substitution_channel_and_the_builder_cmdline() {
        let spec = builder_spec(&inputs());
        assert!(
            spec.vsock
                .iter()
                .any(|p| p.service == GuestService::NetworkFlow)
        );
        // Boots the builder PID 1 over the disk transport, rootfs read-only.
        assert!(spec.cmdline.contains("init=/sbin/mvm-host-vm-init"));
        assert!(spec.cmdline.contains("mvm.builder_transport=disk"));
        assert!(spec.cmdline.contains("mvm.builder_input=/dev/vdc"));
        assert!(spec.cmdline.contains("mvm.builder_output=/dev/vdd"));
        assert!(spec.cmdline.contains("root=/dev/vda ro"));
        assert!(spec.cmdline.contains("mvm.vsock_egress=1"));
    }

    #[test]
    fn builder_spec_without_an_agent_socket_has_no_vsock_ports() {
        let mut i = inputs();
        i.agent_socket = None;
        let spec = builder_spec(&i);
        assert_eq!(spec.vsock.len(), 1);
        assert_eq!(spec.vsock[0].service, GuestService::NetworkFlow);
    }

    #[test]
    fn builder_spec_attaches_runtime_overlay_as_read_only_vde() {
        let mut i = inputs();
        i.runtime_overlay = Some(Path::new("/cache/runtime-overlay.ext4"));
        let spec = builder_spec(&i);
        assert_eq!(spec.blocks.len(), 6);
        assert_eq!(spec.blocks[4].device_node(), "/dev/vde");
        assert_eq!(
            spec.blocks[4].source,
            PathBuf::from("/cache/runtime-overlay.ext4")
        );
        assert!(spec.blocks[4].read_only);
        // The identity drive still lands after the overlay, and the guest
        // finds it by label rather than by this position.
        assert_eq!(spec.blocks[5].device_node(), "/dev/vdf");
        assert_eq!(
            spec.blocks[5].source,
            PathBuf::from("/state/flowmux-identity.ext4")
        );
        assert!(spec.blocks[5].read_only);
        assert!(spec.cmdline.contains("mvm.runtime_data=/dev/vde"));
    }
}
