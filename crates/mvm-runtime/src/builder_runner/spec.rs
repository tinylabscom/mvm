//! Maps a builder VM's resolved host artifacts onto the backend-agnostic
//! `VmmSpec` a `VmmDriver` boots. The builder is the disk-only, trusted sibling
//! of the workload path: four virtio-blk disks (no virtio-fs), booting the
//! builder's PID 1 with no claim-10 egress gate. One-shot and persistent
//! builders take the same boot contract and differ only in lifetime.

use std::path::{Path, PathBuf};

use crate::driver::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};
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
        // A one-shot build spawns its own endpoint and stays alive for the
        // VM's whole life, so it needs no supervisor-owned one.
        builder_egress_endpoint: None,
        // The builder VM boots from no admitted plan, so it carries no
        // wall-clock bound to enforce.
        plan_binding: None,
    }
}

/// The resolved host artifacts a **persistent** builder VM boots with. Same
/// disk layout as [`BuilderSpecInputs`] — `vda` rootfs (RO), `vdb` nix-store
/// (RW), `vdc` input (RO), `vdd` output (RW), optional `vde` overlay (RO) —
/// because a session takes the same boot contract as a one-shot build. What
/// differs is lifetime: the host rewrites the input disk and re-reads the
/// output disk once per dispatch instead of once per VM.
pub struct PersistentBuilderSpecInputs<'a> {
    pub name: &'a str,
    /// arm64 boot `Image` for the builder VM.
    pub kernel: &'a Path,
    /// Builder rootfs (mounted read-only; its baked Nix store is the seed).
    pub rootfs: &'a Path,
    /// Persistent nix-store disk (writable; survives across builds *and*
    /// across dispatches, which is the point of the session).
    pub nix_store: &'a Path,
    /// Input disk: the packed `{job, work, mvm-bins}` tar (read-only to the
    /// guest). The host rewrites it in place before each `Run`, and the guest
    /// re-extracts only the `job` member per dispatch.
    pub input_disk: &'a Path,
    /// Output disk: the guest writes each dispatch's artifact tar here, and
    /// the host reads it back after that dispatch's `Result`.
    pub output_disk: &'a Path,
    /// Optional read-only runtime overlay ext4 for the builder guest.
    pub runtime_overlay: Option<&'a Path>,
    /// Write-only console capture path.
    pub console_log: PathBuf,
    /// Host-side egress relay UDS wired to `EGRESS_PORT`.
    pub egress_socket: PathBuf,
    /// This session's FlowMux identity drive (read-only). Same requirement the
    /// one-shot builder has: the guest reads its signing key and the host
    /// anchor off it before starting the egress client, which will not bind
    /// without them — and a builder with no NIC that cannot reach the proxy
    /// cannot build.
    pub identity_drive: &'a Path,
    /// Host UDS for the guest's job-dispatch listener (the host dials).
    pub dispatch_socket: PathBuf,
    /// Host UDS for the resident builder daemon's typed control plane.
    pub builderd_socket: PathBuf,
    /// Ask the supervisor to own this session's egress endpoint and identity
    /// drive. A session outlives the command that starts it, and the endpoint
    /// self-reaps when orphaned, so the supervisor is the only process whose
    /// life matches the VM's.
    pub builder_egress_endpoint: mvm_vmm::host::hvf_supervisor::BuilderEgressEndpoint,
    pub vcpus: u32,
    pub memory_mib: u32,
}

/// Compose the persistent builder `VmmSpec`.
///
/// One difference from [`builder_spec`], and it is what makes a session
/// possible rather than a single run: the spec names the builder control
/// ports, so the backend binds host sockets the dispatch client can dial.
///
/// The boot contract is otherwise identical, disk transport included. A
/// persistent guest re-reads the `job` member off the input disk on every
/// `Run` and re-writes the output disk after every job, so one pair of
/// transport disks serves the whole session rather than one build.
pub fn persistent_builder_spec(inputs: &PersistentBuilderSpecInputs<'_>) -> VmmSpec {
    let block = |source: &Path, slot: u8, read_only: bool| BlockDev {
        source: source.to_path_buf(),
        read_only,
        ephemeral: false,
        slot,
    };

    let mut blocks = vec![
        block(inputs.rootfs, 0, true),       // vda: rootfs, RO
        block(inputs.nix_store, 1, false),   // vdb: nix-store, RW persist
        block(inputs.input_disk, 2, true),   // vdc: input tar, RO
        block(inputs.output_disk, 3, false), // vdd: output tar, RW persist
    ];
    let cmdline = if let Some(runtime_overlay) = inputs.runtime_overlay {
        blocks.push(block(runtime_overlay, 4, true)); // vde: runtime overlay, RO
        format!("{BUILDER_CMDLINE} mvm.runtime_data={BUILDER_RUNTIME_DEVICE}")
    } else {
        BUILDER_CMDLINE.to_string()
    };
    // Appended last and found in the guest by ext4 label rather than by slot,
    // so the optional overlay above cannot shift it out from under the guest.
    let identity_slot = blocks.len() as u8;
    blocks.push(block(inputs.identity_drive, identity_slot, true));
    // Same RTC-less clock seed the one-shot builder takes: a cold store's HTTPS
    // fetch fails cert validation against a ~1970 clock.
    let cmdline = format!(
        "{cmdline} {}",
        mvm_build::builder_vm::builder_hostepoch_cmdline_token()
    );

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
        shares: Vec::new(),
        trusted_builder: true,
        builder_egress_endpoint: Some(inputs.builder_egress_endpoint.clone()),
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
            input_disk: Path::new("/state/input.img"),
            output_disk: Path::new("/state/output.img"),
            runtime_overlay: None,
            identity_drive: Path::new("/state/flowmux-identity.ext4"),
            console_log: PathBuf::from("/state/console.log"),
            egress_socket: PathBuf::from("/state/vsock-5253.sock"),
            dispatch_socket: PathBuf::from("/state/vsock-21471.sock"),
            builderd_socket: PathBuf::from("/state/vsock-21473.sock"),
            builder_egress_endpoint: mvm_vmm::host::hvf_supervisor::BuilderEgressEndpoint {
                vm_name: "bld-persistent".into(),
                state_dir: PathBuf::from("/state"),
                socket: PathBuf::from("/state/vsock-5253.sock"),
                identity_drive: PathBuf::from("/state/flowmux-identity.ext4"),
            },
            vcpus: 4,
            memory_mib: 8192,
        }
    }

    #[test]
    fn a_persistent_builder_selects_the_disk_transport() {
        // The token that decides it: with `mvm.builder_transport=disk` the
        // guest unpacks `/job`, `/work` and `/mvm-bins` off a block device
        // instead of mounting virtio-fs shares. A persistent session works
        // because the host rewrites that device between dispatches.
        let spec = persistent_builder_spec(&persistent_inputs());
        assert!(spec.cmdline.contains("mvm.builder_transport=disk"));
        assert!(spec.cmdline.contains("mvm.builder_input=/dev/vdc"));
        assert!(spec.cmdline.contains("mvm.builder_output=/dev/vdd"));
        // Still the builder's PID 1 and the same egress posture.
        assert!(spec.cmdline.contains("init=/sbin/mvm-host-vm-init"));
        assert!(spec.cmdline.contains("mvm.vsock_egress=1"));
    }

    #[test]
    fn a_persistent_builder_carries_transport_disks_and_no_shares() {
        let spec = persistent_builder_spec(&persistent_inputs());

        // The claim this whole stage exists for: a builder guest gets no
        // virtio-fs device, so it has no channel to host filesystem structure.
        assert!(
            spec.shares.is_empty(),
            "a persistent builder must declare no virtio-fs shares"
        );

        // Same vda–vdd order as the one-shot builder, so the cmdline device
        // names above are true of the slots the backend attaches, plus this
        // session's identity drive appended last.
        assert_eq!(spec.blocks.len(), 5);
        assert_eq!(spec.blocks[0].device_node(), "/dev/vda");
        assert!(spec.blocks[0].read_only);
        assert_eq!(spec.blocks[1].device_node(), "/dev/vdb");
        assert!(!spec.blocks[1].read_only, "the store must stay writable");
        assert_eq!(spec.blocks[2].device_node(), "/dev/vdc");
        assert_eq!(spec.blocks[2].source, PathBuf::from("/state/input.img"));
        assert!(
            spec.blocks[2].read_only,
            "the guest never writes its inputs"
        );
        assert_eq!(spec.blocks[3].device_node(), "/dev/vdd");
        assert_eq!(spec.blocks[3].source, PathBuf::from("/state/output.img"));
        assert!(!spec.blocks[3].read_only, "the guest writes its artifacts");
        // Without this the guest's egress client cannot authenticate its
        // session, and a builder with no NIC that cannot reach the proxy
        // refuses to boot rather than building against nothing.
        assert_eq!(
            spec.blocks[4].source,
            PathBuf::from("/state/flowmux-identity.ext4")
        );
        assert!(spec.blocks[4].read_only);
        // File-served, never RAM-backed: the output has to survive for the
        // host to read it back after each dispatch.
        assert!(spec.blocks.iter().all(|b| !b.ephemeral));
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
        // The overlay follows the transport disks, so it is the fifth block —
        // a cmdline naming any other device would mount nothing and fail the
        // required-overlay policy.
        let mut inputs = persistent_inputs();
        let overlay = Path::new("/img/runtime-overlay.ext4");
        inputs.runtime_overlay = Some(overlay);
        let spec = persistent_builder_spec(&inputs);

        assert_eq!(spec.blocks.len(), 6);
        assert_eq!(spec.blocks[4].device_node(), BUILDER_RUNTIME_DEVICE);
        assert_eq!(spec.blocks[4].source, overlay);
        assert!(spec.blocks[4].read_only);
        assert!(
            spec.cmdline
                .contains(&format!("mvm.runtime_data={BUILDER_RUNTIME_DEVICE}"))
        );
        // The identity drive still lands after the overlay, and the guest
        // finds it by ext4 label rather than by this position.
        assert_eq!(
            spec.blocks[5].source,
            PathBuf::from("/state/flowmux-identity.ext4")
        );
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
