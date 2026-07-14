//! Maps a builder VM's resolved host artifacts onto the backend-agnostic
//! `VmmSpec` a `VmmDriver` boots. The builder is the disk-only, trusted sibling
//! of the workload path: four virtio-blk disks (no virtio-fs), booting the
//! builder's PID 1 with no claim-10 egress gate.

use std::path::{Path, PathBuf};

use mvm_guest::vsock::{EGRESS_PORT, GUEST_AGENT_PORT};

use crate::driver::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};

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
            guest_port: GUEST_AGENT_PORT,
            host_uds: sock.clone(),
            direction: VsockDirection::HostDials,
        });
    }
    vsock.push(VsockPort {
        guest_port: EGRESS_PORT,
        host_uds: inputs.egress_socket.clone(),
        direction: VsockDirection::HostDials,
    });

    let cmdline = if inputs.runtime_overlay.is_some() {
        format!(
            "{BUILDER_CMDLINE} mvm.runtime_source_policy=required_overlay mvm.runtime_data={BUILDER_RUNTIME_DEVICE}"
        )
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

    VmmSpec {
        name: inputs.name.to_string(),
        kernel: KernelImage::Path(inputs.kernel.to_path_buf()),
        initramfs: None,
        cmdline,
        vcpus: inputs.vcpus,
        memory_mib: inputs.memory_mib,
        mem_initial_mib: None,
        blocks,
        vsock,
        console: ConsoleCapture {
            log_path: inputs.console_log.clone(),
        },
        trusted_builder: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> BuilderSpecInputs<'static> {
        BuilderSpecInputs {
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
        assert_eq!(spec.blocks.len(), 4);
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
        assert!(spec.blocks.iter().all(|b| !b.ephemeral));
    }

    #[test]
    fn builder_spec_is_trusted_with_no_egress_port_and_the_builder_cmdline() {
        let spec = builder_spec(&inputs());
        assert!(spec.trusted_builder);
        assert!(spec.vsock.iter().any(|p| p.guest_port == EGRESS_PORT));
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
        assert_eq!(spec.vsock[0].guest_port, EGRESS_PORT);
    }

    #[test]
    fn builder_spec_attaches_runtime_overlay_as_read_only_vde() {
        let mut i = inputs();
        i.runtime_overlay = Some(Path::new("/cache/runtime-overlay.ext4"));
        let spec = builder_spec(&i);
        assert_eq!(spec.blocks.len(), 5);
        assert_eq!(spec.blocks[4].device_node(), "/dev/vde");
        assert_eq!(
            spec.blocks[4].source,
            PathBuf::from("/cache/runtime-overlay.ext4")
        );
        assert!(spec.blocks[4].read_only);
        assert!(
            spec.cmdline
                .contains("mvm.runtime_source_policy=required_overlay")
        );
        assert!(spec.cmdline.contains("mvm.runtime_data=/dev/vde"));
    }
}
