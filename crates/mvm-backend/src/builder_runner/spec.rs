//! Maps a builder VM's resolved host artifacts onto the backend-agnostic
//! `VmmSpec` a `VmmDriver` boots. The builder is the disk-only, trusted sibling
//! of the workload path: four virtio-blk disks (no virtio-fs), booting the
//! builder's PID 1 with no claim-10 egress gate.

use std::path::{Path, PathBuf};

use mvm_guest::vsock::GUEST_AGENT_PORT;

use crate::driver::{BlockDev, ConsoleCapture, KernelImage, VmmSpec, VsockDirection, VsockPort};

/// Kernel cmdline for the disk-transport builder on the in-house HVF VMM. Mirrors
/// the console args the workload default uses (PL011 earlycon + `ttyAMA0`), but
/// boots the builder's PID 1 (`/sbin/mvm-host-vm-init`, not the workload
/// `/init`), mounts the rootfs read-only, and selects the disk transport with its
/// input/output block devices. The device names match `mvm-host-vm-init`'s
/// defaults (`/dev/vdc` in, `/dev/vdd` out) and the slot order below.
pub const BUILDER_CMDLINE: &str = "earlycon=pl011,0x9000000 console=ttyAMA0 panic=-1 nokaslr \
     loglevel=8 root=/dev/vda ro rootfstype=ext4 init=/sbin/mvm-host-vm-init \
     mvm.builder_transport=disk mvm.builder_input=/dev/vdc mvm.builder_output=/dev/vdd";

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
    /// Write-only console capture path.
    pub console_log: PathBuf,
    /// Optional host→guest agent RPC socket (the host dials the guest agent).
    pub agent_socket: Option<PathBuf>,
    pub vcpus: u32,
    pub memory_mib: u32,
}

/// Compose the builder `VmmSpec`. Trusted-builder: no egress gate, no
/// `EGRESS_PORT`. Every disk is file-served; the writable ones (`vdb`/`vdd`)
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

    VmmSpec {
        name: inputs.name.to_string(),
        kernel: KernelImage::Path(inputs.kernel.to_path_buf()),
        initramfs: None,
        cmdline: BUILDER_CMDLINE.to_string(),
        vcpus: inputs.vcpus,
        memory_mib: inputs.memory_mib,
        mem_initial_mib: None,
        blocks: vec![
            block(inputs.rootfs, 0, true),       // vda: rootfs, RO
            block(inputs.nix_store, 1, false),   // vdb: nix-store, RW persist
            block(inputs.input_disk, 2, true),   // vdc: input tar, RO
            block(inputs.output_disk, 3, false), // vdd: output tar, RW persist
        ],
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
            console_log: PathBuf::from("/state/console.log"),
            agent_socket: Some(PathBuf::from("/state/agent.sock")),
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
        // No EGRESS_PORT — the builder boots ungated.
        assert!(spec.vsock.iter().all(|p| p.guest_port == GUEST_AGENT_PORT));
        // Boots the builder PID 1 over the disk transport, rootfs read-only.
        assert!(spec.cmdline.contains("init=/sbin/mvm-host-vm-init"));
        assert!(spec.cmdline.contains("mvm.builder_transport=disk"));
        assert!(spec.cmdline.contains("mvm.builder_input=/dev/vdc"));
        assert!(spec.cmdline.contains("mvm.builder_output=/dev/vdd"));
        assert!(spec.cmdline.contains("root=/dev/vda ro"));
    }

    #[test]
    fn builder_spec_without_an_agent_socket_has_no_vsock_ports() {
        let mut i = inputs();
        i.agent_socket = None;
        let spec = builder_spec(&i);
        assert!(spec.vsock.is_empty());
    }
}
