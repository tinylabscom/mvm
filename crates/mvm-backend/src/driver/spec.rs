//! `VmmSpec` — the backend-agnostic physical recipe a `VmmDriver` boots.
//!
//! A guest VM has exactly three host-visible channel kinds: block storage,
//! vsock, and a write-only console. There is deliberately no NIC: a guest's
//! only path off the box is a reserved vsock egress port terminated by the
//! host-side egress bridge. Keeping networking out of the spec is what stops a
//! driver from being able to enforce — or bypass — egress policy.

use std::path::PathBuf;

/// Where a VM's kernel comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelImage {
    /// An explicit kernel file on the host (Firecracker, qemu, the in-house VMM).
    Path(PathBuf),
    /// The backend supplies its own bundled kernel (libkrun's libkrunfw).
    Bundled,
}

/// One virtio-blk device. `slot` fixes the guest device-node ordering so the
/// kernel cmdline (roothash, overlay) can name a stable `/dev/vdX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockDev {
    pub source: PathBuf,
    pub read_only: bool,
    /// Load the whole image into guest RAM and drop writes on exit, instead of
    /// serving it from the host file. A writable workload rootfs sets this (its
    /// mutations must not persist to the shared base image); a builder's
    /// nix-store / output disk clears it so writes persist to the host file.
    pub ephemeral: bool,
    pub slot: u8,
}

impl BlockDev {
    /// The guest device node for this slot: 0 -> `/dev/vda`, 1 -> `/dev/vdb`, ...
    /// Panics above slot 25; no workload needs more than 26 disks.
    pub fn device_node(&self) -> String {
        assert!(self.slot <= 25, "block slot {} exceeds /dev/vdz", self.slot);
        let letter = (b'a' + self.slot) as char;
        format!("/dev/vd{letter}")
    }
}

/// Which side opens a vsock connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsockDirection {
    /// The guest listens on `guest_port`; the host dials it (e.g. the agent RPC).
    HostDials,
    /// The host listens on `host_uds`; the guest dials it (e.g. the egress port).
    GuestDials,
}

/// One vsock port mapping between a guest port and a host unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockPort {
    pub guest_port: u32,
    pub host_uds: PathBuf,
    pub direction: VsockDirection,
}

/// Write-only host capture of the guest console. There is no input fd — the
/// host can read the log but never write the guest's console, so a sealed
/// guest stays non-interactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleCapture {
    pub log_path: PathBuf,
}

/// The backend-agnostic physical recipe a [`VmmDriver`](crate::driver::VmmDriver)
/// boots. No NIC: vsock is the only channel off the guest besides storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmmSpec {
    pub name: String,
    pub kernel: KernelImage,
    /// Optional initramfs the kernel unpacks before pivoting to the rootfs. Real
    /// verified-boot workloads (dm-verity init) and the echo-guest proof boot one.
    pub initramfs: Option<PathBuf>,
    pub cmdline: String,
    pub vcpus: u32,
    pub memory_mib: u32,
    /// Initial host commitment for virtio-balloon elasticity; `None` commits
    /// the full `memory_mib` at boot.
    pub mem_initial_mib: Option<u32>,
    pub blocks: Vec<BlockDev>,
    pub vsock: Vec<VsockPort>,
    pub console: ConsoleCapture,
    /// Trusted-builder VM: it carries no untrusted workload, so it boots WITHOUT
    /// the claim-10 egress gate (no `EGRESS_PORT` relay required). A workload
    /// leaves this `false` so a missing egress relay fails closed rather than
    /// booting ungated.
    pub trusted_builder: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_dev_device_node_maps_slot_to_letter() {
        let mk = |slot| BlockDev {
            source: "/x".into(),
            read_only: true,
            ephemeral: false,
            slot,
        };
        assert_eq!(mk(0).device_node(), "/dev/vda");
        assert_eq!(mk(1).device_node(), "/dev/vdb");
        assert_eq!(mk(25).device_node(), "/dev/vdz");
    }
}
