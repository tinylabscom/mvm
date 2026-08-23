//! `VmmSpec` — the backend-agnostic physical recipe a `VmmDriver` boots.
//!
//! A guest VM has exactly three host-visible channel kinds: block storage,
//! vsock, and a write-only console. There is deliberately no NIC: a guest's
//! only path off the box is a reserved vsock egress port terminated by the
//! host-side egress bridge. Keeping networking out of the spec is what stops a
//! driver from being able to enforce — or bypass — egress policy.

use std::path::PathBuf;

use mvm_net::channel::GuestService;

/// Where a VM's kernel comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelImage {
    /// An explicit kernel file on the host (Firecracker, qemu, the hvf VMM).
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

/// One typed guest service mapping to a host unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockPort {
    pub service: GuestService,
    pub host_uds: PathBuf,
    pub direction: VsockDirection,
}

impl VsockPort {
    /// The numeric vsock port used at the VMM boundary.
    pub fn port(&self) -> u32 {
        self.service.port()
    }
}

/// Write-only host capture of the guest console. There is no input fd — the
/// host can read the log but never write the guest's console, so a sealed
/// guest stays non-interactive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleCapture {
    pub log_path: PathBuf,
}

/// One virtio-fs host directory share.
///
/// Backends that support virtio-fs attach this as a guest-visible filesystem
/// tagged with `tag`. `dax` requests direct host-page access when both the
/// backend and the guest kernel support it; backends without DAX support
/// ignore the flag and serve the share through the normal FUSE path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtioFsShare {
    pub tag: String,
    pub host_path: PathBuf,
    pub read_only: bool,
    pub dax: bool,
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
    /// The share of host CPU time the per-VM process may consume, if this
    /// launch was admitted under one. Distinct from `vcpus`, which is how many
    /// processors the guest sees. Drivers hand it to
    /// `mvm_core::cpu_scope::bind_cpu_grant` at spawn, so the process is born
    /// bounded rather than bounded shortly afterwards.
    pub cpu_grant: Option<mvm_contract::grants::CpuGrant>,
    pub memory_mib: u32,
    /// Initial host commitment for virtio-balloon elasticity; `None` commits
    /// the full `memory_mib` at boot.
    pub mem_initial_mib: Option<u32>,
    pub blocks: Vec<BlockDev>,
    pub vsock: Vec<VsockPort>,
    pub console: ConsoleCapture,
    /// virtio-fs host directory shares. A `virtiofs_root` boot supplies one
    /// share tagged `mvmroot`; additional `DirShare` volumes add more tags.
    /// Backends without virtio-fs support must reject a non-empty list.
    pub shares: Vec<VirtioFsShare>,
    /// Trusted-builder VM: it carries no untrusted workload, so it boots
    /// without an egress relay. Workload launches leave this false so a
    /// missing relay fails closed rather than booting ungated.
    pub trusted_builder: bool,
    /// What a supervisor needs to enforce the plan's wall-clock bound and
    /// record the kill. `None` on the boot paths that carry no plan — Stage 0
    /// and the builder VM — which therefore have no bound to enforce.
    pub plan_binding: Option<PlanBinding>,
}

/// The admitted plan plus the two paths a supervisor needs to audit a kill
/// under it.
///
/// Deliberately narrower than [`AuditSubstrate`](crate::host::audit_substrate::AuditSubstrate):
/// it carries no `tenant_id` and no gateway sockets. Those select the
/// supervisor's admission route, and a wall-clock bound has to be enforceable
/// without changing which route a workload takes. Nothing is lost by omitting
/// the tenant — the audit entry takes it from the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanBinding {
    /// The admitted `ExecutionPlan` envelope, as the supervisor re-verifies it.
    /// Untyped here so the spec does not couple to `mvm_core::plan`.
    pub plan_json: serde_json::Value,
    /// `~/.mvm/audit/` — where the chain-signed kill entry lands.
    pub audit_dir: PathBuf,
    /// `~/.mvm/keys/host-signer.ed25519` — the key the chain is signed under.
    pub signing_key_path: PathBuf,
}

impl VmmSpec {
    /// The host unix socket a standing guest service binds to.
    /// `None` when the spec carries no channel for that service. Drivers use
    /// this lookup instead of each re-scanning the raw channel list.
    pub fn host_socket_for_service(&self, service: GuestService) -> Option<PathBuf> {
        self.vsock
            .iter()
            .find(|p| p.service == service)
            .map(|p| p.host_uds.clone())
    }
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

    #[test]
    fn typed_vsock_service_resolves_its_transport_port() {
        let channel = VsockPort {
            service: GuestService::NetworkFlow,
            host_uds: "/run/network-flow.sock".into(),
            direction: VsockDirection::GuestDials,
        };
        assert_eq!(channel.port(), GuestService::NetworkFlow.port());
    }
}
