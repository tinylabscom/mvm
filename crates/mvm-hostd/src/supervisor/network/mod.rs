//! Packet-level helpers shared by the host-side egress path.
//!
//! This module used to host an observer trait, an allowlist resolver, and a
//! `Pipeline` builder feeding a per-packet fan-out. All of it existed to
//! inspect traffic on a guest's virtio-net device. A workload guest has no
//! NIC — egress leaves over vsock to the per-VM substitution endpoint — so
//! the fan-out had no packets to see and was removed along with the gateway
//! bridge that drove it.
//!
//! What survives is what the vsock path actually uses: the packet parser, the
//! substitution/scan stages the endpoint applies, and the flow byte log that
//! `mvmctl cache prune` sweeps.

use crate::supervisor::audit::FlowDirection;

pub mod flow_byte_log;
pub mod packet;
/// Substitution/scan egress-proxy seams.
pub mod stages;

/// Context presented alongside a parsed packet. Borrowed; cheap to build per
/// packet. `tenant` reflects the single-tenant invariant (one guest = one
/// workload).
#[derive(Debug, Clone, Copy)]
pub struct PacketCtx<'a> {
    pub vm_name: &'a str,
    pub tenant: &'a str,
    pub direction: FlowDirection,
    pub flow_id: &'a str,
}
