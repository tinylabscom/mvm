//! Host-side network state that outlives a single flow.
//!
//! A workload guest has no NIC: egress leaves over vsock to the per-VM network
//! endpoint, which decides every destination through `EgressGate`. Nothing on
//! the host parses or inspects guest packets. What remains here is the flow
//! byte log that `mvmctl cache prune` sweeps.

pub mod flow_byte_log;
