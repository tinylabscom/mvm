//! Shared host-side vsock egress support. Policy enforcement lives in the host
//! endpoint/gate; the backend relay code only moves bytes between guest streams
//! and the per-VM endpoint socket.

pub mod egress_gate;
pub(crate) mod substitution_bridge;
