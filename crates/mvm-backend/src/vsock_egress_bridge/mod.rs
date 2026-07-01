//! The single host-side vsock egress bridge: the one place the claim-10 gate and
//! claims-12/13 substitution are enforced, for every backend. Promoted out of the
//! in-house VMM device model so it is backend-agnostic and one implementation
//! serves all backends.

pub mod egress_gate;
pub(crate) mod egress_proxy;
pub(crate) mod substitution_bridge;
