//! Host/guest networking primitives shared across the stack.
//!
//! This module is deliberately small: the wire format itself lives in
//! `mvm-contract::protocol::network_flow`, and policy/egress logic lives in
//! `crate::egress_*` and `crate::ingress_*`. The only thing that belongs here
//! is transport-independent machinery both sides need: the authenticated
//! session protecting FlowMux/control channels, the typed telemetry workers,
//! the typed guest services carried over vsock, and the network provider
//! contract with its registry.
//!
//! The provider contract owns no host resource and performs no host
//! mutation. Ingress/egress default-deny (claim 10) is not re-implemented
//! here: it reuses [`crate::network_policy::NetworkPolicy`], whose `Default`
//! is the empty (deny-all) policy, and egress itself is enforced by the
//! per-VM network endpoint.

pub mod actor_session;
/// Backend-neutral typed services over the VMM's guest-vsock transport.
pub mod channel;
pub mod provider;
pub mod registry;
pub mod session;
pub mod telemetry;
