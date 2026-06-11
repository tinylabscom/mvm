//! Egress proxy substrate.
//!
//! Two layers:
//!
//! - **L4** ([`l4`]) — `(proto, dst_cidr, dst_port_range)` rules
//!   evaluated against the destination IP + port. Pure-policy
//!   substrate today; the TUN/smoltcp userspace-TCP termination
//!   that consumes this policy ships with the per-tenant network-
//!   namespace work.
//! - **L7** (see [`crate::supervisor::l7_proxy`]) — HTTPS CONNECT + plain-HTTP
//!   inspection chain. Constructs `L7EgressProxy` from a parsed
//!   policy bundle.

pub mod l4;
