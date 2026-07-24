//! Egress proxy substrate.
//!
//! Two layers:
//!
//! - **L4** ([`l4`]) — `(proto, dst_cidr, dst_port_range)` rules
//!   evaluated against the destination IP + port. Pure-policy
//!   substrate today; the supervisor's admitted L4 consumers apply these
//!   decisions to host-side connections.
//! - **L7** (see [`crate::supervisor::l7_proxy`]) — HTTPS CONNECT + plain-HTTP
//!   inspection chain. Constructs `L7EgressProxy` from a parsed
//!   policy bundle.

pub mod l4;
