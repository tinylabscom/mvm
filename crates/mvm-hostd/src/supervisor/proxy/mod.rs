//! Plan 60 Phase 3 — egress proxy substrate.
//!
//! Two layers ship as part of Phase 3:
//!
//! - **L4** ([`l4`]) — `(proto, dst_cidr, dst_port_range)` rules
//!   evaluated against the destination IP + port. Pure-policy
//!   substrate today; the TUN/smoltcp userspace-TCP termination
//!   that consumes this policy ships with the per-tenant network-
//!   namespace work (Phase 3 Slice C / mvm-hostd lift).
//! - **L7** (see [`crate::supervisor::l7_proxy`]) — HTTPS CONNECT + plain-HTTP
//!   inspection chain. Already live; Slice A flipped the W5
//!   resolver to construct `L7EgressProxy` from a parsed policy
//!   bundle.

pub mod l4;
