//! Host/guest networking primitives shared across the stack.
//!
//! This module is deliberately small: the wire format itself lives in
//! `mvm-contract::protocol::network_flow`, and policy/egress logic lives in
//! `crate::egress_*` and `crate::ingress_*`. The only thing that belongs here
//! is transport-independent machinery both sides need: the authenticated
//! session protecting FlowMux/control channels and the typed telemetry workers.

pub mod session;
pub mod telemetry;
