//! Guest-egress datapath primitives: DNS resolution, DNS/ICMP admission and flow state.

/// Pure DNS resolution used by the FlowMux endpoint.
pub mod dns_resolver;
pub mod egress_rate;
pub mod icmp_echo;
pub mod icmp_handler;
pub mod network;
