//! Guest-egress datapath primitives: the L4 gate and L7 proxy, DNS resolution, DNS/ICMP admission, the firewall seam and flow state.

/// Pure DNS resolution used by the FlowMux endpoint.
pub mod dns_resolver;
pub mod egress_rate;
pub mod firewall;
#[cfg(feature = "custom-dns")]
pub mod hickory_dns;
pub mod icmp_echo;
pub mod icmp_handler;
pub mod l7_proxy;
pub mod network;
pub mod proxy;
