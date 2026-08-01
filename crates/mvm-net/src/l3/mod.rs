//! Policy core for the L3-over-vsock network mode.
//!
//! Everything here is pure: no sockets, no privileges, no platform calls,
//! and no wall-clock reads. That is deliberate — it is the part that
//! decides whether a guest's packet may exist on the host network, so it
//! must be exhaustively testable in ordinary unprivileged CI.
//!
//! The host gateway (`mvm-hostd::netd`) supplies the I/O and the platform
//! datapath; this crate supplies the decisions. Egress rules are not
//! re-derived here: admission consults the same
//! [`CanonicalEgress`](mvm_core::policy::projection::CanonicalEgress)
//! projection that nftables and the socket-aware gate consume, so
//! `--allow-host api.example.com:443` means one thing everywhere.
//!
//! See `specs/adrs/035-l3-tun-over-vsock.md`.

pub mod admit;
pub mod alloc;
/// Whether a plan's networking mode can serve what the plan asks for.
pub mod compat;
pub mod dns;
pub mod flow;
pub mod ingress;
pub mod session;

pub use admit::{
    AdmittedPacket, DeliverablePacket, DenyCode, GatewayService, IcmpPolicy, InboundVerdict,
    L3Admitter, L3PolicyConfig, OutboundVerdict, clamp_tcp_mss,
};
pub use alloc::{AddressAllocator, AddressLease, AllocError, DEFAULT_POOL};
pub use compat::{ModeCompatError, SubstitutionRequirements, check_mode_compatibility};
pub use dns::{DnsBinding, DnsBindingStore, DnsDeny, DnsLimits};
pub use flow::{FlowAdmission, FlowCounters, FlowKey, FlowLimits, FlowState, FlowTable};
pub use ingress::{IngressError, IngressMapping, IngressTable};
pub use session::{L3Session, SessionError, SessionId, SessionRegistry, SessionState};
