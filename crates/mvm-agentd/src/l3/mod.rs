//! The in-guest side of the L3 TUN-over-vsock tunnel.
//!
//! `mvm0` is a point-to-point TUN interface that terminates **only** in
//! this agent. Every packet the guest stack routes to it is serialized onto
//! a machine-scoped vsock data connection; nothing else in the guest can
//! reach the host network, because nothing else exists to reach it with —
//! this mode runs on backends that present no network device at all.
//!
//! See `specs/adrs/035-l3-tun-over-vsock.md`.

pub mod agent;
pub mod netcfg;
pub mod privdrop;
pub mod tun;

pub use agent::{AgentCounters, AgentError, AgentState, NetAgent};
pub use netcfg::{InterfaceConfigurator, InterfacePlan, RecordingConfigurator};
pub use privdrop::{DropReport, drop_privileges};
pub use tun::{MemoryTun, TunDevice, TunError};

#[cfg(target_os = "linux")]
pub use netcfg::KernelConfigurator;
#[cfg(target_os = "linux")]
pub use tun::LinuxTun;
