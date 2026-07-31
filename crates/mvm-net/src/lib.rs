#![forbid(unsafe_code)]
//! `NetworkProvider` — the provisioning + policy + teardown seam for one
//! VM's network.
//!
//! This crate is the **low seam**: it owns the trait and the policy/registry
//! types, nothing that needs the in-VM shell. The concrete TAP / bridge /
//! native-gateway / passt provider stays in `mvm-backend` (where `run_in_vm` and the
//! `VmSlot` substrate live) and implements this trait; mvmd's WireGuard /
//! Tailscale mesh provider implements it too. Both register against the
//! [`registry::NetworkProviderRegistry`], so a `NetworkMode::Custom` mesh
//! plugs in without a core edit.
//!
//! Ingress/egress default-deny (claim 10) is not re-implemented here — the
//! seam reuses `mvm_core`'s `NetworkPolicy`, whose `Default` is the empty
//! (deny-all) policy.
//!
//! What this crate does **not** yet own: the actual relocation of the
//! firewall / L4 / L7 / packet-observer machinery out of `mvm-hostd` (those
//! carry claims-10/12/13 witnesses and move under their own follow-ups), and
//! the egress-proxy substitution/scan seams.

pub mod enforcement;
/// Policy core for the opt-in L3 TUN-over-vsock network mode: session
/// identity, address allocation, bounded flow state, per-packet admission,
/// DNS bindings, and declared ingress. Pure — the host gateway supplies
/// the I/O and the platform datapath.
pub mod l3;
pub mod provider;
pub mod registry;

pub use enforcement::{EgressEnforcer, EgressWiring, EnforcementError};
pub use provider::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};
pub use registry::NetworkProviderRegistry;
