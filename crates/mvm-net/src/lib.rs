#![forbid(unsafe_code)]
//! `NetworkProvider` — the provisioning + policy + teardown seam for one
//! VM's network.
//!
//! This crate is the **low seam**: it owns the trait and the policy/registry
//! types, nothing that needs the in-VM shell. The concrete TAP / bridge /
//! provider stays in `mvm-backend` (where `run_in_vm` and the
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

/// Backend-neutral typed services over the VMM's guest-vsock transport.
pub mod channel;
pub mod enforcement;
pub mod provider;
pub mod registry;

pub use channel::GuestService;
pub use enforcement::{EgressEnforcer, EgressWiring, EnforcementError};
pub use provider::{NetHandle, NetworkError, NetworkProvider, NetworkSpec};
pub use registry::NetworkProviderRegistry;
