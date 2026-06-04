//! mvm-guest-helpers — in-guest helper binaries (plan 121 D3).
//!
//! Two small helpers baked into the microVM rootfs by `mkGuest` and run
//! inside the guest (never on the host). Each ships as a `[[bin]]`; the
//! library halves live here as modules so they stay unit-testable.
//!
//! - [`addon_dns`] — loopback DNS resolver (`mvm-addon-dns`).
//! - [`addon_vsock_bridge`] — loopback TCP ↔ host-vsock bridge
//!   (`mvm-addon-vsock-bridge`).
//!
//! Folded in from the former `mvm-addon-dns` + `mvm-addon-vsock-bridge`
//! crates.

pub mod addon_dns;
pub mod addon_vsock_bridge;
