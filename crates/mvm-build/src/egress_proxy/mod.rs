//! egress_proxy — builder VM egress allowlist proxy.
//!
//! Folded in from the former `mvm-egress-proxy` crate as
//! a library module so its pub API stays dead-code-clean cross-platform
//! and the unit tests run everywhere. The `mvm-egress-proxy` binary
//! (`src/bin/mvm-egress-proxy.rs`, Linux-only at runtime) is a thin
//! wrapper that constructs an `allowlist::Allowlist`, binds the proxy
//! with `proxy::start`, and waits for SIGTERM.
//!
//! Nothing in a builder VM runs it any more. The proxy dials upstream
//! itself, which in a builder with no NIC reaches nothing, and had there
//! been a route it would have left past the host's egress gate. Dependency
//! installs now go out through the vsock egress client like every other
//! builder job, and the binary is no longer in the host-binary manifests,
//! so it is neither embedded in `mvmctl` nor installed in a builder rootfs.
//! The source remains only because the image repository's host-binary
//! build still names the cargo target; it goes when that build stops.

pub mod allowlist;
pub mod proxy;

pub use allowlist::{ALLOWED_PORT, Allowlist, PRODUCTION_HOSTNAMES};
pub use proxy::{DEFAULT_BIND, ProxyHandle, parse_connect_target, start};
