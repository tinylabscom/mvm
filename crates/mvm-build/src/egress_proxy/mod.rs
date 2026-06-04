//! egress_proxy — builder VM egress allowlist proxy (Plan 73 Followup
//! B.2.x, ADR-047 §"Build-time gates" → "Registry allowlist").
//!
//! Folded in from the former `mvm-egress-proxy` crate (plan 121 D4) as
//! a library module so its pub API stays dead-code-clean cross-platform
//! and the unit tests run everywhere. The `mvm-egress-proxy` binary
//! (`src/bin/mvm-egress-proxy.rs`, Linux-only at runtime) is a thin
//! wrapper that constructs an [`allowlist::Allowlist`], binds the proxy
//! with [`proxy::start`], and waits for SIGTERM.
//!
//! Consumer: `mvm-host-vm-init`'s `run_install` spawns the proxy + sets
//! `HTTPS_PROXY` / `HTTP_PROXY` on the installer's env before invoking
//! `uv` / `pnpm`.

pub mod allowlist;
pub mod proxy;

pub use allowlist::{ALLOWED_PORT, Allowlist, PRODUCTION_HOSTNAMES};
pub use proxy::{DEFAULT_BIND, ProxyHandle, parse_connect_target, start};
