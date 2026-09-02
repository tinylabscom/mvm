//! `mvm-broker` — host services broker subprocess.
//!
//! Owns the dispatch-loop, the UDS listener, and the `SubprocessConfig`
//! envelope the supervisor passes on stdin. Handlers (`host.time.v1`,
//! `host.cost.v1`, `broker.v1`) wire in through `Registry::register` —
//! until any are registered every call returns `Err(NotBound)`.
//!
//! What does NOT live here (owned by the supervisor side unless noted):
//! - Cosign verification of the binary at spawn
//! - TOCTOU-resistant verify-then-exec
//! - Subprocess config-envelope signature verification (this crate; the
//!   envelope is currently parsed unsigned, with the TODO marked at the
//!   parse site)
//! - Per-spawn ephemeral response signing
//! - Seccomp + setpriv + resource caps
//! - Per-workload cgroup + namespace
//! - `pdeathsig` parent-death attach (supervisor side / Linux-only — the
//!   broker subprocess can also call it as a defensive double-attach, but
//!   the supervisor's exec path is the authoritative gate)
//! - vsock 5300 listener wiring (the supervisor sets up the
//!   backend-specific listener and hands an FD; this crate consumes the
//!   FD via [`server::serve_on_listener`])

pub mod audit_client;
pub mod config;
pub mod control;
pub mod controller_proxy;
pub mod daemon;
pub mod handlers;
pub mod registry;
pub mod server;
pub mod service_proxy;
