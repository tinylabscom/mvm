//! `mvm-broker` — host services broker subprocess (Plan 104 §H-L1.3, ADR-061).
//!
//! W1a ships the dispatch-loop skeleton + the UDS listener + the
//! [`SubprocessConfig`] envelope the supervisor passes on stdin. Handlers
//! (`host.time.v1` in W3, `host.cost.v1` in W4a, `broker.v1` in W3) wire
//! in through [`Registry::register`] — until any are registered every call
//! returns `Err(NotBound)`.
//!
//! What does NOT live here (lands in W1b unless noted):
//! - Cosign verification of the binary at spawn (Plan 104 §H-L3.1, supervisor side)
//! - TOCTOU-resistant verify-then-exec (§H-L3.2, supervisor side)
//! - Subprocess config-envelope signature verification (§H-L3.6, this crate;
//!   W1a parses the envelope unsigned and marks the TODO at the parse site)
//! - Per-spawn ephemeral response signing (§H-L4.2, W1b)
//! - Seccomp + setpriv + resource caps (§H-L3.3 / §H-L3.9, supervisor side)
//! - Per-workload cgroup + namespace (§H-L1.4, supervisor side)
//! - `pdeathsig` parent-death attach (§Subprocess lifecycle details,
//!   supervisor side / Linux-only — the broker subprocess can also call
//!   it as a defensive double-attach, but the supervisor's exec path is
//!   the authoritative gate)
//! - vsock 5300 listener wiring (W1b — the supervisor sets up the
//!   backend-specific listener and hands an FD; this crate consumes the
//!   FD via [`server::serve_on_listener`])

pub mod audit_client;
pub mod config;
pub mod handlers;
pub mod registry;
pub mod server;
