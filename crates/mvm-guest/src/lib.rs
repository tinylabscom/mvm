// mvm-guest: vsock protocol and openclaw connector mapping for mvm
// Depends on mvm-core

pub mod builder_agent;
pub mod console;
pub mod entrypoint;
pub mod fs_rpc;
pub mod integrations;
pub mod lifecycle_hooks;
/// Plan 74 W2 — guest-side network defense. The `mvm-guest-netinit`
/// binary calls into this module at boot to install kernel blackhole
/// routes for `MANDATORY_DENY_RANGES` before any workload code runs.
/// The module's types + install loop + tests build everywhere; the
/// `RtnetlinkInstaller` (which talks to `AF_NETLINK`) is Linux-only
/// and gated inside the module.
pub mod netinit;
pub mod probes;
/// In-guest entrypoint runtime for function-call workloads (ADR-0009 /
/// plan 60 Phase 5 Slice C). The `mvm-runner` binary
/// (`src/bin/mvm-runner.rs`) is the thin entry over these testable
/// units. Folded in from the former `mvm-runner` crate (plan 121 A1).
pub mod runner;
pub mod runtime_config;
pub mod volume;
pub mod vsock;
pub mod worker_pool;
pub mod worker_protocol;

/// Process control RPC handler — A2 of the filesystem-volumes plan.
/// Dev-only: gated behind `dev-shell` so symbols are stripped from
/// production guest agents (ADR-002 §W4.3 + ADR-007 §W5).
#[cfg(feature = "dev-shell")]
pub mod process_rpc;
