// mvm-guest: vsock protocol and openclaw connector mapping for mvm
// Depends on mvm-core

pub mod builder_agent;
/// PTY-over-vsock interactive console — the single dev-only interactive path
/// into a guest. Gated behind `dev-shell` so the relay symbols are absent from
/// a sealed production agent (Plan 165 WS-C, claim 15), mirroring `do_exec`
/// (ADR-002 §W4.3). The host-side console client talks to it over vsock and is
/// unaffected by this gate.
#[cfg(feature = "dev-shell")]
pub mod console;
pub mod entrypoint;
/// Plan 129 / ADR-067 §1 (model ii) — in-guest forward-proxy front: parses a
/// workload's proxied request into a `WireRequest` for the substitution client.
pub mod forward_proxy;
pub mod fs_rpc;
/// Plan 122 D — guest-side VMGenID reseed. On a snapshot resume the host
/// delivers a fresh generation token; when it changes (a clone, not a
/// normal wake) the guest reseeds its CSPRNG so two clones don't generate
/// identical key material.
pub mod genid;
pub mod integrations;
pub mod lifecycle_hooks;
/// Plan 74 W2 — guest-side network defense. The `mvm-guest-netinit`
/// binary calls into this module at boot to install kernel blackhole
/// routes for `MANDATORY_DENY_RANGES` before any workload code runs.
/// The module's types + install loop + tests build everywhere; the
/// `RawNetlinkInstaller` (a synchronous `AF_NETLINK` socket via libc,
/// Plan 124 A3) is Linux-only and gated inside the module.
pub mod netinit;
pub mod probes;
/// In-guest entrypoint runtime for function-call workloads (ADR-0009 /
/// plan 60 Phase 5 Slice C). The `mvm-runner` binary
/// (`src/bin/mvm-runner.rs`) is the thin entry over these testable
/// units. Folded in from the former `mvm-runner` crate (plan 121 A1).
pub mod runner;
pub mod runtime_config;
/// Plan 129 / ADR-067 §1 — in-guest substitution client: relays a secret-bearing
/// request to the host substitution endpoint over vsock (the relay half of the
/// guest-local forward proxy).
pub mod substitution_client;
pub mod volume;
pub mod vsock;
pub mod worker_pool;
pub mod worker_protocol;

/// Process control RPC handler — A2 of the filesystem-volumes plan.
/// Dev-only: gated behind `dev-shell` so symbols are stripped from
/// production guest agents (ADR-002 §W4.3 + ADR-007 §W5).
#[cfg(feature = "dev-shell")]
pub mod process_rpc;

/// Streaming exec core — runs `sh -c <cmd>` and emits `ExecEvent` chunks
/// via a closure. Dev-only (claim 4 / ADR-002 §W4.3). Plan 159 WS-5 E.
pub mod exec_stream;
