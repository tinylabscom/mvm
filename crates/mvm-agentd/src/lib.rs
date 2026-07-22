// mvm-agentd: vsock protocol and openclaw connector mapping for mvm
// Depends on mvm-core

/// Loopback DNS resolver (`mvm-addon-dns`).
#[cfg(feature = "addons")]
pub mod addon_dns;
/// Loopback TCP ↔ host-vsock bridge (`mvm-addon-vsock-bridge`).
#[cfg(feature = "addons")]
pub mod addon_vsock_bridge;
/// In-guest host-services broker client: dials the supervisor's guest-facing
/// broker port over vsock and exchanges a framed `ServiceCall` for a framed
/// `ServiceResponse`. The workload→host call half of the broker path.
pub mod broker_client;
pub mod builder_agent;
/// The hvf-VMM builder's guest-side nix build (stages artifacts for the
/// session to stream back).
pub mod builder_build;
/// The hvf-VMM builder's host↔guest build session over one vsock stream.
pub mod builder_session;
/// Builder-VM file transfer over vsock (the hvf VMM has no virtio-fs).
pub mod builder_transfer;
/// PTY-over-vsock interactive console — the single dev-only interactive path
/// into a guest. Gated behind `interactive` so the relay symbols are absent from
/// a sealed production agent (claim 15: no interactive access to a sealed prod
/// microVM), mirroring `do_exec`. The host-side console client talks to it over
/// vsock and is unaffected by this gate.
#[cfg(feature = "interactive")]
pub mod console;
/// Loopback SOCKS5 → host-vsock egress proxy (`mvm-egress-client`).
#[cfg(feature = "addons")]
pub mod egress_client;
pub mod entrypoint;
/// In-guest forward-proxy front: parses a workload's proxied request into a
/// `WireRequest` for the substitution client.
pub mod forward_proxy;
pub mod fs_rpc;
/// Guest-side VMGenID reseed. On a snapshot resume the host
/// delivers a fresh generation token; when it changes (a clone, not a
/// normal wake) the guest reseeds its CSPRNG so two clones don't generate
/// identical key material.
pub mod genid;
/// Shared in-guest network bring-up (eth0 up + DHCP + static fallback), used by
/// both the builder VM init and the workload guest netinit.
pub mod guest_net;
/// Guest-side `/dev/net/tun` helper for the shared packet-tunnel data plane.
pub mod guest_tun;
/// Shared in-guest vsock session helper for the addon/egress helper bins.
#[cfg(feature = "addons")]
mod guest_vsock_session;
/// In-guest `host.audit.v1` typed methods: `emit` / `emit_batch` over the
/// broker transport, letting a workload append to the chain-signed audit log.
pub mod host_audit;
/// In-guest `host.cost.v1` typed methods: `workload` / `tenant` spend queries
/// over the broker transport.
pub mod host_cost;
/// In-guest `host.time.v1` typed method: `now` host wall-clock query over the
/// broker transport.
pub mod host_time;
pub mod integrations;
pub mod lifecycle_hooks;
/// Guest-side network defense. The `mvm-guest-netinit`
/// binary calls into this module at boot to install kernel blackhole
/// routes for `MANDATORY_DENY_RANGES` before any workload code runs.
/// The module's types + install loop + tests build everywhere; the
/// `RawNetlinkInstaller` (a synchronous `AF_NETLINK` socket via libc)
/// is Linux-only and gated inside the module.
pub mod netinit;
/// Guest-side blocking session helper for the shared vsock/UDS packet tunnel.
pub mod network_tunnel;
pub mod probes;
/// In-guest entrypoint runtime for function-call workloads. The
/// `mvm-runner` binary (`src/bin/mvm-runner.rs`) is the thin entry over
/// these testable units. Folded in from the former `mvm-runner` crate.
pub mod runner;
pub mod runtime_config;
/// In-guest substitution client: relays a secret-bearing request to the host
/// substitution endpoint over vsock (the relay half of the guest-local forward
/// proxy).
pub mod substitution_client;
pub mod volume;
pub mod vsock;
pub mod worker_pool;
pub mod worker_protocol;

/// Process control RPC handler. Dev-only: gated behind `interactive` so
/// symbols are stripped from production guest agents.
#[cfg(feature = "interactive")]
pub mod process_rpc;

/// Streaming exec core — runs `sh -c <cmd>` and emits `ExecEvent` chunks
/// via a closure. Dev-only (claim 4: no `do_exec` in production agents).
pub mod exec_stream;
