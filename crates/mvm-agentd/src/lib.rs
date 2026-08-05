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
/// The single waiter for child processes: an orphan reaper that publishes
/// what it collects, so PID-1 reaping cannot destroy an owned child's exit
/// status.
pub mod child_wait;
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
/// Runs one entrypoint call with its pump and its consumer on separate
/// threads, so a consumer that blocks — a host that stopped reading — cannot
/// defer the child's deadline or grow the pump's queue without bound.
pub mod entrypoint_stream;
/// In-guest forward-proxy front: parses a workload's proxied request into a
/// `WireRequest` for the substitution client.
pub mod forward_proxy;
pub mod fs_rpc;
/// Guest-side VMGenID reseed. On a snapshot resume the host
/// delivers a fresh generation token; when it changes (a clone, not a
/// normal wake) the guest reseeds its CSPRNG so two clones don't generate
/// identical key material.
pub mod genid;
/// Post-mount guest environment setup shared by the two guest inits, so the
/// legacy per-rootfs initrd and the universal-initramfs agent cannot drift.
#[cfg(target_os = "linux")]
pub mod guest_bootstrap;
pub mod guest_mount;
/// Shared in-guest network bring-up (eth0 up + DHCP + static fallback), used by
/// both the builder VM init and the workload guest netinit.
pub mod guest_net;
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
pub mod icmp_client;
pub mod integrations;
/// The in-guest half of the L3 TUN-over-vsock tunnel: the `mvm0` device,
/// its host-assigned configuration, the privilege drop, and the packet
/// pump. `mvm0` terminates only in this agent.
pub mod l3;
pub mod lifecycle_hooks;
/// Guest-side network defense. The `mvm-guest-netinit`
/// binary calls into this module at boot to install kernel blackhole
/// routes for `MANDATORY_DENY_RANGES` before any workload code runs.
/// The module's types + install loop + tests build everywhere; the
/// `RawNetlinkInstaller` (a synchronous `AF_NETLINK` socket via libc)
/// is Linux-only and gated inside the module.
pub mod netinit;
/// Shared rtnetlink plumbing: the kernel ABI constants, the request
/// framing, and the synchronous socket that both `netinit`'s blackhole
/// routes and the L3 agent's IPv6 bring-up send through.
pub mod netlink;
pub mod probes;
/// Restore-time guest wall-clock synchronization.
pub mod restore_clock;
/// In-guest entrypoint runtime for function-call workloads. The
/// `mvm-runner` binary (`src/bin/mvm-runner.rs`) is the thin entry over
/// these testable units. Folded in from the former `mvm-runner` crate.
pub mod runner;
pub mod runtime_config;
/// Delivery of admitted input bytes into a running workload's stdin, plus the
/// explicit EOF a read-to-EOF workload needs to ever terminate.
pub mod stream_input;
/// Streaming pump for a spawned workload's stdout / stderr / fd-3 control
/// channel. Emits an `EntrypointEvent` per read while the child is still
/// running, so a long-lived workload is observable long before it exits.
pub mod stream_pump;
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
