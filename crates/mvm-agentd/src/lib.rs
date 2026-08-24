// mvm-agentd: vsock protocol and openclaw connector mapping for mvm
// Depends on mvm-core

/// Loopback DNS resolver (`mvm-addon-dns`).
#[cfg(feature = "addons")]
pub mod addon_dns;
/// Loopback TCP ↔ host-vsock bridge (`mvm-addon-vsock-bridge`).
#[cfg(feature = "addons")]
pub mod addon_vsock_bridge;
/// The workload-facing assurance campaign API.
pub mod assurance;
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
/// PTY-over-vsock console support. Access is enforced by the guest agent's
/// runtime profile and signed verb grant before a request reaches this module.
pub mod console;
/// Shared SOCKS5/HTTP parsing helpers for the FlowMux egress adapter.
#[cfg(feature = "addons")]
pub(crate) mod egress_client;
pub mod entrypoint;
/// Runs one entrypoint call with its pump and its consumer on separate
/// threads, so a consumer that blocks — a host that stopped reading — cannot
/// defer the child's deadline or grow the pump's queue without bound.
pub mod entrypoint_stream;
/// Boot-validated optional extension executables.
pub mod extension;
/// Guest-side FlowMux client for the converged single networking path.
#[cfg(feature = "flowmux-async")]
pub mod flowmux;
/// Load the per-boot FlowMux identity material used by the guest-side adapters.
pub mod flowmux_drive;
/// Loopback SOCKS5/HTTP-proxy → FlowMux egress bridge (`mvm-egress-client`).
#[cfg(feature = "addons")]
pub mod flowmux_egress;
#[cfg(feature = "addons")]
pub mod flowmux_keys;
/// Blocking one-shot FlowMux client for the guest's tokio-free callers.
pub mod flowmux_sync;
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
/// Guest hostname validation and provisioning shared by cold boot and warm
/// post-restore identity delivery.
pub mod guest_hostname;
pub mod guest_mount;
/// Shared in-guest network bring-up (eth0 up + DHCP + static fallback), used by
/// both the builder VM init and the workload guest netinit.
pub mod guest_net;
/// Shared in-guest vsock session helper for the addon/egress helper bins.
#[cfg(feature = "addons")]
pub mod guest_vsock_session;
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
pub mod icmp_mediator;
pub mod integrations;
pub mod lifecycle_hooks;
/// Guest-side network defense. The `mvm-guest-netinit`
/// binary calls into this module at boot to install kernel blackhole
/// routes for `MANDATORY_DENY_RANGES` before any workload code runs.
/// The module's types + install loop + tests build everywhere; the
/// `RawNetlinkInstaller` (a synchronous `AF_NETLINK` socket via libc)
/// is Linux-only and gated inside the module.
pub mod netinit;
/// Shared rtnetlink plumbing: kernel ABI constants, request framing, and the
/// synchronous socket used by `netinit`'s blackhole routes.
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
/// The single resolver for a workload's environment and working directory.
/// Both the entrypoint runner and the interactive console read the image's
/// declared runtime config through it.
pub mod workload_env;

/// Names the fixed workload uid/gid in the workload rootfs account databases,
/// so `whoami`/`id`/`getpwuid` resolve inside images mvm did not build.
pub mod workload_identity;

/// Process control RPC handler. Requests are admitted only after the guest
/// agent's runtime profile and signed verb grant checks succeed.
pub mod process_rpc;

/// Streaming exec core — runs `sh -c <cmd>` and emits `ExecEvent` chunks
/// via a closure. The guest agent admits calls at runtime.
pub mod exec_stream;
