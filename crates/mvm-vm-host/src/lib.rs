//! mvm-vm-host — per-VM supervisor host processes.
//!
//! One process per guest VM. The roles ship as `[[bin]]`s (see Cargo.toml):
//! `mvm-libkrun-supervisor` (libkrun VMM + merged in-process bridge;
//! libkrun-sys-gated), `mvm-hvf-supervisor` (the in-house HVF VMM), and the
//! shared `mvm-bridge` sidecar — the single external-VMM gateway/audit bridge
//! for Firecracker. They are leaf binaries — nothing depends on them as a
//! library; `mvm-backend`'s spawner resolves them by binary name on the launch
//! path.
//!
//! This shared lib carries the bridge config + passt-hash parsers: the unified
//! contract in `bridge::parse` (what `mvm-bridge` reads) plus the original
//! `firecracker_bridge::parse` helpers it re-exports (still fuzzed). Folded in
//! from the former per-VM bin crates.

/// Unified per-VM bridge-sidecar stdin contract. The shared `mvm-bridge`
/// sidecar parses [`bridge::parse::BridgeConfigJson`] and dispatches on its
/// endpoint discriminant; reuses the `firecracker_bridge::parse` plan-decode +
/// passt-hash helpers verbatim.
pub mod bridge;

/// Host-side vsock egress server: terminates the libkrun host-listen UDS,
/// decides the target against the shared claim-10 `EgressGate`, and proxies admitted
/// flows. The async per-connection counterpart to HVF's in-process gateway.
pub mod egress_server;

pub mod exit_capture;
pub mod firecracker_bridge;

/// The prelaunched-supervisor attach verify+merge. Pure (no VM, no
/// `start_enter`) so the rejection ladder is unit-testable.
pub mod prelaunch;
