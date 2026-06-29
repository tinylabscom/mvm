//! mvm-vm-host — per-VM supervisor host processes.
//!
//! One process per guest VM. The roles ship as `[[bin]]`s (see Cargo.toml):
//! `mvm-libkrun-supervisor` (libkrun VMM + merged in-process bridge;
//! libkrun-sys-gated), `mvm-vz-supervisor` (Vz VMM), and the shared `mvm-bridge`
//! sidecar — the single external-VMM gateway/audit bridge for Firecracker + vz
//! (replaces the former `mvm-firecracker-bridge` / `mvm-vz-drainer`). They are
//! leaf binaries — nothing depends on them as a library; `mvm-backend`'s spawner
//! resolves them by binary name on the launch path.
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

pub mod exit_capture;
pub mod firecracker_bridge;

/// Config contract for the `mvm-hvf-supervisor` per-VM host process (raw HVF
/// macOS backend, Plan 214). The bin reads it as JSON on stdin; kept in the lib
/// so the (de)serialize contract is unit-tested without a live boot.
pub mod hvf_supervisor;

/// The prelaunched-supervisor attach verify+merge. Pure (no VM, no
/// `start_enter`) so the rejection ladder is unit-testable.
pub mod prelaunch;

// Rust-native Vz supervisor objc2 bridge. macOS-only — the
// objc2 Virtualization.framework stack only exists there; the
// `mvm-vz-supervisor` bin is the sole consumer. Kept in the lib (not inline in
// the bin) so the config→VZ translation and the dispatch/delegate bridge get
// unit coverage independent of a live VM boot.
#[cfg(target_os = "macos")]
pub mod vz_objc;
