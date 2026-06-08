//! mvm-vm-host — per-VM supervisor host processes (plan 121 D2).
//!
//! One process per guest VM. The three roles ship as cfg-gated
//! `[[bin]]`s (see Cargo.toml): `mvm-libkrun-supervisor`,
//! `mvm-vz-drainer`, `mvm-firecracker-bridge`. They are leaf binaries
//! — nothing depends on them as a library; `mvm-backend`'s spawner
//! resolves them by binary name on the launch path.
//!
//! This shared lib carries only the firecracker-bridge config +
//! passt-hash parsers (`firecracker_bridge::parse`), which both the
//! `mvm-firecracker-bridge` bin and the fuzz harnesses consume.
//! Folded in from the former `mvm-firecracker-bridge` crate.

pub mod exit_capture;
pub mod firecracker_bridge;

// Rust-native Vz supervisor objc2 bridge (Plan 152 WS-B). macOS-only — the
// objc2 Virtualization.framework stack only exists there; the
// `mvm-vz-supervisor` bin is the sole consumer. Kept in the lib (not inline in
// the bin) so the config→VZ translation and the dispatch/delegate bridge get
// unit coverage independent of a live VM boot.
#[cfg(target_os = "macos")]
pub mod vz_objc;
