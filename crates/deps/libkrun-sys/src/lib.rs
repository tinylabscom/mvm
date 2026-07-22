//! Rust bindings for Red Hat libkrun (Linux KVM, macOS Hypervisor.framework).
//!
//! libkrun is a library-style VMM: linked directly into the calling binary
//! rather than spawned as a separate daemon. On Linux it uses KVM; on
//! macOS it uses Hypervisor.framework. mvm supports this path on Linux
//! with KVM and macOS Apple Silicon; macOS Intel is intentionally not a
//! supported local microVM host.
//!
//! # Build modes
//!
//! - **default** (no feature) — no FFI, no link to libkrun. [`start`]
//!   and [`stop`] return [`Error::NotYetWired`]. The workspace compiles
//!   on hosts without libkrun installed.
//! - **`libkrun-sys`** — checked-in FFI bindings from `libkrun.h` plus
//!   `-lkrun` linking. [`start`] and [`stop`] dispatch through
//!   `sys::Context` into real libkrun calls.
//!
//! This crate stays narrowly focused on the FFI; backend dispatch and
//! lifecycle live in `mvm-backend` and `mvm-cli`.
//!
//! # Module layout
//!
//! The safe wrapper is split by concern: `error` (install probing plus
//! the crate's [`Error`] type), `context` ([`KrunContext`] and its
//! supporting types), `start` (the boot path), `bridge` (the
//! gateway-audit-bridge-inserting boot path), and `supervisor`
//! ([`SupervisorConfig`] and the long-lived supervisor entry points).
//! Every item below is re-exported at the crate root regardless of
//! which of those files defines it, so callers keep naming
//! `libkrun_sys::<Name>`.

#[cfg(feature = "libkrun-sys")]
mod sys;

mod bridge;
mod context;
mod error;
mod start;
mod supervisor;

pub use error::{Error, install_hint, install_paths, is_available};

pub use context::{
    GuestEntrypoint, KernelFormat, KrunContext, KrunDisk, KrunVirtioFs, NetworkingMode,
};

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
pub use start::GatewayHandle;
pub use start::{start, start_enter};

#[cfg(all(feature = "libkrun-sys", target_family = "unix"))]
pub use bridge::BridgeFds;
#[cfg(feature = "libkrun-sys")]
pub use bridge::run_supervisor_with_bridge;

#[cfg(feature = "libkrun-sys")]
pub use supervisor::run_supervisor;
#[cfg(not(feature = "libkrun-sys"))]
pub use supervisor::run_supervisor_unavailable;
pub use supervisor::{
    AttachMergeError, AuditSubstrateError, BridgeRestartPolicy, SupervisorAttachConfig,
    SupervisorBaseConfig, SupervisorConfig, stop,
};

#[cfg(feature = "libkrun-sys")]
pub use sys::{BundledKernel, LogLevel, extract_bundled_kernel, init_log, set_log_level};

// passt-backed virtio-net. The supervisor owns the passt child process
// and exposes the socket fd `KrunContext::Passt` consumes. Only Linux /
// macOS — Windows has neither libkrun nor passt. Tests are gated on a
// host-side passt install probe.
#[cfg(target_family = "unix")]
pub mod passt;

// Native-gateway-backed virtio-net. The macOS counterpart to passt; both
// modules share the same shape (spawn child, hand its socket to libkrun, kill
// on Drop) but the native gateway uses libkrun's `krun_add_net_unixgram`
// (path-based) where passt uses `krun_add_net_unixstream` (fd-passed). Same
// unix gate as passt — Windows has neither.
#[cfg(target_family = "unix")]
pub mod native_gateway;

// Tie a spawned networking helper to its supervisor's lifetime so a dead
// supervisor never orphans it (Linux `PR_SET_PDEATHSIG`; no-op elsewhere).
#[cfg(target_family = "unix")]
mod child_lifecycle;

// Sync length-prefixed JSON framing for the supervisor control
// channels. Colocated with the `Supervisor*Config` wire types it frames so both the
// `mvm-backend` writer (`claim_standby`) and the supervisor-bin reader reach it without
// a dependency cycle (`mvm-backend` can't depend on `mvm-hostd`).
pub mod framing;
