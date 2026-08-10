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

mod context;
mod error;
mod start;
mod supervisor;

pub use error::{Error, install_hint, install_paths, is_available};

pub use context::{
    GuestEntrypoint, KernelFormat, KrunContext, KrunDisk, KrunVirtioFs, NetworkingMode,
};

// Exported whenever the module compiles, not only under the FFI feature.
// `start` is written to fail with `Error::NotYetWired` in a featureless
// build — its own test asserts that — so gating the re-export on the feature
// left it reachable from nothing. That went unnoticed only because the
// gateway-bridge boot path referenced it internally; deleting that path made
// the inconsistency visible.
#[cfg(target_family = "unix")]
pub use start::{start, start_enter};

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

// Sync length-prefixed JSON framing for the supervisor control
// channels. Colocated with the `Supervisor*Config` wire types it frames so both the
// `mvm-backend` writer (`claim_standby`) and the supervisor-bin reader reach it without
// a dependency cycle (`mvm-backend` can't depend on `mvm-hostd`).
pub mod framing;
