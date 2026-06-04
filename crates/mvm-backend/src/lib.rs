//! mvm-backend — concrete `VmBackend` implementations.
//!
//! Plan-60 W7+W8 ended this crate's life as a re-export façade.
//! Every concrete backend now lives here:
//!
//! - **Firecracker** (`backend::FirecrackerBackend`) + the `AnyBackend`
//!   dispatch enum + `FirecrackerConfig` — the production Tier 1 path.
//! - **Apple Container** (`apple_container::AppleContainerBackend`) —
//!   macOS 26+ Apple Virtualization.framework.
//! - **Cloud Hypervisor** (`cloud_hypervisor::CloudHypervisorBackend`)
//!   — Tier 1 KVM peer of Firecracker (opt-in).
//! - **Docker** (`docker::DockerBackend`) — Tier 3 fallback.
//! - **libkrun** (`libkrun::LibkrunBackend`) — raw libkrun shim
//!   (Linux KVM / macOS HVF).
//! - **microvm.nix** (`microvm_nix::MicrovmNixBackend`) — Firecracker
//!   via the upstream microvm.nix runner.
//!
//! Plus the FC support modules: `firecracker` (installer helpers),
//! `microvm` (lifecycle), `image` (Mvmfile.toml), `network` (TAP/
//! bridge wiring).
//!
//! ## Dependency direction (post-W8)
//!
//!   mvm-core              ← VmBackend trait + types
//!   base (module)         ← config + shell + linux_env + ui +
//!                           runtime_meta + cow (substrate, was mvm-base)
//!   mvm-providers         ← libkrun/Apple-VZ FFI shims
//!     ↓                     ↓                     ↓
//!     └─────── mvm-backend (this crate) ────────┘
//!                          ↑
//!                     mvm
//!                     (consumes us via `vm::backend::AnyBackend`)
//!                     mvm-cli
//!                     (consumes us directly)

pub mod apple_container;
pub mod artifacts;
pub mod audit_substrate;
pub mod backend;
// Shared host-side substrate (config + shell + linux_env + ui +
// runtime_meta + cow + snapshot_integrity) — folded in from the
// former Lima-era `mvm-base` crate (plan 121 A2). It lives here, not
// in `mvm`, because `mvm-backend`'s concrete backends are its heaviest
// consumer and sit below `mvm`; folding it up into `mvm` would cycle
// (`mvm → mvm-backend → mvm`). `mvm` re-exports these at their old
// paths so the mvmd `mvmctl::runtime::{shell,ui,shell_mock}` contract
// surface keeps resolving.
pub mod base;
pub mod ch_runtime;
pub mod cloud_hypervisor;
pub mod compat;
pub mod docker;
pub mod firecracker;
pub mod handle_registry;
/// Apple Container / Apple Virtualization.framework runtime interface
/// (objc2 + Swift bridge, process spawn + verity wiring) — folded in
/// from the former `mvm-providers` crate (plan 121 C2). The
/// `apple_container` backend dispatch (`AppleContainerBackend`) stays in
/// `apple_container.rs`; this is the lower-level interface it drives.
pub mod providers;
// Plan 102 W6.A.5 — host-side gvproxy lifecycle for the Vz
// backend. VzBackend is stateless and the Swift supervisor doesn't
// spawn gvproxy itself, so the host process spawns gvproxy as a
// detached child (PID sidecar file under the per-VM scratch dir).
// Lifecycle: VzBackend::start spawns + writes PID; VzBackend::stop
// reads PID + signals.
pub mod host_gvproxy;
pub mod image;
pub mod libkrun;
pub mod microvm;
pub mod microvm_nix;
pub mod mock;
pub mod mock_guest_agent;
pub mod netinit_audit;
pub mod network;
// Plan 97 Phase B — Vz (Apple Virtualization.framework) backend.
// Currently a skeleton: trait surface + capabilities + security profile
// + availability probe; lifecycle methods land in a follow-up slice.
pub mod vz;
// Plan 97 Phase E — Rust client for the Vz supervisor's control
// socket (PAUSE / RESUME / BALLOON / SAVE). Used by VzBackend.
pub mod vz_control;

pub use apple_container::AppleContainerBackend;
pub use backend::{AnyBackend, FirecrackerBackend, FirecrackerConfig};
pub use cloud_hypervisor::CloudHypervisorBackend;
pub use docker::DockerBackend;
pub use libkrun::LibkrunBackend;
pub use microvm_nix::{MicrovmNixBackend, MicrovmNixConfig};
pub use mock::MockBackend;
pub use vz::VzBackend;

/// Crate-wide test serialization for tests that mutate `HOME` or
/// other process-global env vars. Re-exported from
/// [`crate::base::runtime_meta::HOME_TEST_LOCK`] so the
/// alt-backend tests share the same mutex with `mvm` tests
/// — without sharing one lock the modules race each other when
/// their tests run on the same `cargo test` binary.
///
/// Tests import from `mvm_base` directly; keep this note near the
/// module list so future process-global tests reuse the same lock.
#[cfg(any())]
pub(crate) use crate::base::runtime_meta::HOME_TEST_LOCK;
