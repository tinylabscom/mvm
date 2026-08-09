//! base — shared substrate for `mvm` + `mvm-backend` (was `mvm-base`).
//!
//! Lifts the substrate that backend implementations need out of
//! `mvm` so the concrete `VmBackend` impls can live in `mvm-backend`
//! without a back-edge into `mvm`.
//!
//! ## What still lives here
//!
//! | Module               | Purpose                                                  |
//! |----------------------|----------------------------------------------------------|
//! | `cow`                | Reflink (CoW) file cloning + `clone_rootfs_for_instance`  |
//! | `config`             | Builder VM name, FC network/path constants, wire types    |
//! | `snapshot_integrity` | Snapshot seal/verify helpers                              |
//!
//! ## What moved down into `mvm-vmm::host`
//!
//! `ui`, `runtime_meta`, `observability_target`, `shell`, and `linux_env`
//! now live in `mvm-vmm::host` so `mvm-backends` can use them without a
//! back-edge into `mvm-runtime`. They are re-exported below at their old
//! `crate::base::*` paths so in-crate callers and the mvmd contract
//! surface keep resolving.
//!
//! ## Re-exports kept by `mvm`
//!
//! `mvm`'s `lib.rs` re-exports the modules at their old
//! paths so the mvmd contract surface (`mvmctl::runtime::shell`,
//! `mvmctl::runtime::ui`, `mvmctl::runtime::shell_mock`) and the
//! console gate (`mvm::vm::runtime_meta`) keep resolving.

pub use mvm_vmm::host::config;
pub mod cow;
pub use mvm_vmm::host::linux_env;
pub use mvm_vmm::host::observability_target;
pub use mvm_vmm::host::runtime_meta;
pub use mvm_vmm::host::shell;
pub mod snapshot_integrity;
pub use mvm_vmm::host::ui;

// Legacy re-export: `crate::base::shell_mock::*` matches the older
// `mvm::shell_mock::*` path that mvmd's quic_integration test relies
// on.
pub use shell::mock as shell_mock;
