//! mvm-base — shared substrate for `mvm` + `mvm-backend`.
//!
//! Lifts the substrate that backend implementations need out of
//! `mvm` so the concrete `VmBackend` impls can live in `mvm-backend`
//! without a back-edge into `mvm`.
//!
//! ## What lives here
//!
//! | Module          | Purpose                                                |
//! |-----------------|--------------------------------------------------------|
//! | `ui`            | `[mvm]` printing + spinners + interactive prompts      |
//! | `runtime_meta`  | Per-VM `~/.mvm/vms/<name>/mode.json` (console gate) |
//! | `cow`           | Reflink (CoW) file cloning + `clone_rootfs_for_instance` |
//! | `config`        | Builder VM name, FC network/path constants, wire types |
//! | `shell`         | Host + Linux-env command execution helpers             |
//! | `linux_env`     | Dispatch trait impls (NativeEnv, VzDevEnv)             |
//!
//! ## Re-exports kept by `mvm`
//!
//! `mvm`'s `lib.rs` re-exports the modules at their old
//! paths so the mvmd contract surface (`mvmctl::runtime::shell`,
//! `mvmctl::runtime::ui`, `mvmctl::runtime::shell_mock`) and the
//! console gate (`mvm::vm::runtime_meta`) keep resolving.

pub mod config;
pub mod cow;
pub mod linux_env;
pub mod runtime_meta;
pub mod shell;
pub mod snapshot_integrity;
pub mod ui;

// Legacy re-export: `crate::base::shell_mock::*` matches the older
// `mvm::shell_mock::*` path that mvmd's quic_integration test relies
// on.
pub use shell::mock as shell_mock;
