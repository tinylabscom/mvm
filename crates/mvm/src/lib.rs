// mvm — VM lifecycle orchestration on top of `mvm-backend::base`.
//
// The leaf substrate (`config`, `shell`, `linux_env`,
// `ui`, `runtime_meta`, `cow`) lives in `mvm-backend::base` so the FC backend
// stack can move into `mvm-backend` without a back-edge. The
// `pub use mvm_backend::base::*` re-exports below preserve the old
// `mvm::{config, shell, linux_env, ui, shell_mock}` paths so
// the mvmd contract surface (consumed via `mvmctl::runtime::*`) keeps
// resolving without forcing a sibling-repo update.

pub mod build_env;
pub mod machine;
pub mod security;
pub mod storage;
pub mod vsock_transport;

pub mod vm;

// Embedded-library surface for the warm-lease ergonomics.
pub use vm::exec_builder::{ExecBuilder, ExecOutcome};
pub use vm::lease::{AcquireSpec, WarmLease};

// The Machine product abstraction — the construction + capability-gate seam
// the CLI, mvmd, and the SDKs share.
pub use machine::{
    CapabilityError, Machine, MachineBuilder, MachineError, MachineSpec, NetworkMode,
};

// Substrate re-exports — see crate doc comment.
pub use mvm_backend::base::{config, linux_env, shell, ui};

// Legacy re-export — preserves `mvm::shell_mock::*` (used by
// mvmd's `mvmd-agent::quic_integration` test and a handful of
// `mvmd-runtime` security modules).
pub use mvm_backend::base::shell_mock;
