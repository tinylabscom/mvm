// mvm-runtime: Shell execution and VM lifecycle
// Depends on mvm-core and mvm-guest

pub mod build_env;
pub mod config;
pub mod linux_env;
pub mod security;
pub mod shell;
pub mod ui;
pub mod vsock_transport;

pub mod vm;

// Legacy re-export — preserve `mvm_runtime::shell_mock::*` path.
pub use shell::mock as shell_mock;
