// mvm-cli: Clap commands, UI, bootstrap
// Depends on mvm-core, mvm, mvm-build

pub mod bootstrap;
pub mod commands;
pub mod config_watcher;
pub mod doctor;
pub mod exec;
pub mod host_binaries;
pub mod http;
pub mod json_out;
pub mod logging;
pub mod metrics_server;
pub mod security_cmd;
pub mod shell_init;
pub mod template_cmd;
pub mod ts_runner;
pub mod ui;
pub mod update;
pub mod watch;

pub use commands::run;

/// Plan synthesis for library consumers — building an
/// [`mvm_core::plan::ExecutionPlan`] from typed inputs.
///
/// Synthesis produces an unsigned plan and confers no authority; signing and
/// admission still gate execution.
pub mod plan_builder {
    pub use crate::commands::vm::plan_builder::{SynthesisInput, synthesize_plan};
}
