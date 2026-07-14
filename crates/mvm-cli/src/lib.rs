// mvm-cli: Clap commands, UI, bootstrap
// Depends on mvm-core, mvm, mvm-build

pub mod bootstrap;
pub mod commands;
pub mod config_watcher;
pub mod doctor;
mod egress_ca_env;
pub mod exec;
pub mod host_binaries;
pub mod http;
pub mod json_out;
pub mod logging;
pub mod metrics_server;
pub mod shell_init;
pub mod signal;
pub mod template_cmd;
pub mod ts_runner;
pub mod ui;
pub mod update;
pub mod watch;

pub use commands::run;

/// Plan synthesis for library consumers — building an
/// [`mvm_core::plan::ExecutionPlan`] from typed inputs.
///
/// The synthesis core now lives in `mvm-core` (beside the plan types) so every
/// driver can reach it; this re-export preserves the `mvm_cli::plan_builder`
/// path. Synthesis produces an unsigned plan and confers no authority; signing
/// and admission still gate execution.
pub mod plan_builder {
    pub use mvm_core::plan::{SynthesisInput, synthesize_plan};
}
