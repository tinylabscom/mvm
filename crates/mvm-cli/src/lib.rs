// mvm-cli: Clap commands, UI, bootstrap
// Depends on mvm-core, mvm, mvm-build

pub mod bench;
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
pub(crate) mod mount_cache;
pub mod shell_init;
pub mod signal;
pub mod template_cmd;
pub mod template_registry;
pub mod ts_runner;
pub mod ui;
pub mod update;
pub mod watch;

pub use commands::run;

/// Launch-budget contract consumed by external validation harnesses.
pub mod launch_contract {
    pub use crate::commands::vm::phase_timing::{WARM_START_MAX_MS, within_warm_start_slo_ms};
}

/// Boot-policy contract surface for the dev-only conformance harness, which
/// drives the real effective-initrd decision instead of re-stating it in
/// Gherkin steps. Not a general-purpose API; other consumers must not take a
/// dependency on it.
pub mod boot_policy {
    pub use crate::commands::vm::up::oci_persist::persistent_oci_effective_initrd;
}

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
