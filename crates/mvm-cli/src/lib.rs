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
