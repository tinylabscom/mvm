// mvm-cli: Clap commands, UI, bootstrap
// Depends on mvm-core, mvm-runtime, mvm-build

pub mod bootstrap;
pub mod commands;
pub mod doctor;
pub mod fleet;
pub mod http;
pub mod logging;
pub mod security_cmd;
pub mod shell_init;
pub mod template_cmd;
pub mod ui;
pub mod upgrade;

pub use commands::run;
