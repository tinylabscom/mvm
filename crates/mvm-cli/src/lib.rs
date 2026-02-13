// mvm-cli: Clap commands, UI, bootstrap
// Depends on mvm-core, mvm-agent, mvm-runtime, mvm-coordinator, mvm-build

pub mod bootstrap;
pub mod commands;
pub mod dev_cluster;
pub mod display;
pub mod doctor;
pub mod http;
pub mod logging;
pub mod output;
pub mod ui;
pub mod upgrade;

pub use commands::run;
