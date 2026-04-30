//! `mvmctl logs` — show console logs from a running microVM.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::microvm;

use super::Cli;
use super::shared::clap_vm_name;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Follow log output (like tail -f)
    #[arg(long, short = 'f')]
    pub follow: bool,
    /// Number of lines to show (default 50)
    #[arg(long, short = 'n', default_value = "50")]
    pub lines: u32,
    /// Show Firecracker hypervisor logs instead of guest console output
    #[arg(long)]
    pub hypervisor: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;
    microvm::logs(&args.name, args.follow, args.lines, args.hypervisor)
}
