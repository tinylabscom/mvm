//! Migration boundary for the retired dynamic port-forward command.

use anyhow::{Result, bail};
use clap::Args as ClapArgs;

use super::Cli;
use super::shared::{clap_port_spec, clap_vm_name};
use mvm_core::user_config::MvmConfig;

const MIGRATION_MESSAGE: &str = "dynamic `machine forward` is retired: ingress must be present in the signed admission plan before boot; declare it with `mvmctl machine run --port HOST:GUEST` or in the machine manifest, then restart the machine";

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Port mapping(s): GUEST_PORT or LOCAL_PORT:GUEST_PORT
    #[arg(short, long, value_name = "PORT", value_parser = clap_port_spec)]
    pub port: Vec<String>,
    /// Port mapping(s) (positional, same as --port)
    #[arg(trailing_var_arg = true, hide = true)]
    pub ports: Vec<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let _ = (args.name, args.port, args.ports);
    retired_forward()
}

fn retired_forward() -> Result<()> {
    bail!(MIGRATION_MESSAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_command_explains_the_signed_plan_migration() {
        let message = retired_forward()
            .expect_err("dynamic forwarding is refused")
            .to_string();
        assert!(message.contains("signed admission plan"));
        assert!(message.contains("machine run --port"));
    }
}
