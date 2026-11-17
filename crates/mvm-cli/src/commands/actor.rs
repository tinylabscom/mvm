use std::path::PathBuf;

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

#[derive(ClapArgs, Debug, Clone)]
pub(super) struct Args {
    #[command(subcommand)]
    pub action: ActorCommand,
}

#[derive(Subcommand, Debug, Clone)]
pub(super) enum ActorCommand {
    /// Admit a local parent and retain its workflow in an independent controller
    Launch {
        /// Strict host-authored JSON manifest containing the parent and exact templates
        manifest: PathBuf,
        /// Print the admitted machine, plan and controller process as JSON
        #[arg(long)]
        json: bool,
    },
}

pub(super) fn run(args: Args) -> Result<()> {
    match args.action {
        ActorCommand::Launch { manifest, json } => {
            let launch = mvm_client::actor::launch_file(&manifest)?;
            if json {
                println!("{}", serde_json::to_string(&launch)?);
            } else {
                println!(
                    "actor {} admitted as {} (controller {})",
                    launch.machine, launch.plan_id, launch.controller_pid
                );
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Cli, Commands};
    use super::*;
    use clap::Parser;

    #[test]
    fn actor_launch_requires_explicit_manifest() {
        assert!(Cli::try_parse_from(["mvmctl", "actor", "launch"]).is_err());
        let cli =
            Cli::try_parse_from(["mvmctl", "actor", "launch", "/tmp/workflow.json", "--json"])
                .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Actor(Args {
                action: ActorCommand::Launch { json: true, .. }
            })
        ));
    }
}
