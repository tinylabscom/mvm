//! `mvmctl network` subcommand handlers.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;
use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: NetworkAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum NetworkAction {
    /// Create a named dev network with its own bridge and subnet
    #[command(alias = "new")]
    Create {
        /// Network name (lowercase alphanumeric + hyphens)
        name: String,
        /// Subnet CIDR (auto-assigned if omitted)
        #[arg(long)]
        subnet: Option<String>,
    },
    /// List all dev networks
    #[command(alias = "ls")]
    List {
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Show details of a named network
    Inspect {
        /// Network name
        name: String,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Remove a named network
    #[command(alias = "rm")]
    Remove {
        /// Network name
        name: String,
    },
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    use mvm_core::dev_network::{DevNetwork, network_path, networks_dir, validate_network_name};

    match args.action {
        NetworkAction::Create { name, subnet: _ } => {
            validate_network_name(&name)?;
            let dir = networks_dir();
            std::fs::create_dir_all(&dir)?;

            let path = network_path(&name);
            if std::path::Path::new(&path).exists() {
                anyhow::bail!("Network {:?} already exists", name);
            }

            // Find the next available slot by scanning existing networks
            let mut max_slot: u8 = 0;
            if let Ok(entries) = std::fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if let Ok(text) = std::fs::read_to_string(entry.path())
                        && let Ok(net) = serde_json::from_str::<DevNetwork>(&text)
                    {
                        let parts: Vec<&str> = net.subnet.split('.').collect();
                        if parts.len() >= 3
                            && let Ok(s) = parts[2].parse::<u8>()
                        {
                            max_slot = max_slot.max(s);
                        }
                    }
                }
            }

            let net = if name == "default" {
                DevNetwork::default_network()
            } else {
                DevNetwork::new(&name, max_slot + 1)?
            };

            let json = serde_json::to_string_pretty(&net)?;
            std::fs::write(&path, json)?;

            mvm_core::audit_emit!(NetworkCreate, "{name}");

            ui::success(&format!(
                "Created network {:?} (bridge={}, subnet={})",
                net.name, net.bridge_name, net.subnet
            ));
            Ok(())
        }
        NetworkAction::List { json } => {
            let dir = networks_dir();
            if !std::path::Path::new(&dir).exists() {
                if json {
                    crate::json_out::emit_json(&Vec::<DevNetwork>::new())?;
                } else {
                    ui::info("No networks configured.");
                }
                return Ok(());
            }

            let mut networks: Vec<DevNetwork> = Vec::new();
            for entry in std::fs::read_dir(&dir)?.flatten() {
                if entry.path().extension().is_some_and(|e| e == "json")
                    && let Ok(text) = std::fs::read_to_string(entry.path())
                    && let Ok(net) = serde_json::from_str::<DevNetwork>(&text)
                {
                    networks.push(net);
                }
            }

            if json {
                crate::json_out::emit_json(&networks)?;
                return Ok(());
            }

            if networks.is_empty() {
                ui::info("No networks configured.");
            } else {
                println!("{:<15} {:<15} {:<20}", "NAME", "BRIDGE", "SUBNET");
                for net in &networks {
                    println!(
                        "{:<15} {:<15} {:<20}",
                        net.name, net.bridge_name, net.subnet
                    );
                }
            }
            Ok(())
        }
        NetworkAction::Inspect { name, json } => {
            let path = network_path(&name);
            if !std::path::Path::new(&path).exists() {
                anyhow::bail!("Network {:?} not found", name);
            }
            let text = std::fs::read_to_string(&path)?;
            let net: DevNetwork = serde_json::from_str(&text)?;
            if json {
                crate::json_out::emit_json(&net)?;
            } else {
                println!("{}", serde_json::to_string_pretty(&net)?);
            }
            Ok(())
        }
        NetworkAction::Remove { name } => {
            if name == "default" {
                anyhow::bail!("Cannot remove the default network");
            }
            let path = network_path(&name);
            if !std::path::Path::new(&path).exists() {
                anyhow::bail!("Network {:?} not found", name);
            }
            std::fs::remove_file(&path)?;

            mvm_core::audit_emit!(NetworkRemove, "{name}");

            ui::success(&format!("Removed network {:?}", name));
            Ok(())
        }
    }
}
