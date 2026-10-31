//! `mvmctl manifest rm` — remove a slot from the local registry.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest::{self, RemoveRequest};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Manifest path (file or directory). Defaults to walking up from cwd.
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
    /// Don't error if the slot doesn't exist
    #[arg(long)]
    pub force: bool,
    /// Also delete the source `mvm.toml` from disk (off by default)
    #[arg(long)]
    pub manifest_file: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let removed = manifest::remove(&RemoveRequest {
        path: args.path,
        force: args.force,
        manifest_file: args.manifest_file,
    })?;
    if removed.manifest_file_deleted {
        println!(
            "Removed slot {} and manifest file {}",
            removed.slot_hash,
            removed.manifest_path.display()
        );
    } else {
        println!("Removed slot {}", removed.slot_hash);
    }
    Ok(())
}
