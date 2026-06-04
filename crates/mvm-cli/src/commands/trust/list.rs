//! `mvmctl trust list` — enumerate the local trust store.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::plan::bundle::KeyId;
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Output as JSON (array of `key_id` strings).
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let dir = super::ensure_trust_dir()?;
    let mut key_ids: Vec<String> = Vec::new();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => {
            // ensure_trust_dir creates the dir, so a read_dir miss
            // here means the directory was deleted between the two
            // syscalls — treat as empty rather than erroring.
            print_result(&[], args.json)?;
            return Ok(());
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".pub") {
            let id = KeyId(stem.to_string());
            if id.is_well_formed() {
                key_ids.push(id.0);
            }
        }
    }
    key_ids.sort();
    print_result(&key_ids, args.json)?;
    Ok(())
}

fn print_result(ids: &[String], json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(ids)?);
    } else if ids.is_empty() {
        println!("(no trusted publishers)");
    } else {
        for id in ids {
            println!("{id}");
        }
    }
    Ok(())
}
