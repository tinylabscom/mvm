//! `mvmctl manifest info` — show details for one slot.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_client::manifest::{self, InfoRequest};
use mvm_core::user_config::MvmConfig;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Manifest path (file or directory). Defaults to walking up from cwd.
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let report = manifest::info(&InfoRequest { path: args.path })?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let persisted = report.persisted;
    let revision = report.snapshot;
    let label = persisted.name.as_deref().unwrap_or("(unnamed)");
    println!("Manifest: {}", persisted.manifest_path);
    println!("  Slot:       {}", persisted.manifest_hash);
    println!("  Name:       {}", label);
    println!("  Flake:      {}", persisted.flake_ref);
    println!("  Profile:    {}", persisted.profile);
    println!("  vCPUs:      {}", persisted.vcpus);
    println!("  Mem (MiB):  {}", persisted.mem_mib);
    println!("  Disk (MiB): {}", persisted.data_disk_mib);
    println!("  Backend:    {}", persisted.backend);
    println!("  Built at:   {}", persisted.updated_at);
    println!("  Toolchain:  {}", persisted.provenance.toolchain_version);
    println!("  Host arch:  {}", persisted.provenance.host_arch);
    if let Some(ir) = &persisted.provenance.ir_hash {
        println!("  IR hash:    {}", ir);
    }
    if let Some(snap) = revision {
        println!("\nSnapshot: yes (created {})", snap.created_at);
    } else {
        println!("\nSnapshot: none — `mvmctl build --snapshot` to create one");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        args: Args,
    }

    #[test]
    fn info_parser_preserves_optional_path_and_json() {
        let args = Command::try_parse_from(["info", "project/mvm.toml", "--json"])
            .unwrap()
            .args;
        assert_eq!(args.path.as_deref(), Some("project/mvm.toml"));
        assert!(args.json);
        let defaults = Command::try_parse_from(["info"]).unwrap().args;
        assert!(defaults.path.is_none() && !defaults.json);
    }
}
