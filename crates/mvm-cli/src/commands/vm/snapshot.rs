//! `mvmctl snapshot ls / rm` — inspect and remove sealed instance snapshots.
//!
//! Sits beside `pause`/`resume`, which produce the sealed snapshots this
//! browses. The store access itself lives in `mvm_client::snapshot` so the
//! CLI and the host library share one implementation (and one audit
//! entry); this file is clap args plus table/JSON rendering.

use anyhow::{Result, bail};
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::clap_vm_name;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct SnapshotArgs {
    #[command(subcommand)]
    pub command: SnapshotCmd,
}

#[derive(clap::Subcommand, Debug, Clone)]
pub(in crate::commands) enum SnapshotCmd {
    /// List sealed instance snapshots under ~/.mvm/instances/*/snapshot/
    Ls {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove a sealed instance snapshot
    Rm {
        /// VM name whose snapshot to remove
        #[arg(value_parser = clap_vm_name)]
        name: String,
        /// Output the removal result as JSON
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run_snapshot(
    _cli: &Cli,
    args: SnapshotArgs,
    _cfg: &MvmConfig,
) -> Result<()> {
    match args.command {
        SnapshotCmd::Ls { json } => snap_ls(json),
        SnapshotCmd::Rm { name, json } => snap_rm(&name, json),
    }
}

fn snap_ls(json: bool) -> Result<()> {
    let entries = mvm_client::snapshot::list_instance_snapshots()?;
    if json {
        #[derive(serde::Serialize)]
        struct Row<'a> {
            vm_name: &'a str,
            vmstate_size_bytes: u64,
            mem_size_bytes: u64,
            epoch: Option<u64>,
            sealed: bool,
        }
        let rows: Vec<Row<'_>> = entries
            .iter()
            .map(|e| Row {
                vm_name: &e.vm_name,
                vmstate_size_bytes: e.vmstate_size_bytes,
                mem_size_bytes: e.mem_size_bytes,
                epoch: e.sidecar.as_ref().map(|s| s.epoch),
                sealed: e.sidecar.is_some(),
            })
            .collect();
        crate::json_out::emit_json(&rows)?;
        return Ok(());
    }
    if entries.is_empty() {
        println!("(no instance snapshots)");
        return Ok(());
    }
    println!(
        "{:<24} {:<7} {:<14} {:<14} STATUS",
        "VM", "EPOCH", "VMSTATE", "MEM"
    );
    for e in &entries {
        let (epoch, status) = match &e.sidecar {
            Some(s) => (s.epoch.to_string(), "sealed"),
            None => ("-".to_string(), "unsealed"),
        };
        println!(
            "{:<24} {:<7} {:<14} {:<14} {}",
            e.vm_name, epoch, e.vmstate_size_bytes, e.mem_size_bytes, status
        );
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct SnapshotRemoveJson<'a> {
    schema_version: u8,
    action: &'static str,
    vm_name: &'a str,
    removed: bool,
}

fn snap_rm(name: &str, json: bool) -> Result<()> {
    let removed = mvm_client::snapshot::remove_instance_snapshot(name)?;
    if !removed {
        bail!("no snapshot found for VM {:?}", name);
    }
    if json {
        crate::json_out::emit_json(&SnapshotRemoveJson {
            schema_version: 1,
            action: "rm",
            vm_name: name,
            removed: true,
        })?;
    } else {
        println!("{}: snapshot removed", name);
    }
    Ok(())
}
