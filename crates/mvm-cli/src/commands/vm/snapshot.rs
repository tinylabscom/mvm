//! `mvmctl snapshot ls / rm` — inspect and remove sealed instance snapshots.
//!
//! Sits beside `pause`/`resume`, which produce the sealed snapshots this browses.
//! These are a read/delete surface over `~/.mvm/instances/*/snapshot/`, not the
//! pause/resume lifecycle op, so they reach the snapshot store directly rather
//! than through the machine-lifecycle facade.

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use mvm_core::naming::validate_vm_name;
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
    let entries = mvm_runtime::vm::instance_snapshot::list_instance_snapshots()?;
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
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    let removed = mvm_runtime::vm::instance_snapshot::delete_instance_snapshot(name)?;
    if !removed {
        bail!("no snapshot found for VM {:?}", name);
    }
    let registry_path = mvm_runtime::vm::name_registry::registry_path();
    if let Ok(mut registry) = mvm_runtime::vm::name_registry::VmNameRegistry::load(&registry_path) {
        let _ = registry.set_paused(name, false);
        let _ = registry.save(&registry_path);
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
    mvm_core::audit_emit!(SnapshotDelete, vm: name);
    Ok(())
}
