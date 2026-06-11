//! `mvmctl diff` — show filesystem changes inside a running microVM.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use crate::ui;

use mvm_core::naming::validate_vm_name;
use mvm_core::user_config::MvmConfig;
use mvm_guest::vsock::FsChange;

use super::Cli;
use super::shared::{clap_vm_name, human_bytes};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Name of the VM
    #[arg(value_parser = clap_vm_name)]
    pub name: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    validate_vm_name(&args.name).with_context(|| format!("Invalid VM name: {:?}", args.name))?;

    let changes = fs_diff(&args.name)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&changes)?);
    } else if changes.is_empty() {
        ui::info("No filesystem changes detected.");
    } else {
        ui::info(&format!("{} change(s):", changes.len()));
        for change in &changes {
            let prefix = match change.kind {
                mvm_guest::vsock::FsChangeKind::Created => "+",
                mvm_guest::vsock::FsChangeKind::Modified => "~",
                mvm_guest::vsock::FsChangeKind::Deleted => "-",
            };
            if change.size > 0 {
                println!(
                    "  {} {} ({})",
                    prefix,
                    change.path,
                    human_bytes(change.size)
                );
            } else {
                println!("  {} {}", prefix, change.path);
            }
        }
    }

    Ok(())
}

/// Fetch the guest fs-diff over the backend-aware transport.
/// Like `fs::fs_request`, the `--hypervisor mock` fast path stays ahead of
/// the `vsock_transport::for_vm` probe — which resolves the right socket per
/// VMM (Firecracker's `v.sock`, or the per-port UNIX socket libkrun/QEMU
/// expose) but is unaware of the in-memory mock backend.
fn fs_diff(name: &str) -> Result<Vec<FsChange>> {
    let mock_dir = mvm_backend::MockBackend::vm_dir(name);
    if mock_dir.join("runtime").join("v.sock").exists() {
        return mvm_guest::vsock::query_fs_diff(&mock_dir.to_string_lossy());
    }
    let mut stream =
        mvm::vsock_transport::for_vm(name)?.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    mvm_guest::vsock::query_fs_diff_on(&mut stream)
}
