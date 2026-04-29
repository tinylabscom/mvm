//! `mvmctl diff` — show filesystem changes inside a running microVM.

use anyhow::{Context, Result};

use crate::ui;

use mvm_core::naming::validate_vm_name;
use mvm_runtime::vm::microvm;

use super::shared::human_bytes;

pub(super) fn cmd_diff(name: &str, json: bool) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;

    let instance_dir = microvm::resolve_running_vm_dir(name)?;
    let changes = mvm_guest::vsock::query_fs_diff(&instance_dir)?;

    if json {
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
