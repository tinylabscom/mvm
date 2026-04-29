//! `mvmctl logs` — show console logs from a running microVM.

use anyhow::{Context, Result};

use mvm_core::naming::validate_vm_name;
use mvm_runtime::vm::microvm;

pub(super) fn cmd_logs(name: &str, follow: bool, lines: u32, hypervisor: bool) -> Result<()> {
    validate_vm_name(name).with_context(|| format!("Invalid VM name: {:?}", name))?;
    microvm::logs(name, follow, lines, hypervisor)
}
