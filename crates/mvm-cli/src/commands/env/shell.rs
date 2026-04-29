//! Helper for opening a shell in the Lima dev VM. Used by `mvmctl dev shell`
//! (no standalone top-level command).

use anyhow::Result;

use crate::shell_init;
use crate::ui;

use mvm_runtime::config;
use mvm_runtime::shell;
use mvm_runtime::vm::lima;

use super::shared::shell_escape;

/// Open a shell into the Lima dev VM. Optionally cds into a project dir first.
pub(super) fn open_shell(project: Option<&str>) -> Result<()> {
    lima::require_running()?;

    // Print welcome banner with tool versions
    let fc_ver =
        shell::run_in_vm_stdout("firecracker --version 2>/dev/null | head -1").unwrap_or_default();
    let nix_ver = shell::run_in_vm_stdout("nix --version 2>/dev/null").unwrap_or_default();

    ui::info("mvmctl development shell");
    ui::info(&format!(
        "  Firecracker: {}",
        if fc_ver.trim().is_empty() {
            "not installed"
        } else {
            fc_ver.trim()
        }
    ));
    ui::info(&format!(
        "  Nix:         {}",
        if nix_ver.trim().is_empty() {
            "not installed"
        } else {
            nix_ver.trim()
        }
    ));
    let mvm_in_vm = shell::run_in_vm_stdout("test -f /usr/local/bin/mvmctl && echo yes || echo no")
        .unwrap_or_default();
    if mvm_in_vm.trim() == "yes" {
        let mvm_ver = shell::run_in_vm_stdout("/usr/local/bin/mvmctl --version 2>/dev/null")
            .unwrap_or_default();
        ui::info(&format!(
            "  mvmctl:      {}",
            if mvm_ver.trim().is_empty() {
                "installed"
            } else {
                mvm_ver.trim()
            }
        ));
    } else {
        ui::warn("  mvmctl not installed in VM. Run 'mvmctl sync' to build and install it.");
    }

    ui::info(&format!("  Lima VM:     {}\n", config::VM_NAME));

    // Ensure shell completions and dev aliases are in the VM's ~/.zshrc
    // (the host's ~/.zshrc is separate from the VM's)
    if let Err(e) = shell_init::ensure_shell_init_in_vm() {
        ui::warn(&format!("Shell init in VM failed: {e}"));
    }

    match project {
        Some(path) => {
            let cmd = format!("cd {} && exec bash -l", shell_escape(path));
            shell::replace_process("limactl", &["shell", config::VM_NAME, "bash", "-c", &cmd])
        }
        None => shell::replace_process("limactl", &["shell", config::VM_NAME, "bash", "-l"]),
    }
}
