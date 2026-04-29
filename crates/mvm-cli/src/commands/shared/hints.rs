//! Wrap a command result with actionable hints for common errors.

use anyhow::Result;

use crate::ui;

pub fn with_hints(result: Result<()>) -> Result<()> {
    if let Err(ref e) = result {
        let msg = format!("{:#}", e);
        if msg.contains("limactl: command not found") || msg.contains("limactl: not found") {
            ui::warn("Hint: Install Lima with 'brew install lima' or run 'mvmctl bootstrap'.");
        } else if msg.contains("firecracker: command not found")
            || msg.contains("firecracker: not found")
        {
            ui::warn("Hint: Run 'mvmctl setup' to install Firecracker.");
        } else if msg.contains("/dev/kvm") {
            ui::warn(
                "Hint: Enable KVM/virtualization in your BIOS or VM settings.\n      \
                 On macOS, KVM is available inside the Lima VM.",
            );
        } else if msg.contains("Permission denied") && msg.contains(".mvm") {
            ui::warn("Hint: Check directory permissions on ~/.mvm (set MVM_DATA_DIR to override).");
        } else if msg.contains("nix: command not found") || msg.contains("nix: not found") {
            ui::warn("Hint: Nix is installed inside the Lima VM. Run 'mvmctl shell' first.");
        } else if msg.contains("Lima VM is not running") || msg.contains("VM is not started") {
            ui::warn(
                "Hint: Start the dev environment with 'mvmctl dev' or run 'mvmctl setup' \
                 to initialise it first.",
            );
        } else if msg.contains("already exists") && msg.contains("template") {
            ui::warn("Hint: Use '--force' to overwrite the existing template.");
        } else if msg.contains("error: builder for") && msg.contains("failed with exit code") {
            ui::warn(
                "Hint: Nix build failed. Check the log above for the failing derivation.\n      \
                 Common fixes: ensure flake inputs are up to date ('nix flake update'), \
                 or check your flake.nix for syntax errors.",
            );
        } else if msg.contains("does not provide attribute")
            || msg.contains("flake has no")
            || msg.contains("does not provide a package")
        {
            ui::warn(
                "Hint: Flake attribute not found. Your flake.lock may be stale.\n      \
                 Try: nix flake update (inside the Lima VM or flake directory).",
            );
        } else if msg.contains("No space left on device") || msg.contains("ENOSPC") {
            ui::warn(
                "Hint: Disk full. Run 'mvmctl doctor' to check space, \
                 or run 'nix-collect-garbage -d' inside the Lima VM.",
            );
        } else if msg.contains("timed out") || msg.contains("connection refused") {
            ui::warn(
                "Hint: The Lima VM may be unresponsive. Try 'mvmctl status' or \
                 restart with 'mvmctl stop && mvmctl dev'.",
            );
        } else if msg.contains("hash mismatch") && msg.contains("got:") {
            ui::warn(
                "Hint: Fixed-output derivation hash changed. Run \
                 'mvmctl template build <name> --update-hash' to recompute.",
            );
        } else if msg.contains("does it exist?") && msg.contains("template") {
            ui::warn("Hint: List available templates with 'mvmctl template list'.");
        }
    }
    result
}
