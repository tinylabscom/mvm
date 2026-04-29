//! `mvmctl flake` subcommand handlers.

use anyhow::Result;
use clap::Subcommand;

use mvm_runtime::shell;
use mvm_runtime::vm::lima;

use super::shared::resolve_flake_ref;
use crate::bootstrap;
use crate::ui;

#[derive(Subcommand)]
pub(crate) enum FlakeCmd {
    /// Run `nix flake check` to validate a flake before building
    Check {
        /// Flake path or reference (default: current directory)
        #[arg(long, default_value = ".")]
        flake: String,
        /// Output structured JSON instead of human-readable output
        #[arg(long)]
        json: bool,
    },
}

pub(super) fn cmd_flake(action: FlakeCmd) -> Result<()> {
    match action {
        FlakeCmd::Check { flake, json } => cmd_flake_check(&flake, json),
    }
}

fn cmd_flake_check(flake: &str, json: bool) -> Result<()> {
    let resolved = resolve_flake_ref(flake)?;

    if bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let script = format!("nix flake check {resolved}");

    if json {
        // Capture combined stdout+stderr so we can embed it in JSON.
        let output = shell::run_in_vm_capture(&script);
        match output {
            Ok(out) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                if out.status.success() {
                    println!("{{\"valid\":true}}");
                } else {
                    let msg = combined.trim().replace('"', "'");
                    println!("{{\"valid\":false,\"error\":\"{msg}\"}}");
                    std::process::exit(1);
                }
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string().replace('"', "'");
                println!("{{\"valid\":false,\"error\":\"{msg}\"}}");
                std::process::exit(1);
            }
        }
    } else {
        // Stream output directly so the user sees nix progress in real time.
        match shell::run_in_vm_visible(&script) {
            Ok(()) => {
                ui::success("Flake is valid.");
                Ok(())
            }
            Err(e) => Err(e.context("Flake check failed")),
        }
    }
}
