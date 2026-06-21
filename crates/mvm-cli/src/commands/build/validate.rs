//! `mvmctl validate` — run `nix flake check` to validate a flake before
//! building. Flat verb (no subcommand layer) since `check` is the only
//! action.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm::shell;
use mvm_build::builderd_dispatch::{self, FlakeCheckVerdict};
use mvm_core::user_config::MvmConfig;

use crate::ui;

use super::Cli;
use super::shared::resolve_flake_ref;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Flake path or reference (default: current directory)
    #[arg(long, default_value = ".")]
    pub flake: String,
    /// Output structured JSON instead of human-readable output
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let resolved = resolve_flake_ref(&args.flake)?;

    // Opt-in: route the flake check through the resident builder daemon as a
    // typed `FlakeCheck` over vsock instead of a shell-in-the-VM. Default off
    // until the routing is proven per backend.
    //
    // Only a *remote* flake ref (`github:…`, `path:…` — anything the builder can
    // fetch on its own) is routed: the builder VM does not mount the host's
    // working tree, so a local-path flake would not be reachable inside it and
    // would be reported (wrongly) as invalid. Staging a local flake into the
    // builder is the next WS-D slice; until then local flakes keep the legacy
    // path. `resolve_flake_ref` passes remote refs through unchanged (they carry
    // a `:`) and canonicalizes local paths to a `:`-free absolute path.
    let remote_ref = resolved.contains(':');
    if remote_ref && std::env::var("MVM_BUILDERD_DISPATCH").as_deref() == Ok("1") {
        if let Some(socket) = builderd_dispatch::resolve_ready_builder_socket() {
            return run_via_builderd(&socket, &resolved, args.json);
        }
        ui::warn("MVM_BUILDERD_DISPATCH=1 set but no ready builder daemon; using the shell path");
    }

    let script = format!("nix flake check {resolved}");

    if args.json {
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

/// Run the flake check through the resident builder daemon (typed `FlakeCheck`
/// over vsock) and render the same output shape as the legacy shell path.
fn run_via_builderd(socket: &std::path::Path, flake: &str, json: bool) -> Result<()> {
    // Stream the daemon's `nix` log lines; in JSON mode they are suppressed so
    // stdout carries only the verdict object.
    let mut log = |line: &str| {
        if !json {
            print!("{line}");
        }
    };
    let verdict = builderd_dispatch::flake_check_via_builderd(socket, flake, &mut log)
        .context("flake check via the builder daemon")?;
    match verdict {
        FlakeCheckVerdict::Valid => {
            if json {
                println!("{{\"valid\":true}}");
            } else {
                ui::success("Flake is valid.");
            }
            Ok(())
        }
        FlakeCheckVerdict::Invalid { message } => {
            if json {
                let msg = message.trim().replace('"', "'");
                println!("{{\"valid\":false,\"error\":\"{msg}\"}}");
            } else {
                eprintln!("{}", message.trim());
            }
            std::process::exit(1);
        }
    }
}
