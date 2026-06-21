//! `mvmctl validate` — run `nix flake check` to validate a flake before
//! building. Flat verb (no subcommand layer) since `check` is the only
//! action.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm::shell;
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

    // Prefer the typed `mvm-builderd` FlakeCheck when the caller opted in
    // (`MVM_BUILDERD_TYPED`) and a builder daemon is reachable; otherwise fall
    // back to the in-VM shell path below. The flake the daemon checks is the
    // same resolved path, valid inside the builder VM via the project share.
    let vms_root = mvm_build::builder_vm::builder_vm_cache_dir().join("vms");
    if let mvm_build::builder_route::FlakeCheckDispatch::Took(result) =
        mvm_build::builder_route::try_typed_flake_check(&vms_root, &resolved)
    {
        return render_typed_verdict(result, args.json);
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

/// Render the verdict of a typed `mvm-builderd` flake check, mirroring the
/// legacy path's JSON/human output and exit-code contract.
fn render_typed_verdict(
    result: Result<
        mvm_build::builder_route::FlakeCheckVerdict,
        mvm_build::builderd_client::BuilderdClientError,
    >,
    json: bool,
) -> Result<()> {
    use mvm_build::builder_route::FlakeCheckVerdict;
    match result {
        Ok(FlakeCheckVerdict::Valid) => {
            if json {
                println!("{{\"valid\":true}}");
            } else {
                ui::success("Flake is valid.");
            }
            Ok(())
        }
        Ok(FlakeCheckVerdict::Invalid { message }) => {
            if json {
                let msg = message.trim().replace('"', "'");
                println!("{{\"valid\":false,\"error\":\"{msg}\"}}");
                std::process::exit(1);
            }
            Err(anyhow::anyhow!("Flake check failed:\n{}", message.trim()))
        }
        // The daemon was reachable but the typed exchange failed. Surface it
        // rather than silently doing host work — the opt-in was explicit.
        Err(e) => Err(anyhow::anyhow!("typed flake check failed: {e}")),
    }
}
