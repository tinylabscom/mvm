//! `mvmctl build` — build an Mvmfile or Nix flake into a microVM image.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Serialize;

use crate::bootstrap;
use crate::ui;

use mvm_core::naming::validate_flake_ref;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::{image, lima};

use super::Cli;
use super::shared::{PhaseEvent, clap_flake_ref, resolve_flake_ref};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Image name (built-in like "openclaw") or path to directory with Mvmfile.toml
    #[arg(default_value = ".")]
    pub path: String,
    /// Output path for the built .elf image
    #[arg(short, long)]
    pub output: Option<String>,
    /// Nix flake reference (enables flake build mode)
    #[arg(long, value_parser = clap_flake_ref)]
    pub flake: Option<String>,
    /// Flake package variant (e.g. worker, gateway). Omit to use flake default
    #[arg(long)]
    pub profile: Option<String>,
    /// Watch flake.lock and rebuild on change (flake mode)
    #[arg(long)]
    pub watch: bool,
    /// Output structured JSON events instead of human-readable output
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if let Some(flake_ref) = args.flake {
        build_flake(&flake_ref, args.profile.as_deref(), args.watch, args.json)
    } else {
        build_mvmfile(&args.path, args.output.as_deref())
    }
}

fn build_mvmfile(path: &str, output: Option<&str>) -> Result<()> {
    let elf_path = image::build(path, output)?;
    ui::success(&format!("\nImage ready: {}", elf_path));
    ui::info(&format!("Run with: mvmctl start {}", elf_path));
    Ok(())
}

fn build_flake(flake_ref: &str, profile: Option<&str>, watch: bool, json: bool) -> Result<()> {
    validate_flake_ref(flake_ref)
        .with_context(|| format!("Invalid flake reference: {:?}", flake_ref))?;

    let build_env = mvm_runtime::build_env::default_build_env();
    let env = build_env.as_ref();

    // Skip Lima when Nix is available on the host (macOS with linux-builder).
    let using_host_nix = mvm_core::platform::current().has_host_nix();
    if !using_host_nix && bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    let resolved = resolve_flake_ref(flake_ref)?;
    let watch_enabled = watch && !resolved.contains(':');

    if watch && resolved.contains(':') && !json {
        ui::warn("Watch mode requires a local flake; running a single build instead.");
    }

    loop {
        let profile_display = profile.unwrap_or("default");

        if json {
            PhaseEvent::new("build", "nix-build", "started")
                .with_message(&format!("flake={} profile={}", resolved, profile_display))
                .emit();
        } else {
            ui::step(
                1,
                2,
                &format!("Building flake {} (profile={})", resolved, profile_display),
            );
        }

        let result = match mvm_build::dev_build::dev_build(env, &resolved, profile) {
            Ok(r) => r,
            Err(e) => {
                if json {
                    PhaseEvent::new("build", "nix-build", "failed")
                        .with_error(&format!("{:#}", e))
                        .emit();
                }
                return Err(e);
            }
        };
        if let Err(e) = mvm_build::dev_build::ensure_guest_agent_if_needed(env, &result) {
            ui::warn(&format!(
                "Could not verify guest agent ({}). If built with mkGuest, the agent is already included.",
                e
            ));
        }

        if json {
            #[derive(Serialize)]
            struct BuildResult {
                timestamp: String,
                command: &'static str,
                phase: &'static str,
                status: &'static str,
                revision: String,
                cached: bool,
                kernel: String,
                rootfs: String,
            }
            let event = BuildResult {
                timestamp: chrono::Utc::now().to_rfc3339(),
                command: "build",
                phase: "nix-build",
                status: "completed",
                revision: result.revision_hash.clone(),
                cached: result.cached,
                kernel: result.vmlinux_path.clone(),
                rootfs: result.rootfs_path.clone(),
            };
            if let Ok(j) = serde_json::to_string(&event) {
                println!("{}", j);
            }
        } else {
            ui::step(2, 2, "Build complete");

            if result.cached {
                ui::success(&format!("\nCache hit — revision {}", result.revision_hash));
            } else {
                ui::success(&format!(
                    "\nBuild complete — revision {}",
                    result.revision_hash
                ));
            }

            ui::info(&format!("  Kernel: {}", result.vmlinux_path));
            ui::info(&format!("  Rootfs: {}", result.rootfs_path));
            ui::info(&format!("\nRun with: mvmctl run --flake {}", flake_ref));
        }

        if !watch_enabled {
            return Ok(());
        }

        // Watch mode: wait for filesystem changes using native events
        if !json {
            ui::info("Watching for .nix and .lock changes (Ctrl+C to exit)...");
        }
        match crate::watch::wait_for_changes(&resolved) {
            Ok(trigger) => {
                if !json {
                    let display = crate::watch::display_trigger(&trigger, &resolved);
                    ui::info(&format!("\nChange detected: {display} — rebuilding..."));
                }
            }
            Err(e) => {
                if !json {
                    ui::warn(&format!("Watch error: {e} — falling back to single build"));
                }
                return Ok(());
            }
        }
    }
}
