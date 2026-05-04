//! `mvmctl build` — build an Mvmfile or Nix flake into a microVM image.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Serialize;

use crate::bootstrap;
use crate::ui;

use mvm_core::manifest::{
    self, Manifest, PersistedManifest, Provenance, resolve_manifest_config_path,
};
use mvm_core::naming::validate_flake_ref;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;
use mvm_runtime::vm::{image, lima};

use super::Cli;
use super::shared::{PhaseEvent, clap_flake_ref, resolve_flake_ref};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Path to a manifest file, manifest directory, or legacy Mvmfile/built-in image name
    /// (defaults to walking up from cwd looking for mvm.toml or Mvmfile.toml).
    #[arg(default_value = ".")]
    pub path: String,
    /// Explicit manifest path (file or directory). Overrides the positional path
    /// argument and forces manifest mode; useful when invoking from outside the
    /// project tree.
    #[arg(short = 'c', long = "mvm-config")]
    pub mvm_config: Option<String>,
    /// Output path for the built .elf image (legacy Mvmfile mode only)
    #[arg(short, long)]
    pub output: Option<String>,
    /// Nix flake reference (forces flake-only build mode, no manifest discovery)
    #[arg(long, value_parser = clap_flake_ref)]
    pub flake: Option<String>,
    /// Flake package variant (e.g. worker, gateway). Omit to use flake default
    #[arg(long)]
    pub profile: Option<String>,
    /// Watch flake.lock and rebuild on change (flake mode)
    #[arg(long)]
    pub watch: bool,
    /// Force rebuild — clears the dev build cache before running nix build.
    #[arg(long)]
    pub force: bool,
    /// Recompute the Nix fixed-output derivation hash (after a package version bump).
    #[arg(long)]
    pub update_hash: bool,
    /// Output structured JSON events instead of human-readable output
    #[arg(long)]
    pub json: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // Dispatch order:
    //   1. --flake <ref> → forced flake mode (no manifest discovery)
    //   2. --mvm-config <path> → explicit manifest mode
    //   3. positional path is a manifest file/dir → manifest mode
    //   4. cwd walk-up finds a manifest → manifest mode
    //   5. fall back to legacy Mvmfile / built-in image build via image::build
    if let Some(flake_ref) = args.flake {
        return build_flake(&flake_ref, args.profile.as_deref(), args.watch, args.json);
    }

    if let Some(manifest_path) = resolve_manifest_for_args(&args)? {
        return build_manifest(&manifest_path, args.force, args.update_hash, args.json);
    }

    build_mvmfile(&args.path, args.output.as_deref())
}

/// Resolve a manifest filesystem path from the CLI args, or `None` if no
/// manifest applies and we should fall through to legacy mvmfile mode.
///
/// Resolution order:
///   1. `--mvm-config <path>` — explicit; error if it doesn't resolve to a manifest.
///   2. Positional `path` arg points at a manifest file or a directory containing one.
///   3. Cwd walk-up (Cargo-style) finds a manifest; stops at `.git` boundary.
fn resolve_manifest_for_args(args: &Args) -> Result<Option<std::path::PathBuf>> {
    if let Some(cfg) = &args.mvm_config {
        let resolved = resolve_manifest_config_path(std::path::Path::new(cfg))
            .with_context(|| format!("--mvm-config {cfg:?}"))?;
        return Ok(Some(resolved));
    }

    // Positional path: file (`./mvm.toml`), directory containing one, or
    // (legacy) "." / image-name fallthrough.
    let p = std::path::Path::new(&args.path);
    if p.is_file() && p.extension().and_then(|e| e.to_str()) == Some("toml") {
        return Ok(Some(p.to_path_buf()));
    }
    if p.is_dir() {
        if let Some(found) = manifest::manifest_in_dir(p)? {
            return Ok(Some(found));
        }
        // Empty directory — try cwd walk-up before falling through.
        return manifest::discover_manifest_from_dir(p);
    }

    // Path is neither a manifest file nor a directory — fall through.
    Ok(None)
}

/// Build a microVM from a manifest (`mvm.toml` / `Mvmfile.toml`).
fn build_manifest(
    manifest_path: &std::path::Path,
    force: bool,
    update_hash: bool,
    json: bool,
) -> Result<()> {
    let manifest = Manifest::read_file(manifest_path)?;
    let canonical = std::fs::canonicalize(manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;

    // Resolve flake "." relative to the manifest's parent directory so a
    // user running `mvmctl build /elsewhere/mvm.toml` from any cwd still
    // picks up the right flake.
    let resolved_flake = if manifest.flake == "." {
        canonical
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| ".".to_string())
    } else if !manifest.flake.contains(':') && !std::path::Path::new(&manifest.flake).is_absolute()
    {
        // Relative path inside the flake field — resolve against manifest's parent.
        canonical
            .parent()
            .map(|p| p.join(&manifest.flake).display().to_string())
            .unwrap_or_else(|| manifest.flake.clone())
    } else {
        manifest.flake.clone()
    };

    // Skip Lima when Nix is available on the host (macOS with linux-builder).
    let using_host_nix = mvm_core::platform::current().has_host_nix();
    if !using_host_nix && bootstrap::is_lima_required() {
        lima::require_running()?;
    }

    if json {
        PhaseEvent::new("build", "manifest", "started")
            .with_message(&format!(
                "manifest={} flake={} profile={}",
                canonical.display(),
                resolved_flake,
                manifest.profile
            ))
            .emit();
    } else {
        ui::step(
            1,
            2,
            &format!(
                "Building manifest {} (flake={}, profile={})",
                canonical.display(),
                resolved_flake,
                manifest.profile
            ),
        );
    }

    // Synthesize a fresh PersistedManifest. If a slot record already
    // exists at the same hash, template_build_from_manifest's
    // template_persist_slot call refreshes updated_at/provenance and
    // preserves created_at via touch(); the synthesized created_at here
    // is only used for first-build slots.
    let backend = mvm_runtime::vm::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    // Override flake_ref to the resolved (absolute) path so the slot's
    // record matches what dev_build actually saw.
    let mut persisted =
        PersistedManifest::from_manifest(&manifest, &canonical, &backend, Provenance::current())?;
    persisted.flake_ref = resolved_flake;

    let revision = match tmpl::template_build_from_manifest(&persisted, force, update_hash) {
        Ok(r) => r,
        Err(e) => {
            if json {
                PhaseEvent::new("build", "manifest", "failed")
                    .with_error(&format!("{:#}", e))
                    .emit();
            }
            return Err(e);
        }
    };

    if json {
        #[derive(Serialize)]
        struct BuildResult {
            timestamp: String,
            command: &'static str,
            phase: &'static str,
            status: &'static str,
            manifest_path: String,
            slot_hash: String,
            revision: String,
        }
        let event = BuildResult {
            timestamp: chrono::Utc::now().to_rfc3339(),
            command: "build",
            phase: "manifest",
            status: "completed",
            manifest_path: persisted.manifest_path.clone(),
            slot_hash: persisted.manifest_hash.clone(),
            revision: revision.revision_hash.clone(),
        };
        if let Ok(j) = serde_json::to_string(&event) {
            println!("{}", j);
        }
    } else {
        ui::step(2, 2, "Build complete");
        ui::info(&format!("  Slot:     {}", persisted.manifest_hash));
        ui::info(&format!("  Revision: {}", revision.revision_hash));
        ui::info(&format!("\nRun with: mvmctl up {}", canonical.display()));
    }

    Ok(())
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
