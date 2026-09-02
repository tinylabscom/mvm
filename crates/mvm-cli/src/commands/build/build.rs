//! `mvmctl build` — build an Mvmfile or Nix flake into a microVM image.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;
use serde::Serialize;

use crate::ui;

use mvm_core::manifest::{
    self, MANIFEST_SCHEMA_VERSION, Manifest, PersistedManifest, Provenance,
    key_for_manifest_identity, resolve_manifest_config_path,
};
use mvm_core::naming::validate_flake_ref;
use mvm_core::user_config::MvmConfig;
use mvm_runtime::image;
use mvm_runtime::vm::template::lifecycle as tmpl;

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
    /// Narrow the build to the application-dependency volume only.
    /// Invalidates the cached deps volume(s) for any lockfile under
    /// the project root, so the next install pipeline run starts
    /// from a clean state. Useful for: someone bumped the lockfile
    /// but didn't change other code; or someone manually deleted
    /// `~/.mvm/volumes/deps/<hash>/` and wants the cache index
    /// cleared to repopulate. Skips the rootfs `nix build`.
    #[arg(long)]
    pub deps: bool,
    /// Force single-shot builds even when a persistent-builder
    /// session is active. By default, when
    /// `mvmctl persistent-builder start` has been run and the
    /// supervisor is alive, builds route through the persistent
    /// VM, amortizing the per-job boot fan-out. This flag forces
    /// the legacy single-shot path — useful for isolation /
    /// debugging or when comparing timings.
    #[arg(long)]
    pub no_persistent_builder: bool,
    /// Build-mode override flags (`--dev` / `--prod`). Default: `--prod`.
    #[command(flatten)]
    pub build_mode: super::super::shared::BuildModeFlags,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    // `--no-persistent-builder` flips the env-var bridge that
    // `mvm_build::pipeline::dev_build` reads. Set once at the top so every
    // subsequent dispatch (flake / manifest / mvmfile) sees the same toggle,
    // and left set for the process's lifetime so every codepath under
    // `mvmctl build` agrees on the choice.
    if args.no_persistent_builder {
        crate::commands::set_cli_env("MVM_NO_PERSISTENT_BUILDER", "1");
    }
    // `--deps` narrows the build to the deps
    // volume only. We invalidate the cache index entries pointing at
    // the project's lockfile and short-circuit before the rootfs
    // build. The next install-pipeline run (`mvmctl build` without
    // `--deps`, or `mvmctl up`) rebuilds the volume from scratch.
    if args.deps {
        return invalidate_deps_cache(&args);
    }
    // Dispatch order:
    //   1. --flake <ref> → forced flake mode (no manifest discovery)
    //   2. --mvm-config <path> → explicit manifest mode
    //   3. positional path is a manifest file/dir → manifest mode
    //   4. cwd walk-up finds a manifest → manifest mode
    //   5. fall back to legacy Mvmfile / built-in image build via image::build
    if let Some(flake_ref) = args.flake {
        let mode = args.build_mode.resolve();
        return build_flake(
            &flake_ref,
            args.profile.as_deref(),
            args.watch,
            args.json,
            mode,
        );
    }

    if let Some(manifest_path) = resolve_manifest_for_args(&args)? {
        return build_manifest(
            &manifest_path,
            args.force,
            args.update_hash,
            args.json,
            args.build_mode.resolve(),
        );
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
    mode: mvm_build::pipeline::BuildMode,
) -> Result<()> {
    let manifest = Manifest::read_file(manifest_path)?;
    let canonical = std::fs::canonicalize(manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;

    // An `image`-source manifest selects an OCI image, not a flake, and takes
    // the other arm — it does not fall through to building the default "."
    // flake.
    if let Some(image_ref) = manifest.image.clone() {
        return build_manifest_from_image(&manifest, &canonical, &image_ref, json, mode);
    }

    // Resolve flake "." relative to the manifest's parent directory so a
    // user running `mvmctl build /elsewhere/mvm.toml` from any cwd still
    // picks up the right flake.
    let flake = manifest.flake_ref();
    let resolved_flake = if flake == "." {
        canonical
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| ".".to_string())
    } else if !flake.contains(':') && !std::path::Path::new(flake).is_absolute() {
        // Relative path inside the flake field — resolve against manifest's parent.
        canonical
            .parent()
            .map(|p| p.join(flake).display().to_string())
            .unwrap_or_else(|| flake.to_string())
    } else {
        flake.to_string()
    };

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
    let backend = mvm_runtime::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    // Override flake_ref to the resolved (absolute) path so the slot's
    // record matches what dev_build actually saw.
    let mut persisted =
        PersistedManifest::from_manifest(&manifest, &canonical, &backend, Provenance::current())?;
    persisted.flake_ref = resolved_flake;

    let revision = match tmpl::template_build_from_manifest(&persisted, force, update_hash, mode) {
        Ok(r) => r,
        Err(e) => {
            if json {
                PhaseEvent::new("build", "manifest", "failed")
                    .with_error(&format!("{:#}", e))
                    .emit();
            }
            audit_build_error("manifest", &persisted.manifest_path, &e);
            return Err(e);
        }
    };

    audit_build_ok(
        "manifest",
        &persisted.manifest_path,
        &persisted.manifest_hash,
        &revision.revision_hash,
    );

    // Record the compiled image as an audited version-lineage node before
    // reporting success. A build that produced an image but could not record
    // its lineage is a failure to surface, not a silent skip.
    super::image_lineage::record_flake_build_node(&persisted, &revision)?;

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
        ui::info(&format!(
            "\nRun with: mvmctl machine run --manifest {}",
            canonical.display()
        ));
    }

    Ok(())
}

/// Build a slot from an `image`-source manifest.
///
/// Materializes the OCI reference through the same path a `run --image` boots
/// through, then installs the result as a slot revision with the same layout
/// the flake arm produces. What the two arms share is deliberate: after this
/// returns, `--manifest <path>` cannot tell which one built the slot.
fn build_manifest_from_image(
    manifest: &Manifest,
    canonical: &std::path::Path,
    image_ref: &str,
    json: bool,
    mode: mvm_build::pipeline::BuildMode,
) -> Result<()> {
    if json {
        PhaseEvent::new("build", "manifest", "started")
            .with_message(&format!(
                "manifest={} image={}",
                canonical.display(),
                image_ref
            ))
            .emit();
    } else {
        ui::step(
            1,
            2,
            &format!(
                "Building manifest {} (image={})",
                canonical.display(),
                image_ref
            ),
        );
    }

    let backend = mvm_runtime::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    let persisted =
        PersistedManifest::from_manifest(manifest, canonical, &backend, Provenance::current())?;

    let kernel = super::super::env::builder_vm::ensure_workload_kernel()
        .context("resolving the workload kernel for an image-backed build")?;

    // Keyed by the slot, not by a machine name: the artifact belongs to the
    // manifest, and two machines booting the same slot must not each
    // re-materialize it.
    let cache_key = format!("slot-{}", persisted.manifest_hash);
    let rootfs = tokio::runtime::Runtime::new()
        .context("starting the runtime for the image pull")?
        .block_on(mvm_client::local::materialize_image_rootfs(
            image_ref, &cache_key,
        ))
        .with_context(|| format!("materializing {image_ref}"))?;

    let revision = match mvm_runtime::vm::template::lifecycle::template_build_from_image(
        &persisted,
        &mvm_runtime::vm::template::lifecycle::ImageBuildSources {
            rootfs,
            kernel: std::path::PathBuf::from(&kernel),
            image_ref: image_ref.to_string(),
        },
        mode,
    ) {
        Ok(r) => r,
        Err(e) => {
            if json {
                PhaseEvent::new("build", "manifest", "failed")
                    .with_error(&format!("{e:#}"))
                    .emit();
            }
            audit_build_error("manifest", &persisted.manifest_path, &e);
            return Err(e);
        }
    };

    audit_build_ok(
        "manifest",
        &persisted.manifest_path,
        &persisted.manifest_hash,
        &revision.revision_hash,
    );

    if json {
        PhaseEvent::new("build", "manifest", "completed")
            .with_message(&format!(
                "manifest={} slot={} revision={}",
                canonical.display(),
                persisted.manifest_hash,
                revision.revision_hash
            ))
            .emit();
    } else {
        ui::step(2, 2, "Build complete");
        ui::info(&format!("  Slot:     {}", persisted.manifest_hash));
        ui::info(&format!("  Revision: {}", revision.revision_hash));
        ui::info(&format!(
            "\nRun with: mvmctl machine run --manifest {}",
            canonical.display()
        ));
    }

    Ok(())
}

fn build_mvmfile(path: &str, output: Option<&str>) -> Result<()> {
    let elf_path = match image::build(path, output) {
        Ok(p) => p,
        Err(e) => {
            audit_build_error("mvmfile", path, &e);
            return Err(e);
        }
    };
    audit_build_ok("mvmfile", path, "", &elf_path);
    ui::success(&format!("\nImage ready: {}", elf_path));
    Ok(())
}

fn build_flake(
    flake_ref: &str,
    profile: Option<&str>,
    watch: bool,
    json: bool,
    mode: mvm_build::pipeline::BuildMode,
) -> Result<()> {
    validate_flake_ref(flake_ref)
        .with_context(|| format!("Invalid flake reference: {:?}", flake_ref))?;

    let build_env = mvm_runtime::build_env::default_build_env();
    let env = build_env.as_ref();

    // A steady-state `mvmctl build` runs the user's nix build
    // inside the builder VM, which needs the layer-1 builder image (vmlinux +
    // rootfs.ext4) in cache. `mvmctl bootstrap` bootstraps it on macOS, but the native-
    // Linux dev path never does — so ensure it here (Stage 0 honours the
    // selected builder backend; a cached image is a no-op). Without this the
    // first `mvmctl build` on a fresh Linux host fails in `ensure_builder_vm_image`.
    //
    // Skip when `MVM_BUILD_STUB_OUTDIR` short-circuits the build (the test
    // escape hatch — no builder VM is spawned), mirroring the same guard
    // `mvm_build::dev_build::dev_build` honours.
    #[cfg(feature = "builder-vm")]
    if std::env::var("MVM_BUILD_STUB_OUTDIR")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        crate::commands::env::builder_vm::bootstrap_builder_vm_image()
            .context("ensuring the builder VM image before the flake build (Stage 0 bootstrap)")?;
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

        // An image build is the other cost a launch measurement must never
        // absorb; record it at the one site that starts one.
        mvm_core::launch_trace::record_image_build();
        let result = match mvm_build::dev_build::dev_build(env, &resolved, profile, mode) {
            Ok(r) => r,
            Err(e) => {
                if json {
                    PhaseEvent::new("build", "nix-build", "failed")
                        .with_error(&format!("{:#}", e))
                        .emit();
                }
                audit_build_error("flake", &resolved, &e);
                return Err(e);
            }
        };
        audit_build_ok("flake", &resolved, "", &result.revision_hash);
        // No post-build agent injection: every mkGuest image resolves its
        // agent from the runtime overlay (or mkGuest's own bake) at boot,
        // so there is nothing to verify or patch into the rootfs here.

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

/// Emit a `TemplateBuild` audit line for a successful build.
///
/// `mode` is one of `manifest` / `flake` / `mvmfile` so the audit log
/// distinguishes the build-graph entry path; the artifact identifier
/// (revision hash for nix builds, ELF path for mvmfile) lands in the
/// detail string so a reader can correlate without parsing JSON.
fn audit_build_ok(mode: &str, source: &str, slot_hash: &str, artifact: &str) {
    let detail = if slot_hash.is_empty() {
        format!("mode={mode} source={source} artifact={artifact}")
    } else {
        format!("mode={mode} source={source} slot_hash={slot_hash} artifact={artifact}")
    };
    mvm_core::audit_emit!(TemplateBuild, "{detail}");
}

/// Emit a `TemplateBuildError` audit line for a failed build.
///
/// Records the same `mode`/`source` shape as the success path so an
/// operator scanning the log sees a paired success/failure pattern.
/// Only the first line of the error chain lands in the detail to keep
/// the audit record bounded.
fn audit_build_error(mode: &str, source: &str, err: &anyhow::Error) {
    let head = err.to_string();
    let head = head.lines().next().unwrap_or("").trim();
    mvm_core::audit_emit!(
        TemplateBuildError,
        "mode={mode} source={source} error={head}"
    );
}

/// `mvmctl build --deps` implementation.
///
/// Narrows the build to the deps volume by invalidating the cache
/// index entries pointing at lockfiles under the project root. The
/// next install-pipeline run rebuilds the volume from scratch. We
/// deliberately do NOT spawn the builder VM here — that's the
/// install pipeline's job, kicked off by the
/// orchestrator on the next `mvmctl build` / `mvmctl up`.
///
/// Invalidation strategy: walk `<deps_volumes_dir>/index/`, read
/// each `<lockfile_hash>` pointer's volume hash, and delete both
/// the pointer + the volume directory if the volume's
/// `meta.json.annotations.lockfile_sha256` matches the sha256 of a
/// lockfile we can find at the project root. Lockfile names tried:
/// `uv.lock`, `pnpm-lock.yaml`, `package-lock.json`, `npm-shrinkwrap.json`.
///
/// When no lockfile is found, we fall back to invalidating the
/// entire cache index (the user's intent is "force rebuild"; we
/// honor it bluntly rather than no-op).
fn invalidate_deps_cache(args: &Args) -> Result<()> {
    let project_root = resolve_project_root(args)?;
    let cache_root = mvm_build::app_deps::resolve_cache_root(None);
    let index_dir = cache_root.join("index");
    if !index_dir.is_dir() {
        ui::info(
            "No deps cache index found; nothing to invalidate. The next \
             `mvmctl build` will populate it on first install.",
        );
        return Ok(());
    }

    let lockfile_hashes = lockfile_sha256s_under(&project_root);
    let mut invalidated: Vec<String> = Vec::new();

    for entry in
        std::fs::read_dir(&index_dir).with_context(|| format!("reading {}", index_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let pointer = match std::fs::read_to_string(&path) {
            Ok(s) => s.trim().to_string(),
            Err(_) => continue,
        };
        if pointer.is_empty() {
            continue;
        }
        let volume_dir = cache_root.join(&pointer);
        // Decide whether to drop this entry. If we found lockfiles,
        // match against their sha256s; if not, drop everything.
        let matches = if lockfile_hashes.is_empty() {
            true
        } else {
            volume_lockfile_sha256(&volume_dir)
                .map(|s| lockfile_hashes.iter().any(|h| h == &s))
                .unwrap_or(false)
        };
        if !matches {
            continue;
        }
        // Remove the pointer and the volume directory (best-effort
        // for the volume — a missing volume is a non-error here).
        if let Err(e) = std::fs::remove_file(&path) {
            ui::warn(&format!(
                "could not remove index pointer {}: {e}",
                path.display(),
            ));
            continue;
        }
        if volume_dir.is_dir()
            && let Err(e) = std::fs::remove_dir_all(&volume_dir)
        {
            ui::warn(&format!(
                "could not remove cached volume {}: {e}",
                volume_dir.display()
            ));
        }
        invalidated.push(pointer);
    }

    if invalidated.is_empty() {
        ui::info(
            "No matching deps cache entries to invalidate. Run `mvmctl build` \
             without `--deps` to (re)populate the volume on next install.",
        );
    } else {
        ui::success(&format!(
            "Invalidated {} cached deps volume(s). The next install pipeline \
             run will rebuild the volume from scratch.",
            invalidated.len(),
        ));
    }
    Ok(())
}

/// Best-effort project root resolver: honor `--mvm-config`, otherwise
/// canonicalize the positional `path`, otherwise fall back to cwd.
fn resolve_project_root(args: &Args) -> Result<std::path::PathBuf> {
    if let Some(cfg) = &args.mvm_config {
        let p = std::path::Path::new(cfg);
        let canon = std::fs::canonicalize(p).with_context(|| format!("--mvm-config {cfg:?}"))?;
        let root = if canon.is_file() {
            canon.parent().map(std::path::Path::to_path_buf)
        } else {
            Some(canon)
        }
        .unwrap_or_else(|| std::path::PathBuf::from("."));
        return Ok(root);
    }
    let p = std::path::Path::new(&args.path);
    if p.exists() {
        let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
        let root = if canon.is_file() {
            canon.parent().map(std::path::Path::to_path_buf)
        } else {
            Some(canon)
        }
        .unwrap_or_else(|| std::path::PathBuf::from("."));
        return Ok(root);
    }
    Ok(std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")))
}

/// Scan the project root for known lockfile names and return their
/// sha256s. The orchestrator (`mvm_build::app_deps`) keys the cache on
/// the lockfile bytes' sha256 (mixed with language + gate tokens), so
/// matching by raw sha256 catches every volume bound to one of these
/// lockfiles regardless of language/gate.
fn lockfile_sha256s_under(project_root: &std::path::Path) -> Vec<String> {
    use sha2::{Digest, Sha256};
    let candidates = [
        "uv.lock",
        "pnpm-lock.yaml",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "requirements.txt",
        "Pipfile.lock",
    ];
    let mut out = Vec::new();
    for name in &candidates {
        let p = project_root.join(name);
        let Ok(bytes) = std::fs::read(&p) else {
            continue;
        };
        let mut h = Sha256::new();
        h.update(&bytes);
        let digest = h.finalize();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        out.push(hex);
    }
    out
}

/// Build a Nix flake into a reusable template slot and return the slot hash.
///
/// This is the backing function for `machine run --flake <ref>`: it runs the
/// same flake build as `mvmctl build --flake` but registers the result as a
/// `PersistedManifest` slot so downstream persistent and transient runners can
/// reference it by hash without re-running the build.
///
/// The slot hash is the `sha256(flake_synthetic_path)` key under
/// `~/.mvm/cache/templates/`. Repeated calls with the same resolved flake ref
/// return the same hash and skip the build on a cache hit.
pub(in crate::commands) fn build_flake_to_slot(
    flake_ref: &str,
    profile: Option<&str>,
) -> Result<String> {
    validate_flake_ref(flake_ref)
        .with_context(|| format!("Invalid flake reference: {:?}", flake_ref))?;

    #[cfg(feature = "builder-vm")]
    if std::env::var("MVM_BUILD_STUB_OUTDIR")
        .map(|v| v.trim().is_empty())
        .unwrap_or(true)
    {
        crate::commands::env::builder_vm::bootstrap_builder_vm_image()
            .context("ensuring the builder VM image before flake build")?;
    }

    let resolved = resolve_flake_ref(flake_ref)?;
    let backend = mvm_runtime::backend::AnyBackend::auto_select()
        .name()
        .to_string();
    let mode = mvm_build::pipeline::BuildMode::Dev;

    // Synthesize a manifest so we can use the slot-registration machinery.
    // The manifest_path key is a deterministic fake path derived from the
    // flake ref — it is never read from disk (the PersistedManifest records
    // the resolved flake_ref directly) and exists solely to give the slot
    // a stable sha256 key.
    let persisted = flake_slot_manifest(&resolved, profile, &backend);

    let slot_hash = persisted.manifest_hash.clone();
    let revision = tmpl::template_build_from_manifest(&persisted, false, false, mode)
        .with_context(|| format!("building flake {resolved:?} into slot {slot_hash}"))?;

    audit_build_ok("flake-slot", &resolved, &slot_hash, &revision.revision_hash);

    // Record the compiled image as an audited version-lineage node (same
    // fail-closed posture as the manifest build path).
    super::image_lineage::record_flake_build_node(&persisted, &revision)?;

    Ok(slot_hash)
}

fn flake_slot_manifest(
    resolved_flake_ref: &str,
    profile: Option<&str>,
    backend: &str,
) -> PersistedManifest {
    let synthetic_path = format!("<flake-slot>/{resolved_flake_ref}");
    PersistedManifest {
        schema_version: MANIFEST_SCHEMA_VERSION,
        manifest_path: synthetic_path.clone(),
        manifest_hash: key_for_manifest_identity(&synthetic_path),
        flake_ref: resolved_flake_ref.to_string(),
        profile: profile.unwrap_or("default").to_string(),
        vcpus: 2,
        mem_mib: 512,
        mem_initial_mib: None,
        data_disk_mib: 0,
        name: None,
        backend: backend.to_string(),
        provenance: Provenance::current(),
        created_at: mvm_core::time::utc_now(),
        updated_at: mvm_core::time::utc_now(),
    }
}

/// Read the volume's `meta.json.annotations.lockfile_sha256`. Returns
/// `None` when the volume is missing, unreadable, or doesn't carry
/// the annotation (older volumes won't).
fn volume_lockfile_sha256(volume_dir: &std::path::Path) -> Option<String> {
    let meta = volume_dir.join("meta.json");
    let bytes = std::fs::read(meta).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("annotations")?
        .get("lockfile_sha256")?
        .as_str()
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flake_slot_manifest_hashes_synthetic_identity_without_canonicalizing() {
        let resolved = "/tmp/flake-that-does-not-exist";
        let persisted = flake_slot_manifest(resolved, Some("minimal"), "mock");

        assert_eq!(persisted.manifest_path, format!("<flake-slot>/{resolved}"));
        assert_eq!(
            persisted.manifest_hash,
            key_for_manifest_identity(&persisted.manifest_path)
        );
        assert_eq!(persisted.flake_ref, resolved);
        assert_eq!(persisted.profile, "minimal");
    }
}
