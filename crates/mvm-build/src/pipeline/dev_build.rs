use anyhow::{Context, Result};
use tracing::instrument;

use mvm_core::build_env::ShellEnvironment;

use super::BuildMode;

/// Build the chained `--override-input` arguments that swap the user
/// flake's `mvm` input for the dev variant at `nix/dev/`, and the dev
/// variant's own `mvm` input for the local `nix/` parent flake.
///
/// Both overrides use `git+file:///<workspace>?dir=...` URIs (not `path:`)
/// because the flakes contain `path:..` / `./..` references that need to
/// resolve relative to the git source root, not relative to the
/// store-copied flake directory. With `git+file:`, Nix uses git-source
/// resolution and the relative paths land where they should. With
/// `path:`, Nix copies the flake directory in isolation and `..` becomes
/// `/nix/store`, which has no flake.nix or Cargo.lock.
///
/// This is the SOLE place in the build pipeline that wires in the dev
/// guest agent. User flakes never reference `nix/dev/`; they always
/// declare `mvm.url = "github:tinylabscom/mvm?dir=nix"` (or a local path
/// equivalent), which resolves to the production library. mvmctl, by
/// definition the dev tool, injects these overrides on every `nix build`
/// it performs so its images get the dev agent (vsock Exec handler
/// compiled in). mvmd, the production coordinator, never calls this code
/// path — its pool builds stay prod-only.
///
/// Resolution order:
///   1. `MVM_DEV_FLAKE_URL` env var — escape hatch. When set, used
///      verbatim as the override target. The chained `mvm/mvm` override
///      is suppressed because callers using this env var are pointing at
///      a self-contained dev flake (e.g. `github:tinylabscom/mvm?dir=nix/dev`
///      once published) that already pins its own `mvm` input correctly.
///   2. Workspace root resolved by walking up from the compile-time
///      manifest dir until we find `nix/flake.nix` (parent flake) and
///      `nix/dev/flake.nix` (dev variant) as siblings. Both get
///      `git+file:///<workspace>?dir=...` overrides.
///   3. Fallback: emit a warning and skip. The build proceeds with the
///      production agent, surfacing the misconfiguration explicitly
///      rather than silently producing a non-functional `mvmctl exec`
///      image.
#[cfg(test)]
fn dev_override_flags(env: &dyn ShellEnvironment, mode: BuildMode) -> String {
    if !mode.injects_dev_override() {
        // Prod-shape build: produce sealed images with the prod
        // guest agent. No override, no --impure. The W6.2 console
        // gate will refuse attach against the resulting image.
        return String::new();
    }

    if let Ok(url) = std::env::var("MVM_DEV_FLAKE_URL")
        && !url.trim().is_empty()
    {
        return format!(" --override-input mvm {}", shell_quote(url.trim()));
    }

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut candidate = std::path::PathBuf::from(manifest_dir);
    loop {
        let parent_flake = candidate.join("nix/flake.nix");
        let dev_dir = candidate.join("nix/dev");
        if parent_flake.is_file() && dev_dir.join("flake.nix").is_file() {
            let workspace = candidate.display().to_string();
            return format!(
                " --override-input mvm git+file://{}?dir=nix/dev \
                 --override-input mvm/mvm git+file://{}?dir=nix",
                shell_quote(&workspace),
                shell_quote(&workspace),
            );
        }
        if !candidate.pop() {
            break;
        }
    }

    env.log_warn(
        "Could not locate nix/dev (the dev variant flake); building with the \
         production guest agent. `mvmctl exec` and `mvmctl console` will be \
         unavailable against the resulting image. Set MVM_DEV_FLAKE_URL to \
         override.",
    );
    String::new()
}

/// Base directory for dev build artifacts ($HOME/.mvm/dev/builds).
fn dev_builds_dir() -> String {
    format!("{}/dev/builds", mvm_core::config::mvm_data_dir())
}

/// Path the CLI writes when `dev up` notices the host-backed Nix
/// store has grown past the GC threshold. Lives under the data dir
/// because the data dir is the only path the dev VM and the host
/// agree on (via the `datadir` VirtioFS share mounted at the same
/// absolute path in both).
#[cfg(test)]
fn gc_sentinel_path() -> String {
    format!(
        "{}/dev/nix-store-needs-gc",
        mvm_core::config::mvm_data_dir()
    )
}

/// Consume the GC sentinel: if it exists, run `nix-collect-garbage
/// --delete-older-than 14d` inside the VM (the only place the in-VM
/// nix daemon's locks are honoured), then remove the sentinel
/// regardless of whether GC succeeded — leaving it in place would
/// make every subsequent build re-trigger the GC, defeating the
/// purpose of the threshold check.
#[cfg(test)]
fn run_gc_if_requested(env: &dyn ShellEnvironment) {
    let sentinel = gc_sentinel_path();
    let quoted = shell_quote(&sentinel);
    let exists_check = format!("test -e {quoted} && echo yes || echo no");
    let exists = env
        .shell_exec_stdout(&exists_check)
        .map(|s| s.trim() == "yes")
        .unwrap_or(false);
    if !exists {
        return;
    }
    env.log_info("Host-backed Nix store passed GC threshold; running nix-collect-garbage --delete-older-than 14d");
    if let Err(e) = env.shell_exec_visible("nix-collect-garbage --delete-older-than 14d") {
        env.log_warn(&format!("nix-collect-garbage failed (continuing): {e}"));
    }

    // The artifact dirs at $HOME/.mvm/dev/builds/<hash>/ are
    // host-side caches keyed on a Nix store path. Once that store
    // path has been GC'd (no longer registered with `nix-store
    // --query --hash`), the cache entry is stale: its files were
    // hardlinked from store paths that have been removed, so they're
    // either missing or about to dangle. Reaping these entries
    // alongside the store keeps the host's data dir bounded without
    // requiring the user to know about a separate cleanup ritual.
    let builds_dir = dev_builds_dir();
    let prune_script = format!(
        "for d in {builds}/*; do \
           [ -d \"$d\" ] || continue; \
           rev=$(basename \"$d\"); \
           if ! nix-store --query --hash \"/nix/store/$rev\"-* >/dev/null 2>&1; then \
             rm -rf \"$d\"; \
             echo \"  pruned stale build artifacts: $rev\"; \
           fi; \
         done",
        builds = shell_quote(&builds_dir),
    );
    if let Err(e) = env.shell_exec_visible(&prune_script) {
        env.log_warn(&format!("Could not prune stale build artifacts: {e}"));
    }

    let cleanup = format!("rm -f {quoted}");
    if let Err(e) = env.shell_exec(&cleanup) {
        env.log_warn(&format!("Could not remove GC sentinel {sentinel}: {e}"));
    }
}

/// Result of a dev build via `nix build` in the Lima VM.
#[derive(Debug, Clone)]
pub struct DevBuildResult {
    /// Directory containing artifacts: ~/.mvm/dev/builds/<hash>/
    pub build_dir: String,
    /// Path to the kernel image.
    pub vmlinux_path: String,
    /// Path to the initial ramdisk (NixOS stage-1), if present.
    pub initrd_path: Option<String>,
    /// Path to the root filesystem.
    pub rootfs_path: String,
    /// Nix store hash used as the revision identifier.
    pub revision_hash: String,
    /// Whether the build was a cache hit (artifacts already existed).
    pub cached: bool,
    /// Path to the microvm.nix runner directory, if the build output
    /// contains runner scripts (e.g. `bin/microvm-run`). When present,
    /// the microvm.nix backend can be used instead of manual Firecracker
    /// API calls.
    pub runner_dir: Option<String>,
    /// Artifact file sizes (kernel, rootfs, initrd).
    pub artifact_sizes: mvm_core::pool::ArtifactSizes,
}

/// Result of dev-build cache cleanup.
#[derive(Debug, Clone)]
pub struct DevBuildCleanupReport {
    /// Number of revision directories removed.
    pub removed_count: usize,
    /// Absolute paths of removed revision directories.
    pub removed_paths: Vec<String>,
}

/// Remove old cached dev builds, keeping the newest `keep` revisions.
///
/// Operates directly on the host filesystem under [`dev_builds_dir`]
/// (`~/.mvm/dev/builds/`). Lima-era versions of this function shelled
/// through `ShellEnvironment` so the `ls`/`rm` ran inside the dev VM,
/// but the dev VM only ever bind-mounted the same host directory —
/// the indirection was the artifact of a now-retired runtime, not a
/// semantic requirement. Running on the host directly drops the
/// dev-VM dependency: `mvmctl cleanup` now works in CI / fresh
/// installs where the builder VM isn't (yet) reachable.
///
/// Returns a report with the number of removed revisions and the
/// list of removed absolute paths.
#[instrument(skip_all, fields(keep))]
pub fn cleanup_old_dev_builds(keep: usize) -> Result<DevBuildCleanupReport> {
    cleanup_builds_in(std::path::Path::new(&dev_builds_dir()), keep)
}

/// Inner helper that operates on an explicit `builds_dir`. Lifted
/// out so unit tests can drive the logic against a tempdir without
/// touching `HOME` / `MVM_DATA_DIR`. The public
/// [`cleanup_old_dev_builds`] is the production entry point.
///
/// Newest-first sort uses mtime. Ties go to lexicographic order so a
/// deterministic outcome survives the rare clock-resolution collision.
fn cleanup_builds_in(builds_dir: &std::path::Path, keep: usize) -> Result<DevBuildCleanupReport> {
    if !builds_dir.is_dir() {
        return Ok(DevBuildCleanupReport {
            removed_count: 0,
            removed_paths: vec![],
        });
    }

    // Collect (path, mtime) tuples for every immediate child dir.
    // Files at this level are unexpected — the layout is one dir per
    // revision hash — but we tolerate them by ignoring (they're not
    // candidates for prune).
    let mut entries: Vec<(std::path::PathBuf, std::time::SystemTime)> = Vec::new();
    for entry in std::fs::read_dir(builds_dir)
        .with_context(|| format!("reading {}", builds_dir.display()))?
        .flatten()
    {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        entries.push((path, mtime));
    }
    // Newest first; ties broken by lexicographic path order so the
    // outcome is deterministic on filesystems whose mtime resolution
    // is coarser than the test loop creates entries.
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    if entries.len() <= keep {
        return Ok(DevBuildCleanupReport {
            removed_count: 0,
            removed_paths: vec![],
        });
    }

    let mut removed_paths = Vec::new();
    for (path, _) in entries.iter().skip(keep) {
        std::fs::remove_dir_all(path).with_context(|| format!("removing {}", path.display()))?;
        removed_paths.push(path.display().to_string());
    }

    Ok(DevBuildCleanupReport {
        removed_count: removed_paths.len(),
        removed_paths,
    })
}

/// Build a microVM image from a Nix flake inside the configured builder VM.
///
/// Runs `nix build` with visible output, then copies the resulting
/// kernel and rootfs to a dev build directory keyed by Nix store hash.
/// Re-running the same build is a near-instant cache hit.
///
/// When `profile` is `None`, builds the flake's default package.
/// When `Some("worker")`, builds `packages.<system>.tenant-worker`, etc.
#[instrument(skip_all, fields(flake_ref))]
pub fn dev_build(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Result<DevBuildResult> {
    // Plan 68: `MVM_BUILD_STUB_OUTDIR` lets the live test suite
    // skip the Nix build entirely and treat the env-var's value as
    // the build output directory. The directory must contain
    // `vmlinux` + `rootfs.ext4`. Same env-var-escape-hatch shape
    // `MVM_DIRECT_BOOT` uses for `mvmctl up`. Logged loudly so a
    // production misconfiguration can't go silent.
    if let Ok(stub) = std::env::var("MVM_BUILD_STUB_OUTDIR")
        && !stub.trim().is_empty()
    {
        env.log_warn(&format!(
            "MVM_BUILD_STUB_OUTDIR={stub} set; skipping nix build (test path)."
        ));
        let _ = (flake_ref, profile, mode);
        let stub_path = std::path::PathBuf::from(stub.trim());
        let revision_hash = stub_path
            .file_name()
            .and_then(|s| s.to_str())
            .map(String::from)
            .unwrap_or_else(|| "stub".to_string());
        return Ok(DevBuildResult {
            build_dir: stub_path.display().to_string(),
            vmlinux_path: stub_path.join("vmlinux").display().to_string(),
            rootfs_path: stub_path.join("rootfs.ext4").display().to_string(),
            initrd_path: None,
            revision_hash,
            cached: false,
            runner_dir: None,
            artifact_sizes: mvm_core::pool::ArtifactSizes::default(),
        });
    }

    #[cfg(feature = "builder-vm")]
    {
        env.log_info("Building via the Linux builder VM; host-side Nix is not used.");
        dev_build_via_builder_vm(env, flake_ref, profile, mode)
    }

    #[cfg(not(feature = "builder-vm"))]
    {
        let _ = (env, flake_ref, profile, mode);
        anyhow::bail!(
            "Builder VM support was compiled out (feature `builder-vm` disabled). \
             Use the default mvmctl build or rebuild with `--features builder-vm` \
             so Nix evaluation and image builds can run inside the project builder VM."
        );
    }
}

#[cfg(test)]
fn dev_build_via_shell_env(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Result<DevBuildResult> {
    if !builder_env_has_nix(env) {
        let _ = (env, flake_ref, profile, mode);
        anyhow::bail!(
            "No `nix` on PATH inside the builder environment. Rebuild or restart \
             the project builder VM before running the dev build."
        );
    }

    // Honour the host-side GC sentinel before any new build work
    // touches the store. The CLI's `dev up` writes
    // `~/.mvm/dev/nix-store-needs-gc` (mounted at the same path
    // inside the VM via the datadir share) when the upper layer's
    // allocated bytes cross threshold; we collect garbage exactly
    // once, then remove the sentinel. Doing it here — inside the VM,
    // before we hold any new gcroots — means the daemon owns the
    // store locks and only unreferenced paths get reaped. Failure is
    // a warning, not a build failure: a missing or unreachable nix
    // binary should never block the user's work.
    run_gc_if_requested(env);

    let attr = resolve_dev_build_attribute(env, flake_ref, profile);

    // Run optional pre-build hook if the flake provides one.
    // This supports templates that install external software (e.g. via an
    // upstream installer script) before the Nix build runs.
    let pre_build_impure = run_pre_build_hook(env, flake_ref)?;

    // mvmctl is a dev tool, so every image it builds gets the dev guest
    // agent (vsock Exec handler compiled in) injected via --override-input
    // against the dev sibling flake at `nix/dev/`. User flakes contain no
    // dev/prod toggle — see `dev_override_flags()` for the contract.
    let dev_override = dev_override_flags(env, mode);

    // The override target references the workspace's `Cargo.lock` from a
    // path outside the user flake's source closure, which pure-eval rejects.
    // `--impure` is required whenever we apply the override.
    let impure_flag = if !dev_override.is_empty() {
        " --impure"
    } else {
        pre_build_impure
    };

    // Step 1: Run nix build with visible output so the user sees progress
    env.log_info(&format!("Building: nix build {}", attr));
    let build_cmd = format!(
        "nix build {} --no-link{}{}",
        attr, impure_flag, dev_override
    );
    let _build_span = tracing::info_span!("build_image", flake = %flake_ref).entered();
    let build_start = std::time::Instant::now();
    env.shell_exec_visible(&build_cmd)
        .with_context(|| format!("nix build failed for {}", attr))?;
    mvm_core::observability::metrics::global()
        .build_image_duration_ms
        .store(
            build_start.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

    // Step 2: Capture the output path (instant, uses Nix cache)
    let output = env
        .shell_exec_stdout(&format!(
            "nix build {} --no-link --print-out-paths{}{}",
            attr, impure_flag, dev_override,
        ))
        .with_context(|| "Failed to get nix build output path")?;

    let nix_output_path = output
        .lines()
        .rev()
        .find(|l| l.starts_with("/nix/store/"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "nix build did not produce an output path. Output:\n{}",
                output
            )
        })?
        .trim()
        .to_string();

    env.log_info(&format!("Build output: {}", nix_output_path));

    // Step 3: Extract revision hash from /nix/store/<hash>-...
    let revision_hash = extract_revision_hash(&nix_output_path);
    let build_dir = dev_build_dir(&revision_hash);

    // Step 4: Check cache — skip copy if artifacts already exist
    if check_cache(env, &revision_hash)? {
        env.log_success(&format!("Cache hit: {}", build_dir));
        let initrd_path = detect_initrd(env, &build_dir);
        let runner_dir = detect_runner(env, &build_dir);
        let artifact_sizes = measure_artifact_sizes(env, &build_dir, initrd_path.is_some());
        return Ok(DevBuildResult {
            vmlinux_path: format!("{}/vmlinux", build_dir),
            initrd_path,
            rootfs_path: format!("{}/rootfs.ext4", build_dir),
            build_dir,
            revision_hash,
            cached: true,
            runner_dir,
            artifact_sizes,
        });
    }

    // Step 5: Copy artifacts from Nix store to dev build directory
    copy_dev_artifacts(env, &nix_output_path, &build_dir)?;

    // Step 5a: Emit the W7.x.1 sidecar manifest (`mvm-meta.json`)
    // alongside the rootfs. Best-effort: a missing sidecar is fine
    // (consumer in `vm/runtime_meta.rs::from_sidecar` defaults to
    // accessible-by-default), but a present sidecar lights up the
    // W6.2 console gate end-to-end. Failures here log + continue —
    // surfacing the gap without breaking the build.
    crate::builder_vm::emit_sidecar_via_passthru_query(
        env,
        &attr,
        &build_dir,
        &dev_override,
        impure_flag,
    );

    env.log_success(&format!("Artifacts stored at {}", build_dir));

    let initrd_path = detect_initrd(env, &build_dir);
    let runner_dir = detect_runner(env, &build_dir);
    let artifact_sizes = measure_artifact_sizes(env, &build_dir, initrd_path.is_some());
    Ok(DevBuildResult {
        vmlinux_path: format!("{}/vmlinux", build_dir),
        initrd_path,
        rootfs_path: format!("{}/rootfs.ext4", build_dir),
        build_dir,
        revision_hash,
        cached: false,
        runner_dir,
        artifact_sizes,
    })
}

/// Build path that always runs Nix inside the project builder VM.
#[cfg(feature = "builder-vm")]
fn dev_build_via_builder_vm(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Result<DevBuildResult> {
    use crate::libkrun_builder::LibkrunBuilderVm;

    // Plan 89 W3 part 7: when a persistent-builder session is
    // alive AND the user hasn't opted out via
    // `MVM_NO_PERSISTENT_BUILDER=1`, route through the persistent
    // supervisor. Any error here (incl. supervisor crash mid-
    // dispatch) falls back to single-shot silently with a warning
    // — the single-shot path is the safety net.
    if !persistent_dispatch_disabled()
        && let Some(record) = crate::persistent_builder::read_active_session()
    {
        tracing::info!(
            session_id = %record.session_id,
            socket = %record.dispatch_socket_path.display(),
            "routing build through persistent supervisor"
        );
        let persistent = crate::persistent_builder::PersistentBuilderVm::new(record.clone());
        match dev_build_with_builder_vm(env, flake_ref, profile, mode, &persistent) {
            Ok(result) => return Ok(result),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "persistent dispatch failed; falling back to single-shot builder VM"
                );
            }
        }
    }

    dev_build_with_builder_vm(env, flake_ref, profile, mode, &LibkrunBuilderVm::default())
}

/// Read `MVM_NO_PERSISTENT_BUILDER`. Any non-empty value disables
/// persistent routing. The flag has CLI surface via `mvmctl build
/// --no-persistent-builder`; this env-var check is the bridge so
/// `dev_build`'s public signature doesn't need a new parameter
/// threaded through every caller (mvmctl, test harnesses, mvmd).
#[cfg(feature = "builder-vm")]
fn persistent_dispatch_disabled() -> bool {
    std::env::var_os("MVM_NO_PERSISTENT_BUILDER")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
}

/// Plan 120 / ADR-046: resolve the in-repo mvm workspace to build a user
/// flake against, or `None` to keep the flake's own `mvm` pin.
///
/// Returns the workspace root only when **both** hold:
///   (a) mvmctl was compiled from a source checkout whose `nix/flake.nix`
///       still exists on disk (walk up from the compile-time manifest dir,
///       the same source-checkout signal the CLI's `find_builder_vm_flake`
///       uses), and
///   (b) the user flake pins `mvm` to GitHub — so `--override-input mvm`
///       has an input to replace and we're genuinely swapping a remote
///       fetch for the local checkout.
#[cfg(feature = "builder-vm")]
fn local_mvm_workspace(user_flake: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = loop {
        if dir.join("nix/flake.nix").is_file() {
            break dir;
        }
        if !dir.pop() {
            return None;
        }
    };
    let flake_nix = std::fs::read_to_string(user_flake.join("flake.nix")).ok()?;
    flake_nix
        .contains("github:tinylabscom/mvm")
        .then_some(workspace)
}

#[cfg(feature = "builder-vm")]
fn dev_build_with_builder_vm<B: crate::builder_vm::BuilderVm>(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
    builder: &B,
) -> Result<DevBuildResult> {
    use crate::builder_vm::{BuilderJob, BuilderMounts, host_system_linux};
    use crate::libkrun_builder::GUEST_WORK_DIR;

    let system = host_system_linux();
    let attr_path = match profile {
        Some(p) if p != "default" => format!("packages.{system}.tenant-{p}"),
        _ => format!("packages.{system}.default"),
    };
    let _ = mode;

    let user_flake = std::path::PathBuf::from(if flake_ref == "." {
        std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| ".".to_string())
    } else {
        flake_ref.to_string()
    });

    // Plan 120 / ADR-046 source-checkout invariant: a compiled flake pins
    // `mvm` to GitHub for portability, but when mvmctl runs from a source
    // checkout we must build the workload against the in-repo nix flake so
    // a contributor's changes are exercised without a release round-trip.
    // In that case mount the workspace at /work and stage the user flake
    // into the job dir; `cmd.sh` overrides `mvm` to `path:/work/nix`.
    // Otherwise keep the legacy layout: the user flake is `/work`.
    let (flake_src, staged_user_flake) = match local_mvm_workspace(&user_flake) {
        Some(workspace) => {
            env.log_info(
                "Source checkout: building workload against the in-repo mvm flake \
                 (--override-input mvm path:/work/nix).",
            );
            (workspace, Some(user_flake))
        }
        None => (user_flake, None),
    };

    let job = BuilderJob::Flake {
        flake_ref: GUEST_WORK_DIR.to_string(),
        attr_path,
    };
    let staging = unique_dev_staging_dir();
    std::fs::create_dir_all(&staging).with_context(|| format!("creating staging dir {staging}"))?;

    // Plan 115 / ADR-065: dev_build_with_builder_vm is called for
    // user-flake builds (mvmctl build / dev up against the user's flake).
    // User flakes do not embed host-vm binaries, so /mvm-bins is unused
    // here. A temp dir satisfies validate_mounts' directory-exists check.
    let host_bins_tmp =
        tempfile::TempDir::new().with_context(|| "creating temp host_bin_dir for dev build")?;
    let mounts = BuilderMounts {
        flake_src,
        host_nix_store: None,
        artifact_out: std::path::PathBuf::from(&staging),
        host_bin_dir: host_bins_tmp.path().to_path_buf(),
        staged_user_flake,
    };

    let artifacts = builder
        .run_build(&job, &mounts)
        .map_err(|e| anyhow::anyhow!("builder VM: {e}"))?;
    let revision_hash = match artifacts {
        crate::builder_vm::BuilderArtifacts::Image { revision_hash, .. } => revision_hash,
        crate::builder_vm::BuilderArtifacts::InstallVolume { .. } => {
            anyhow::bail!("builder VM returned install-volume artifacts for a flake build");
        }
    };

    let final_dir = dev_build_dir(&revision_hash);
    if std::path::Path::new(&final_dir).exists() {
        env.log_info(&format!(
            "Cache hit on rev {revision_hash}; discarding staged build."
        ));
        let _ = std::fs::remove_dir_all(&staging);
    } else if let Err(e) = std::fs::rename(&staging, &final_dir) {
        std::fs::create_dir_all(&final_dir)
            .with_context(|| format!("creating final build dir {final_dir}"))?;
        for entry in
            std::fs::read_dir(&staging).with_context(|| format!("reading staging dir {staging}"))?
        {
            let entry = entry?;
            let dst = std::path::Path::new(&final_dir).join(entry.file_name());
            std::fs::copy(entry.path(), &dst).with_context(|| {
                format!("copying {} -> {}", entry.path().display(), dst.display())
            })?;
        }
        let _ = std::fs::remove_dir_all(&staging);
        tracing::debug!(error = %e, "rename failed; fell back to copy");
    }

    let build_dir = final_dir;
    let vmlinux_path = format!("{build_dir}/vmlinux");
    let rootfs_path = format!("{build_dir}/rootfs.ext4");
    let initrd_path = detect_initrd(env, &build_dir);
    let runner_dir = detect_runner(env, &build_dir);
    let artifact_sizes = measure_artifact_sizes(env, &build_dir, initrd_path.is_some());

    env.log_success(&format!(
        "Builder VM build complete; artifacts at {build_dir}"
    ));

    Ok(DevBuildResult {
        build_dir,
        vmlinux_path,
        initrd_path,
        rootfs_path,
        revision_hash,
        cached: false,
        runner_dir,
        artifact_sizes,
    })
}

/// Run the flake's `pre-build.sh` hook if it exists.
///
/// Some templates install external software (e.g. via an upstream installer
/// script) before the Nix build. If `<flake_ref>/pre-build.sh` exists and
/// is executable, it is run with visible output. Returns `" --impure"` when
/// the hook ran (so `nix build` can reference host paths), or `""` otherwise.
#[cfg(test)]
fn run_pre_build_hook(env: &dyn ShellEnvironment, flake_ref: &str) -> Result<&'static str> {
    let pre_build = format!("{}/pre-build.sh", flake_ref);
    let check = env
        .shell_exec_stdout(&format!(
            "test -f {} && test -x {} && echo yes || echo no",
            shell_quote(&pre_build),
            shell_quote(&pre_build),
        ))
        .unwrap_or_default();

    if check.trim() != "yes" {
        return Ok("");
    }

    env.log_info("Running pre-build hook (pre-build.sh)...");
    env.shell_exec_visible(&format!("bash {}", shell_quote(&pre_build)))
        .with_context(|| "pre-build.sh hook failed")?;

    // The hook may install files outside the Nix store (e.g. /opt/openclaw)
    // that the flake references via builtins.path. --impure is required for
    // nix build to access these host paths.
    Ok(" --impure")
}

/// Resolve the Nix attribute for a dev build.
///
/// - `None` → builds the flake's `default` package (convention: `default = worker`).
/// - `Some(profile)` → builds `packages.<system>.tenant-<profile>`.
#[cfg(test)]
fn resolve_dev_build_attribute(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
) -> String {
    match profile {
        Some(p) if p != "default" => {
            let system = nix_system();
            let attr = format!("{}#packages.{}.tenant-{}", flake_ref, system, p);
            env.log_info(&format!("Build attribute: {}", attr));
            attr
        }
        _ => {
            // Build the flake's default package for the target Linux system
            // (not the host, which may be macOS).
            let system = nix_system();
            let attr = format!("{}#packages.{}.default", flake_ref, system);
            env.log_info(&format!("Build attribute: {} (default)", attr));
            attr
        }
    }
}

/// Extract the Nix store hash from an output path like `/nix/store/<hash>-name`.
#[cfg(test)]
fn extract_revision_hash(nix_output_path: &str) -> String {
    nix_output_path
        .strip_prefix("/nix/store/")
        .and_then(|s| s.split('-').next())
        .unwrap_or("unknown")
        .to_string()
}

/// Return the dev build directory for a given revision hash.
#[cfg(any(test, feature = "builder-vm"))]
fn dev_build_dir(revision_hash: &str) -> String {
    format!("{}/{}", dev_builds_dir(), revision_hash)
}

#[cfg(feature = "builder-vm")]
fn unique_dev_staging_dir() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{}/.staging-{}-{}",
        dev_builds_dir(),
        std::process::id(),
        nanos
    )
}

#[cfg(test)]
fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

/// True if `nix` is available inside the builder shell environment.
#[cfg(test)]
fn builder_env_has_nix(env: &dyn ShellEnvironment) -> bool {
    env.shell_exec_stdout("nix --version 2>/dev/null | head -1")
        .map(|s| s.trim().starts_with("nix "))
        .unwrap_or(false)
}

/// Check whether cached artifacts exist for a revision hash.
#[cfg(test)]
fn check_cache(env: &dyn ShellEnvironment, revision_hash: &str) -> Result<bool> {
    let build_dir = dev_build_dir(revision_hash);
    let result = env.shell_exec_stdout(&format!(
        "test -f {dir}/vmlinux && test -f {dir}/rootfs.ext4 && echo yes || echo no",
        dir = build_dir,
    ))?;
    Ok(result.trim() == "yes")
}

/// Copy kernel, initrd, and rootfs from a Nix store output to the dev build directory.
#[cfg(test)]
fn copy_dev_artifacts(
    env: &dyn ShellEnvironment,
    nix_output_path: &str,
    build_dir: &str,
) -> Result<()> {
    env.shell_exec(&format!(
        r#"
        set -euo pipefail
        mkdir -p {dir}

        # Copy kernel (try 'kernel' then 'vmlinux')
        if [ -e {out}/kernel ]; then
            cp -L {out}/kernel {dir}/vmlinux
        elif [ -e {out}/vmlinux ]; then
            cp -L {out}/vmlinux {dir}/vmlinux
        else
            echo 'ERROR: kernel not found in build output' >&2
            ls -la {out}/ >&2
            exit 1
        fi

        # Copy initrd if present (NixOS stage-1 for proper activation)
        if [ -e {out}/initrd ]; then
            cp -L {out}/initrd {dir}/initrd
        fi

        # Copy rootfs (try 'rootfs' then 'rootfs.ext4')
        if [ -e {out}/rootfs ]; then
            cp -L {out}/rootfs {dir}/rootfs.ext4
        elif [ -e {out}/rootfs.ext4 ]; then
            cp -L {out}/rootfs.ext4 {dir}/rootfs.ext4
        else
            echo 'ERROR: rootfs not found in build output' >&2
            ls -la {out}/ >&2
            exit 1
        fi

        # Copy microvm.nix runner scripts if present
        if [ -d {out}/bin ] && [ -x {out}/bin/microvm-run ]; then
            mkdir -p {dir}/bin
            cp -rL {out}/bin/* {dir}/bin/
            chmod +x {dir}/bin/*
        fi

        # Copy OCI image if present (for Apple Container dev mode)
        if [ -e {out}/image.tar.gz ]; then
            cp -L {out}/image.tar.gz {dir}/image.tar.gz
        fi

        echo "Artifacts:"
        ls -lh {dir}/
        "#,
        out = nix_output_path,
        dir = build_dir,
    ))
    .with_context(|| format!("Failed to copy artifacts to {}", build_dir))
}

/// Measure artifact file sizes in the build directory using `stat -c%s`.
#[cfg(any(test, feature = "builder-vm"))]
fn measure_artifact_sizes(
    env: &dyn ShellEnvironment,
    build_dir: &str,
    has_initrd: bool,
) -> mvm_core::pool::ArtifactSizes {
    let parse_size = |path: &str| -> u64 {
        env.shell_exec_stdout(&format!("stat -c%s {} 2>/dev/null || echo 0", path))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };

    let vmlinux_bytes = parse_size(&format!("{}/vmlinux", build_dir));
    let rootfs_bytes = parse_size(&format!("{}/rootfs.ext4", build_dir));
    let initrd_bytes = if has_initrd {
        Some(parse_size(&format!("{}/initrd", build_dir)))
    } else {
        None
    };

    mvm_core::pool::ArtifactSizes {
        vmlinux_bytes,
        rootfs_bytes,
        initrd_bytes,
        nix_closure_bytes: None,
    }
}

/// Check whether an initrd exists in the build directory.
#[cfg(any(test, feature = "builder-vm"))]
fn detect_initrd(env: &dyn ShellEnvironment, build_dir: &str) -> Option<String> {
    let path = format!("{}/initrd", build_dir);
    let result = env
        .shell_exec_stdout(&format!("test -f {} && echo yes || echo no", path))
        .ok()?;
    if result.trim() == "yes" {
        Some(path)
    } else {
        None
    }
}

/// Check whether a microvm.nix runner script exists in the build directory.
///
/// The root flake's `mkGuest` copies the runner to `$out/bin/microvm-run`
/// when the microvm.nix runner is available. If found, returns the runner
/// directory path (parent of `bin/`).
#[cfg(any(test, feature = "builder-vm"))]
fn detect_runner(env: &dyn ShellEnvironment, build_dir: &str) -> Option<String> {
    let runner_path = format!("{}/bin/microvm-run", build_dir);
    let result = env
        .shell_exec_stdout(&format!("test -x {} && echo yes || echo no", runner_path))
        .ok()?;
    if result.trim() == "yes" {
        Some(build_dir.to_string())
    } else {
        None
    }
}

/// Return the Nix Linux system identifier for the current architecture.
pub fn linux_system() -> &'static str {
    nix_system()
}

fn nix_system() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64-linux"
    } else {
        "x86_64-linux"
    }
}

// ============================================================================
// Guest agent auto-injection
// ============================================================================

/// Detect the mvm workspace root for building the guest-agent from source.
///
/// Tries in order:
/// 1. `MVM_SRC` environment variable (explicit override)
/// 2. Compile-time `CARGO_MANIFEST_DIR` — the build crate lives at
///    `<workspace>/crates/mvm-build`, so we go up 2 levels.
fn detect_mvm_src() -> Option<String> {
    if let Ok(p) = std::env::var("MVM_SRC")
        && !p.is_empty()
    {
        return Some(p);
    }

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest_dir.parent()?.parent()?;
    if workspace.join("crates/mvm-guest").is_dir() {
        return Some(workspace.to_string_lossy().to_string());
    }

    None
}

/// Best-effort guest agent injection after a dev build.
///
/// Auto-detects the mvm workspace root and injects the guest agent into the
/// rootfs if it's not already present. Never fails the overall build — logs
/// a message and returns `Ok(())` if injection cannot be performed.
#[instrument(skip_all)]
pub fn ensure_guest_agent_if_needed(
    env: &dyn ShellEnvironment,
    build_result: &DevBuildResult,
) -> Result<()> {
    // Plan 68: same stub-outdir escape-hatch as `dev_build`. When the
    // build itself was a stub, the rootfs is a placeholder file, not
    // an ext4 image — attempting to `sudo mount` it would prompt for
    // a password and hang the test. Skip injection in that mode.
    if std::env::var("MVM_BUILD_STUB_OUTDIR")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
    {
        env.log_warn("MVM_BUILD_STUB_OUTDIR set; skipping guest-agent injection (test path).");
        return Ok(());
    }
    let mvm_src = match detect_mvm_src() {
        Some(p) => p,
        None => {
            env.log_info(
                "Cannot detect mvm source tree for guest-agent injection. \
                 Include the guest-agent module in your flake manually.",
            );
            return Ok(());
        }
    };
    ensure_guest_agent(env, build_result, &mvm_src)
}

/// Ensure the guest agent is present in the built rootfs.
///
/// Checks whether `mvm-guest-agent` exists in the rootfs. If not, builds it
/// from the mvm workspace and injects it (binary, systemd service, drop-in dir)
/// into the ext4 image. This guarantees every mvm-built image has the guest agent
/// regardless of whether the user's flake explicitly includes it.
fn ensure_guest_agent(
    env: &dyn ShellEnvironment,
    build_result: &DevBuildResult,
    mvm_src_path: &str,
) -> Result<()> {
    let rootfs = &build_result.rootfs_path;

    // Step 1: Check if agent is already in the rootfs
    let check_script = [
        "MOUNT=$(mktemp -d)",
        &format!("sudo mount -o loop,ro {} \"$MOUNT\"", rootfs),
        "FOUND=$(find \"$MOUNT/nix/store\" -name mvm-guest-agent -type f 2>/dev/null | head -1)",
        "sudo umount \"$MOUNT\"",
        "rmdir \"$MOUNT\"",
        "if [ -n \"$FOUND\" ]; then echo found; else echo missing; fi",
    ]
    .join(" && ");

    let check = env.shell_exec_stdout(&check_script)?;

    if check.trim() == "found" {
        env.log_info("Guest agent already present in rootfs");
        return Ok(());
    }

    env.log_info("Guest agent not found in rootfs — injecting...");

    // Step 2: Build the guest-agent from the mvm workspace
    let build_cmd = format!(
        "nix-build --no-out-link {}/nix/packages/mvm-guest-agent.nix \
         --arg pkgs 'import <nixpkgs> {{}}' \
         --arg mvmSrc {} \
         --arg rustPlatform '(import <nixpkgs> {{}}).rustPlatform'",
        mvm_src_path, mvm_src_path,
    );

    let agent_store_path = match env.shell_exec_stdout(&build_cmd) {
        Ok(p) if p.trim().starts_with("/nix/store/") => p.trim().to_string(),
        _ => {
            env.log_info(
                "Could not build guest-agent for injection. \
                 Add the guest-agent module to your flake manually.",
            );
            return Ok(());
        }
    };

    // Step 3: Get the full nix store closure
    let closure = env
        .shell_exec_stdout(&format!("nix-store -qR {}", agent_store_path))
        .with_context(|| "Failed to query guest-agent closure")?;

    // Step 4: Inject into rootfs
    inject_agent_into_rootfs(env, rootfs, &agent_store_path, closure.trim())
}

/// Mount the rootfs, copy the agent closure, create systemd service, unmount.
fn inject_agent_into_rootfs(
    env: &dyn ShellEnvironment,
    rootfs: &str,
    agent_store_path: &str,
    closure_lines: &str,
) -> Result<()> {
    // Build the injection script. All paths come from nix-store output
    // (trusted, not user input).
    let mut script = String::new();
    script.push_str("set -euo pipefail\n");
    script.push_str("MOUNT=$(mktemp -d)\n");
    script.push_str(&format!("sudo mount -o loop {} \"$MOUNT\"\n", rootfs));

    // Copy each store path if not already present
    for line in closure_lines.lines() {
        let path = line.trim();
        if path.is_empty() || !path.starts_with("/nix/store/") {
            continue;
        }
        script.push_str(&format!(
            "[ -e \"$MOUNT{}\" ] || sudo cp -a {} \"$MOUNT{}\"\n",
            path, path, path
        ));
    }

    // Create systemd service file
    script.push_str("sudo mkdir -p \"$MOUNT/etc/systemd/system\"\n");
    script.push_str(&format!(
        concat!(
            "printf '[Unit]\\nDescription=MVM Guest Agent\\nAfter=basic.target\\n\\n",
            "[Service]\\nType=simple\\nExecStart={}/bin/mvm-guest-agent\\n",
            "Restart=on-failure\\nRestartSec=2s\\n\\n",
            "[Install]\\nWantedBy=multi-user.target\\n' ",
            "| sudo tee \"$MOUNT/etc/systemd/system/mvm-guest-agent.service\" > /dev/null\n"
        ),
        agent_store_path,
    ));

    // Enable for multi-user.target
    script.push_str(
        "sudo mkdir -p \"$MOUNT/etc/systemd/system/multi-user.target.wants\"\n\
         sudo ln -sf /etc/systemd/system/mvm-guest-agent.service \
         \"$MOUNT/etc/systemd/system/multi-user.target.wants/mvm-guest-agent.service\"\n",
    );

    // Create integrations drop-in directory
    script.push_str("sudo mkdir -p \"$MOUNT/etc/mvm/integrations.d\"\n");

    // Unmount
    script.push_str("sudo umount \"$MOUNT\"\nrmdir \"$MOUNT\"\n");

    env.shell_exec(&script)
        .with_context(|| "Failed to inject guest-agent into rootfs")?;

    env.log_success("Guest agent injected into rootfs");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Mock ShellEnvironment for testing dev_build logic without a real VM.
    struct TestEnv {
        stdout_responses: Mutex<HashMap<String, String>>,
        exec_log: Mutex<Vec<String>>,
        logs: Mutex<Vec<String>>,
    }

    impl TestEnv {
        fn new() -> Self {
            let env = Self {
                stdout_responses: Mutex::new(HashMap::new()),
                exec_log: Mutex::new(Vec::new()),
                logs: Mutex::new(Vec::new()),
            };
            // Legacy shell-path helper tests still probe for `nix`
            // before exercising their mock Nix commands.
            env.stub_stdout("nix --version", "nix (Nix) 2.24.10\n");
            env
        }

        fn stub_stdout(&self, pattern: &str, response: &str) {
            self.stdout_responses
                .lock()
                .unwrap()
                .insert(pattern.to_string(), response.to_string());
        }
    }

    impl ShellEnvironment for TestEnv {
        fn shell_exec(&self, script: &str) -> Result<()> {
            self.exec_log.lock().unwrap().push(script.to_string());
            Ok(())
        }

        fn shell_exec_stdout(&self, script: &str) -> Result<String> {
            self.exec_log.lock().unwrap().push(script.to_string());
            let responses = self.stdout_responses.lock().unwrap();
            for (pattern, response) in responses.iter() {
                if script.contains(pattern) {
                    return Ok(response.clone());
                }
            }
            Ok(String::new())
        }

        fn shell_exec_visible(&self, script: &str) -> Result<()> {
            self.exec_log.lock().unwrap().push(script.to_string());
            Ok(())
        }

        fn log_info(&self, msg: &str) {
            self.logs.lock().unwrap().push(format!("INFO: {}", msg));
        }

        fn log_success(&self, msg: &str) {
            self.logs.lock().unwrap().push(format!("SUCCESS: {}", msg));
        }
    }

    #[cfg(feature = "builder-vm")]
    struct RecordingBuilderVm {
        seen: Mutex<
            Vec<(
                crate::builder_vm::BuilderJob,
                crate::builder_vm::BuilderMounts,
            )>,
        >,
        revision_hash: String,
    }

    #[cfg(feature = "builder-vm")]
    impl RecordingBuilderVm {
        fn new(revision_hash: &str) -> Self {
            Self {
                seen: Mutex::new(Vec::new()),
                revision_hash: revision_hash.to_string(),
            }
        }
    }

    #[cfg(feature = "builder-vm")]
    impl crate::builder_vm::BuilderVm for RecordingBuilderVm {
        fn run_build(
            &self,
            job: &crate::builder_vm::BuilderJob,
            mounts: &crate::builder_vm::BuilderMounts,
        ) -> Result<crate::builder_vm::BuilderArtifacts, crate::builder_vm::BuilderVmError>
        {
            self.seen
                .lock()
                .expect("recording builder mutex poisoned")
                .push((job.clone(), mounts.clone()));
            std::fs::create_dir_all(&mounts.artifact_out)
                .map_err(|e| crate::builder_vm::BuilderVmError::ExtractionFailed(e.to_string()))?;
            std::fs::write(mounts.artifact_out.join("vmlinux"), b"kernel")
                .map_err(|e| crate::builder_vm::BuilderVmError::ExtractionFailed(e.to_string()))?;
            std::fs::write(mounts.artifact_out.join("rootfs.ext4"), b"rootfs")
                .map_err(|e| crate::builder_vm::BuilderVmError::ExtractionFailed(e.to_string()))?;

            Ok(crate::builder_vm::BuilderArtifacts::Image {
                rootfs_path: mounts.artifact_out.join("rootfs.ext4"),
                kernel_path: Some(mounts.artifact_out.join("vmlinux")),
                revision_hash: self.revision_hash.clone(),
                lock_hash: Some("lockhash".to_string()),
                accessible: Some(true),
            })
        }
    }

    #[test]
    fn test_extract_revision_hash_valid() {
        let hash = extract_revision_hash("/nix/store/abc123def456-tenant-worker-minimal");
        assert_eq!(hash, "abc123def456");
    }

    #[test]
    fn test_extract_revision_hash_no_prefix() {
        let hash = extract_revision_hash("/some/other/path");
        assert_eq!(hash, "unknown");
    }

    #[test]
    fn test_extract_revision_hash_empty() {
        let hash = extract_revision_hash("");
        assert_eq!(hash, "unknown");
    }

    #[test]
    fn test_dev_build_dir() {
        let dir = dev_build_dir("abc123");
        assert!(dir.ends_with("/dev/builds/abc123"), "got: {}", dir);
    }

    #[test]
    fn test_dev_build_dir_preserves_full_hash() {
        let dir = dev_build_dir("abc123def456ghi789");
        assert!(
            dir.ends_with("/dev/builds/abc123def456ghi789"),
            "got: {}",
            dir
        );
    }

    #[test]
    fn test_nix_system() {
        let system = nix_system();
        assert!(
            system == "aarch64-linux" || system == "x86_64-linux",
            "unexpected system: {}",
            system
        );
    }

    #[test]
    fn test_cleanup_old_dev_builds_no_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let report = cleanup_builds_in(&tmp.path().join("does-not-exist"), 2).unwrap();
        assert_eq!(report.removed_count, 0);
        assert!(report.removed_paths.is_empty());
    }

    #[test]
    fn test_cleanup_old_dev_builds_keeps_newest() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let builds = tmp.path().join("builds");
        std::fs::create_dir_all(&builds).expect("mkdir builds");

        // Create three build dirs with a 50 ms gap so mtimes are
        // distinct on filesystems with coarse resolution (HFS+ is
        // 1 s; APFS / most Linux is 1 ns — 50 ms covers both).
        for name in ["oldest", "middle", "newest"] {
            std::fs::create_dir(builds.join(name)).expect("mkdir build subdir");
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let report = cleanup_builds_in(&builds, 1).unwrap();
        assert_eq!(report.removed_count, 2);
        // Removed paths are sorted newest-first then by removal
        // order — "middle" and "oldest" should be in the report.
        let names: Vec<String> = report
            .removed_paths
            .iter()
            .filter_map(|p| {
                std::path::Path::new(p)
                    .file_name()?
                    .to_str()
                    .map(String::from)
            })
            .collect();
        assert!(names.contains(&"oldest".to_string()), "got {names:?}");
        assert!(names.contains(&"middle".to_string()), "got {names:?}");
        assert!(
            !names.contains(&"newest".to_string()),
            "newest must be kept; got {names:?}"
        );
        assert!(
            builds.join("newest").is_dir(),
            "newest build dir must still exist on disk"
        );
        assert!(
            !builds.join("middle").exists() && !builds.join("oldest").exists(),
            "pruned build dirs must be removed from disk"
        );
    }

    #[test]
    fn test_resolve_attribute_with_profile() {
        let env = TestEnv::new();

        let attr = resolve_dev_build_attribute(&env, "/home/user/my-project", Some("worker"));

        let system = nix_system();
        assert_eq!(
            attr,
            format!("/home/user/my-project#packages.{}.tenant-worker", system)
        );
    }

    #[test]
    fn test_resolve_attribute_custom_profile() {
        let env = TestEnv::new();

        let attr = resolve_dev_build_attribute(&env, "/tmp/flake", Some("gateway"));

        let system = nix_system();
        assert_eq!(
            attr,
            format!("/tmp/flake#packages.{}.tenant-gateway", system)
        );
    }

    #[test]
    fn test_resolve_attribute_default() {
        let env = TestEnv::new();

        let attr = resolve_dev_build_attribute(&env, "/tmp/flake", None);
        let system = linux_system();

        assert_eq!(attr, format!("/tmp/flake#packages.{system}.default"));
    }

    #[test]
    fn test_check_cache_hit() {
        let env = TestEnv::new();
        env.stub_stdout("test -f", "yes");

        let cached = check_cache(&env, "abc123").unwrap();
        assert!(cached);
    }

    #[test]
    fn test_check_cache_miss() {
        let env = TestEnv::new();
        env.stub_stdout("test -f", "no");

        let cached = check_cache(&env, "abc123").unwrap();
        assert!(!cached);
    }

    #[test]
    fn test_dev_build_cached() {
        let env = TestEnv::new();
        env.stub_stdout("nix --version", "nix (Nix) 2.24.10");

        // nix build --no-link (visible) succeeds
        // nix build --print-out-paths returns the path
        env.stub_stdout(
            "--print-out-paths",
            "/nix/store/abc123-tenant-worker-minimal\n",
        );
        // Cache check returns yes
        env.stub_stdout("test -f", "yes");

        let result =
            dev_build_via_shell_env(&env, "/home/user/project", Some("minimal"), BuildMode::Dev)
                .unwrap();

        assert!(result.cached);
        assert_eq!(result.revision_hash, "abc123");
        let expected_dir = dev_build_dir("abc123");
        assert_eq!(result.build_dir, expected_dir);
        assert_eq!(result.vmlinux_path, format!("{expected_dir}/vmlinux"));
        assert_eq!(result.rootfs_path, format!("{expected_dir}/rootfs.ext4"));
    }

    #[test]
    fn test_dev_build_fresh() {
        let env = TestEnv::new();
        env.stub_stdout("nix --version", "nix (Nix) 2.24.10");

        env.stub_stdout("--print-out-paths", "/nix/store/xyz789-tenant-minimal\n");
        // Cache miss
        env.stub_stdout("test -f", "no");

        let result =
            dev_build_via_shell_env(&env, "/tmp/flake", Some("minimal"), BuildMode::Dev).unwrap();

        assert!(!result.cached);
        assert_eq!(result.revision_hash, "xyz789");
        assert_eq!(result.build_dir, dev_build_dir("xyz789"));

        // Verify a copy script was executed
        let exec_log = env.exec_log.lock().unwrap();
        let has_copy = exec_log.iter().any(|s| s.contains("cp -L"));
        assert!(has_copy, "Expected copy script in exec log");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_vm_dev_build_uses_vm_job_shape_without_host_nix() {
        let env = TestEnv::new();
        env.stub_stdout("initrd", "0");
        env.stub_stdout("microvm-run", "no");
        env.stub_stdout("stat -c%s", "6");
        let revision_hash = format!("builderrev-success-{}", std::process::id());
        let final_dir = dev_build_dir(&revision_hash);
        let _ = std::fs::remove_dir_all(&final_dir);
        let builder = RecordingBuilderVm::new(&revision_hash);
        let result = dev_build_with_builder_vm(
            &env,
            "/tmp/source-flake",
            Some("worker"),
            BuildMode::Dev,
            &builder,
        )
        .expect("builder VM dev build should succeed with fake builder");

        assert_eq!(result.revision_hash, revision_hash);
        assert_eq!(result.build_dir, final_dir);
        assert!(std::path::Path::new(&result.vmlinux_path).is_file());
        assert!(std::path::Path::new(&result.rootfs_path).is_file());

        let seen = builder
            .seen
            .lock()
            .expect("recording builder mutex poisoned");
        assert_eq!(seen.len(), 1);
        let (job, mounts) = &seen[0];
        assert_eq!(
            mounts.flake_src,
            std::path::PathBuf::from("/tmp/source-flake")
        );
        assert!(mounts.host_nix_store.is_none());
        let staging_name = mounts
            .artifact_out
            .file_name()
            .and_then(|name| name.to_str())
            .expect("staging dir should have a utf-8 basename");
        assert!(
            staging_name.starts_with(&format!(".staging-{}-", std::process::id())),
            "staging dir should be unique per build: {}",
            mounts.artifact_out.display()
        );
        assert_eq!(
            job,
            &crate::builder_vm::BuilderJob::Flake {
                flake_ref: crate::libkrun_builder::GUEST_WORK_DIR.to_string(),
                attr_path: format!(
                    "packages.{}.tenant-worker",
                    crate::builder_vm::host_system_linux()
                ),
            }
        );

        let exec_log = env.exec_log.lock().expect("exec log mutex poisoned");
        assert!(
            exec_log.iter().all(|entry| !entry.contains("nix ")),
            "builder VM path must not probe or invoke host-side Nix: {exec_log:?}"
        );
        std::fs::remove_dir_all(&final_dir).expect("clean fake builder artifacts");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_vm_dev_build_fails_closed_when_builder_errors() {
        let env = TestEnv::new();
        let result = dev_build_with_builder_vm(
            &env,
            "/tmp/source-flake",
            None,
            BuildMode::Prod,
            &crate::builder_vm::StubBuilderVm,
        );

        let err = result.expect_err("stub builder must fail closed");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("builder VM"),
            "error should name the builder VM boundary: {msg}"
        );
        assert!(
            !std::path::Path::new(&dev_build_dir("unknown")).exists(),
            "failure must not synthesize a host-Nix artifact directory"
        );
        let exec_log = env.exec_log.lock().expect("exec log mutex poisoned");
        assert!(
            exec_log.iter().all(|entry| !entry.contains("nix ")),
            "builder failure path must not fall back to host-side Nix: {exec_log:?}"
        );
    }

    #[test]
    fn test_dev_build_result_paths_consistent() {
        let dir = dev_build_dir("hash123");
        let result = DevBuildResult {
            build_dir: dir.clone(),
            vmlinux_path: format!("{dir}/vmlinux"),
            initrd_path: Some(format!("{dir}/initrd")),
            rootfs_path: format!("{dir}/rootfs.ext4"),
            revision_hash: "hash123".to_string(),
            cached: false,
            runner_dir: None,
            artifact_sizes: Default::default(),
        };

        assert!(result.vmlinux_path.starts_with(&result.build_dir));
        assert!(result.rootfs_path.starts_with(&result.build_dir));
        assert!(
            result
                .initrd_path
                .as_ref()
                .unwrap()
                .starts_with(&result.build_dir)
        );
    }

    #[test]
    fn test_dev_build_result_with_runner() {
        let dir = dev_build_dir("hash456");
        let result = DevBuildResult {
            build_dir: dir.clone(),
            vmlinux_path: format!("{dir}/vmlinux"),
            initrd_path: None,
            rootfs_path: format!("{dir}/rootfs.ext4"),
            revision_hash: "hash456".to_string(),
            cached: false,
            runner_dir: Some(dir.clone()),
            artifact_sizes: Default::default(),
        };

        assert!(result.runner_dir.is_some());
        assert_eq!(result.runner_dir.as_ref().unwrap(), &dir);
    }

    #[test]
    fn test_pre_build_hook_skipped_when_absent() {
        let env = TestEnv::new();
        // Default: shell_exec_stdout returns "" for unknown commands,
        // so the hook check returns "no" equivalent → skip.
        let flag = run_pre_build_hook(&env, "/tmp/flake").unwrap();
        assert_eq!(flag, "");
    }

    #[test]
    fn test_pre_build_hook_runs_when_present() {
        let env = TestEnv::new();
        env.stub_stdout("test -f", "yes");

        let flag = run_pre_build_hook(&env, "/tmp/flake").unwrap();
        assert_eq!(flag, " --impure");

        // Verify the hook script was executed.
        let exec_log = env.exec_log.lock().unwrap();
        assert!(
            exec_log.iter().any(|s| s.contains("pre-build.sh")),
            "Expected pre-build.sh in exec log"
        );
    }

    #[test]
    fn test_dev_build_with_pre_build_hook() {
        let env = TestEnv::new();
        env.stub_stdout("nix --version", "nix (Nix) 2.24.10");

        // Pre-build hook exists.
        env.stub_stdout("test -f", "yes");
        // nix build output.
        env.stub_stdout("--print-out-paths", "/nix/store/abc123-tenant-minimal\n");

        let result =
            dev_build_via_shell_env(&env, "/tmp/flake", Some("minimal"), BuildMode::Dev).unwrap();

        // Verify --impure was added to nix build commands.
        let exec_log = env.exec_log.lock().unwrap();
        let nix_build_cmds: Vec<_> = exec_log
            .iter()
            .filter(|s| s.contains("nix build"))
            .collect();
        assert!(
            nix_build_cmds.iter().all(|s| s.contains("--impure")),
            "Expected --impure in nix build commands: {:?}",
            nix_build_cmds
        );

        assert_eq!(result.revision_hash, "abc123");
    }

    #[test]
    fn test_measure_artifact_sizes() {
        let env = TestEnv::new();
        env.stub_stdout("vmlinux", "12345678");
        env.stub_stdout("rootfs.ext4", "45678901");

        let sizes = measure_artifact_sizes(&env, "/tmp/build", false);
        assert_eq!(sizes.vmlinux_bytes, 12_345_678);
        assert_eq!(sizes.rootfs_bytes, 45_678_901);
        assert!(sizes.initrd_bytes.is_none());
        assert!(sizes.nix_closure_bytes.is_none());
    }

    #[test]
    fn test_measure_artifact_sizes_with_initrd() {
        let env = TestEnv::new();
        env.stub_stdout("vmlinux", "12345678");
        env.stub_stdout("rootfs.ext4", "45678901");
        env.stub_stdout("initrd", "2345678");

        let sizes = measure_artifact_sizes(&env, "/tmp/build", true);
        assert_eq!(sizes.vmlinux_bytes, 12_345_678);
        assert_eq!(sizes.rootfs_bytes, 45_678_901);
        assert_eq!(sizes.initrd_bytes, Some(2_345_678));
    }

    #[test]
    fn builder_env_has_nix_returns_true_when_probe_stubbed() {
        // Default TestEnv stubs the builder VM `nix --version` probe to a success response.
        let env = TestEnv::new();
        assert!(builder_env_has_nix(&env));
    }

    #[test]
    fn builder_env_has_nix_returns_false_when_probe_empty() {
        // Override the default stub with an empty response, which is what a broken builder VM would return.
        let env = TestEnv::new();
        env.stub_stdout("nix --version", "");
        assert!(!builder_env_has_nix(&env));
    }

    #[test]
    fn dev_build_bails_clearly_when_nix_missing() {
        let env = TestEnv::new();
        env.stub_stdout("nix --version", "");
        let result = dev_build_via_shell_env(
            &env,
            "/definitely/not/a/real/flake/dir",
            Some("minimal"),
            BuildMode::Dev,
        );
        let err = result.expect_err("must bail when no nix is available");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("No `nix` on PATH inside the builder environment"),
            "bail must name missing nix: {msg}"
        );
    }

    #[test]
    fn test_dev_build_includes_artifact_sizes() {
        let env = TestEnv::new();
        env.stub_stdout("nix --version", "nix (Nix) 2.24.10");

        env.stub_stdout("--print-out-paths", "/nix/store/xyz789-tenant-minimal\n");
        env.stub_stdout("test -f", "no");
        // stat calls return sizes
        env.stub_stdout("stat -c%s", "99999");

        let result =
            dev_build_via_shell_env(&env, "/tmp/flake", Some("minimal"), BuildMode::Dev).unwrap();
        // Sizes should be populated (exact value depends on stub matching)
        assert!(result.artifact_sizes.vmlinux_bytes > 0 || result.artifact_sizes.rootfs_bytes > 0);
    }

    fn fixture_passthru_json(accessible: bool) -> String {
        format!(
            r#"{{
              "name": "fixture",
              "accessible": {accessible},
              "sealed": {sealed},
              "entrypointKind": "shell",
              "initSystem": "busybox",
              "expectedBootMs": 300,
              "agentBinary": "stub",
              "rootlessEntrypoint": false,
              "hypervisor": "libkrun"
            }}"#,
            sealed = !accessible,
        )
    }

    #[test]
    fn emit_sidecar_writes_json_when_passthru_query_succeeds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = TestEnv::new();
        env.stub_stdout("--json", &fixture_passthru_json(true));

        crate::builder_vm::emit_sidecar_via_passthru_query(
            &env,
            "/tmp/flake#packages.x86_64-linux.tenant-worker",
            tmp.path().to_str().unwrap(),
            "",
            "",
        );

        let sidecar = crate::builder_vm::ArtifactManifest::read_from_dir(tmp.path())
            .expect("read")
            .expect("present");
        assert!(sidecar.accessible);
        assert_eq!(sidecar.name, "fixture");
        assert_eq!(sidecar.hypervisor, "libkrun");
    }

    #[test]
    fn emit_sidecar_no_sidecar_when_passthru_query_returns_garbage() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = TestEnv::new();
        env.stub_stdout("--json", "{not json");

        crate::builder_vm::emit_sidecar_via_passthru_query(
            &env,
            "/tmp/flake#packages.x86_64-linux.tenant-worker",
            tmp.path().to_str().unwrap(),
            "",
            "",
        );

        let sidecar = crate::builder_vm::ArtifactManifest::read_from_dir(tmp.path()).expect("read");
        assert!(sidecar.is_none());
    }

    #[test]
    fn emit_sidecar_no_sidecar_when_query_returns_empty() {
        // TestEnv returns Ok("") for unstubbed commands; empty
        // stdout fails JSON parsing → log+continue → no sidecar.
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = TestEnv::new();

        crate::builder_vm::emit_sidecar_via_passthru_query(
            &env,
            "/tmp/flake#packages.x86_64-linux.tenant-worker",
            tmp.path().to_str().unwrap(),
            "",
            "",
        );

        let sidecar = crate::builder_vm::ArtifactManifest::read_from_dir(tmp.path()).expect("read");
        assert!(sidecar.is_none());
    }

    #[test]
    fn emit_sidecar_threads_overrides_into_command() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let env = TestEnv::new();
        env.stub_stdout("--override-input mvm", &fixture_passthru_json(false));

        crate::builder_vm::emit_sidecar_via_passthru_query(
            &env,
            "/tmp/flake#packages.x86_64-linux.tenant-worker",
            tmp.path().to_str().unwrap(),
            " --override-input mvm git+file:///workspace?dir=nix/dev",
            " --impure",
        );

        let sidecar = crate::builder_vm::ArtifactManifest::read_from_dir(tmp.path())
            .expect("read")
            .expect("present");
        assert!(!sidecar.accessible, "sealed fixture round-tripped");
    }

    #[test]
    fn build_mode_prod_emits_no_dev_override() {
        // The whole point of W6.2.2: production-shape commands
        // must not inject the dev sibling-flake override.
        let env = TestEnv::new();
        let flags = dev_override_flags(&env, BuildMode::Prod);
        assert!(
            flags.is_empty(),
            "Prod must produce no override; got: {flags:?}"
        );
    }

    #[test]
    fn build_mode_dev_emits_override_when_workspace_layout_present() {
        // In the workspace, dev_override_flags walks up from
        // CARGO_MANIFEST_DIR for nix/dev/flake.nix. When found, it
        // returns the override; when not, it logs a warning and
        // returns "". Either outcome is valid here — we only assert
        // that injects_dev_override is honored: if the layout is
        // present, Dev produces an override; if absent (no warning
        // sentinel to check for in this mock), the env var escape
        // hatch can force one.
        let env = TestEnv::new();
        // SAFETY: tests only; MVM_DEV_FLAKE_URL is process-global
        // but the value is harmless and we restore it.
        let prev = std::env::var("MVM_DEV_FLAKE_URL").ok();
        unsafe { std::env::set_var("MVM_DEV_FLAKE_URL", "git+file:///tmp/fake?dir=nix/dev") };
        let flags = dev_override_flags(&env, BuildMode::Dev);
        unsafe {
            match prev {
                Some(v) => std::env::set_var("MVM_DEV_FLAKE_URL", v),
                None => std::env::remove_var("MVM_DEV_FLAKE_URL"),
            }
        }
        assert!(
            flags.contains("--override-input mvm"),
            "Dev with MVM_DEV_FLAKE_URL set must produce an override; got: {flags:?}"
        );
    }

    #[test]
    fn build_mode_helper_classifies_correctly() {
        assert!(BuildMode::Dev.injects_dev_override());
        assert!(!BuildMode::Prod.injects_dev_override());
    }
}
