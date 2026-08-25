#[cfg(feature = "builder-vm")]
use std::path::Path;

use anyhow::{Context, Result};
use tracing::instrument;

use mvm_core::build_env::ShellEnvironment;

use super::BuildMode;

/// Base directory for dev build artifacts ($HOME/.mvm/dev/builds).
fn dev_builds_dir() -> String {
    format!("{}/dev/builds", mvm_core::config::mvm_home())
}

/// Result of a dev build via `nix build` in the builder VM.
#[derive(Debug, Clone)]
pub struct DevBuildResult {
    /// Directory containing artifacts: `~/.mvm/dev/builds/<hash>/`
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
    /// Path to the microvm.nix-lineage runner directory, if the build output
    /// contains runner scripts (e.g. `bin/microvm-run`). When present,
    /// the QEMU backend can use them instead of manual Firecracker
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
/// Operates directly on the host filesystem under `dev_builds_dir`
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
/// touching `HOME` / `MVM_HOME`. The public
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
    // `MVM_BUILD_STUB_OUTDIR` lets the live test suite skip the
    // Nix build entirely and treat the env-var's value as the
    // build output directory. The directory must contain
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

/// Build path that always runs Nix inside the project builder VM.
#[cfg(feature = "builder-vm")]
fn dev_build_via_builder_vm(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Result<DevBuildResult> {
    // Host-side build cache: when the resolved build inputs match a prior
    // build whose artifacts still exist, skip the builder VM + nix eval
    // entirely. The fingerprint covers every nix input (user flake +
    // workspace + profile + mode + mvmctl version), so a hit means the
    // image would be byte-identical — see `build_cache`'s soundness note.
    let fingerprint = build_cache_fingerprint(flake_ref, profile, mode);
    if let Some(fp) = fingerprint.as_deref()
        && let Some(hit) = cached_build_result(fp)
    {
        env.log_success(&format!(
            "Build cache hit — reusing {} (skipped builder VM + nix eval)",
            hit.build_dir
        ));
        return Ok(hit);
    }

    let result = dev_build_via_builder_vm_uncached(env, flake_ref, profile, mode)?;

    // Record the fingerprint → typed cache record mapping so the next
    // identical build short-circuits (and can verify what it finds rather
    // than trusting the path). Best-effort: a read-only cache dir, or an
    // artifact set the record can't describe, just means the next build
    // re-evaluates.
    if let Some(fp) = fingerprint.as_deref()
        && let Err(e) = write_cache_record_for_result(fp, &result)
    {
        tracing::debug!(error = %e, "failed to write build-cache record");
    }
    Ok(result)
}

/// Build and persist an [`mvm_core::action::ActionCacheRecord`] for a
/// freshly built `result`, keyed by the input `fingerprint`.
///
/// `rootfs.ext4` is the one universal artifact; every other candidate
/// (`vmlinux`, `initrd`, `bin/microvm-run`, `image.tar.gz`) is recorded only
/// when it actually exists in the revision dir. When `rootfs.ext4` is
/// absent, no record is written at all: an absent record reads back as a
/// cold miss, so we never serve a cache hit we cannot re-verify (fail
/// closed: never trust the path over a verified digest).
#[cfg(feature = "builder-vm")]
fn write_cache_record_for_result(fingerprint: &str, result: &DevBuildResult) -> Result<()> {
    let build_dir = Path::new(&result.build_dir);
    if !build_dir.join("rootfs.ext4").is_file() {
        return Ok(());
    }
    let mut rel_paths: Vec<&str> = vec!["rootfs.ext4"];
    if build_dir.join("vmlinux").is_file() {
        rel_paths.push("vmlinux");
    }
    if build_dir.join("initrd").is_file() {
        rel_paths.push("initrd");
    }
    if build_dir.join("bin").join("microvm-run").is_file() {
        rel_paths.push("bin/microvm-run");
    }
    if build_dir.join("image.tar.gz").is_file() {
        rel_paths.push("image.tar.gz");
    }

    let action_digest = mvm_core::action::ActionDigest::from_fingerprint_hex(fingerprint)
        .map_err(|e| anyhow::anyhow!("invalid build-cache fingerprint {fingerprint:?}: {e}"))?;
    let record = mvm_core::action::build_record(
        action_digest,
        result.revision_hash.clone(),
        build_dir,
        &rel_paths,
    )?;
    crate::pipeline::build_cache::write_cache_record(fingerprint, &record)
}

/// Compute the host-side build fingerprint for the cache, or `None` when
/// the cache is disabled (`MVM_NO_BUILD_CACHE`) or the inputs can't be
/// fingerprinted (in which case we fall through to a normal build).
#[cfg(feature = "builder-vm")]
fn build_cache_fingerprint(
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Option<String> {
    if std::env::var_os("MVM_NO_BUILD_CACHE").is_some_and(|v| !v.is_empty()) {
        return None;
    }
    let user_flake = resolve_user_flake(flake_ref);
    let mvm_workspace = local_mvm_workspace(&user_flake);
    match crate::pipeline::build_cache::workload_build_fingerprint(
        &user_flake,
        profile,
        mode,
        mvm_workspace.as_deref(),
    ) {
        Ok(fp) => Some(fp),
        Err(e) => {
            tracing::debug!(error = %e, "build-cache fingerprint unavailable; building normally");
            None
        }
    }
}

/// Reconstruct a cache-hit [`DevBuildResult`] from a recorded
/// [`mvm_core::action::ActionCacheRecord`], or `None` when there is no
/// record, it fails to parse, or verification against the artifacts
/// actually on disk fails.
///
/// A missing or unparseable record is a plain miss: there is nothing to
/// evict, since nothing was trusted. A record that parses but fails
/// on-disk verification is a miss *and* evicts the stale entry (both the
/// record and the build dir it named), so a tampered or partially-collected
/// cache entry is never served twice and a fresh build runs unconditionally.
#[cfg(feature = "builder-vm")]
fn cached_build_result(fingerprint: &str) -> Option<DevBuildResult> {
    let record = crate::pipeline::build_cache::read_cache_record(fingerprint)?;
    let build_dir = dev_build_dir(&record.revision);
    if let Err(e) = mvm_core::action::verify_artifacts_on_disk(Path::new(&build_dir), &record) {
        tracing::debug!(error = %e, "build-cache entry failed verification; evicting");
        crate::pipeline::build_cache::evict_cache_record(fingerprint);
        // The build dir must go too, not just the record: the next build's
        // `dev_build_with_builder_vm` promotes fresh artifacts into
        // `dev_build_dir(revision)` only when that path is *absent* — it
        // trusts an existing directory by revision name alone, with no hash
        // check. Leaving the poisoned dir in place would make the next
        // build discard its own freshly-built good output, re-adopt the
        // poisoned bytes because the name matched, and let
        // `write_cache_record_for_result` bless them again — one detected
        // tamper would otherwise recur forever instead of self-healing on
        // the very next build.
        let _ = std::fs::remove_dir_all(&build_dir);
        return None;
    }

    let revision_hash = record.revision;
    let rootfs_path = format!("{build_dir}/rootfs.ext4");
    let initrd_path = detect_initrd(&build_dir);
    let runner_dir = detect_runner(&build_dir);
    let artifact_sizes = measure_artifact_sizes(&build_dir, initrd_path.is_some());
    Some(DevBuildResult {
        vmlinux_path: format!("{build_dir}/vmlinux"),
        rootfs_path,
        initrd_path,
        runner_dir,
        artifact_sizes,
        revision_hash,
        cached: true,
        build_dir,
    })
}

/// Resolve a flake-ref argument to a concrete directory path (`.` →
/// current dir). Shared by the cache fingerprint and the build dispatch
/// so both reason about the same user flake.
#[cfg(feature = "builder-vm")]
fn resolve_user_flake(flake_ref: &str) -> std::path::PathBuf {
    if flake_ref == "." {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    } else {
        std::path::PathBuf::from(flake_ref)
    }
}

/// The builder-VM build dispatch (persistent supervisor when one is live,
/// else a single-shot builder VM). Split out from
/// [`dev_build_via_builder_vm`] so the host-side cache short-circuit wraps
/// it without entangling the dispatch logic.
#[cfg(feature = "builder-vm")]
fn dev_build_via_builder_vm_uncached(
    env: &dyn ShellEnvironment,
    flake_ref: &str,
    profile: Option<&str>,
    mode: BuildMode,
) -> Result<DevBuildResult> {
    // When a persistent-builder session is alive AND the user
    // hasn't opted out via `MVM_NO_PERSISTENT_BUILDER=1` AND the
    // residency policy is not `cold`, route through the persistent
    // supervisor. Cold always boots a single-shot builder that tears
    // down per build. Any dispatch error (incl. supervisor crash
    // mid-dispatch) falls back to single-shot with a warning —
    // the single-shot path is the safety net.
    let residency = mvm_core::residency::resolve_residency().0;
    if let Some(reason) = crate::persistent_builder::enforce_active_session_policy(
        &residency,
        crate::persistent_builder::current_unix_secs(),
    ) {
        tracing::info!(
            ?reason,
            "persistent builder session stopped by residency policy"
        );
    }
    if persistent_routing_allowed(&residency, persistent_dispatch_disabled())
        && let Some(record) = crate::persistent_builder::read_active_session()
    {
        tracing::info!(
            session_id = %record.session_id,
            socket = %record.dispatch_socket_path.display(),
            "routing build through persistent supervisor"
        );
        // Typed-only persistent route: a reachable mvm-builderd builds
        // `/work#<attr>` and the host reads the daemon-exported artifacts off
        // the `/job` share. No reachable daemon → `None`; a daemon build
        // failure or transport error → warn. Either falls through to the
        // single-shot builder below — the safety net. The legacy in-VM
        // shell-job dispatch was removed; typed is the only persistent path.
        match try_typed_persistent_build(env, &record, profile) {
            Some(Ok(result)) => return Ok(result),
            Some(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    "typed builder dispatch failed; falling back to single-shot builder VM"
                );
            }
            None => {}
        }
    }

    // No session was adopted above. Before falling through to a single-shot
    // builder — which will *queue* for the store image — check whether the
    // image is already held. If it is, this build cannot have it to itself,
    // and waiting serializes two builds that could have shared one warm store.
    // A session is how they share it: adopt a live one, or start one.
    //
    // Contention is the trigger, deliberately. An uncontended build takes the
    // image directly, which is cheaper than booting a session it would be the
    // only user of.
    if persistent_routing_allowed(&residency, persistent_dispatch_disabled())
        && crate::builder_vm_runtime::nix_store_image_is_contended(
            &crate::builder_vm::builder_vm_cache_dir(),
            crate::libkrun_builder::host_arch_tag(),
        )
        && let crate::persistent_builder::SessionAcquisition::Ready(record) =
            crate::persistent_builder::adopt_or_start_session()
    {
        tracing::info!(
            session_id = %record.session_id,
            "store image is busy; sharing the persistent builder that holds it"
        );
        match try_typed_persistent_build(env, &record, profile) {
            Some(Ok(result)) => return Ok(result),
            Some(Err(e)) => {
                tracing::warn!(
                    error = %e,
                    "dispatch into the shared builder failed; queueing for the store image"
                );
            }
            None => {}
        }
    }

    // The single-shot path honours the builder-backend selection
    // (`--builder` / `MVM_BUILDER_BACKEND` / auto-detect) instead of
    // hardcoding libkrun, so `mvmctl build` routes a steady-state build through
    // the chosen VMM (QEMU on `MVM_BUILDER_BACKEND=qemu`). Linux-native hosts
    // now auto-detect qemu by default; macOS 26 Apple Silicon auto-detects the
    // hvf builder; other hosts stay on libkrun.
    //
    // Auto-fallback: macOS auto-detect may retry hvf on the shared libkrun
    // builder path, but Linux auto libkrun now stays libkrun-only even on a
    // VMM-level failure. A genuine build error surfaces unchanged, and an
    // explicit `--builder`/`MVM_BUILDER_BACKEND` stays single-backend.
    use crate::builder_backend_select as bbs;
    let selected = bbs::resolve_choice();
    let explicit = bbs::resolve_env_override().is_some();
    bbs::run_with_builder_fallback_anyhow(selected, explicit, |choice| {
        let builder = bbs::try_resolve_builder_backend_with_override(Some(choice))
            .map_err(anyhow::Error::new)?;
        dev_build_with_builder_vm(env, flake_ref, profile, mode, builder.as_ref())
    })
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

/// Whether a build may route to the persistent builder: the user has not opted
/// out (`MVM_NO_PERSISTENT_BUILDER`) and the residency policy is not `cold`
/// (cold builds boot a single-shot builder that boots and tears down per build).
#[cfg(feature = "builder-vm")]
fn persistent_routing_allowed(
    policy: &mvm_core::residency::ResidencyPolicy,
    dispatch_disabled: bool,
) -> bool {
    !dispatch_disabled && policy.allows_persistent_builder()
}

/// Resolve the in-repo mvm workspace to build a user
/// flake against, or `None` to keep the flake's own `mvm` pin.
///
/// Returns the workspace root only when **both** hold:
///   (a) mvmctl was compiled from a source checkout whose `nix/flake.nix`
///       still exists on disk (walk up from the compile-time manifest dir,
///       the same source-checkout signal the CLI's `find_builder_vm_flake`
///       uses), or the user flake itself lives inside a source checkout
///       whose `nix/flake.nix` can be discovered at runtime, and
///   (b) the user flake pins `mvm` to GitHub — so `--override-input mvm`
///       has an input to replace and we're genuinely swapping a remote
///       fetch for the local checkout.
#[cfg(feature = "builder-vm")]
fn local_mvm_workspace(user_flake: &std::path::Path) -> Option<std::path::PathBuf> {
    let workspace = find_mvm_workspace_root(&std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")))
        .or_else(|| find_mvm_workspace_root(user_flake))?;
    let flake_nix = std::fs::read_to_string(user_flake.join("flake.nix")).ok()?;
    flake_nix
        .contains("github:tinylabscom/mvm")
        .then_some(workspace)
}

/// Walk up from `start` until we find a directory containing
/// `nix/flake.nix`, which marks the root of the mvm source tree.
#[cfg(feature = "builder-vm")]
fn find_mvm_workspace_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        if dir.join("nix/flake.nix").is_file() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[cfg(feature = "builder-vm")]
fn dev_build_with_builder_vm<B: crate::builder_vm::BuilderVm + ?Sized>(
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

    let user_flake = resolve_user_flake(flake_ref);

    // Source-checkout invariant: a compiled flake pins
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
    // Armed the moment the dir exists, so every early return below (the
    // builder error, the install-volume bail) cleans it up on drop. Only
    // `disarm()`ed once the artifacts have actually left `staging` behind
    // (renamed, copied-then-removed, or discarded on a cache hit).
    let mut staging_guard = StagingDirGuard::new(std::path::PathBuf::from(&staging));

    // dev_build_with_builder_vm is called for
    // user-flake builds (mvmctl build against the user's flake).
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
        // Preserve the `BuilderVmError` as a downcastable anyhow source (not a
        // stringified context) so the single-shot caller's auto-fallback can
        // detect a VMM-level failure (`run_with_builder_fallback_anyhow`).
        .map_err(|e| anyhow::Error::new(e).context("builder VM"))?;
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
        copy_staged_artifacts(&staging, &final_dir)?;
        let _ = std::fs::remove_dir_all(&staging);
        tracing::debug!(error = %e, "rename failed; fell back to copy");
    }
    // The staging dir is gone one way or another by this point (renamed
    // away, or removed above) — disarm so Drop doesn't redundantly try.
    staging_guard.disarm();

    let build_dir = final_dir;
    let vmlinux_path = format!("{build_dir}/vmlinux");
    let rootfs_path = format!("{build_dir}/rootfs.ext4");
    let initrd_path = detect_initrd(&build_dir);
    let runner_dir = detect_runner(&build_dir);
    let artifact_sizes = measure_artifact_sizes(&build_dir, initrd_path.is_some());

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

/// Attempt a guest-image build through the resident `mvm-builderd` typed
/// control plane — the only persistent build route.
///
/// Returns `None` when there is no reachable daemon, so the caller falls back to
/// the single-shot builder; `Some(Ok(_))` once the daemon built the image and
/// exported its artifacts to the `/job` share, which we read into the dev build
/// dir; `Some(Err(_))` on a daemon-reported build failure or a transport/IO
/// error (the caller logs and falls back to the single-shot builder).
///
/// Builds `/work#<attr>`.
#[cfg(feature = "builder-vm")]
fn try_typed_persistent_build(
    env: &dyn ShellEnvironment,
    record: &crate::persistent_builder::SessionRecord,
    profile: Option<&str>,
) -> Option<Result<DevBuildResult>> {
    use crate::builder_route::{BuildDispatch, BuildVerdict, try_typed_build};
    use crate::builder_vm::host_system_linux;
    use crate::libkrun_builder::GUEST_WORK_DIR;

    let system = host_system_linux();
    let attr_path = match profile {
        Some(p) if p != "default" => format!("packages.{system}.tenant-{p}"),
        _ => format!("packages.{system}.default"),
    };

    // A fresh per-build subdir under the session's `/job` share for the daemon
    // to export into: host `<job_dir>/<id>/out` is guest `/job/<id>/out`.
    let job_id = uuid::Uuid::new_v4().to_string();
    let host_out = crate::persistent_builder::artifact_dir_for(&record.job_dir, &job_id);
    if let Err(e) = std::fs::create_dir_all(&host_out) {
        return Some(Err(anyhow::anyhow!(
            "creating typed build output dir {}: {e}",
            host_out.display()
        )));
    }
    let guest_out = format!(
        "/job/{job_id}/{out}",
        out = crate::persistent_builder::ARTIFACT_SUBDIR
    );

    let vms_root = crate::builder_vm::builder_vm_cache_dir().join("vms");
    match try_typed_build(&vms_root, GUEST_WORK_DIR, &attr_path, Some(&guest_out)) {
        BuildDispatch::Fellback => None,
        BuildDispatch::Took(Ok(BuildVerdict::Built { store_path, .. })) => {
            Some(finalize_typed_persistent_build(env, &host_out, &store_path))
        }
        BuildDispatch::Took(Ok(BuildVerdict::Failed { message })) => Some(Err(anyhow::anyhow!(
            "typed builder build failed: {message}"
        ))),
        BuildDispatch::Took(Err(e)) => {
            Some(Err(anyhow::anyhow!("typed builder dispatch error: {e}")))
        }
    }
}

/// Read a typed build's exported artifacts off the `/job` share into the dev
/// build cache dir and assemble the [`DevBuildResult`]. `store_path` is the
/// daemon-reported `/nix/store/...` out-path, from which the cache revision hash
/// is derived (matching the legacy persistent path's sidecar-derived hash).
#[cfg(feature = "builder-vm")]
fn finalize_typed_persistent_build(
    env: &dyn ShellEnvironment,
    host_out: &std::path::Path,
    store_path: &str,
) -> Result<DevBuildResult> {
    let revision_hash = crate::persistent_builder::extract_nix_store_hash(store_path.trim())
        .ok_or_else(|| anyhow::anyhow!("malformed store path from typed build: {store_path:?}"))?
        .to_string();

    let final_dir = dev_build_dir(&revision_hash);
    if std::path::Path::new(&final_dir).exists() {
        env.log_info(&format!(
            "Cache hit on rev {revision_hash}; discarding typed build export."
        ));
    } else {
        std::fs::create_dir_all(&final_dir)
            .with_context(|| format!("creating final build dir {final_dir}"))?;
        let host_out_str = host_out
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-utf8 output dir {}", host_out.display()))?;
        copy_staged_artifacts(host_out_str, &final_dir)?;
    }
    // Best-effort: drop the per-build export subdir under the `/job` share.
    if let Some(job_sub) = host_out.parent() {
        let _ = std::fs::remove_dir_all(job_sub);
    }

    let build_dir = final_dir;
    let vmlinux_path = format!("{build_dir}/vmlinux");
    let rootfs_path = format!("{build_dir}/rootfs.ext4");
    let initrd_path = detect_initrd(&build_dir);
    let runner_dir = detect_runner(&build_dir);
    let artifact_sizes = measure_artifact_sizes(&build_dir, initrd_path.is_some());

    env.log_success(&format!(
        "Builder VM build complete (typed); artifacts at {build_dir}"
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

#[cfg(feature = "builder-vm")]
fn copy_staged_artifacts(staging: &str, final_dir: &str) -> Result<()> {
    for entry in
        std::fs::read_dir(staging).with_context(|| format!("reading staging dir {staging}"))?
    {
        let entry = entry?;
        let dst = std::path::Path::new(final_dir).join(entry.file_name());
        copy_staged_artifact(&entry.path(), &dst)?;
    }
    Ok(())
}

#[cfg(feature = "builder-vm")]
fn copy_staged_artifact(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    if src.file_name().is_some_and(|name| name == "rootfs.ext4") {
        return copy_sparse_file(src, dst);
    }
    std::fs::copy(src, dst)
        .map(|_| ())
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))
}

#[cfg(feature = "builder-vm")]
fn copy_sparse_file(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};

    const CHUNK_SIZE: usize = 1024 * 1024;

    let mut input = std::fs::File::open(src)
        .with_context(|| format!("opening sparse source {}", src.display()))?;
    let metadata = input
        .metadata()
        .with_context(|| format!("stat sparse source {}", src.display()))?;
    let mut output = std::fs::File::create(dst)
        .with_context(|| format!("creating sparse destination {}", dst.display()))?;
    output
        .set_len(metadata.len())
        .with_context(|| format!("sizing sparse destination {}", dst.display()))?;

    let mut buf = vec![0_u8; CHUNK_SIZE];
    loop {
        let read = input
            .read(&mut buf)
            .with_context(|| format!("reading sparse source {}", src.display()))?;
        if read == 0 {
            break;
        }
        if buf[..read].iter().all(|byte| *byte == 0) {
            output
                .seek(SeekFrom::Current(read as i64))
                .with_context(|| format!("seeking sparse destination {}", dst.display()))?;
        } else {
            output
                .write_all(&buf[..read])
                .with_context(|| format!("writing sparse destination {}", dst.display()))?;
        }
    }
    Ok(())
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

/// Removes a staging directory on drop unless [`Self::disarm`] was called
/// first.
///
/// `dev_build_with_builder_vm` used to leak `.staging-*` dirs under
/// `dev_builds_dir()` on a mid-build failure: the cleanup was only reached
/// on the success path, so a builder error or an unexpected artifact shape
/// (`InstallVolume` for a flake build) returned early and left the staged
/// files behind forever. Tying removal to `Drop` makes every exit path —
/// present and future — clean up structurally instead of needing a matching
/// `remove_dir_all` at each `return`/`?`/`bail!`.
#[cfg(feature = "builder-vm")]
struct StagingDirGuard {
    path: std::path::PathBuf,
    armed: bool,
}

#[cfg(feature = "builder-vm")]
impl StagingDirGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path, armed: true }
    }

    /// Call once the staging dir has already been consumed (renamed away)
    /// or removed, so `Drop` doesn't attempt a redundant no-op removal.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "builder-vm")]
impl Drop for StagingDirGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// Measure artifact file sizes in the build directory.
///
/// `build_dir` is always a host path (the dev-build cache dir the build
/// just wrote), so this reads it directly rather than shelling through
/// whichever `ShellEnvironment` happens to be active — on macOS 26+ that
/// environment dials a VM that has no view of the host filesystem.
#[cfg(any(test, feature = "builder-vm"))]
fn measure_artifact_sizes(build_dir: &str, has_initrd: bool) -> mvm_core::pool::ArtifactSizes {
    let file_size = |path: &str| std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

    let vmlinux_bytes = file_size(&format!("{}/vmlinux", build_dir));
    let rootfs_bytes = file_size(&format!("{}/rootfs.ext4", build_dir));
    let initrd_bytes = if has_initrd {
        Some(file_size(&format!("{}/initrd", build_dir)))
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

/// Check whether an initrd exists in the build directory (a host path).
#[cfg(any(test, feature = "builder-vm"))]
fn detect_initrd(build_dir: &str) -> Option<String> {
    let path = format!("{}/initrd", build_dir);
    std::path::Path::new(&path).exists().then_some(path)
}

/// Check whether a microvm.nix runner script exists in the build directory
/// (a host path).
///
/// The root flake's `mkGuest` copies the runner to `$out/bin/microvm-run`
/// when the microvm.nix runner is available. If found, returns the runner
/// directory path (parent of `bin/`).
#[cfg(any(test, feature = "builder-vm"))]
fn detect_runner(build_dir: &str) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;

    let runner_path = format!("{}/bin/microvm-run", build_dir);
    let is_executable = std::fs::metadata(&runner_path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    is_executable.then(|| build_dir.to_string())
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
    #[test]
    fn finalize_typed_build_derives_hash_and_copies_exported_artifacts() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut process_env = mvm_core::util::test_env::TestEnv::new();
        process_env.set("MVM_HOME", temp.path().join("mvm-home"));

        // Stand in for the daemon's export onto the `/job` share:
        // `<job_dir>/<id>/out/{vmlinux,rootfs.ext4}`.
        let host_out = temp.path().join("job").join("build-1").join("out");
        std::fs::create_dir_all(&host_out).unwrap();
        std::fs::write(host_out.join("vmlinux"), b"kernel").unwrap();
        std::fs::write(host_out.join("rootfs.ext4"), b"rootfs").unwrap();

        let env = TestEnv::new();
        let store_path = "/nix/store/abc123hash-mvm-guest-image";
        let result = finalize_typed_persistent_build(&env, &host_out, store_path).unwrap();

        // Revision hash is the store-path leading hash; artifacts land in the
        // dev build cache dir keyed by it.
        assert_eq!(result.revision_hash, "abc123hash");
        assert_eq!(result.build_dir, dev_build_dir("abc123hash"));
        assert_eq!(std::fs::read(&result.vmlinux_path).unwrap(), b"kernel");
        assert_eq!(std::fs::read(&result.rootfs_path).unwrap(), b"rootfs");
        assert!(!result.cached);
        // The per-build `/job` export subdir is cleaned up.
        assert!(!host_out.exists());
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn finalize_typed_build_rejects_a_malformed_store_path() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut process_env = mvm_core::util::test_env::TestEnv::new();
        process_env.set("MVM_HOME", temp.path().join("mvm-home"));
        let host_out = temp.path().join("job").join("build-2").join("out");
        std::fs::create_dir_all(&host_out).unwrap();
        let env = TestEnv::new();
        assert!(finalize_typed_persistent_build(&env, &host_out, "not-a-store-path").is_err());
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

    #[cfg(all(feature = "builder-vm", unix))]
    #[test]
    fn fallback_copy_preserves_sparse_rootfs_artifact() {
        use std::io::{Read, Seek, SeekFrom, Write};
        #[cfg(target_os = "linux")]
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().expect("create temp dir");
        let src = temp.path().join("rootfs.ext4");
        let dst = temp.path().join("copied-rootfs.ext4");
        let mut file = std::fs::File::create(&src).expect("create sparse source");
        file.set_len(16 * 1024 * 1024).expect("size sparse source");
        file.seek(SeekFrom::Start(15 * 1024 * 1024))
            .expect("seek near sparse source end");
        file.write_all(b"tail").expect("write sparse source tail");
        drop(file);

        copy_staged_artifact(&src, &dst).expect("copy sparse rootfs");

        let src_meta = std::fs::metadata(&src).expect("stat source");
        let dst_meta = std::fs::metadata(&dst).expect("stat destination");
        assert_eq!(dst_meta.len(), src_meta.len());
        #[cfg(target_os = "linux")]
        assert!(
            dst_meta.blocks() < dst_meta.len() / 512,
            "destination should stay sparse: len={}, blocks={}",
            dst_meta.len(),
            dst_meta.blocks()
        );

        let mut tail = [0_u8; 4];
        let mut copied = std::fs::File::open(&dst).expect("open copied rootfs");
        copied
            .seek(SeekFrom::Start(15 * 1024 * 1024))
            .expect("seek copied tail");
        copied.read_exact(&mut tail).expect("read copied tail");
        assert_eq!(&tail, b"tail");
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn builder_vm_dev_build_uses_vm_job_shape_without_host_nix() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut process_env = mvm_core::util::test_env::TestEnv::new();
        process_env.set("MVM_HOME", temp.path().join("mvm-home"));
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
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut process_env = mvm_core::util::test_env::TestEnv::new();
        process_env.set("MVM_HOME", temp.path().join("mvm-home"));
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

        // The regression this guards: a builder error used to return before
        // the staging dir (created just before `run_build` is invoked) was
        // ever cleaned up, leaking a `.staging-*` dir under the builds dir
        // on every failed build.
        let leaked_staging = std::fs::read_dir(dev_builds_dir())
            .map(|entries| {
                entries
                    .flatten()
                    .any(|entry| entry.file_name().to_string_lossy().starts_with(".staging-"))
            })
            .unwrap_or(false);
        assert!(
            !leaked_staging,
            "a builder failure must not leave a .staging-* dir behind"
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn staging_dir_guard_removes_dir_on_drop_without_disarm() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join("staging-guard-armed");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        {
            let _guard = StagingDirGuard::new(staging.clone());
            assert!(staging.exists());
        }
        assert!(
            !staging.exists(),
            "an armed guard must remove the dir on drop"
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn staging_dir_guard_leaves_dir_when_disarmed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let staging = tmp.path().join("staging-guard-disarmed");
        std::fs::create_dir_all(&staging).expect("create staging dir");
        {
            let mut guard = StagingDirGuard::new(staging.clone());
            guard.disarm();
        }
        assert!(
            staging.exists(),
            "a disarmed guard must leave the dir alone on drop"
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn cache_hit_verifies_and_serves() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut env_guard = mvm_core::util::test_env::TestEnv::new();
        env_guard.isolate_mvm_home(temp.path());

        let fingerprint = "a".repeat(64);
        let revision = "rev-cache-hit";
        let build_dir_path = std::path::PathBuf::from(dev_build_dir(revision));
        std::fs::create_dir_all(&build_dir_path).expect("create revision dir");
        std::fs::write(build_dir_path.join("rootfs.ext4"), b"rootfs contents")
            .expect("write rootfs.ext4");

        let action_digest = mvm_core::action::ActionDigest::from_fingerprint_hex(&fingerprint)
            .expect("valid fingerprint");
        let record = mvm_core::action::build_record(
            action_digest,
            revision.to_string(),
            &build_dir_path,
            &["rootfs.ext4"],
        )
        .expect("build_record over real artifacts");
        crate::pipeline::build_cache::write_cache_record(&fingerprint, &record)
            .expect("write cache record");

        let result = cached_build_result(&fingerprint).expect("verified cache entry should hit");
        assert!(result.cached);
        assert_eq!(result.revision_hash, revision);
        assert_eq!(result.build_dir, build_dir_path.to_str().unwrap());
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn tampered_cache_entry_is_evicted() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut env_guard = mvm_core::util::test_env::TestEnv::new();
        env_guard.isolate_mvm_home(temp.path());

        let fingerprint = "b".repeat(64);
        let revision = "rev-tampered";
        let build_dir_path = std::path::PathBuf::from(dev_build_dir(revision));
        std::fs::create_dir_all(&build_dir_path).expect("create revision dir");
        std::fs::write(build_dir_path.join("rootfs.ext4"), b"original bytes")
            .expect("write rootfs.ext4");

        let action_digest = mvm_core::action::ActionDigest::from_fingerprint_hex(&fingerprint)
            .expect("valid fingerprint");
        let record = mvm_core::action::build_record(
            action_digest,
            revision.to_string(),
            &build_dir_path,
            &["rootfs.ext4"],
        )
        .expect("build_record over real artifacts");
        crate::pipeline::build_cache::write_cache_record(&fingerprint, &record)
            .expect("write cache record");

        // Flip a byte after the record was written — the recorded digest no
        // longer matches what's on disk.
        let mut bytes = std::fs::read(build_dir_path.join("rootfs.ext4")).expect("read rootfs");
        bytes[0] ^= 0xFF;
        std::fs::write(build_dir_path.join("rootfs.ext4"), bytes).expect("rewrite rootfs");

        let cache_dir = crate::pipeline::build_cache::build_cache_dir();
        assert!(
            cache_dir.join(&fingerprint).exists(),
            "sanity: the record file must exist before eviction"
        );
        assert!(
            build_dir_path.exists(),
            "sanity: the poisoned build dir must exist before eviction"
        );

        assert!(
            cached_build_result(&fingerprint).is_none(),
            "a tampered artifact must never be served"
        );
        assert!(
            !cache_dir.join(&fingerprint).exists(),
            "a failed verification must delete the stale record file, not merely refuse it"
        );
        assert!(
            crate::pipeline::build_cache::read_cache_record(&fingerprint).is_none(),
            "a failed verification must evict the stale record, not merely refuse it"
        );
        // The build dir must be gone too, not just the record: the next
        // `dev_build_with_builder_vm` run promotes fresh artifacts into
        // `dev_build_dir(revision)` only when that path doesn't already
        // exist (it trusts an existing dir by revision name, no hash
        // check). If eviction only deleted the record, the poisoned dir
        // would survive and get silently re-adopted (and re-blessed with a
        // fresh record) on the very next build.
        assert!(
            !build_dir_path.exists(),
            "eviction must remove the poisoned build dir so a rebuild can't re-adopt it by name"
        );
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn missing_record_is_cold_miss() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut env_guard = mvm_core::util::test_env::TestEnv::new();
        env_guard.isolate_mvm_home(temp.path());

        let fingerprint = "c".repeat(64);
        let revision = "rev-no-record";
        let build_dir_path = std::path::PathBuf::from(dev_build_dir(revision));
        std::fs::create_dir_all(&build_dir_path).expect("create revision dir");
        std::fs::write(build_dir_path.join("rootfs.ext4"), b"bytes").expect("write rootfs.ext4");
        // Deliberately no cache record written for `fingerprint`.

        assert!(cached_build_result(&fingerprint).is_none());
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn legacy_plaintext_record_is_cold_miss() {
        let temp = tempfile::tempdir().expect("create temp MVM_HOME");
        let mut env_guard = mvm_core::util::test_env::TestEnv::new();
        env_guard.isolate_mvm_home(temp.path());

        let fingerprint = "d".repeat(64);
        let revision = "rev-legacy";
        let build_dir_path = std::path::PathBuf::from(dev_build_dir(revision));
        std::fs::create_dir_all(&build_dir_path).expect("create revision dir");
        std::fs::write(build_dir_path.join("rootfs.ext4"), b"bytes").expect("write rootfs.ext4");

        // Pre-typed-record cache entries were a bare `<revision>\n` marker.
        let cache_dir = crate::pipeline::build_cache::build_cache_dir();
        std::fs::create_dir_all(&cache_dir).expect("create build-cache dir");
        std::fs::write(cache_dir.join(&fingerprint), format!("{revision}\n"))
            .expect("write legacy record");

        assert!(cached_build_result(&fingerprint).is_none());
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
    fn test_measure_artifact_sizes() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("vmlinux"), vec![0u8; 1234]).unwrap();
        std::fs::write(tmp.path().join("rootfs.ext4"), vec![0u8; 5678]).unwrap();

        let sizes = measure_artifact_sizes(tmp.path().to_str().unwrap(), false);
        assert_eq!(sizes.vmlinux_bytes, 1234);
        assert_eq!(sizes.rootfs_bytes, 5678);
        assert!(sizes.initrd_bytes.is_none());
        assert!(sizes.nix_closure_bytes.is_none());
    }

    #[test]
    fn test_measure_artifact_sizes_with_initrd() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("vmlinux"), vec![0u8; 1234]).unwrap();
        std::fs::write(tmp.path().join("rootfs.ext4"), vec![0u8; 5678]).unwrap();
        std::fs::write(tmp.path().join("initrd"), vec![0u8; 42]).unwrap();

        let sizes = measure_artifact_sizes(tmp.path().to_str().unwrap(), true);
        assert_eq!(sizes.vmlinux_bytes, 1234);
        assert_eq!(sizes.rootfs_bytes, 5678);
        assert_eq!(sizes.initrd_bytes, Some(42));
    }

    #[test]
    fn test_measure_artifact_sizes_missing_files_are_zero() {
        // A build_dir that exists but hasn't been populated yet (or a
        // probe racing the copy step) must fail closed to zero, not
        // panic or silently skip the field.
        let tmp = tempfile::tempdir().unwrap();

        let sizes = measure_artifact_sizes(tmp.path().to_str().unwrap(), true);
        assert_eq!(sizes.vmlinux_bytes, 0);
        assert_eq!(sizes.rootfs_bytes, 0);
        assert_eq!(sizes.initrd_bytes, Some(0));
    }

    #[test]
    fn test_detect_initrd_finds_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("initrd"), b"stage-1").unwrap();

        let build_dir = tmp.path().to_str().unwrap();
        assert_eq!(
            detect_initrd(build_dir),
            Some(format!("{build_dir}/initrd"))
        );
    }

    #[test]
    fn test_detect_initrd_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(detect_initrd(tmp.path().to_str().unwrap()), None);
    }

    #[test]
    fn test_detect_runner_finds_executable_script() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let runner = bin_dir.join("microvm-run");
        std::fs::write(&runner, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&runner, std::fs::Permissions::from_mode(0o755)).unwrap();

        let build_dir = tmp.path().to_str().unwrap();
        assert_eq!(detect_runner(build_dir), Some(build_dir.to_string()));
    }

    #[test]
    fn test_detect_runner_returns_none_when_not_executable() {
        let tmp = tempfile::tempdir().unwrap();
        let bin_dir = tmp.path().join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        // std::fs::write's default mode (0o644) carries no execute bit.
        std::fs::write(bin_dir.join("microvm-run"), b"#!/bin/sh\nexit 0\n").unwrap();

        assert_eq!(detect_runner(tmp.path().to_str().unwrap()), None);
    }

    #[test]
    fn test_detect_runner_returns_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(detect_runner(tmp.path().to_str().unwrap()), None);
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

        let sidecar = crate::builder_vm::GuestSidecar::read_from_dir(tmp.path())
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

        let sidecar = crate::builder_vm::GuestSidecar::read_from_dir(tmp.path()).expect("read");
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

        let sidecar = crate::builder_vm::GuestSidecar::read_from_dir(tmp.path()).expect("read");
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

        let sidecar = crate::builder_vm::GuestSidecar::read_from_dir(tmp.path())
            .expect("read")
            .expect("present");
        assert!(!sidecar.accessible, "sealed fixture round-tripped");
    }

    #[test]
    fn build_mode_helper_classifies_correctly() {
        assert!(BuildMode::Dev.injects_dev_override());
        assert!(!BuildMode::Prod.injects_dev_override());
    }

    #[cfg(feature = "builder-vm")]
    #[test]
    fn persistent_routing_blocked_by_cold_or_opt_out() {
        use mvm_core::residency::ResidencyPolicy;
        // warm/parked + not opted out → allowed
        assert!(persistent_routing_allowed(
            &ResidencyPolicy::always_warm(),
            false
        ));
        assert!(persistent_routing_allowed(
            &ResidencyPolicy::parked(),
            false
        ));
        // cold → blocked even when not opted out
        assert!(!persistent_routing_allowed(&ResidencyPolicy::cold(), false));
        // explicit opt-out always blocks
        assert!(!persistent_routing_allowed(
            &ResidencyPolicy::always_warm(),
            true
        ));
    }
}
