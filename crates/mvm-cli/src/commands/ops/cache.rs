//! `mvmctl cache` subcommand handlers.

use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand};

use crate::ui;
use mvm_core::user_config::MvmConfig;

use super::Cli;
use super::shared::{human_age_secs, human_bytes};

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: CacheAction,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum CacheAction {
    /// Remove stale items from the cache directory
    Prune {
        /// Print what would be removed without actually removing anything
        #[arg(long)]
        dry_run: bool,
        /// Also sweep orphaned project builds — built artifacts whose
        /// source `mvm.toml` file is gone from disk. Equivalent to
        /// running `mvmctl manifest prune --orphans`; bundled here so
        /// "clean everything" is one command. ("Builds" is the user-
        /// facing noun for what `mvmctl build` produces; internally
        /// these are slot directories under `~/.mvm/templates/`.)
        #[arg(long)]
        orphan_builds: bool,
        /// Also reap orphaned per-VM helpers — `mvm-libkrun-supervisor`,
        /// `gvproxy`, and console-tail processes that were reparented
        /// to launchd when the parent `mvmctl` was killed mid-run, plus
        /// their `~/.cache/mvm/builder-vm/vms/<id>/` cache directories.
        /// Plan 95 §FU-1. Skips dirs whose PIDs are still children of a
        /// live `mvmctl` (those are in-flight `dev up` runs, not orphans).
        #[arg(long)]
        reap_orphans: bool,
    },
    /// Show cache directory path and disk usage
    Info,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let cache_dir = mvm_core::config::mvm_cache_dir();

    match args.action {
        CacheAction::Info => {
            println!("Cache directory: {cache_dir}");
            let path = std::path::Path::new(&cache_dir);
            if !path.exists() {
                println!("(not yet created)");
                return Ok(());
            }
            println!("Disk usage: {}", human_bytes(dir_size(path)));
            // Plan 93 Phase 3: surface vendored-blob ages, the
            // cross-target builder-VM cache size, assembled rootfs ages,
            // and the last Stage 0 source fingerprint.
            let stage0_dir = mvm_build::stage0::stage0_cache_dir();
            let blob_filenames: Vec<&str> = mvm_build::stage0::assets_for_host_arch()
                .iter()
                .map(|a| a.cache_filename)
                .collect();
            for line in stage0_cache_report(path, &stage0_dir, &blob_filenames) {
                println!("{line}");
            }
            Ok(())
        }
        CacheAction::Prune {
            dry_run,
            orphan_builds,
            reap_orphans,
        } => {
            // Plan 95 §FU-1 — reap orphaned per-VM helpers. Done first
            // so subsequent steps see a clean process list and so the
            // sweeper can drop the per-VM cache dirs along with the
            // helpers that were holding their sockets/PIDs.
            if reap_orphans {
                match super::super::env::apple_container::reap_orphaned_vm_helpers(dry_run) {
                    Ok(o) => {
                        if o.killed == 0 && o.removed_dirs == 0 {
                            ui::info("No orphaned VM helpers.");
                        } else if dry_run {
                            ui::info(&format!(
                                "(dry-run) Would reap {} orphaned helper PID(s) and {} cache dir(s) ({}).",
                                o.killed,
                                o.removed_dirs,
                                human_bytes(o.freed_bytes)
                            ));
                        } else {
                            ui::success(&format!(
                                "Reaped {} orphaned helper PID(s) and {} cache dir(s), freed {}.",
                                o.killed,
                                o.removed_dirs,
                                human_bytes(o.freed_bytes)
                            ));
                        }
                    }
                    Err(e) => {
                        ui::warn(&format!("Orphan-helper reap failed: {e:#}"));
                    }
                }
            }

            // Optionally sweep orphaned builds first. Same logic as
            // `mvmctl manifest prune --orphans` — bundled here so the
            // user can do a single clean-everything pass without
            // remembering both verbs.
            if orphan_builds {
                if dry_run {
                    ui::info(
                        "(dry-run) Would scan for orphaned builds — see `mvmctl manifest prune --orphans --dry-run` for details.",
                    );
                } else {
                    match mvm::vm::template::lifecycle::template_prune_orphan_slots() {
                        Ok((count, _)) => {
                            mvm_core::audit_emit!(SlotPrune, "source=cache_prune count={count}");
                            if count > 0 {
                                ui::success(&format!("Pruned {count} orphaned build(s)."));
                            } else {
                                ui::info("No orphaned builds.");
                            }
                        }
                        Err(e) => {
                            ui::warn(&format!("Orphan-build prune failed: {e}"));
                        }
                    }
                }
            }

            let path = std::path::Path::new(&cache_dir);
            if !path.exists() {
                ui::info("Cache directory does not exist. Nothing to prune.");
                if !dry_run {
                    mvm_core::audit_emit!(CachePrune, "removed=0 freed_bytes=0 cache_dir=missing");
                }
                return Ok(());
            }

            // Prune: remove empty subdirectories and temp files
            let mut removed = 0u64;
            let mut freed = 0u64;

            // Plan 77 W2: sweep orphaned Stage 0 staging dirs first.
            // They live under `~/.cache/mvm/builder-vm/.<arch>.stage0-*`
            // (or the legacy `<arch>-staging` shape) and are left
            // behind by crashed `mvmctl dev up` invocations. The sweep
            // takes the Stage 0 advisory lock to avoid racing a live
            // bootstrap; if the lock is held it skips silently and we
            // proceed with the temp-file sweep.
            match super::super::env::apple_container::sweep_orphaned_stage0_staging_dirs(dry_run) {
                Ok(super::super::env::apple_container::Stage0SweepOutcome::Swept {
                    removed: r,
                    freed_bytes,
                }) => {
                    removed += r;
                    freed += freed_bytes;
                }
                Ok(super::super::env::apple_container::Stage0SweepOutcome::SkippedLockHeld) => {
                    ui::info(
                        "Stage 0 builder VM bootstrap appears to be running on this host; \
                         skipping orphan staging cleanup.",
                    );
                }
                Err(e) => {
                    ui::warn(&format!("Stage 0 staging sweep failed: {e:#}"));
                }
            }

            // Plan 141 — flow-byte-log retention sweep. Per-tenant subdirs
            // under `<audit>/flow-bytes/` hold opt-in payload records;
            // remove files older than the default window. No tenant policy
            // is in scope at prune time, so use the conservative default.
            const FLOW_BYTE_LOG_MAX_AGE_DAYS: u32 = 7;
            let flow_bytes_dir = mvm_core::config::mvm_audit_dir().join("flow-bytes");
            if dry_run {
                if flow_bytes_dir.exists() {
                    ui::info("(dry-run) Would sweep expired flow-byte-log records.");
                }
            } else {
                match mvm_hostd::supervisor::network::flow_byte_log::sweep_retention(
                    &flow_bytes_dir,
                    FLOW_BYTE_LOG_MAX_AGE_DAYS,
                ) {
                    Ok(n) => removed += n,
                    Err(e) => ui::warn(&format!("flow-byte-log sweep failed: {e}")),
                }
            }

            for entry in walkdir(path)? {
                let entry_path = entry.path();
                // Remove temp files (mvm-lima-*, .tmp)
                if let Some(name) = entry_path.file_name().and_then(|n| n.to_str())
                    && (name.starts_with("mvm-lima-") || name.ends_with(".tmp"))
                {
                    let size = entry_path.metadata().map(|m| m.len()).unwrap_or(0);
                    if dry_run {
                        println!(
                            "Would remove: {} ({})",
                            entry_path.display(),
                            human_bytes(size)
                        );
                    } else if entry_path.is_dir() {
                        let _ = std::fs::remove_dir_all(entry_path);
                    } else {
                        let _ = std::fs::remove_file(entry_path);
                    }
                    removed += 1;
                    freed += size;
                }
            }

            if removed == 0 {
                ui::info("Nothing to prune.");
            } else if dry_run {
                ui::info(&format!(
                    "Would remove {} items, freeing {}",
                    removed,
                    human_bytes(freed)
                ));
            } else {
                ui::success(&format!(
                    "Pruned {} items, freed {}",
                    removed,
                    human_bytes(freed)
                ));
            }
            // Plan 37 §6: every state-changing CLI verb emits one
            // audit record. We only mutate disk on the non-dry-run
            // path; dry-run reads only and stays out of the log.
            if !dry_run {
                mvm_core::audit_emit!(CachePrune, "removed={removed} freed_bytes={freed}");
            }
            Ok(())
        }
    }
}

/// Whole-second age of a file from its mtime, or `None` if it can't be
/// stat'd / is in the future.
fn file_age_secs(path: &std::path::Path) -> Option<u64> {
    let modified = std::fs::metadata(path).ok()?.modified().ok()?;
    std::time::SystemTime::now()
        .duration_since(modified)
        .ok()
        .map(|d| d.as_secs())
}

/// Build the Plan 93 Phase 3 `cache info` enrichment lines: vendored
/// Stage 0 blob ages, the builder-VM cross-target cache size, per-arch
/// assembled rootfs ages, and the last Stage 0 source-fingerprint
/// prefix. Path-injectable + side-effect-free (only stats + reads the
/// fingerprint sidecar) so it's hermetically testable; never hashes the
/// multi-GB rootfs (mtime + the cheap sidecar only).
fn stage0_cache_report(
    cache_root: &std::path::Path,
    stage0_dir: &std::path::Path,
    blob_filenames: &[&str],
) -> Vec<String> {
    let mut lines = Vec::new();

    if !blob_filenames.is_empty() {
        lines.push("Vendored blobs (Stage 0):".to_string());
        for fname in blob_filenames {
            let p = stage0_dir.join(fname);
            match std::fs::metadata(&p) {
                Ok(m) => {
                    let age = file_age_secs(&p)
                        .map(human_age_secs)
                        .unwrap_or_else(|| "?".to_string());
                    lines.push(format!("  {fname}: {age} old ({})", human_bytes(m.len())));
                }
                Err(_) => lines.push(format!("  {fname}: (absent)")),
            }
        }
    }

    let builder = cache_root.join("builder-vm");
    if builder.is_dir() {
        lines.push(format!(
            "Builder VM cache: {} ({} on disk)",
            builder.display(),
            human_bytes(dir_size(&builder))
        ));
        // Persistent Nix store images are SPARSE — a large logical cap
        // (DEFAULT_NIX_STORE_MIB, 64 GiB) over a small real footprint,
        // GC'd in-VM when allocated blocks cross 20 GiB. Surface both so
        // the cap never reads as real disk usage.
        if let Ok(entries) = std::fs::read_dir(&builder) {
            let mut imgs: Vec<std::path::PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.is_file()
                        && p.file_name()
                            .map(|n| {
                                let n = n.to_string_lossy();
                                n.starts_with("nix-store-") && n.ends_with(".img")
                            })
                            .unwrap_or(false)
                })
                .collect();
            imgs.sort();
            for p in imgs {
                if let Ok(m) = std::fs::metadata(&p) {
                    let name = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    lines.push(format!(
                        "  {name}: {} on disk / {} cap (sparse)",
                        human_bytes(file_allocated_bytes(&m)),
                        human_bytes(m.len())
                    ));
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(&builder) {
            // Per-arch artifact dirs only — skip `vms/` (per-VM scratch)
            // and dotfiles. Sorted for stable output.
            let mut arch_dirs: Vec<std::path::PathBuf> = entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.is_dir())
                .filter(|p| {
                    let n = p
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    n != "vms" && !n.starts_with('.')
                })
                .collect();
            arch_dirs.sort();
            for p in arch_dirs {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let rootfs = p.join("rootfs.ext4");
                if let Ok(m) = std::fs::metadata(&rootfs) {
                    let age = file_age_secs(&rootfs)
                        .map(human_age_secs)
                        .unwrap_or_else(|| "?".to_string());
                    lines.push(format!(
                        "  {name}/rootfs.ext4: {age} old ({} on disk)",
                        human_bytes(file_allocated_bytes(&m))
                    ));
                }
                if let Ok(s) = std::fs::read_to_string(p.join(".mvm-source.sha256")) {
                    let prefix: String = s.trim().chars().take(8).collect();
                    lines.push(format!("  {name}/ last Stage 0 fingerprint: {prefix}"));
                }
            }
        }
    }

    lines
}

/// Real on-disk footprint of a file (allocated blocks), not its
/// apparent length. The builder VM's persistent `nix-store-<arch>.img`
/// is SPARSE: it advertises a large logical cap (`DEFAULT_NIX_STORE_MIB`,
/// 64 GiB) but consumes only the blocks actually written. `len()` would
/// report that cap as if it were real disk — which is exactly what makes
/// an `ls -l` look alarming. Block count × 512 is the truth `du` shows.
#[cfg(unix)]
fn file_allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    meta.blocks().saturating_mul(512)
}
#[cfg(not(unix))]
fn file_allocated_bytes(meta: &std::fs::Metadata) -> u64 {
    meta.len()
}

/// Recursively calculate directory size in bytes — by *allocated* blocks,
/// so sparse images count their real footprint, not their logical cap.
fn dir_size(path: &std::path::Path) -> u64 {
    walkdir(path)
        .unwrap_or_default()
        .iter()
        .filter(|e| e.path().is_file())
        .map(|e| {
            e.path()
                .metadata()
                .map(|m| file_allocated_bytes(&m))
                .unwrap_or(0)
        })
        .sum()
}

/// Simple recursive directory walker.
fn walkdir(path: &std::path::Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let epath = entry.path();
            let is_dir = epath.is_dir();
            entries.push(entry);
            if is_dir && let Ok(sub) = walkdir(&epath) {
                entries.extend(sub);
            }
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_byte_log_sweep_targets_audit_flow_bytes_dir() {
        // The cache-prune wiring sweeps `<audit>/flow-bytes/`; assert that
        // path contract (the supervisor writer must agree) and that the
        // sweep helper removes an aged record while keeping a fresh one.
        let dir = mvm_core::config::mvm_audit_dir().join("flow-bytes");
        assert!(dir.ends_with("audit/flow-bytes"));

        let root = tempfile::tempdir().unwrap();
        let tenant = root.path().join("acme");
        std::fs::create_dir_all(&tenant).unwrap();
        std::fs::write(tenant.join("vm.bin"), b"x").unwrap();
        // age = 0 (cutoff = now) removes the just-written file; large window keeps it.
        let removed =
            mvm_hostd::supervisor::network::flow_byte_log::sweep_retention(root.path(), 0).unwrap();
        assert_eq!(removed, 1);
        std::fs::write(tenant.join("vm.bin"), b"x").unwrap();
        let kept =
            mvm_hostd::supervisor::network::flow_byte_log::sweep_retention(root.path(), 3650)
                .unwrap();
        assert_eq!(kept, 0);
    }

    #[test]
    fn stage0_cache_report_surfaces_blobs_and_builder_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Vendored Stage 0 blob present (one) + one we ask about that's absent.
        let stage0 = root.join("stage0");
        std::fs::create_dir_all(&stage0).unwrap();
        std::fs::write(stage0.join("alpine-minirootfs-aarch64.tar.gz"), b"hello").unwrap();

        // builder-vm/<arch>/ with an assembled rootfs + fingerprint sidecar.
        let arch = root.join("builder-vm").join("aarch64");
        std::fs::create_dir_all(&arch).unwrap();
        std::fs::write(arch.join("rootfs.ext4"), b"rootfsdata").unwrap();
        std::fs::write(arch.join(".mvm-source.sha256"), "abcd1234deadbeef\n").unwrap();
        // A per-VM scratch dir that must be skipped.
        std::fs::create_dir_all(root.join("builder-vm").join("vms").join("v1")).unwrap();

        let blobs = ["alpine-minirootfs-aarch64.tar.gz", "missing-blob.tar.gz"];
        let joined = stage0_cache_report(root, &stage0, &blobs).join("\n");

        assert!(joined.contains("alpine-minirootfs-aarch64.tar.gz: "));
        assert!(joined.contains("missing-blob.tar.gz: (absent)"));
        assert!(joined.contains("aarch64/rootfs.ext4: "));
        assert!(joined.contains("last Stage 0 fingerprint: abcd1234"));
        // The full 16-char sidecar is truncated to 8.
        assert!(!joined.contains("abcd1234deadbeef"));
        // `vms/` is not reported as an arch dir.
        assert!(!joined.contains("vms/rootfs.ext4"));
    }

    #[test]
    #[cfg(unix)]
    fn stage0_cache_report_shows_sparse_nix_store_real_footprint() {
        use std::os::unix::fs::MetadataExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let builder = root.join("builder-vm");
        std::fs::create_dir_all(&builder).unwrap();

        // Sparse image: 64 GiB apparent cap, but only a few bytes written
        // (one block allocated). set_len creates a hole, not real blocks.
        let img = builder.join("nix-store-aarch64.img");
        let f = std::fs::File::create(&img).unwrap();
        f.set_len(64 * 1024 * 1024 * 1024).unwrap();
        drop(f);

        let m = std::fs::metadata(&img).unwrap();
        let allocated = m.blocks().saturating_mul(512);
        assert!(
            allocated < m.len(),
            "fixture must be sparse: allocated {allocated} should be << apparent {}",
            m.len()
        );

        let joined = stage0_cache_report(root, &root.join("stage0"), &[]).join("\n");
        assert!(
            joined.contains("nix-store-aarch64.img:") && joined.contains("cap (sparse)"),
            "report must surface the sparse nix-store image: {joined}"
        );
        // The 64 GiB apparent cap must NOT be what the dir-size line reports.
        assert!(
            !joined.contains("Builder VM cache:") || !joined.contains("64.0 GB"),
            "builder cache disk usage must reflect allocated blocks, not the cap: {joined}"
        );
    }

    #[test]
    fn stage0_cache_report_empty_when_nothing_present() {
        let tmp = tempfile::tempdir().unwrap();
        // No stage0 dir, no builder-vm dir, no blobs.
        let lines = stage0_cache_report(tmp.path(), &tmp.path().join("stage0"), &[]);
        assert!(lines.is_empty());
    }
}
