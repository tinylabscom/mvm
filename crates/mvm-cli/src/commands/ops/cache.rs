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
        /// Skip reaping orphaned per-VM helpers. By default `prune` reaps
        /// `mvm-libkrun-supervisor` / legacy gateway / console-tail processes that
        /// were reparented to launchd when their parent `mvmctl` was killed
        /// mid-run, plus their `~/.mvm/cache/builder-vm/vms/<id>/` cache
        /// directories — so dead microVMs don't accumulate. The sweep is
        /// liveness-aware: a running VM (a detached `up -d`, the persistent dev
        /// builder, any in-flight builder VM bootstrap) is spared; only already-dead
        /// helpers are reaped. Pass this to prune disk only, touching no
        /// processes.
        #[arg(long)]
        no_reap_orphans: bool,
        /// Also remove top-level cache entries left behind by a subsystem mvm
        /// no longer has (their disk is never reclaimed otherwise). Without
        /// this flag prune only *reports* them. Only the names on the
        /// [`RETIRED_CACHE_ENTRIES`] deny-list are ever removed, so a cache
        /// that is still in use is never a candidate.
        #[arg(long)]
        orphan_dirs: bool,
        /// Reclaim regenerable caches too — the Stage 0 vendored blobs
        /// (`stage0/`), the prebuilt default microVM image (`default-microvm/`),
        /// and pulled OCI layers (`oci/`). These cost a re-fetch or rebuild the
        /// next time they're needed, so they're opt-in. Implies `--orphan-dirs`.
        #[arg(long)]
        deep: bool,
    },
    /// Show cache directory path and disk usage
    Info {
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Show cached attested packs: identity, size, expiry, and whether the
    /// host runtime pack is ready for an instant launch.
    Status {
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
    },
    /// Repair a degraded builder VM store. Clears
    /// `~/.mvm/cache/builder-vm/` so the next `mvmctl bootstrap`/`build` cold-rebuilds it.
    /// Use this when a build keeps failing with a dangling-store error
    /// (`error: path '/nix/store/…-source/flake.nix' does not exist`).
    Repair {
        /// Print what would be freed without removing anything
        #[arg(long)]
        dry_run: bool,
        /// Emit machine-readable JSON to stdout
        #[arg(long)]
        json: bool,
        /// Clear the store even while a Stage 0 bootstrap is in flight. By
        /// default repair refuses if the Stage 0 advisory lock is held (another
        /// build is mid-bootstrap) so it never yanks the store from
        /// an active build. Only pass this if you are certain the lock is stale
        /// (e.g. left by a crashed run).
        #[arg(long)]
        force: bool,
        /// Remove only the persistent Nix store image, keeping the builder
        /// kernel/rootfs and the Stage 0 seed. Use this when the store itself
        /// is the damaged piece — the guest refuses to build and names ext4
        /// errors on it — so recovery costs one image instead of the whole
        /// cache.
        #[arg(long)]
        store_only: bool,
    },
}

/// Structured output for `cache info --json`.
#[derive(serde::Serialize)]
struct CacheInfo {
    cache_dir: String,
    exists: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    disk_usage_bytes: Option<u64>,
    /// Per-top-level-entry footprint, largest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    entries: Vec<CacheDirEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    detail_lines: Vec<String>,
}

/// One row of the `cache info` per-entry breakdown.
#[derive(serde::Serialize)]
struct CacheDirEntry {
    name: String,
    bytes: u64,
    /// `true` for an entry belonging to a subsystem mvm no longer has —
    /// what `cache prune --orphan-dirs` reclaims.
    retired: bool,
}

/// Structured output for `cache status --json`: one row per cached pack plus
/// the host runtime pack's instant-launch verdict.
#[derive(serde::Serialize)]
struct CacheStatusReport {
    packs: Vec<CacheStatusEntry>,
    instant_launch_ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    instant_launch_reason: Option<String>,
}

/// One row of the `cache status` table.
#[derive(serde::Serialize)]
struct CacheStatusEntry {
    pack_hash: String,
    kind: mvm_core::packs::PackKind,
    arch: mvm_core::arch::GuestArch,
    backends: Vec<mvm_core::packs::PackBackend>,
    channel: String,
    size_bytes: u64,
    expires_at: chrono::DateTime<chrono::Utc>,
    expired: bool,
    signing_key_id: mvm_core::plan::bundle::KeyId,
    revocation_channel: String,
    last_used_unix: Option<i64>,
}

fn collect_cache_info() -> Result<CacheInfo> {
    let cache_dir = mvm_core::config::mvm_cache_dir();
    let path = std::path::Path::new(&cache_dir);
    if !path.exists() {
        return Ok(CacheInfo {
            cache_dir,
            exists: false,
            disk_usage_bytes: None,
            entries: Vec::new(),
            detail_lines: Vec::new(),
        });
    }
    let disk_usage_bytes = dir_size(path);
    let entries = cache_dir_breakdown(path)
        .into_iter()
        .map(|(name, bytes)| {
            let retired = RETIRED_CACHE_ENTRIES.contains(&name.as_str());
            CacheDirEntry {
                name,
                bytes,
                retired,
            }
        })
        .collect();
    let stage0_dir = mvm_build::stage0::stage0_cache_dir();
    let blob_filenames: Vec<&str> = mvm_build::stage0::assets_for_host_arch()
        .iter()
        .map(|a| a.cache_filename)
        .collect();
    let detail_lines = stage0_cache_report(path, &stage0_dir, &blob_filenames);
    Ok(CacheInfo {
        cache_dir,
        exists: true,
        disk_usage_bytes: Some(disk_usage_bytes),
        entries,
        detail_lines,
    })
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let cache_dir = mvm_core::config::mvm_cache_dir();

    match args.action {
        CacheAction::Info { json } => {
            let info = collect_cache_info()?;
            if json {
                crate::json_out::emit_json(&info)?;
                return Ok(());
            }
            println!("Cache directory: {cache_dir}");
            if !info.exists {
                println!("(not yet created)");
                return Ok(());
            }
            println!(
                "Disk usage: {}",
                human_bytes(info.disk_usage_bytes.unwrap_or(0))
            );
            // Per-entry breakdown (largest first) so the operator can see what
            // is actually consuming the cache before reclaiming. A retired
            // entry belongs to a subsystem mvm no longer has — `cache prune
            // --orphan-dirs` reclaims it.
            if !info.entries.is_empty() {
                println!("By entry:");
                for e in &info.entries {
                    let tag = if e.retired { "  (retired)" } else { "" };
                    println!("  {:<22} {}{tag}", e.name, human_bytes(e.bytes));
                }
            }
            // Surface vendored-blob ages, the cross-target builder-VM
            // cache size, assembled rootfs ages, and the last Stage 0
            // source fingerprint.
            for line in &info.detail_lines {
                println!("{line}");
            }
            // Discoverability pointer for the builder-store recovery path. Shown
            // only when a builder store exists (a fresh host has nothing to
            // repair). This is a static hint, not a corruption probe — store
            // damage only surfaces when the guest mounts the image, so `info`
            // can't cheaply detect it from the host; the failure path and
            // `doctor` carry the live diagnosis.
            if std::path::Path::new(&cache_dir).join("builder-vm").is_dir() {
                println!(
                    "If `mvmctl bootstrap`/`build` fails with a dangling-store or mount error, \
                     run `mvmctl cache repair`."
                );
            }
            Ok(())
        }
        CacheAction::Status { json } => {
            let packs = mvm_core::pack_cache::list_cached_packs()?;
            let now = chrono::Utc::now();
            let diagnosis = crate::commands::vm::runtime_pack::runtime_pack_diagnosis()?;
            let reason = crate::commands::vm::runtime_pack::not_instant_reason(&diagnosis);

            if json {
                let report = CacheStatusReport {
                    packs: packs
                        .iter()
                        .map(|p| CacheStatusEntry {
                            pack_hash: p.pack_hash.as_str().to_string(),
                            kind: p.kind.clone(),
                            arch: p.arch,
                            backends: p.backends.clone(),
                            channel: p.channel.clone(),
                            size_bytes: p.size_bytes,
                            expires_at: p.expires_at,
                            expired: p.expires_at < now,
                            signing_key_id: p.signing_key_id.clone(),
                            revocation_channel: p.revocation_channel.clone(),
                            last_used_unix: p.last_used_unix,
                        })
                        .collect(),
                    instant_launch_ready: reason.is_none(),
                    instant_launch_reason: reason,
                };
                crate::json_out::emit_json(&report)?;
                return Ok(());
            }

            if packs.is_empty() {
                ui::info("No packs cached.");
                return Ok(());
            }

            for p in &packs {
                let expired = p.expires_at < now;
                let backends = p
                    .backends
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let short_hash = &p.pack_hash.as_str()[..p.pack_hash.as_str().len().min(12)];
                println!(
                    "{short_hash:<12}  {:<10?}  {:<8?}  {backends:<18}  {:<10}  {:>10}  {}  {}",
                    p.kind,
                    p.arch,
                    p.channel,
                    human_bytes(p.size_bytes),
                    p.expires_at.format("%Y-%m-%d"),
                    if expired { "EXPIRED" } else { "ok" },
                );
            }
            match &reason {
                Some(r) => ui::info(&format!("Instant launch: unavailable — {r}")),
                None => ui::info("Instant launch: ready"),
            }
            Ok(())
        }
        CacheAction::Repair {
            dry_run,
            json,
            force,
            store_only,
        } => {
            use super::super::env::builder_vm;

            // Guard 1 — never yank the store from an in-flight bootstrap. A
            // held Stage 0 lock means another build is mid-bootstrap.
            // `--force` overrides (for a stale lock left by a crash).
            if !force && builder_vm::stage0_bootstrap_in_flight() {
                anyhow::bail!(
                    "a Stage 0 builder bootstrap appears to be in progress (lock held at \
                     {}/builder-vm/stage0.lock). Refusing to clear the builder store from under \
                     a live build. Wait for it to finish, or pass --force if you are certain the \
                     lock is stale (e.g. after a crash).",
                    cache_dir,
                );
            }

            let repair = if store_only {
                mvm_build::builder_vm::clear_builder_store_image(dry_run)
                    .map_err(|e| anyhow::anyhow!("clearing builder store image: {e}"))?
            } else {
                mvm_build::builder_vm::clear_builder_store(dry_run)
                    .map_err(|e| anyhow::anyhow!("clearing builder store: {e}"))?
            };
            if json {
                crate::json_out::emit_json(&repair)?;
                return Ok(());
            }
            if !repair.existed {
                ui::notice(&format!(
                    "Builder store {} is already absent — nothing to repair.",
                    repair.path
                ));
            } else if dry_run {
                ui::notice(&format!(
                    "Would clear builder store {} ({}). Re-run without --dry-run to repair.",
                    repair.path,
                    human_bytes(repair.bytes_freed)
                ));
            } else {
                mvm_core::audit_emit!(
                    CachePrune,
                    "op=builder_store_repair freed_bytes={} cache_dir={}",
                    repair.bytes_freed,
                    repair.path
                );
                ui::notice(&format!(
                    "Cleared builder store {} ({} freed). The next `mvmctl bootstrap` rebuilds it.",
                    repair.path,
                    human_bytes(repair.bytes_freed)
                ));
            }
            Ok(())
        }
        CacheAction::Prune {
            dry_run,
            orphan_builds,
            no_reap_orphans,
            orphan_dirs,
            deep,
        } => {
            // `--deep` is the "reclaim everything regenerable" sledgehammer; it
            // subsumes the orphan-dir sweep.
            let orphan_dirs = orphan_dirs || deep;
            // Reap orphaned per-VM helpers by default (liveness-aware: live VMs
            // are spared). Done first so subsequent steps see a clean process
            // list and so the sweeper can drop the per-VM cache dirs along with
            // the helpers that were holding their sockets/PIDs.
            if !no_reap_orphans {
                match super::super::env::builder_vm::reap_orphaned_vm_helpers(dry_run) {
                    Ok(o) => {
                        if o.killed == 0 && o.removed_dirs == 0 {
                            ui::info("No orphaned VM helpers.");
                        } else if dry_run {
                            ui::notice(&format!(
                                "(dry-run) Would reap {} orphaned helper PID(s) and {} cache dir(s) ({}).",
                                o.killed,
                                o.removed_dirs,
                                human_bytes(o.freed_bytes)
                            ));
                        } else {
                            ui::notice(&format!(
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
                    match mvm_runtime::vm::template::lifecycle::template_prune_orphan_slots() {
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

            // Sweep orphaned Stage 0 staging dirs first.
            // They live under `~/.mvm/cache/builder-vm/.<arch>.stage0-*`
            // (or the legacy `<arch>-staging` shape) and are left
            // behind by crashed builder VM bootstrap invocations. The sweep
            // takes the Stage 0 advisory lock to avoid racing a live
            // bootstrap; if the lock is held it skips silently and we
            // proceed with the temp-file sweep.
            match super::super::env::builder_vm::sweep_orphaned_stage0_staging_dirs(dry_run) {
                Ok(super::super::env::builder_vm::Stage0SweepOutcome::Swept {
                    removed: r,
                    freed_bytes,
                }) => {
                    removed += r;
                    freed += freed_bytes;
                }
                Ok(super::super::env::builder_vm::Stage0SweepOutcome::SkippedLockHeld) => {
                    ui::info(
                        "Stage 0 builder VM bootstrap appears to be running on this host; \
                         skipping orphan staging cleanup.",
                    );
                }
                Err(e) => {
                    ui::warn(&format!("Stage 0 staging sweep failed: {e:#}"));
                }
            }

            // Flow-byte-log retention sweep. Per-tenant subdirs
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

            // Reap stale supervisor standbys under `~/.mvm/pool/`.
            // The TTL guards a fresh pool (only dead-pid or expired standbys go); a
            // live-expired standby's entitled supervisor is SIGTERM'd before its dir is
            // dropped, so idle entitled processes never accumulate. Shares
            // `STANDBY_POOL_TTL` with the launch-path reaper so both agree on "stale".
            use mvm_runtime::standby_pool::STANDBY_POOL_TTL;
            if dry_run {
                if let Ok(pool) = mvm_runtime::standby_pool::SupervisorStandbyPool::open()
                    && let Ok(n) = pool.list().map(|v| v.len())
                    && n > 0
                {
                    ui::info(&format!(
                        "(dry-run) Would reap stale entries among {n} standby(s)."
                    ));
                }
            } else {
                match mvm_runtime::standby_pool::SupervisorStandbyPool::open().and_then(|pool| {
                    pool.reap_stale(STANDBY_POOL_TTL, mvm_core::time::now_unix_secs())
                }) {
                    Ok(reaped) if !reaped.is_empty() => {
                        removed += reaped.len() as u64;
                        ui::info(&format!("Reaped {} stale standby(s).", reaped.len()));
                    }
                    Ok(_) => {}
                    Err(e) => ui::warn(&format!("standby pool reap failed: {e}")),
                }
            }

            // Untagged-checkpoint GC: tagged checkpoints are user-pinned; untagged
            // ones follow cache retention, unless a still-resumable session names
            // one as its resume point. One corrupt meta.json makes list() fail,
            // which logs a warning and skips the sweep — acceptable for a prune pass.
            const CHECKPOINT_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;
            let ckpt_store = mvm_runtime::checkpoint::CheckpointStore::open();
            if dry_run {
                if !ckpt_store.list().unwrap_or_default().is_empty() {
                    ui::info("(dry-run) Would sweep expired untagged checkpoints.");
                }
            } else {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let sessions = mvm_runtime::agent_session::AgentSessionStore::open();
                match mvm_runtime::agent_session::pinned_checkpoints(&sessions) {
                    Ok(pinned) => {
                        match sweep_untagged_checkpoints(
                            &ckpt_store,
                            now,
                            CHECKPOINT_MAX_AGE_SECS,
                            &pinned,
                        ) {
                            Ok(n) => removed += n as u64,
                            Err(e) => ui::warn(&format!("checkpoint sweep failed: {e}")),
                        }
                    }
                    Err(e) => ui::warn(&format!(
                        "checkpoint sweep skipped: could not determine session-pinned checkpoints: {e}"
                    )),
                }
            }

            // Expired-pack sweep: an attested pack whose trust metadata expired
            // is never instant-launch-eligible, so reclaiming it is always safe.
            // Valid-but-unused (LRU) pack reclamation is a separate concern and
            // is not swept here.
            match mvm_core::pack_cache::prune_expired_packs(chrono::Utc::now(), dry_run) {
                Ok(expired) => {
                    if !expired.is_empty() {
                        if dry_run {
                            ui::info(&format!(
                                "(dry-run) Would remove {} expired pack(s).",
                                expired.len()
                            ));
                        } else {
                            ui::info(&format!("Removed {} expired pack(s).", expired.len()));
                            mvm_core::audit_emit!(
                                CachePrune,
                                "source=pack_cache_prune count={}",
                                expired.len()
                            );
                        }
                        removed += expired.len() as u64;
                    }
                }
                Err(e) => ui::warn(&format!("expired-pack sweep failed: {e}")),
            }

            // Version-aware pack prune: reclaim non-active pack versions
            // beyond the newest few per key, distinct from the expired-pack
            // sweep above (which only removes packs whose trust metadata has
            // lapsed). Keeps the active version plus the most recent
            // runners-up so a rollback via `mvmctl pack activate` stays
            // possible instead of every downloaded/built version
            // accumulating forever.
            match mvm_core::pack_cache::prune_versions(PACK_VERSION_KEEP_RECENT, dry_run) {
                Ok(pruned) => {
                    if !pruned.is_empty() {
                        ui::info(&pack_version_prune_report(pruned.len(), dry_run));
                        if !dry_run {
                            mvm_core::audit_emit!(
                                CachePrune,
                                "source=pack_version_prune count={}",
                                pruned.len()
                            );
                        }
                        removed += pruned.len() as u64;
                    }
                }
                Err(e) => ui::warn(&format!("pack version prune failed: {e}")),
            }

            for entry in walkdir(path)? {
                let entry_path = entry.path();
                // Remove temp files (mvm-lima-*, .tmp)
                if let Some(name) = entry_path.file_name().and_then(|n| n.to_str())
                    && (name.starts_with("mvm-lima-") || name.ends_with(".tmp"))
                {
                    let size = dir_size(&entry_path);
                    if dry_run {
                        println!(
                            "Would remove: {} ({})",
                            entry_path.display(),
                            human_bytes(size)
                        );
                    } else {
                        let _ = remove_cache_path(&entry_path);
                    }
                    removed += 1;
                    freed += size;
                }
            }

            // Leftovers from a subsystem mvm no longer has. Reported by
            // default; removed only with `--orphan-dirs`/`--deep`.
            let retired = classify_retired_entries(path);
            if !retired.is_empty() {
                if orphan_dirs {
                    let (n, b) = reclaim_entries(&retired, "retired cache entry", dry_run);
                    removed += n;
                    freed += b;
                } else {
                    let total: u64 = retired.iter().map(|e| e.bytes).sum();
                    ui::info(&format!(
                        "{} retired cache entr{} ({} total) not removed — \
                         re-run with `--orphan-dirs` to reclaim:",
                        retired.len(),
                        if retired.len() == 1 { "y" } else { "ies" },
                        human_bytes(total),
                    ));
                    for e in &retired {
                        ui::info(&format!(
                            "  {} ({})",
                            e.path.display(),
                            human_bytes(e.bytes)
                        ));
                    }
                }
            }

            // `--deep`: reclaim regenerable caches (Stage 0 blobs, the prebuilt
            // default microVM image, pulled OCI layers). Opt-in: each costs a
            // re-fetch/rebuild next time it's needed.
            if deep {
                let targets = regenerable_cache_targets(path);
                if targets.is_empty() {
                    ui::info("No regenerable caches to reclaim.");
                } else {
                    for (entry, label) in &targets {
                        ui::info(&format!("  {label}"));
                        let (n, b) = reclaim_entries(
                            std::slice::from_ref(entry),
                            "regenerable cache",
                            dry_run,
                        );
                        removed += n;
                        freed += b;
                    }
                }
            }

            if removed == 0 {
                ui::notice("Nothing to prune.");
            } else if dry_run {
                ui::notice(&format!(
                    "Would remove {} items, freeing {}",
                    removed,
                    human_bytes(freed)
                ));
            } else {
                ui::notice(&format!(
                    "Pruned {} items, freed {}",
                    removed,
                    human_bytes(freed)
                ));
            }

            // Make the persistent /nix store images' footprint
            // visible at prune time. We don't boot a VM to GC on demand
            // (out of scope); GC now runs automatically in-build past the
            // cap. Report the sizes + the cap so the operator can see the
            // bloat and understand the auto-reclaim behaviour.
            for line in builder_store_gc_report(path) {
                println!("{line}");
            }
            // Every state-changing CLI verb emits one audit record.
            // We only mutate disk on the non-dry-run
            // path; dry-run reads only and stays out of the log.
            if !dry_run {
                mvm_core::audit_emit!(CachePrune, "removed={removed} freed_bytes={freed}");
            }
            Ok(())
        }
    }
}

/// Top-level entries under `mvm_cache_dir()` that belonged to a subsystem mvm
/// no longer has. `prune --orphan-dirs` removes these and nothing else.
///
/// This is deliberately a deny-list. The inverse — an allow-list of every
/// live cache dir, deleting whatever is missing from it — has to be extended
/// every time any subsystem anywhere in the workspace grows a cache, and the
/// price of forgetting is that prune deletes a cache that is still in use.
/// Naming the dead names instead inverts the failure: forgetting to retire a
/// name leaks disk, which an operator can see and we can fix later.
///
/// CONTRACT: when you delete a subsystem, add the cache entry it owned here in
/// the same change.
const RETIRED_CACHE_ENTRIES: &[&str] = &[
    // Stage 0's store mount point from the container-era bootstrap.
    "docker-nix-store",
    // Builder store mount point superseded by the persistent store image.
    "builder-nix-store",
];

/// Regenerable caches reclaimed by `prune --deep`: expensive to refetch or
/// rebuild, so never swept by the safe default. Each tuple is
/// `(name, human label)`; the dir is `cache_root/<name>`.
const REGENERABLE_CACHE_ENTRIES: &[(&str, &str)] = &[
    (
        "stage0",
        "Stage 0 vendored blobs (re-fetched on next cold bootstrap)",
    ),
    (
        "default-microvm",
        "prebuilt default microVM image (rebuilt on next default-image use)",
    ),
    ("oci", "pulled OCI layers (re-pulled on next image pull)"),
];

/// A reclaimable cache entry: its path and real on-disk footprint.
struct CacheEntry {
    path: std::path::PathBuf,
    bytes: u64,
}

/// Top-level entries under `cache_root` named in [`RETIRED_CACHE_ENTRIES`].
/// Side-effect-free (stats only) so it's hermetically testable. Sorted by
/// descending footprint so the biggest reclaim shows first.
fn classify_retired_entries(cache_root: &std::path::Path) -> Vec<CacheEntry> {
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return Vec::new();
    };
    let mut out: Vec<CacheEntry> = entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| RETIRED_CACHE_ENTRIES.contains(&n))
                .unwrap_or(false)
        })
        .map(|e| {
            let path = e.path();
            CacheEntry {
                bytes: dir_size(&path),
                path,
            }
        })
        .collect();
    out.sort_by_key(|e| std::cmp::Reverse(e.bytes));
    out
}

/// Regenerable caches present under `cache_root`, in
/// [`REGENERABLE_CACHE_ENTRIES`] order. Side-effect-free; only existing dirs
/// are returned.
fn regenerable_cache_targets(cache_root: &std::path::Path) -> Vec<(CacheEntry, &'static str)> {
    REGENERABLE_CACHE_ENTRIES
        .iter()
        .filter_map(|(name, label)| {
            let path = cache_root.join(name);
            path.is_dir().then(|| {
                (
                    CacheEntry {
                        bytes: dir_size(&path),
                        path,
                    },
                    *label,
                )
            })
        })
        .collect()
}

/// Per-top-level-entry on-disk breakdown of the cache root, sorted by
/// descending real footprint (sparse images count allocated blocks, not their
/// cap). Drives the `cache info` table. Side-effect-free.
fn cache_dir_breakdown(cache_root: &std::path::Path) -> Vec<(String, u64)> {
    let Ok(entries) = std::fs::read_dir(cache_root) else {
        return Vec::new();
    };
    let mut rows: Vec<(String, u64)> = entries
        .flatten()
        .map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            (name, dir_size(&e.path()))
        })
        .collect();
    rows.sort_by_key(|(_, bytes)| std::cmp::Reverse(*bytes));
    rows
}

/// Remove (or, under `dry_run`, just tally) a set of reclaimable entries.
/// Returns `(count, bytes)` actually removed/would-remove. Each path is
/// printed so the operator sees exactly what goes.
fn reclaim_entries(entries: &[CacheEntry], kind: &str, dry_run: bool) -> (u64, u64) {
    let mut removed = 0u64;
    let mut freed = 0u64;
    for e in entries {
        if dry_run {
            println!(
                "Would remove {kind}: {} ({})",
                e.path.display(),
                human_bytes(e.bytes)
            );
        } else {
            match remove_cache_path(&e.path) {
                Ok(()) => println!(
                    "Removed {kind}: {} ({})",
                    e.path.display(),
                    human_bytes(e.bytes)
                ),
                Err(err) => {
                    ui::warn(&format!("could not remove {}: {err}", e.path.display()));
                    continue;
                }
            }
        }
        removed += 1;
        freed += e.bytes;
    }
    (removed, freed)
}

/// Remove untagged checkpoints older than `max_age_secs`. Tagged checkpoints
/// are user-pinned and never swept; neither is a checkpoint in `pinned` — the
/// resume point of a session that is still `Active` or `Hibernated`. Without
/// that guard, a session parked longer than `max_age_secs` would lose the
/// checkpoint it resumes from and become permanently unresumable: the session
/// record survives, pointing at nothing. Returns the count removed.
pub(super) fn sweep_untagged_checkpoints(
    store: &mvm_runtime::checkpoint::CheckpointStore,
    now_unix: u64,
    max_age_secs: u64,
    pinned: &std::collections::BTreeSet<mvm_core::checkpoint::CheckpointDigest>,
) -> anyhow::Result<usize> {
    let mut removed = 0;
    for m in store.list()? {
        if m.tag.is_some() {
            continue;
        }
        if now_unix.saturating_sub(m.created_unix) <= max_age_secs {
            continue;
        }
        if pinned.contains(&m.meta_digest) {
            println!(
                "Kept checkpoint: {} (pinned by a parked session's resume point)",
                m.id
            );
            continue;
        }
        store.remove(&m.id)?;
        println!("Removed checkpoint: {} (untagged, aged out)", m.id);
        removed += 1;
    }
    Ok(removed)
}

/// Number of non-active pack versions `mvmctl cache prune` keeps around per
/// `(kind, arch, backend)` key, on top of whichever version is active. Kept as
/// a named constant (not a literal at the call site) so the retention policy
/// is documented in one place and a rollback via `mvmctl pack activate` stays
/// possible for a little while after a newer version is promoted.
const PACK_VERSION_KEEP_RECENT: usize = 2;

/// User-facing summary line for the version-aware pack prune step, split out
/// so the message format is unit-testable without exercising the pack cache.
fn pack_version_prune_report(removed: usize, dry_run: bool) -> String {
    if dry_run {
        format!("(dry-run) Would remove {removed} old pack version(s).")
    } else {
        format!("Removed {removed} old pack version(s).")
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

/// Build the `cache info` enrichment lines: vendored
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

/// Report the builder VM's persistent `nix-store-*.img` footprints plus
/// the in-build GC cap. Path-injectable + side-effect-free so it's
/// hermetically testable. `len()` is the sparse *apparent* cap; allocated
/// blocks (`st_blocks * 512`, via [`file_allocated_bytes`]) are the real
/// footprint that grows unbounded without GC — so we surface both.
///
/// We only *report* here: booting a builder VM to GC on demand is out of
/// scope. GC runs automatically at the end of every in-VM build
/// once the store crosses the cap.
fn builder_store_gc_report(cache_root: &std::path::Path) -> Vec<String> {
    let builder = cache_root.join("builder-vm");
    if !builder.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(&builder) else {
        return Vec::new();
    };
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
    if imgs.is_empty() {
        return Vec::new();
    }
    imgs.sort();

    let mut lines = vec!["Builder persistent /nix store images:".to_string()];
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
    // Surface the resolved cap (honours MVM_BUILDER_STORE_GC_GIB) and note
    // that GC is automatic — so the operator doesn't go hunting for a
    // `cache gc` verb that intentionally doesn't exist.
    let cap_gib = mvm_build::builder_vm_runtime::builder_store_gc_cap_kib() / 1024 / 1024;
    lines.push(format!(
        "  auto-GC cap: {cap_gib} GiB used (override {}). \
         Past the cap, `nix-collect-garbage --delete-older-than 14d` runs \
         automatically at the end of each in-VM build (#630).",
        mvm_build::builder_vm_runtime::MVM_BUILDER_STORE_GC_GIB_ENV,
    ));
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

/// Recursive on-disk footprint of a cache entry. One line, because every
/// counter in this file must agree with `du` and with each other.
fn dir_size(path: &std::path::Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(path)
}

/// Recursive directory walker that never descends through a symlink.
///
/// The temp-file sweep deletes what this yields, so following a link would
/// let a `foo.tmp` symlink inside the cache reach files outside it.
fn walkdir(path: &std::path::Path) -> Result<Vec<std::fs::DirEntry>> {
    let mut entries = Vec::new();
    if !path.is_dir() {
        return Ok(entries);
    }
    let mut pending = vec![path.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            // `DirEntry::file_type` reports the link itself, not its target.
            let descend = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
            if descend {
                pending.push(entry.path());
            }
            entries.push(entry);
        }
    }
    Ok(entries)
}

/// Remove a cache path, whatever kind of thing it is.
///
/// Decided from `symlink_metadata`: a symlink pointing at a directory must be
/// unlinked, never `remove_dir_all`'d, or the sweep empties the target.
fn remove_cache_path(path: &std::path::Path) -> std::io::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_removes_untagged_keeps_tagged() {
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
        use mvm_runtime::checkpoint::CheckpointStore;

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let mk = |id: &str, tag: Option<&str>, age: u64| {
            CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
                .tag(tag.map(String::from))
                .content(vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "h".into(),
                }])
                .supervisor_config_digest("d")
                .created_unix(age)
                .build()
        };
        store.write_meta(&mk("old-untagged", None, 0)).unwrap();
        store
            .write_meta(&mk("old-tagged", Some("gold"), 0))
            .unwrap();

        let now = 10_000_000u64;
        let removed =
            super::sweep_untagged_checkpoints(&store, now, 1, &Default::default()).unwrap();
        assert_eq!(removed, 1);
        assert!(store.read_meta(&CheckpointId::new("old-tagged")).is_ok());
        assert!(store.read_meta(&CheckpointId::new("old-untagged")).is_err());
    }

    #[test]
    fn prune_skips_a_checkpoint_pinned_by_a_parked_session() {
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
        use mvm_runtime::checkpoint::CheckpointStore;

        let tmp = tempfile::tempdir().unwrap();
        let store = CheckpointStore::at(tmp.path());
        let mk = |id: &str, age: u64| {
            CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
                .content(vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "h".into(),
                }])
                .supervisor_config_digest("d")
                .created_unix(age)
                .build()
        };
        let pinned_meta = mk("pinned-untagged", 0);
        let unpinned_meta = mk("unpinned-untagged", 0);
        store.write_meta(&pinned_meta).unwrap();
        store.write_meta(&unpinned_meta).unwrap();

        let mut pinned = std::collections::BTreeSet::new();
        pinned.insert(pinned_meta.meta_digest.clone());

        let now = 10_000_000u64;
        let removed = super::sweep_untagged_checkpoints(&store, now, 1, &pinned).unwrap();
        assert_eq!(removed, 1, "only the unpinned checkpoint should be reaped");
        assert!(
            store
                .read_meta(&CheckpointId::new("pinned-untagged"))
                .is_ok(),
            "a checkpoint pinned by a parked session must survive the sweep"
        );
        assert!(
            store
                .read_meta(&CheckpointId::new("unpinned-untagged"))
                .is_err()
        );
    }

    #[test]
    fn pinned_checkpoints_derived_from_a_real_session_protects_its_checkpoint() {
        // Task 1's other test builds the pinned set by hand, which proves the
        // sweep honours whatever set it's handed but not that the set the CLI
        // actually derives from disk is the right one. This test closes that
        // gap: a real `AgentSessionRecord` naming a real checkpoint's
        // `meta_digest` as its `parent_checkpoint`, run through the same
        // `pinned_checkpoints` the prune path calls, must protect that exact
        // checkpoint — and only that one.
        use mvm_contract::protocol::agent_session::AgentSessionId;
        use mvm_core::checkpoint::{CheckpointClass, CheckpointId, CheckpointMeta};
        use mvm_runtime::agent_session::{AgentSessionRecord, AgentSessionStore, SandboxResidency};
        use mvm_runtime::checkpoint::CheckpointStore;

        let ckpt_tmp = tempfile::tempdir().unwrap();
        let ckpt_store = CheckpointStore::at(ckpt_tmp.path());
        let mk = |id: &str, age: u64| {
            CheckpointMeta::builder(CheckpointId::new(id), CheckpointClass::FsQuick, "vm")
                .content(vec![mvm_core::checkpoint::ContentBlob {
                    name: "rootfs.ext4".into(),
                    sha256: "h".into(),
                }])
                .supervisor_config_digest("d")
                .created_unix(age)
                .build()
        };
        let resumed_from = mk("resumed-from", 0);
        let orphaned = mk("orphaned", 0);
        ckpt_store.write_meta(&resumed_from).unwrap();
        ckpt_store.write_meta(&orphaned).unwrap();

        let session_tmp = tempfile::tempdir().unwrap();
        let session_store = AgentSessionStore::at(session_tmp.path());
        let record = AgentSessionRecord {
            session_id: AgentSessionId::parse("sess-parked").unwrap(),
            generation: 1,
            state: SandboxResidency::Hibernated,
            members: vec!["vm-alpha".to_string()],
            parent_checkpoint: Some(resumed_from.meta_digest.clone()),
            created_unix: 0,
            updated_unix: 0,
            journal_cursor: 0,
            approval_head: None,
            storage_tier: None,
            park_reason: None,
        };
        session_store.write(&record).unwrap();

        let pinned = mvm_runtime::agent_session::pinned_checkpoints(&session_store).unwrap();

        let now = 10_000_000u64;
        let removed = super::sweep_untagged_checkpoints(&ckpt_store, now, 1, &pinned).unwrap();
        assert_eq!(removed, 1, "only the orphaned checkpoint should be reaped");
        assert!(
            ckpt_store
                .read_meta(&CheckpointId::new("resumed-from"))
                .is_ok(),
            "the checkpoint the parked session actually resumes from must survive"
        );
        assert!(
            ckpt_store
                .read_meta(&CheckpointId::new("orphaned"))
                .is_err(),
            "a checkpoint no session names must still be reaped"
        );
    }

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
        std::fs::write(stage0.join("nix-seed-aarch64.tar.xz"), b"hello").unwrap();

        // builder-vm/<arch>/ with an assembled rootfs + fingerprint sidecar.
        let arch = root.join("builder-vm").join("aarch64");
        std::fs::create_dir_all(&arch).unwrap();
        std::fs::write(arch.join("rootfs.ext4"), b"rootfsdata").unwrap();
        std::fs::write(arch.join(".mvm-source.sha256"), "abcd1234deadbeef\n").unwrap();
        // A per-VM scratch dir that must be skipped.
        std::fs::create_dir_all(root.join("builder-vm").join("vms").join("v1")).unwrap();

        let blobs = ["nix-seed-aarch64.tar.xz", "missing-blob.tar.gz"];
        let joined = stage0_cache_report(root, &stage0, &blobs).join("\n");

        assert!(joined.contains("nix-seed-aarch64.tar.xz: "));
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

    #[test]
    fn builder_store_gc_report_empty_without_images() {
        let tmp = tempfile::tempdir().unwrap();
        // No builder-vm dir at all.
        assert!(builder_store_gc_report(tmp.path()).is_empty());
        // builder-vm dir present but no nix-store images.
        std::fs::create_dir_all(tmp.path().join("builder-vm")).unwrap();
        assert!(builder_store_gc_report(tmp.path()).is_empty());
    }

    #[test]
    fn builder_store_gc_report_surfaces_images_cap_and_note() {
        let tmp = tempfile::tempdir().unwrap();
        let builder = tmp.path().join("builder-vm");
        std::fs::create_dir_all(&builder).unwrap();
        // A sparse-looking store image + a non-matching file that must be ignored.
        let img = builder.join("nix-store-aarch64.img");
        std::fs::File::create(&img)
            .unwrap()
            .set_len(64 * 1024 * 1024 * 1024)
            .unwrap();
        std::fs::write(builder.join("rootfs.ext4"), b"not a store img").unwrap();

        let joined = builder_store_gc_report(tmp.path()).join("\n");
        assert!(joined.contains("Builder persistent /nix store images:"));
        assert!(joined.contains("nix-store-aarch64.img:"));
        assert!(joined.contains("cap (sparse)"));
        // The auto-GC note + env override name must be present.
        assert!(joined.contains("auto-GC cap:"));
        assert!(joined.contains("MVM_BUILDER_STORE_GC_GIB"));
        assert!(joined.contains("--delete-older-than 14d"));
        // The non-matching file is not reported as a store image.
        assert!(!joined.contains("rootfs.ext4"));
    }

    /// A cache dir mvm writes today must never be a removal candidate, and a
    /// regenerable target must not also be retired (`--deep` would reclaim it
    /// twice and double-count the bytes).
    #[test]
    fn live_cache_dirs_are_never_removal_candidates() {
        // Every top-level entry a current subsystem writes under the cache
        // root. Each name is resolved by a helper in the crate that owns it.
        for live in [
            "builder-vm",
            "stage0",
            "oci",
            "default-microvm",
            "host-bins",
            "packs",
            "initramfs",
            "runtime-overlay",
            "runtime-overlay-bins",
            "guest-agent-build",
            "verity-initrd",
            "sdk-sidecar",
            "warm-artifacts",
            "audit-verify",
            "builder-health",
            "local-run",
        ] {
            assert!(
                !RETIRED_CACHE_ENTRIES.contains(&live),
                "{live} is written by a current subsystem and must never be pruned"
            );
        }
        for (name, _) in REGENERABLE_CACHE_ENTRIES {
            assert!(
                !RETIRED_CACHE_ENTRIES.contains(name),
                "{name} is reclaimed by --deep and must not also be retired"
            );
        }
    }

    /// The sweep selects retired names only. A live cache dir that nothing in
    /// this file knows about — the shape every new subsystem starts in — must
    /// survive, and a retired one must be selected.
    #[test]
    fn retired_classification_selects_only_retired_names() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Live caches, including ones this module has never heard of.
        for live in ["stage0", "builder-vm", "guest-agent-build", "packs"] {
            std::fs::create_dir_all(root.join(live)).unwrap();
            std::fs::write(root.join(live).join("blob.bin"), vec![0u8; 8192]).unwrap();
        }
        // Retired: a small one and a bigger one.
        std::fs::create_dir_all(root.join("docker-nix-store")).unwrap();
        std::fs::write(root.join("docker-nix-store/big.bin"), vec![0u8; 64 * 1024]).unwrap();
        std::fs::create_dir_all(root.join("builder-nix-store")).unwrap();
        std::fs::write(root.join("builder-nix-store/small.bin"), b"hi").unwrap();

        let retired = classify_retired_entries(root);
        let names: Vec<String> = retired
            .iter()
            .map(|e| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec!["docker-nix-store", "builder-nix-store"],
            "largest first; live caches skipped"
        );
        assert!(retired[0].bytes >= retired[1].bytes);
    }

    /// End-to-end on the sweep the flag drives: the live caches survive and
    /// the retired one is gone. A fix that simply stopped deleting would fail
    /// the second half.
    #[test]
    fn orphan_dir_sweep_removes_the_retired_entry_and_spares_live_caches() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let live = [
            "guest-agent-build",
            "runtime-overlay-bins",
            "runtime-overlay",
            "sdk-sidecar",
            "verity-initrd",
            "audit-verify",
            "initramfs",
            "packs",
            "builder-health",
        ];
        for name in live {
            std::fs::create_dir_all(root.join(name)).unwrap();
            std::fs::write(root.join(name).join("blob.bin"), vec![0u8; 4096]).unwrap();
        }
        std::fs::create_dir_all(root.join("docker-nix-store")).unwrap();
        std::fs::write(root.join("docker-nix-store/blob.bin"), vec![0u8; 4096]).unwrap();

        let (removed, _) = reclaim_entries(
            &classify_retired_entries(root),
            "retired cache entry",
            /* dry_run = */ false,
        );

        assert_eq!(removed, 1, "only the retired entry is a candidate");
        assert!(
            !root.join("docker-nix-store").exists(),
            "the retired entry must be reclaimed"
        );
        for name in live {
            assert!(
                root.join(name).join("blob.bin").exists(),
                "{name} is a live cache and must survive the sweep"
            );
        }
    }

    /// `--deep` targets resolve only to regenerable dirs that actually exist.
    #[test]
    fn regenerable_targets_only_existing_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("stage0")).unwrap();
        std::fs::write(root.join("stage0/blob"), vec![0u8; 4096]).unwrap();
        std::fs::create_dir_all(root.join("oci")).unwrap();
        // default-microvm absent → not a target.

        let targets = regenerable_cache_targets(root);
        let names: Vec<String> = targets
            .iter()
            .map(|(e, _)| e.path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["stage0", "oci"]);
        assert!(targets[0].0.bytes >= 4096);
    }

    /// `reclaim_entries` removes on the live path, tallies without touching disk
    /// under dry-run.
    #[test]
    fn reclaim_entries_dry_run_is_a_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path().join("victim");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("f"), vec![0u8; 2048]).unwrap();
        let entries = vec![CacheEntry {
            bytes: dir_size(&d),
            path: d.clone(),
        }];

        let (n, b) = reclaim_entries(&entries, "test", /* dry_run = */ true);
        assert_eq!(n, 1);
        assert!(b >= 2048);
        assert!(d.exists(), "dry-run must not remove anything");

        let (n, _) = reclaim_entries(&entries, "test", /* dry_run = */ false);
        assert_eq!(n, 1);
        assert!(!d.exists(), "live run must remove the entry");
    }

    /// `cache info`'s breakdown is sorted largest-first and lists every
    /// entry.
    #[test]
    fn cache_dir_breakdown_sorted_and_includes_all_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("stage0")).unwrap();
        std::fs::write(root.join("stage0/a"), vec![0u8; 1024]).unwrap();
        std::fs::create_dir_all(root.join("ur-seed")).unwrap();
        std::fs::write(root.join("ur-seed/a"), vec![0u8; 8192]).unwrap();

        let rows = cache_dir_breakdown(root);
        assert_eq!(rows[0].0, "ur-seed", "largest entry first");
        assert!(rows.iter().any(|(n, _)| n == "stage0"));
    }

    /// The reclaim estimate must be the disk a delete actually returns.
    /// A materialized OCI rootfs is mostly symlinks: a walker that follows
    /// them re-walks whole subtrees and charges a link its target's blocks,
    /// which is how the dry run came to promise several times the disk that
    /// exists.
    #[cfg(unix)]
    #[test]
    fn dir_size_does_not_inflate_a_tree_full_of_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let payload = root.join("layer");
        std::fs::create_dir_all(payload.join("bin")).unwrap();
        std::fs::write(payload.join("bin/busybox"), vec![0u8; 256 * 1024]).unwrap();

        let real_bytes = dir_size(root);

        // The links an unpacked image carries: applets pointing at one binary,
        // and the `/usr/bin -> /bin` style directory alias beside them.
        for applet in ["sh", "ls", "cat", "cp", "mv", "rm", "sed", "awk"] {
            std::os::unix::fs::symlink(
                payload.join("bin/busybox"),
                payload.join("bin").join(applet),
            )
            .unwrap();
        }
        std::os::unix::fs::symlink(payload.join("bin"), root.join("usr-bin")).unwrap();

        let with_links = dir_size(root);
        assert!(
            with_links < real_bytes + 256 * 1024,
            "symlinks must not multiply the estimate: {real_bytes} bytes of \
             payload measured {with_links} once linked"
        );
    }

    /// The temp-file sweep deletes what the walker yields, so the walker must
    /// not reach through a link into a tree the operator did not ask to prune.
    #[cfg(unix)]
    #[test]
    fn walkdir_does_not_descend_through_a_symlinked_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("precious.tmp"), b"keep me").unwrap();

        let cache = tmp.path().join("cache");
        std::fs::create_dir_all(&cache).unwrap();
        std::os::unix::fs::symlink(&outside, cache.join("link")).unwrap();

        let reached: Vec<String> = walkdir(&cache)
            .unwrap()
            .iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(reached, vec!["link"], "the link is yielded, not followed");
    }

    /// The version-aware pack prune step reports what it removed (or would
    /// remove) in the same "would remove"/"removed" shape as the rest of
    /// `cache prune`'s output.
    #[test]
    fn pack_version_prune_report_reflects_dry_run() {
        assert_eq!(
            pack_version_prune_report(3, true),
            "(dry-run) Would remove 3 old pack version(s)."
        );
        assert_eq!(
            pack_version_prune_report(3, false),
            "Removed 3 old pack version(s)."
        );
        assert_eq!(
            pack_version_prune_report(0, false),
            "Removed 0 old pack version(s)."
        );
    }
}
