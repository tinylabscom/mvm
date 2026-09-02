//! `mvmctl cleanup` — remove old build artifacts (in-VM) and optionally
//! wipe host-side cache / state directories (`--cache` / `--state` /
//! `--nuclear`).
//!
//! Without any tier flag the command is the same lightweight in-VM
//! cleanup it has always been (clears the dev VM's `/tmp`, prunes
//! `~/.mvm/dev/builds/`, runs `nix-collect-garbage -d`). The tier
//! flags add host-side directory sweeps that run after the in-VM
//! step and are gated by a confirmation prompt.
//!
//! `--cache` and `--state` are selective, so they name the paths they
//! take. `--nuclear` is the opposite: it enumerates the mvm root and
//! removes every entry it finds, minus whatever `--keep-identity`
//! spares. Defining "everything" by subtraction is the point — the
//! allow-list this replaced spared any directory nobody remembered to
//! add to it, which had grown to most of the tree (`images`,
//! `machines`, `checkpoints`, `snapshots`, `instances`, `pool`,
//! `state`, `share`, `bin`, ...).
//!
//! Safety:
//! - Tier flags refuse to run if any VM is currently running, unless
//!   `--force` is set. Wiping `~/.mvm/vms/<id>/` or
//!   `~/.mvm/cache/builder-vm/vms/<id>/` while a supervisor is reading
//!   the state dir corrupts the running guest. Liveness goes through
//!   the shared `state_dir_has_live_process` probe so every backend's
//!   PID marker counts, not just libkrun's.
//! - `--nuclear` always requires an interactive text confirmation
//!   (`DELETE-EVERYTHING`). `--yes` does not bypass it.

use anyhow::{Context, Result, anyhow};
use clap::{ArgGroup, Args as ClapArgs};
use std::ffi::OsStr;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::ui;

use mvm_core::user_config::MvmConfig;
use mvm_runtime::shell;
use mvm_vmm::host::process_liveness::state_dir_has_live_process;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
#[command(group(
    ArgGroup::new("tier")
        .args(["cache", "state", "nuclear"])
        .multiple(false),
))]
pub(in crate::commands) struct Args {
    /// Number of newest in-VM build revisions to keep
    #[arg(long)]
    pub keep: Option<usize>,
    /// Remove all in-VM cached build revisions
    #[arg(long)]
    pub all: bool,

    /// Also wipe `~/.mvm/cache` (Stage 0 staging, builder VM artifacts).
    /// All cache contents are regenerable; the next build rebuilds them.
    #[arg(long)]
    pub cache: bool,
    /// Wipe `~/.mvm/cache` PLUS regenerable subdirs of `~/.mvm`
    /// (`dev`, `vms`, `log`, `dev-cluster`, `mock-vms`, `tool-staging`).
    /// Preserves identity (`keys`, `audit`, `volumes`, `secrets`,
    /// `config.toml`) and `templates`.
    #[arg(long)]
    pub state: bool,
    /// Wipe every entry under `~/.mvm`, leaving the (0700) root dir
    /// itself in place. Past audit logs become unverifiable under the
    /// new signer. Requires an interactive text confirmation; `--yes`
    /// does NOT bypass it.
    #[arg(long)]
    pub nuclear: bool,
    /// With `--nuclear`, spare the host's cryptographic identity:
    /// `keys`, `audit`, `attestation`, `secrets`, `secret-bindings`,
    /// `egress-ca`, `.secret-store.key`, `snapshot.key` and
    /// `config.toml`. Everything else under `~/.mvm` still goes.
    #[arg(long, requires = "nuclear")]
    pub keep_identity: bool,

    /// Print what would be removed by the tier sweep without removing it.
    /// Has no effect on the in-VM cleanup step.
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the y/N prompt for `--cache` / `--state`. `--nuclear` still
    /// requires its interactive text confirmation regardless of `--yes`.
    #[arg(long)]
    pub yes: bool,
    /// Allow the tier sweep to proceed even when a VM is running.
    /// Wiping live VM state corrupts the running guest — use only when
    /// the VM is already known-dead and the PID file is stale.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tier {
    Cache,
    State,
    Nuclear,
}

impl Tier {
    fn name(self) -> &'static str {
        match self {
            Tier::Cache => "cache",
            Tier::State => "state",
            Tier::Nuclear => "nuclear",
        }
    }
}

/// Whether a nuclear sweep spares the host's cryptographic identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    /// Delete identity material along with everything else.
    Wipe,
    /// Preserve [`IDENTITY_PATHS`] so past audit logs stay verifiable
    /// and stored secrets stay decryptable.
    Keep,
}

impl Identity {
    fn from_flag(keep: bool) -> Self {
        if keep { Identity::Keep } else { Identity::Wipe }
    }

    /// Entry names a sweep must skip under this setting.
    fn spared(self) -> &'static [&'static str] {
        match self {
            Identity::Wipe => &[],
            Identity::Keep => IDENTITY_PATHS,
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Identity::Wipe => "",
            Identity::Keep => " (identity preserved)",
        }
    }
}

/// Entries directly under the mvm root that `--keep-identity` spares.
///
/// Everything here is either a private key, material encrypted under
/// one, the audit chain those keys sign, or the hand-written
/// `config.toml` — the paths a rebuild cannot reproduce. They travel
/// together because sparing one without the others is useless:
/// dropping `keys` makes every past audit entry unverifiable, and
/// dropping `.secret-store.key` leaves `secrets` an undecryptable
/// blob. Everything else under the root is rebuildable, refetchable,
/// or regenerated on next use.
const IDENTITY_PATHS: &[&str] = &[
    "keys",
    "audit",
    "attestation",
    "secrets",
    "secret-bindings",
    "egress-ca",
    ".secret-store.key",
    "snapshot.key",
    "config.toml",
];

pub(in crate::commands) fn run(cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let tier = pick_tier(&args);

    let keep_count = if args.all { 0 } else { args.keep.unwrap_or(5) };
    if !args.all && keep_count == 0 {
        anyhow::bail!("--keep must be greater than 0 (or use --all)");
    }

    // Refuse host-side tier sweep if a VM is currently running, unless
    // --force overrides. Wipe-while-running would tear the supervisor
    // and its state dir apart. Check this before the in-VM cleanup so
    // a refused command leaves nothing half-done.
    if let Some(t) = tier
        && !args.force
        && let Some(running) = first_running_vm()
    {
        anyhow::bail!(
            "refusing to run cleanup --{} while VM '{}' appears to be running.\n\
             Stop it first (`mvmctl machine stop {}`), or pass --force to wipe anyway.",
            t.name(),
            running,
            running,
        );
    }

    // ---- in-VM cleanup (preserved behavior; runs every invocation) ----
    let disk_before = vm_disk_usage_pct();
    if let Some(pct) = disk_before {
        ui::info(&format!("Dev VM disk usage: {}%", pct));
    }
    ui::info("Clearing temporary files...");
    let _ = shell::run_in_vm("sudo rm -rf /tmp/* /var/tmp/* 2>/dev/null");

    let report = mvm_build::dev_build::cleanup_old_dev_builds(keep_count)?;
    if cli.verbose > 0 {
        if report.removed_paths.is_empty() {
            ui::info("No cached build paths removed.");
        } else {
            ui::info("Removed cached build paths:");
            for path in &report.removed_paths {
                println!("  {}", path);
            }
        }
    }
    if args.all {
        ui::success(&format!(
            "Removed {} cached build(s).",
            report.removed_count
        ));
    } else {
        ui::success(&format!(
            "Removed {} cached build(s), kept newest {}.",
            report.removed_count, keep_count
        ));
    }
    if disk_before.is_none() {
        ui::info("Skipping nix-collect-garbage: dev VM is not running.");
    } else {
        ui::info("Running nix-collect-garbage...");
        match shell::run_in_vm_stdout("nix-collect-garbage -d 2>&1 | tail -3") {
            Ok(output) => {
                let trimmed = output.trim();
                if !trimmed.is_empty() {
                    println!("{trimmed}");
                }
            }
            Err(e) => {
                ui::warn(&format!("nix-collect-garbage failed: {e}"));
                ui::info("Retrying after clearing Nix profile generations...");
                let _ = shell::run_in_vm("rm -rf ~/.local/state/nix/profiles/* 2>/dev/null");
                match shell::run_in_vm_stdout("nix-collect-garbage -d 2>&1 | tail -3") {
                    Ok(output) => {
                        let trimmed = output.trim();
                        if !trimmed.is_empty() {
                            println!("{trimmed}");
                        }
                    }
                    Err(e2) => ui::warn(&format!("nix-collect-garbage retry failed: {e2}")),
                }
            }
        }
    }
    let disk_after = vm_disk_usage_pct();
    if let Some(pct) = disk_after {
        let freed_msg = match disk_before {
            Some(before) if before > pct => format!(" (freed {}%)", before - pct),
            _ => String::new(),
        };
        ui::success(&format!("Dev VM disk usage: {}%{}", pct, freed_msg));
    }
    let removed = report.removed_count;
    mvm_core::audit_emit!(SlotPrune, "source=cleanup removed={removed}");

    // ---- host-side tier sweep (new) ----
    if let Some(t) = tier {
        let data_root = PathBuf::from(mvm_core::config::mvm_home());
        let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let identity = Identity::from_flag(args.keep_identity);
        let plan = build_plan_at(&data_root, &cache_root, t, identity);

        ui::info(&format!("Cleanup tier: {}{}", t.name(), identity.suffix()));
        if plan.paths.is_empty() {
            ui::info("Nothing to wipe — none of the tier's paths exist on disk.");
            return Ok(());
        }
        ui::info(&format!("Will remove {} path(s):", plan.paths.len()));
        for path in &plan.paths {
            let size = dir_size(path);
            println!(
                "  {} ({})",
                path.display(),
                super::super::shared::human_bytes(size)
            );
        }

        if args.dry_run {
            ui::info("(dry-run) No paths removed.");
            return Ok(());
        }

        if !confirm_tier(t, identity, args.yes)? {
            ui::info("Cancelled.");
            return Ok(());
        }

        let spinner = ui::spinner("Cleaning mvm cache...");
        let exec_result = execute_plan(&plan);
        spinner.finish_and_clear();
        let exec = exec_result?;
        ui::success(&format!(
            "Cleanup tier {}: removed {} path(s), freed {}",
            t.name(),
            exec.paths_removed,
            super::super::shared::human_bytes(exec.bytes_freed),
        ));
        let tier_name = t.name();
        let bytes = exec.bytes_freed;
        let count = exec.paths_removed;
        mvm_core::audit_emit!(
            Cleanup,
            "tier={tier_name} paths_removed={count} bytes_freed={bytes}"
        );
    }

    Ok(())
}

fn pick_tier(args: &Args) -> Option<Tier> {
    if args.nuclear {
        Some(Tier::Nuclear)
    } else if args.state {
        Some(Tier::State)
    } else if args.cache {
        Some(Tier::Cache)
    } else {
        None
    }
}

/// Prompt the user to confirm a tier sweep. `--nuclear` always requires
/// an interactive text confirmation (`DELETE-EVERYTHING`) and ignores
/// `--yes` — with or without `--keep-identity`, since it still destroys
/// templates, machines, checkpoints and images irreversibly.
/// `--cache`/`--state` accept a y/N prompt that `--yes` can bypass.
fn confirm_tier(tier: Tier, identity: Identity, yes_flag: bool) -> Result<bool> {
    if tier == Tier::Nuclear {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "--nuclear requires an interactive terminal for confirmation. \
                 Run from a TTY."
            );
        }
        match identity {
            Identity::Wipe => ui::warn(
                "NUCLEAR will delete every entry under the mvm root, \
                 including the host signer keypair, audit chain, \
                 attestation identity, secrets and config.toml. Past \
                 audit logs will become unverifiable. Pass --keep-identity \
                 to spare them.",
            ),
            Identity::Keep => ui::warn(
                "NUCLEAR will delete every entry under the mvm root except \
                 the host's cryptographic identity: templates, machines, \
                 images, checkpoints and snapshots all go.",
            ),
        }
        let entered = ui::prompt_text("Type DELETE-EVERYTHING to confirm:")
            .context("reading destructive confirmation from interactive prompt")?;
        Ok(entered.trim() == "DELETE-EVERYTHING")
    } else if yes_flag {
        Ok(true)
    } else {
        Ok(ui::confirm(&format!("Proceed with --{}?", tier.name())))
    }
}

/// Returns the name of the first VM that appears to be running, or
/// None if none are. Errors during the probe are conservative: a
/// failed readdir returns None (the check is a guardrail, not a
/// guarantee).
fn first_running_vm() -> Option<String> {
    first_running_vm_at(&mvm_core::config::vms_dir())
}

/// `first_running_vm` against an explicit VM state root, so tests can
/// point it at a tempdir.
///
/// Liveness goes through the shared [`state_dir_has_live_process`]
/// probe rather than a local `libkrun.pid` read. That probe knows all
/// five supervisor PID markers; a `libkrun.pid`-only check reports a
/// running HVF, Firecracker or QEMU guest as stopped, and HVF is the
/// auto-detect default on macOS 26+. It also treats a zombie as dead,
/// which a bare `kill(pid, 0)` does not.
fn first_running_vm_at(vms_root: &Path) -> Option<String> {
    std::fs::read_dir(vms_root)
        .ok()?
        .flatten()
        .find(|entry| state_dir_has_live_process(&entry.path()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CleanupPlan {
    paths: Vec<PathBuf>,
}

/// Build the set of paths a tier sweep would remove, anchored at the
/// supplied data + cache roots. Tests pass tempdirs; production passes
/// `mvm_home()` / `mvm_cache_dir()`. A path is only added if it
/// currently exists on disk — the plan IS the actual delete list, not
/// a hypothetical superset.
fn build_plan_at(
    data_root: &Path,
    cache_root: &Path,
    tier: Tier,
    identity: Identity,
) -> CleanupPlan {
    if tier == Tier::Nuclear {
        // No `cache_root`: `mvm_cache_dir()` is unconditionally
        // `<mvm_home>/cache`, so the root walk already covers it.
        return nuclear_plan(data_root, identity);
    }
    selective_plan(data_root, cache_root, tier)
}

/// The `--cache` / `--state` plan: enumerate the regenerable subdirs
/// those tiers are defined to take. Enumerating is correct here —
/// these tiers are selective by intent, so a directory that isn't
/// named is one they are supposed to leave alone.
fn selective_plan(data_root: &Path, cache_root: &Path, tier: Tier) -> CleanupPlan {
    let mut paths = Vec::new();
    if cache_root.exists() {
        paths.push(cache_root.to_path_buf());
    }
    if tier == Tier::State {
        for sub in &[
            "dev",
            "vms",
            "log",
            "dev-cluster",
            "mock-vms",
            "tool-staging",
        ] {
            let p = data_root.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
    }
    CleanupPlan { paths }
}

/// The `--nuclear` plan: every entry under the mvm root, minus the
/// identity material `--keep-identity` spares. The root directory
/// itself survives so its 0700 mode cannot be re-established wrong by
/// whichever command next writes under it. That used to name a helper
/// which nothing called, so the re-establishment it described never
/// happened; `mvm_core::config::create_private_dir` is what performs it
/// now, on the whole chain, from any writer.
///
/// This is deliberately defined by subtraction. The enumerated version
/// it replaced named thirteen paths and therefore spared every state
/// directory added after it was written — by then `images`,
/// `machines`, `checkpoints`, `snapshots`, `instances`, `pool`,
/// `state`, `share`, `bin`, `host-agent`, `observers` and `run`, or
/// most of the tree by size. A subsystem that adds a directory is now
/// covered the day it lands, with no list to remember.
fn nuclear_plan(data_root: &Path, identity: Identity) -> CleanupPlan {
    let spared = identity.spared();
    let mut paths: Vec<PathBuf> = match std::fs::read_dir(data_root) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| !spared.iter().any(|s| OsStr::new(s) == e.file_name()))
            .map(|e| e.path())
            .collect(),
        Err(_) => Vec::new(),
    };
    // readdir order is unspecified; sort so the preview the user
    // confirms lists the same paths in the same order every run.
    paths.sort();
    CleanupPlan { paths }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ExecutionReport {
    paths_removed: usize,
    bytes_freed: u64,
}

fn execute_plan(plan: &CleanupPlan) -> Result<ExecutionReport> {
    let mut report = ExecutionReport::default();
    for path in &plan.paths {
        let size = dir_size(path);
        if path.is_dir() {
            std::fs::remove_dir_all(path)
                .map_err(|e| anyhow!("removing {}: {e}", path.display()))?;
        } else if path.exists() {
            std::fs::remove_file(path).map_err(|e| anyhow!("removing {}: {e}", path.display()))?;
        }
        report.paths_removed += 1;
        report.bytes_freed += size;
    }
    Ok(report)
}

/// Disk a delete of `path` would return. Shared with `cache prune` so the two
/// verbs never quote different numbers for the same tree.
fn dir_size(path: &Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(path)
}

/// Read the dev VM root filesystem usage percentage.
fn vm_disk_usage_pct() -> Option<u8> {
    let output = shell::run_in_vm_stdout("df --output=pcent / 2>/dev/null | tail -1").ok()?;
    output.trim().trim_end_matches('%').trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn touch(p: &Path, bytes: usize) {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(p, vec![b'x'; bytes]).unwrap();
    }

    fn populate(root: &Path) {
        touch(&root.join("keys/host-signer.ed25519"), 32);
        touch(&root.join("keys/host-signer.pub"), 32);
        touch(&root.join("audit/local.jsonl"), 4096);
        touch(&root.join("volumes/registry.json"), 64);
        touch(&root.join("secrets/master"), 128);
        touch(&root.join("templates/foo/artifacts/r1/build"), 2048);
        touch(&root.join("dev/builds/abc"), 1024);
        touch(&root.join("vms/dev/libkrun.pid"), 6);
        touch(&root.join("log/launch.log"), 512);
        touch(&root.join("dev-cluster/state"), 100);
        touch(&root.join("mock-vms/.keep"), 1);
        touch(&root.join("tool-staging/scratch"), 50);
        touch(&root.join("config.toml"), 80);
        // Directories that postdate the enumerated nuclear plan. On a
        // real host these are the bulk of the tree, and the allow-list
        // spared every one of them.
        touch(&root.join("images/sha256-abc/rootfs.ext4"), 8192);
        touch(&root.join("machines/web/machine.json"), 256);
        touch(&root.join("checkpoints/web/mem.snap"), 4096);
        touch(&root.join("snapshots/web/state.bin"), 2048);
        touch(&root.join("instances/one/meta.json"), 64);
        touch(&root.join("pool/standby/a"), 32);
        touch(&root.join("state/inventory.json"), 128);
        touch(&root.join("share/dev/socket"), 16);
        touch(&root.join("bin/mvm-libkrun-supervisor"), 1024);
        touch(&root.join("host-agent/local/agent.sock"), 8);
        touch(&root.join("observers/one.json"), 24);
        touch(&root.join("attestation/identity.ed25519"), 32);
        touch(&root.join("egress-ca/ca.key"), 32);
        touch(&root.join("secret-bindings/one.json"), 48);
        touch(&root.join(".secret-store.key"), 32);
        touch(&root.join("snapshot.key"), 32);
    }

    /// Entry names directly under `root`, for asserting plan contents.
    fn plan_names(plan: &CleanupPlan, root: &Path) -> Vec<PathBuf> {
        plan.paths
            .iter()
            .map(|p| p.strip_prefix(root).unwrap_or(p).to_path_buf())
            .collect()
    }

    fn populate_cache(root: &Path) {
        touch(&root.join("builder-vm/nix-store-aarch64.img"), 16384);
        touch(&root.join("stage0/nix-seed-aarch64.tar.xz"), 4096);
    }

    #[test]
    fn tier_cache_only_targets_cache_root() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Cache, Identity::Wipe);
        assert_eq!(plan.paths, vec![cache.path().to_path_buf()]);
    }

    #[test]
    fn tier_state_adds_regenerable_subdirs_preserves_identity_and_templates() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::State, Identity::Wipe);
        let names: Vec<_> = plan
            .paths
            .iter()
            .map(|p| p.strip_prefix(data.path()).unwrap_or(p).to_path_buf())
            .collect();
        assert!(plan.paths[0].starts_with(cache.path()));
        for sub in &[
            "dev",
            "vms",
            "log",
            "dev-cluster",
            "mock-vms",
            "tool-staging",
        ] {
            assert!(
                names.iter().any(|p| p == Path::new(sub)),
                "expected `{sub}` in state plan: {names:?}",
            );
        }
        for sub in &["keys", "audit", "volumes", "secrets", "templates"] {
            assert!(
                !names.iter().any(|p| p == Path::new(sub)),
                "state tier must not include `{sub}` (identity/template path)",
            );
        }
        assert!(
            !names.iter().any(|p| p == Path::new("config.toml")),
            "state tier must not include config.toml",
        );
    }

    #[test]
    fn tier_nuclear_takes_every_entry_under_the_root() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let names = plan_names(&plan, data.path());

        let mut on_disk: Vec<PathBuf> = std::fs::read_dir(data.path())
            .unwrap()
            .flatten()
            .map(|e| PathBuf::from(e.file_name()))
            .collect();
        on_disk.sort();
        let mut got = names.clone();
        got.sort();
        assert_eq!(got, on_disk, "nuclear must take every root entry");
    }

    /// The regression that motivated replacing the enumerated plan: a
    /// directory no list knows about must still be swept. This is the
    /// assertion the allow-list version cannot pass at any length,
    /// because the failure mode was always the next unlisted name.
    #[test]
    fn tier_nuclear_covers_a_directory_no_list_knows_about() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        touch(&data.path().join("some-future-subsystem/state.db"), 512);

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let names = plan_names(&plan, data.path());
        assert!(
            names
                .iter()
                .any(|p| p == Path::new("some-future-subsystem")),
            "nuclear plan missing the unlisted dir: {names:?}",
        );
    }

    #[test]
    fn tier_nuclear_keep_identity_spares_exactly_the_identity_paths() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Keep);
        let names = plan_names(&plan, data.path());

        for sub in IDENTITY_PATHS {
            assert!(
                !names.iter().any(|p| p == Path::new(sub)),
                "--keep-identity must spare `{sub}`: {names:?}",
            );
        }
        // Everything else still goes — sparing identity is not sparing
        // the workload state that makes nuclear worth running.
        for sub in &["images", "checkpoints", "snapshots", "templates", "dev"] {
            assert!(
                names.iter().any(|p| p == Path::new(sub)),
                "--keep-identity must still take `{sub}`: {names:?}",
            );
        }
    }

    #[test]
    fn tier_nuclear_empties_the_root_but_leaves_it_in_place() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        execute_plan(&plan).unwrap();

        assert!(data.path().is_dir(), "the mvm root itself must survive");
        assert_eq!(
            std::fs::read_dir(data.path()).unwrap().count(),
            0,
            "the mvm root must be empty",
        );
    }

    /// `mvm_cache_dir()` is always `<mvm_home>/cache`, so nuclear picks
    /// the cache up from the root walk and lists it exactly once.
    #[test]
    fn tier_nuclear_lists_the_in_root_cache_exactly_once() {
        let data = tempdir().unwrap();
        let cache = data.path().join("cache");
        populate(data.path());
        populate_cache(&cache);

        let plan = build_plan_at(data.path(), &cache, Tier::Nuclear, Identity::Wipe);
        let hits = plan.paths.iter().filter(|p| **p == cache).count();
        assert_eq!(
            hits, 1,
            "in-root cache listed {hits} times: {:?}",
            plan.paths
        );
    }

    #[test]
    fn plan_skips_paths_that_dont_exist() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        touch(&data.path().join("keys/host-signer.ed25519"), 32);
        touch(&data.path().join("dev/builds/x"), 8);

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let names: Vec<_> = plan
            .paths
            .iter()
            .map(|p| p.strip_prefix(data.path()).unwrap_or(p).to_path_buf())
            .collect();
        assert!(names.iter().any(|p| p == Path::new("dev")));
        assert!(names.iter().any(|p| p == Path::new("keys")));
        for sub in &["audit", "secrets", "templates", "vms", "config.toml"] {
            assert!(
                !names.iter().any(|p| p == Path::new(sub)),
                "missing `{sub}` should not be in plan",
            );
        }
    }

    #[test]
    fn execute_plan_removes_paths_and_reports_bytes() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear, Identity::Wipe);
        let total_in_plan: u64 = plan.paths.iter().map(|p| dir_size(p)).sum();
        let report = execute_plan(&plan).unwrap();

        assert_eq!(report.paths_removed, plan.paths.len());
        assert_eq!(report.bytes_freed, total_in_plan);
        for p in &plan.paths {
            assert!(!p.exists(), "{} should be removed", p.display());
        }
    }

    /// The estimate must cover every file in the tree. It measures allocated
    /// blocks rather than apparent length, so the floor is the payload.
    #[test]
    fn dir_size_sums_recursive_file_bytes() {
        let dir = tempdir().unwrap();
        touch(&dir.path().join("a/b/c.bin"), 100);
        touch(&dir.path().join("a/d.bin"), 50);
        touch(&dir.path().join("e.bin"), 25);
        assert!(dir_size(dir.path()) >= 175, "{}", dir_size(dir.path()));
    }

    #[test]
    fn dir_size_handles_single_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("just-one.bin");
        touch(&f, 42);
        assert!(dir_size(&f) >= 42, "{}", dir_size(&f));
    }

    /// A `cleanup` estimate is quoted to an operator deciding whether to run
    /// it, so it must not promise disk that a delete cannot return. A tree of
    /// links to one payload frees the payload once.
    #[cfg(unix)]
    #[test]
    fn dir_size_is_not_inflated_by_links_to_one_payload() {
        let dir = tempdir().unwrap();
        let payload = dir.path().join("payload.bin");
        touch(&payload, 128 * 1024);
        let baseline = dir_size(dir.path());

        std::os::unix::fs::symlink(&payload, dir.path().join("soft")).unwrap();
        std::fs::hard_link(&payload, dir.path().join("hard")).unwrap();

        let with_links = dir_size(dir.path());
        assert!(
            with_links < baseline + 128 * 1024,
            "links must not multiply the estimate: {baseline} became {with_links}"
        );
    }

    /// A reaped child's PID: guaranteed to name no live process.
    fn dead_pid() -> u32 {
        let mut child = std::process::Command::new("/usr/bin/true")
            .spawn()
            .expect("spawning /usr/bin/true");
        let pid = child.id();
        child.wait().expect("reaping /usr/bin/true");
        pid
    }

    /// HVF is the auto-detect default on macOS 26+, and its supervisor
    /// writes `hvf.pid`. A guard that only reads `libkrun.pid` waves
    /// the sweep through while that guest is running.
    #[test]
    fn running_vm_guard_sees_a_non_libkrun_backend() {
        for marker in &["hvf.pid", "fc.pid", "qemu.pid", "pid"] {
            let vms = tempdir().unwrap();
            let dir = vms.path().join("web");
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(marker), std::process::id().to_string()).unwrap();
            assert_eq!(
                first_running_vm_at(vms.path()).as_deref(),
                Some("web"),
                "`{marker}` must read as running",
            );
        }
    }

    #[test]
    fn running_vm_guard_ignores_a_dead_pid() {
        let vms = tempdir().unwrap();
        let dir = vms.path().join("web");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("libkrun.pid"), dead_pid().to_string()).unwrap();
        assert_eq!(first_running_vm_at(vms.path()), None);
    }

    #[test]
    fn running_vm_guard_returns_none_on_an_empty_root() {
        let vms = tempdir().unwrap();
        assert_eq!(first_running_vm_at(vms.path()), None);
        assert_eq!(first_running_vm_at(&vms.path().join("nope")), None);
    }

    #[test]
    fn pick_tier_priority_nuclear_wins() {
        // Clap's ArgGroup enforces mutual exclusion at parse time, but the
        // pick_tier helper itself must be deterministic when called from
        // tests that construct `Args` directly and bypass clap.
        let args = Args {
            keep: None,
            all: false,
            cache: true,
            state: true,
            nuclear: true,
            keep_identity: false,
            dry_run: false,
            yes: false,
            force: false,
        };
        assert_eq!(pick_tier(&args), Some(Tier::Nuclear));
    }

    #[test]
    fn pick_tier_returns_none_when_no_tier_flag_set() {
        let args = Args {
            keep: None,
            all: false,
            cache: false,
            state: false,
            nuclear: false,
            keep_identity: false,
            dry_run: false,
            yes: false,
            force: false,
        };
        assert_eq!(pick_tier(&args), None);
    }
}
