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
//! Safety:
//! - Tier flags refuse to run if any VM is currently running, unless
//!   `--force` is set. Wiping `~/.mvm/vms/<id>/` or
//!   `~/.cache/mvm/builder-vm/vms/<id>/` while a supervisor is reading
//!   the state dir corrupts the running guest.
//! - `--nuclear` always requires an interactive text confirmation
//!   (`DELETE-EVERYTHING`). `--yes` does not bypass it.

use anyhow::{Result, anyhow};
use clap::{ArgGroup, Args as ClapArgs};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::ui;

use mvm::shell;
use mvm_core::user_config::MvmConfig;

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
    /// Print each cached in-VM build path that gets removed
    #[arg(long)]
    pub verbose: bool,

    /// Also wipe `~/.cache/mvm` (Stage 0 staging, builder VM artifacts).
    /// All cache contents are regenerable; the next `dev up` rebuilds them.
    #[arg(long)]
    pub cache: bool,
    /// Wipe `~/.cache/mvm` PLUS regenerable subdirs of `~/.mvm`
    /// (`dev`, `vms`, `log`, `dev-cluster`, `mock-vms`, `tool-staging`).
    /// Preserves identity (`keys`, `audit`, `volumes`, `secrets`,
    /// `config.toml`) and `templates`.
    #[arg(long)]
    pub state: bool,
    /// Wipe everything `--state` covers PLUS identity (`keys`, `audit`,
    /// `volumes`, `secrets`, `config.toml`) and `templates`. Past audit
    /// logs become unverifiable under the new signer. Requires an
    /// interactive text confirmation; `--yes` does NOT bypass it.
    #[arg(long)]
    pub nuclear: bool,

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

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
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
             Stop it first (`mvmctl stop {}` or `mvmctl dev down`), or pass --force to wipe anyway.",
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
    if args.verbose {
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
        let data_root = PathBuf::from(mvm_core::config::mvm_data_dir());
        let cache_root = PathBuf::from(mvm_core::config::mvm_cache_dir());
        let plan = build_plan_at(&data_root, &cache_root, t);

        ui::info(&format!("Cleanup tier: {}", t.name()));
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

        if !confirm_tier(t, args.yes)? {
            ui::info("Cancelled.");
            return Ok(());
        }

        let exec = execute_plan(&plan)?;
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
/// `--yes`. `--cache`/`--state` accept a y/N prompt that `--yes` can bypass.
fn confirm_tier(tier: Tier, yes_flag: bool) -> Result<bool> {
    if tier == Tier::Nuclear {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(
                "--nuclear requires an interactive terminal for confirmation. \
                 Run from a TTY."
            );
        }
        ui::warn(
            "NUCLEAR will delete the host signer keypair, audit chain, \
             sealed-deps master keys, secrets, config.toml, and templates. \
             Past audit logs will become unverifiable.",
        );
        let entered = inquire::Text::new("Type DELETE-EVERYTHING to confirm:")
            .prompt()
            .map_err(|e| anyhow!("prompt aborted: {e}"))?;
        Ok(entered.trim() == "DELETE-EVERYTHING")
    } else if yes_flag {
        Ok(true)
    } else {
        Ok(ui::confirm(&format!("Proceed with --{}?", tier.name())))
    }
}

/// Returns the name of the first VM that appears to be running, or
/// None if none are. Probes both the Apple Container dev VM and any
/// libkrun-managed VM whose `~/.mvm/vms/<id>/libkrun.pid` points at
/// a live process. Errors during the probe are conservative: a failed
/// readdir returns None (the check is a guardrail, not a guarantee).
fn first_running_vm() -> Option<String> {
    if super::apple_container::is_apple_container_dev_running() {
        return Some("mvm-dev (Apple Container)".to_string());
    }
    let vms_root = PathBuf::from(mvm_core::config::mvm_data_dir()).join("vms");
    let entries = std::fs::read_dir(&vms_root).ok()?;
    for entry in entries.flatten() {
        let pid_path = entry.path().join("libkrun.pid");
        if !pid_path.exists() {
            continue;
        }
        let Ok(pid_text) = std::fs::read_to_string(&pid_path) else {
            continue;
        };
        let Ok(pid) = pid_text.trim().parse::<i32>() else {
            continue;
        };
        if pid_alive(pid) {
            let name = entry.file_name().to_string_lossy().into_owned();
            return Some(name);
        }
    }
    None
}

fn pid_alive(pid: i32) -> bool {
    // SAFETY: kill(pid, 0) does not deliver a signal; it only validates
    // that the kernel can address `pid`. ESRCH -> dead; 0 / EPERM -> alive.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    // EPERM means the process exists but we lack permission to signal —
    // still alive for our purposes.
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CleanupPlan {
    paths: Vec<PathBuf>,
}

/// Build the set of paths a tier sweep would remove, anchored at the
/// supplied data + cache roots. Tests pass tempdirs; production passes
/// `mvm_data_dir()` / `mvm_cache_dir()`. A path is only added if it
/// currently exists on disk — the plan IS the actual delete list, not
/// a hypothetical superset.
fn build_plan_at(data_root: &Path, cache_root: &Path, tier: Tier) -> CleanupPlan {
    let mut paths = Vec::new();
    if cache_root.exists() {
        paths.push(cache_root.to_path_buf());
    }
    if matches!(tier, Tier::State | Tier::Nuclear) {
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
    if tier == Tier::Nuclear {
        for sub in &["keys", "audit", "volumes", "secrets", "templates"] {
            let p = data_root.join(sub);
            if p.exists() {
                paths.push(p);
            }
        }
        let cfg = data_root.join("config.toml");
        if cfg.exists() {
            paths.push(cfg);
        }
    }
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

fn dir_size(path: &Path) -> u64 {
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&p) else {
            continue;
        };
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                stack.push(entry_path);
            } else if let Ok(meta) = entry_path.metadata() {
                total += meta.len();
            }
        }
    }
    total
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

        let plan = build_plan_at(data.path(), cache.path(), Tier::Cache);
        assert_eq!(plan.paths, vec![cache.path().to_path_buf()]);
    }

    #[test]
    fn tier_state_adds_regenerable_subdirs_preserves_identity_and_templates() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::State);
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
    fn tier_nuclear_includes_identity_templates_and_config() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        populate(data.path());
        populate_cache(cache.path());

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear);
        let names: Vec<_> = plan
            .paths
            .iter()
            .map(|p| p.strip_prefix(data.path()).unwrap_or(p).to_path_buf())
            .collect();
        for sub in &[
            "dev",
            "vms",
            "log",
            "dev-cluster",
            "mock-vms",
            "tool-staging",
            "keys",
            "audit",
            "volumes",
            "secrets",
            "templates",
            "config.toml",
        ] {
            assert!(
                names.iter().any(|p| p == Path::new(sub)),
                "nuclear plan missing `{sub}`: {names:?}",
            );
        }
    }

    #[test]
    fn plan_skips_paths_that_dont_exist() {
        let data = tempdir().unwrap();
        let cache = tempdir().unwrap();
        touch(&data.path().join("keys/host-signer.ed25519"), 32);
        touch(&data.path().join("dev/builds/x"), 8);

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear);
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

        let plan = build_plan_at(data.path(), cache.path(), Tier::Nuclear);
        let total_in_plan: u64 = plan.paths.iter().map(|p| dir_size(p)).sum();
        let report = execute_plan(&plan).unwrap();

        assert_eq!(report.paths_removed, plan.paths.len());
        assert_eq!(report.bytes_freed, total_in_plan);
        for p in &plan.paths {
            assert!(!p.exists(), "{} should be removed", p.display());
        }
    }

    #[test]
    fn dir_size_sums_recursive_file_bytes() {
        let dir = tempdir().unwrap();
        touch(&dir.path().join("a/b/c.bin"), 100);
        touch(&dir.path().join("a/d.bin"), 50);
        touch(&dir.path().join("e.bin"), 25);
        assert_eq!(dir_size(dir.path()), 175);
    }

    #[test]
    fn dir_size_handles_single_file() {
        let dir = tempdir().unwrap();
        let f = dir.path().join("just-one.bin");
        touch(&f, 42);
        assert_eq!(dir_size(&f), 42);
    }

    #[test]
    fn pick_tier_priority_nuclear_wins() {
        // Clap's ArgGroup enforces mutual exclusion at parse time, but the
        // pick_tier helper itself must be deterministic when called from
        // tests that construct `Args` directly and bypass clap.
        let args = Args {
            keep: None,
            all: false,
            verbose: false,
            cache: true,
            state: true,
            nuclear: true,
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
            verbose: false,
            cache: false,
            state: false,
            nuclear: false,
            dry_run: false,
            yes: false,
            force: false,
        };
        assert_eq!(pick_tier(&args), None);
    }
}
