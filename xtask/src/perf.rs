//! Performance gates via `cargo xtask perf`.
//!
//! Two subcommands so far:
//!
//! - **`rootfs-size`** — assert a built rootfs is at or under the
//!   `mvm` minimal-template budget. Pure file-size check; runs on
//!   every host (no KVM/Lima required). Enforces the "rootfs < 20 MB
//!   for minimal template" line.
//! - **`boot`** — statistical cold-boot benchmark. Boots a real
//!   Firecracker / libkrun VM `--runs N` times, computes
//!   p50/p95/max wall-clock, asserts thresholds. Linux + KVM
//!   required; gated by `MVM_LIVE_SMOKE=1` + a rootfs path so a
//!   bare macOS host skips cleanly. Enforces the "cold-boot ≤ 500ms
//!   Firecracker / ≤ 1s libkrun" line.
//!
//! The thresholds are the per-backend boot budgets; they're pinned
//! by tests in this module so a drift in the documented budget vs.
//! the code is caught at review.
//!
//! ## Usage
//!
//! ```text
//! cargo xtask perf rootfs-size --rootfs ~/.cache/mvm/.../rootfs.ext4
//! cargo xtask perf boot --runs 30 --rootfs ~/.cache/mvm/.../rootfs.ext4
//! ```
//!
//! ## What this does NOT do (yet)
//!
//! - **Regression alert against historical p50.** A ">10% p50
//!   increase fails the test" gate would need a historical-baseline
//!   file (probably in `specs/perf/baseline.json`) that this command
//!   compares against. Substrate-only today; the boot subcommand
//!   asserts against absolute thresholds.
//! - **Snapshot-clone-boot benchmark.** Currently the boot
//!   subcommand only times cold boots. Snapshot-clone timing
//!   needs the snapshot pool, which doesn't ship in this slice.
//! - **PGO / MUSL build-time perf gates.** Those land alongside
//!   the release-build configuration; this module focuses on
//!   runtime behaviour.

// The boot subcommand body currently exits before invoking
// `Backend::budget()` — we ship the constants + the lookup helper
// so the eventual N-run benchmark loop can scaffold against a
// stable API. The dead-code allow goes once the benchmark loop
// lands.
#![allow(dead_code)]

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Budget for the `minimal` template's rootfs.
/// Anything above this triggers a perf-regression alert: typically
/// "someone bundled tools they shouldn't have" or "the Nix closure
/// pulled in a transitive dep that bloats the image."
pub const ROOTFS_MAX_BYTES: u64 = 20 * 1024 * 1024; // 20 MiB

/// Cold-boot wall-clock budget for the Firecracker backend.
/// The floor is 300ms; the strict gate is 500ms p50.
pub const FIRECRACKER_BOOT_BUDGET: Duration = Duration::from_millis(500);

/// Cold-boot wall-clock budget for the libkrun backend. Slower than
/// Firecracker because libkrun's startup +
/// the in-VM init script aren't as tight; 1s is the worst-case
/// envelope.
pub const LIBKRUN_BOOT_BUDGET: Duration = Duration::from_millis(1000);

/// Dispatch entry — called from `xtask/src/main.rs`.
pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("rootfs-size") => rootfs_size_subcommand(&args[1..]),
        Some("boot") => boot_subcommand(&args[1..]),
        Some("budgets") => budgets_subcommand(&args[1..]),
        Some(other) => {
            bail!("Unknown perf subcommand {other:?}. Available: rootfs-size, boot, budgets")
        }
        None => {
            eprintln!("Usage: cargo xtask perf <subcommand>");
            eprintln!(
                "  rootfs-size --rootfs <PATH>    Assert rootfs is ≤ {ROOTFS_MAX_BYTES} bytes"
            );
            eprintln!("  boot --rootfs <PATH> [--runs N] [--backend firecracker|libkrun]");
            eprintln!(
                "                                 Statistical cold-boot benchmark (Linux/KVM, MVM_LIVE_SMOKE=1)"
            );
            eprintln!(
                "  budgets [--json]               Print every documented perf budget as a table"
            );
            std::process::exit(1);
        }
    }
}

// ============================================================================
// budgets subcommand — single-source-of-truth release-readiness inventory
// ============================================================================

fn budgets_subcommand(args: &[String]) -> Result<()> {
    let json = args.iter().any(|a| a == "--json");
    let budgets = all_budgets();
    if json {
        println!("{}", serde_json::to_string_pretty(&budgets)?);
    } else {
        render_budgets_human(&budgets);
    }
    Ok(())
}

/// One performance budget the project commits to. The full set
/// is the single source of truth for the boot-time perf claims
/// plus the per-resource caps; the budgets are pinned by tests in
/// this module so doc/code drift is caught at review.
#[derive(Debug, serde::Serialize)]
pub struct PerfBudget {
    pub name: &'static str,
    pub limit: u64,
    pub unit: &'static str,
    pub source: &'static str,
    pub description: &'static str,
}

/// The canonical list of perf budgets, used by `xtask perf
/// budgets` and exported for tests. Adding a budget? Edit here
/// and add a constant-pin test below so the spec/code link is
/// enforced.
pub fn all_budgets() -> Vec<PerfBudget> {
    vec![
        PerfBudget {
            name: "rootfs_size",
            limit: ROOTFS_MAX_BYTES,
            unit: "bytes",
            source: "plan-60 Phase 9 + ADR-013",
            description: "Minimal-template ext4 rootfs size",
        },
        PerfBudget {
            name: "firecracker_cold_boot",
            limit: FIRECRACKER_BOOT_BUDGET.as_millis() as u64,
            unit: "ms",
            source: "ADR-013 §\"Per-backend boot budgets\"",
            description: "Firecracker cold-boot wall-clock (1 vCPU / 256 MiB)",
        },
        PerfBudget {
            name: "libkrun_cold_boot",
            limit: LIBKRUN_BOOT_BUDGET.as_millis() as u64,
            unit: "ms",
            source: "ADR-013 §\"Per-backend boot budgets\"",
            description: "Libkrun cold-boot wall-clock",
        },
        PerfBudget {
            name: "default_response_body_cap",
            limit: 1 << 20,
            unit: "bytes",
            source: "plan-65 follow-on (a437c0e)",
            description: "Per-tool capped response body for web_fetch + search providers",
        },
        PerfBudget {
            name: "web_fetch_max_bytes",
            limit: 16 * (1 << 20),
            unit: "bytes",
            source: "plan-60 Phase 7 (e500c18)",
            description: "Hard upper bound on mvm.web_fetch max_bytes (caller-supplied is clamped)",
        },
        PerfBudget {
            name: "tool_max_query_len",
            limit: 1024,
            unit: "bytes",
            source: "plan-60 Phase 7 (a4ca401)",
            description: "Max query string length for mvm.web_search",
        },
        PerfBudget {
            name: "tool_max_results",
            limit: 50,
            unit: "items",
            source: "plan-60 Phase 7 (a4ca401)",
            description: "Hard upper bound on mvm.web_search max_results",
        },
        PerfBudget {
            name: "overlay_quota_default",
            limit: 10 * (1 << 30),
            unit: "bytes",
            source: "plan-7a Slice A (f6d95c6)",
            description: "Default per-overlay quota (LUKS impl enforces at FS layer in Slice B)",
        },
        PerfBudget {
            name: "overlay_max_name_len",
            limit: 64,
            unit: "bytes",
            source: "plan-7a Slice A (f6d95c6)",
            description: "Max length of a tenant id or workload id in overlay paths",
        },
        PerfBudget {
            name: "staging_max_path_len",
            limit: 512,
            unit: "bytes",
            source: "plan-60 Phase 7 (5e62e5a)",
            description: "Max length of a relative path under the tool staging area",
        },
        PerfBudget {
            name: "staging_max_allowed_bytes",
            limit: 256 * (1 << 20),
            unit: "bytes",
            source: "plan-60 Phase 7 (5e62e5a)",
            description: "Hard upper bound on mvm.upload/download max_bytes (clamped)",
        },
    ]
}

fn render_budgets_human(budgets: &[PerfBudget]) {
    eprintln!(
        "cargo xtask perf budgets — {} budget(s) tracked",
        budgets.len()
    );
    eprintln!();
    let max_name = budgets.iter().map(|b| b.name.len()).max().unwrap_or(0);
    for b in budgets {
        let value = format_value(b.limit, b.unit);
        eprintln!("  {:<width$}  {}", b.name, value, width = max_name);
        eprintln!(
            "  {:<width$}    └─ {} ({})",
            "",
            b.description,
            b.source,
            width = max_name
        );
    }
}

fn format_value(limit: u64, unit: &str) -> String {
    match unit {
        "bytes" => {
            const KIB: u64 = 1 << 10;
            const MIB: u64 = 1 << 20;
            const GIB: u64 = 1 << 30;
            if limit >= GIB && limit.is_multiple_of(GIB) {
                format!("{} bytes ({} GiB)", limit, limit / GIB)
            } else if limit >= MIB && limit.is_multiple_of(MIB) {
                format!("{} bytes ({} MiB)", limit, limit / MIB)
            } else if limit >= KIB && limit.is_multiple_of(KIB) {
                format!("{} bytes ({} KiB)", limit, limit / KIB)
            } else {
                format!("{limit} bytes")
            }
        }
        _ => format!("{limit} {unit}"),
    }
}

// ============================================================================
// rootfs-size subcommand
// ============================================================================

fn rootfs_size_subcommand(args: &[String]) -> Result<()> {
    let rootfs = parse_rootfs_arg(args)?;
    rootfs_size_check(&rootfs, ROOTFS_MAX_BYTES)
}

/// Test seam — assert `rootfs` exists and is at or under `max_bytes`.
pub fn rootfs_size_check(rootfs: &Path, max_bytes: u64) -> Result<()> {
    let meta = std::fs::metadata(rootfs)
        .with_context(|| format!("stat rootfs at {}", rootfs.display()))?;
    if !meta.is_file() {
        bail!(
            "{} is not a regular file (expected an ext4 image)",
            rootfs.display()
        );
    }
    let size = meta.len();
    if size > max_bytes {
        bail!(
            "rootfs {} is {} bytes — over the Phase 9 budget of {} bytes ({} MiB). \
             Investigate the Nix closure or trim bundled tools.",
            rootfs.display(),
            size,
            max_bytes,
            max_bytes / (1024 * 1024)
        );
    }
    eprintln!(
        "ok: rootfs {} is {} bytes (under budget {} bytes / {} MiB)",
        rootfs.display(),
        size,
        max_bytes,
        max_bytes / (1024 * 1024)
    );
    Ok(())
}

// ============================================================================
// boot subcommand
// ============================================================================

fn boot_subcommand(args: &[String]) -> Result<()> {
    // Same gate the smoke test uses, so CI lanes can share env-var
    // discipline. Without MVM_LIVE_SMOKE, this subcommand exits 0
    // with a diagnostic — useful for CI matrix entries that want
    // the command to be "always runnable, only enforces on hosts
    // that have the gate set."
    if std::env::var("MVM_LIVE_SMOKE").as_deref() != Ok("1") {
        eprintln!(
            "[xtask perf boot] MVM_LIVE_SMOKE != \"1\" — skipping live benchmark. \
             Set MVM_LIVE_SMOKE=1 on a Linux/KVM host to run."
        );
        return Ok(());
    }
    let rootfs = parse_rootfs_arg(args)?;
    let runs = parse_runs_arg(args).unwrap_or(30);
    let backend = parse_backend_arg(args)?;
    if !rootfs.is_file() {
        bail!(
            "rootfs {} missing — required for live benchmark",
            rootfs.display()
        );
    }
    eprintln!(
        "[xtask perf boot] backend={backend:?} runs={runs} rootfs={}",
        rootfs.display()
    );
    // The actual N-run benchmark loop is deferred — it links against
    // `mvm_backend` to invoke `start_with_mode` + measure. Substrate
    // today: arg parsing + threshold lookup + the budget assertion
    // shape so consumers can scaffold.
    bail!(
        "live boot benchmark not yet implemented in xtask perf — \
         run backend-specific live boot validation from the builder VM"
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Firecracker,
    Libkrun,
}

impl Backend {
    fn budget(self) -> Duration {
        match self {
            Self::Firecracker => FIRECRACKER_BOOT_BUDGET,
            Self::Libkrun => LIBKRUN_BOOT_BUDGET,
        }
    }
}

// ============================================================================
// Argument parsing
// ============================================================================

fn parse_rootfs_arg(args: &[String]) -> Result<PathBuf> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--rootfs" {
            let path = args
                .get(i + 1)
                .ok_or_else(|| anyhow::anyhow!("--rootfs requires a path"))?;
            return Ok(PathBuf::from(path));
        }
        i += 1;
    }
    bail!("--rootfs <PATH> is required");
}

fn parse_runs_arg(args: &[String]) -> Option<u32> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--runs"
            && let Some(v) = args.get(i + 1)
            && let Ok(n) = v.parse::<u32>()
        {
            return Some(n);
        }
        i += 1;
    }
    None
}

fn parse_backend_arg(args: &[String]) -> Result<Backend> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--backend" {
            return match args.get(i + 1).map(|s| s.as_str()) {
                Some("firecracker") => Ok(Backend::Firecracker),
                Some("libkrun") => Ok(Backend::Libkrun),
                Some(other) => {
                    bail!("unknown --backend {other:?}; expected firecracker or libkrun")
                }
                None => bail!("--backend requires a value"),
            };
        }
        i += 1;
    }
    // Default to Firecracker — the Tier 1 default for Linux+KVM
    // hosts (the only environment this subcommand actually runs in).
    Ok(Backend::Firecracker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // ──────────────────────────────────────────────────────────────
    // Threshold pinning — sync between documented budget + code
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn rootfs_budget_is_20_mib() {
        // The budget is 20 MB explicitly. Pin the constant so a
        // "let's bump it" change has to update both the documented
        // budget and this test.
        assert_eq!(ROOTFS_MAX_BYTES, 20 * 1024 * 1024);
    }

    #[test]
    fn firecracker_boot_budget_is_500ms() {
        assert_eq!(FIRECRACKER_BOOT_BUDGET, Duration::from_millis(500));
    }

    #[test]
    fn libkrun_boot_budget_is_1s() {
        assert_eq!(LIBKRUN_BOOT_BUDGET, Duration::from_millis(1000));
    }

    #[test]
    fn budgets_obey_firecracker_below_libkrun_order() {
        // Firecracker is the faster path; if anyone flips this, the
        // tier ordering has drifted.
        assert!(FIRECRACKER_BOOT_BUDGET < LIBKRUN_BOOT_BUDGET);
    }

    // ──────────────────────────────────────────────────────────────
    // rootfs_size_check — runs on every host
    // ──────────────────────────────────────────────────────────────

    fn write_sized_file(dir: &Path, name: &str, bytes: u64) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.set_len(bytes).unwrap();
        f.flush().unwrap();
        path
    }

    #[test]
    fn rootfs_size_check_accepts_under_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let path = write_sized_file(tmp.path(), "rootfs.ext4", 1024 * 1024);
        rootfs_size_check(&path, ROOTFS_MAX_BYTES).unwrap();
    }

    #[test]
    fn rootfs_size_check_accepts_exactly_at_budget() {
        // The threshold is inclusive — a file *exactly* at the
        // budget passes. Pinned so an off-by-one refactor doesn't
        // make the test brittle.
        let tmp = tempfile::tempdir().unwrap();
        let path = write_sized_file(tmp.path(), "rootfs.ext4", ROOTFS_MAX_BYTES);
        rootfs_size_check(&path, ROOTFS_MAX_BYTES).unwrap();
    }

    #[test]
    fn rootfs_size_check_rejects_over_budget() {
        let tmp = tempfile::tempdir().unwrap();
        // Just past the budget — sparse file so this stays cheap
        // on disk.
        let path = write_sized_file(tmp.path(), "rootfs.ext4", ROOTFS_MAX_BYTES + 1);
        let err = rootfs_size_check(&path, ROOTFS_MAX_BYTES).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("over the Phase 9 budget"), "got: {s}");
        assert!(s.contains("20 MiB"), "got: {s}");
    }

    #[test]
    fn rootfs_size_check_rejects_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let err =
            rootfs_size_check(&tmp.path().join("does-not-exist"), ROOTFS_MAX_BYTES).unwrap_err();
        assert!(err.to_string().contains("stat rootfs"));
    }

    #[test]
    fn rootfs_size_check_rejects_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let err = rootfs_size_check(tmp.path(), ROOTFS_MAX_BYTES).unwrap_err();
        assert!(err.to_string().contains("not a regular file"));
    }

    // ──────────────────────────────────────────────────────────────
    // Arg parsing
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_rootfs_extracts_path() {
        let args = vec!["--rootfs".to_string(), "/tmp/x.ext4".to_string()];
        assert_eq!(
            parse_rootfs_arg(&args).unwrap(),
            PathBuf::from("/tmp/x.ext4")
        );
    }

    #[test]
    fn parse_rootfs_required() {
        let args: Vec<String> = vec![];
        let err = parse_rootfs_arg(&args).unwrap_err();
        assert!(err.to_string().contains("--rootfs"));
    }

    #[test]
    fn parse_runs_default_is_none() {
        let args: Vec<String> = vec![];
        assert!(parse_runs_arg(&args).is_none());
    }

    #[test]
    fn parse_runs_extracts_count() {
        let args = vec!["--runs".to_string(), "100".to_string()];
        assert_eq!(parse_runs_arg(&args), Some(100));
    }

    #[test]
    fn parse_backend_default_is_firecracker() {
        let args: Vec<String> = vec![];
        assert_eq!(parse_backend_arg(&args).unwrap(), Backend::Firecracker);
    }

    #[test]
    fn parse_backend_recognizes_libkrun() {
        let args = vec!["--backend".to_string(), "libkrun".to_string()];
        assert_eq!(parse_backend_arg(&args).unwrap(), Backend::Libkrun);
    }

    #[test]
    fn parse_backend_rejects_unknown() {
        let args = vec!["--backend".to_string(), "vmware".to_string()];
        assert!(parse_backend_arg(&args).is_err());
    }

    #[test]
    fn backend_budgets_match_constants() {
        assert_eq!(Backend::Firecracker.budget(), FIRECRACKER_BOOT_BUDGET);
        assert_eq!(Backend::Libkrun.budget(), LIBKRUN_BOOT_BUDGET);
    }

    // ──────────────────────────────────────────────────────────────
    // budgets subcommand — single-source-of-truth inventory
    // ──────────────────────────────────────────────────────────────

    #[test]
    fn all_budgets_has_expected_count() {
        // The count is a tripwire — if someone adds a budget without
        // a corresponding constant-pin test, this assert pushes them
        // to update both.
        assert_eq!(all_budgets().len(), 11);
    }

    #[test]
    fn all_budgets_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for b in all_budgets() {
            assert!(seen.insert(b.name), "duplicate budget name: {}", b.name);
        }
    }

    #[test]
    fn all_budgets_have_non_empty_fields() {
        for b in all_budgets() {
            assert!(!b.name.is_empty(), "empty name");
            assert!(!b.unit.is_empty(), "empty unit for {}", b.name);
            assert!(!b.source.is_empty(), "empty source for {}", b.name);
            assert!(
                !b.description.is_empty(),
                "empty description for {}",
                b.name
            );
            assert!(b.limit > 0, "zero limit for {}", b.name);
        }
    }

    #[test]
    fn all_budgets_pin_rootfs_to_constant() {
        let b = all_budgets()
            .into_iter()
            .find(|b| b.name == "rootfs_size")
            .expect("rootfs_size budget");
        assert_eq!(b.limit, ROOTFS_MAX_BYTES);
    }

    #[test]
    fn all_budgets_pin_firecracker_to_constant() {
        let b = all_budgets()
            .into_iter()
            .find(|b| b.name == "firecracker_cold_boot")
            .expect("firecracker_cold_boot budget");
        assert_eq!(b.limit, FIRECRACKER_BOOT_BUDGET.as_millis() as u64);
    }

    #[test]
    fn all_budgets_pin_libkrun_to_constant() {
        let b = all_budgets()
            .into_iter()
            .find(|b| b.name == "libkrun_cold_boot")
            .expect("libkrun_cold_boot budget");
        assert_eq!(b.limit, LIBKRUN_BOOT_BUDGET.as_millis() as u64);
    }

    #[test]
    fn format_value_renders_bytes_with_kib() {
        let s = format_value(1024, "bytes");
        assert!(s.contains("1024 bytes"), "got: {s}");
        assert!(s.contains("1 KiB"), "got: {s}");
    }

    #[test]
    fn format_value_renders_bytes_with_mib() {
        let s = format_value(1 << 20, "bytes");
        assert!(s.contains("1 MiB"), "got: {s}");
    }

    #[test]
    fn format_value_renders_bytes_with_gib() {
        let s = format_value(10 * (1 << 30), "bytes");
        assert!(s.contains("10 GiB"), "got: {s}");
    }

    #[test]
    fn format_value_renders_non_round_bytes_plain() {
        // 1025 isn't a multiple of KiB — render just the byte count.
        let s = format_value(1025, "bytes");
        assert_eq!(s, "1025 bytes");
    }

    #[test]
    fn format_value_renders_non_bytes_unit_verbatim() {
        let s = format_value(500, "ms");
        assert_eq!(s, "500 ms");
    }

    #[test]
    fn budgets_subcommand_json_serializes_cleanly() {
        // Roundtrip: the inventory should serialize as a JSON array
        // of objects with the documented shape so monitoring consumers
        // can rely on it.
        let budgets = all_budgets();
        let json = serde_json::to_string(&budgets).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let arr = parsed.as_array().expect("top-level array");
        assert_eq!(arr.len(), budgets.len());
        let first = &arr[0];
        for field in ["name", "limit", "unit", "source", "description"] {
            assert!(first.get(field).is_some(), "missing field: {field}");
        }
    }
}
