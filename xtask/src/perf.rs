//! Performance gates via `cargo xtask perf`.
//!
//! The storage and boot gates are exposed through `cargo xtask perf`:
//!
//! - **`rootfs-size`** — assert a built rootfs is at or under the
//!   `mvm` minimal-template budget. Pure file-size check; runs on
//!   every host (no KVM/Lima required). Enforces the "rootfs < 20 MB
//!   for minimal template" line.
//! - **`boot`** — statistical cold-boot benchmark. Boots a real
//!   Firecracker / libkrun VM `--runs N` times, computes
//!   p50/p95/max wall-clock, asserts thresholds. Linux + KVM
//!   required; gated by `MVM_LIVE_SMOKE=1` + a rootfs path so a
//!   bare macOS host skips cleanly. Enforces the "cold-boot < 200ms
//!   Firecracker / ≤ 1s libkrun" line.
//! - **`footprint`** — sum the Nix-built rootfs, runtime overlay, initramfs,
//!   verity sidecars, and optional kernel, assert the supplied guest artifacts
//!   stay below 50 MB, and optionally enforce the rootfs Nix closure inventory
//!   and kernel built-in-symbol budget.
//!
//! The thresholds are the per-backend boot budgets; they're pinned
//! by tests in this module so a drift in the documented budget vs.
//! the code is caught at review.
//!
//! The filesystem subcommand measures the current pure-Rust immutable ext4
//! path and emits a stable baseline for candidate filesystem comparisons.
//!
//! ## Usage
//!
//! ```text
//! cargo xtask perf rootfs-size --rootfs ~/.mvm/cache/.../rootfs.ext4
//! cargo xtask perf boot --runs 30 --rootfs ~/.mvm/cache/.../rootfs.ext4
//! cargo xtask perf footprint --rootfs result/rootfs.ext4 --overlay overlay/overlay.ext4 --initramfs result/initramfs.cpio.gz --kernel result/vmlinux --kernel-config result/workload.config --closure-paths result/rootfs-closure-paths
//! cargo xtask perf footprint --rootfs result/rootfs.ext4 --overlay overlay/overlay.ext4 --guest-rss-bytes 4194304
//! cargo xtask perf footprint --rootfs result/rootfs.ext4 --overlay overlay/overlay.ext4 --sdk-sidecar sidecar/sdk.ext4
//! ```
//!
//! ## What this does NOT do (yet)
//!
//! - **Regression alert against historical p50.** A ">10% p50
//!   increase fails the test" gate would need a historical-baseline
//!   file that this command compares against. Substrate-only today;
//!   the boot subcommand asserts against absolute thresholds.
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

/// Maximum complete default guest artifact footprint: rootfs, runtime overlay,
/// initramfs, their dm-verity sidecars, and kernel. The workload's own
/// application payload remains outside this contract.
pub const GUEST_STORAGE_MAX_BYTES: u64 = 50_000_000; // 50 MB

/// Maximum number of registered Nix store paths retained in the default
/// rootfs: static BusyBox and the static privilege-drop helper.
pub const GUEST_ROOTFS_MAX_STORE_PATHS: usize = 2;

/// Maximum current RSS for the idle guest-agent process.
pub const GUEST_AGENT_RSS_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Maximum size of the optional SDK sidecar image (the glibc host-services
/// cdylib plus its loader closure).
///
/// Deliberately budgeted and reported **outside** [`GUEST_STORAGE_MAX_BYTES`]:
/// the sidecar is attached only to workloads whose signed plan binds an
/// SDK-served host service, so folding it into the base ledger would report a
/// footprint no ordinary workload actually pays. Mirrors `sdkSidecarSizeBytes`
/// in `nix/images/runtime-overlay/flake.nix`.
pub const SDK_SIDECAR_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Cold-boot wall-clock budget for the Firecracker backend.
/// Every prepared-cold dispatch must be strictly below this threshold.
pub const FIRECRACKER_BOOT_BUDGET: Duration = Duration::from_millis(200);

/// Cold-boot wall-clock budget for the libkrun backend. Slower than
/// Firecracker because libkrun's startup +
/// the in-VM init script aren't as tight; 1s is the worst-case
/// envelope.
pub const LIBKRUN_BOOT_BUDGET: Duration = Duration::from_millis(1000);

/// Dispatch entry — called from `xtask/src/main.rs`.
pub fn run(args: &[String]) -> Result<()> {
    match args.first().map(|s| s.as_str()) {
        Some("rootfs-size") => rootfs_size_subcommand(&args[1..]),
        Some("footprint") => footprint_subcommand(&args[1..]),
        Some("filesystem") => filesystem_subcommand(&args[1..]),
        Some("boot") => boot_subcommand(&args[1..]),
        Some("budgets") => budgets_subcommand(&args[1..]),
        Some(other) => {
            bail!(
                "Unknown perf subcommand {other:?}. Available: rootfs-size, footprint, filesystem, boot, budgets"
            )
        }
        None => {
            eprintln!("Usage: cargo xtask perf <subcommand>");
            eprintln!(
                "  rootfs-size --rootfs <PATH>    Assert rootfs is ≤ {ROOTFS_MAX_BYTES} bytes"
            );
            eprintln!(
                "  footprint --rootfs <PATH> --overlay <PATH> [--initramfs <PATH>] [--rootfs-verity <PATH>] [--overlay-verity <PATH>] [--kernel <PATH>] [--kernel-config <PATH>] [--closure-paths <PATH>] [--guest-rss-bytes <N>] [--sdk-sidecar <PATH>]"
            );
            eprintln!(
                "                                 Assert the supplied guest artifacts total ≤ {GUEST_STORAGE_MAX_BYTES} bytes"
            );
            eprintln!(
                "  filesystem --root <PATH> [--json]  Measure the immutable directory-to-ext4 baseline"
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
// filesystem subcommand — immutable materializer baseline
// ============================================================================

fn filesystem_subcommand(args: &[String]) -> Result<()> {
    let root = required_path_arg(args, "--root")?;
    let report = filesystem_baseline(&root)?;
    if args.iter().any(|arg| arg == "--json") {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        eprintln!(
            "ok: ext4 baseline emitted {} bytes from {} nodes (image {})",
            report.image_size_bytes, report.nodes.total, report.image_sha256
        );
        eprintln!(
            "  source {}  hash {} µs  walk {} µs  build {} µs  total {} µs",
            report.source_content_sha256,
            report.timings.source_hash_micros,
            report.timings.walk_micros,
            report.timings.build_micros,
            report.timings.total_micros
        );
    }
    Ok(())
}

fn filesystem_baseline(root: &Path) -> Result<mvm_fs::rootfs::Ext4MaterializationReport> {
    mvm_fs::rootfs::measure_ext4_pure(root, &mvm_fs::rootfs::MaterializeOptions::default())
        .with_context(|| {
            format!(
                "measure immutable filesystem baseline at {}",
                root.display()
            )
        })
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
            source: "plan-60 Phase 9 + ADR-005",
            description: "Minimal-template ext4 rootfs size",
        },
        PerfBudget {
            name: "guest_storage_size",
            limit: GUEST_STORAGE_MAX_BYTES,
            unit: "bytes",
            source: "lightweight guest footprint contract",
            description: "Nix-built rootfs + runtime overlay + verity sidecars + workload kernel",
        },
        PerfBudget {
            name: "guest_agent_rss",
            limit: GUEST_AGENT_RSS_MAX_BYTES,
            unit: "bytes",
            source: "lightweight guest RSS contract",
            description: "Idle guest-agent current resident memory",
        },
        PerfBudget {
            name: "firecracker_cold_boot",
            limit: FIRECRACKER_BOOT_BUDGET.as_millis() as u64,
            unit: "ms",
            source: "ADR-005 §\"Per-backend boot budgets\"",
            description: "Firecracker cold-boot wall-clock (1 vCPU / 256 MiB)",
        },
        PerfBudget {
            name: "libkrun_cold_boot",
            limit: LIBKRUN_BOOT_BUDGET.as_millis() as u64,
            unit: "ms",
            source: "ADR-005 §\"Per-backend boot budgets\"",
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
// footprint subcommand
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct FootprintArtifact {
    name: &'static str,
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct FootprintEntry {
    name: String,
    path: PathBuf,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct ClosureInventory {
    path: PathBuf,
    store_path_count: usize,
    store_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct KernelConfigSummary {
    path: PathBuf,
    builtin_symbols: usize,
    budget: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct FootprintReport {
    limit_bytes: u64,
    total_bytes: u64,
    entries: Vec<FootprintEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rootfs_closure: Option<ClosureInventory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_agent_rss_bytes: Option<u64>,
    /// The optional SDK sidecar, budgeted on its own and excluded from
    /// `total_bytes` — it ships only to workloads that bind an SDK-served host
    /// service, so it is not part of the base guest footprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    sdk_sidecar: Option<FootprintEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kernel_config: Option<KernelConfigSummary>,
}

fn footprint_subcommand(args: &[String]) -> Result<()> {
    let json = args.iter().any(|arg| arg == "--json");
    let artifacts = parse_footprint_artifacts(args)?;
    let rootfs_closure = optional_path_arg(args, "--closure-paths")?
        .as_deref()
        .map(|path| read_closure_inventory(path, GUEST_ROOTFS_MAX_STORE_PATHS))
        .transpose()?;
    let guest_agent_rss_bytes = optional_u64_arg(args, "--guest-rss-bytes")?;
    if let Some(rss_bytes) = guest_agent_rss_bytes {
        guest_rss_check(rss_bytes, GUEST_AGENT_RSS_MAX_BYTES)?;
    }
    let sdk_sidecar = optional_path_arg(args, "--sdk-sidecar")?
        .map(|path| sdk_sidecar_check(&path, SDK_SIDECAR_MAX_BYTES))
        .transpose()?;
    let kernel_config = optional_path_arg(args, "--kernel-config")?
        .map(|path| kernel_config_summary(&path))
        .transpose()?;
    let mut report = guest_storage_footprint_check(&artifacts, GUEST_STORAGE_MAX_BYTES)?;
    report.rootfs_closure = rootfs_closure;
    report.guest_agent_rss_bytes = guest_agent_rss_bytes;
    report.sdk_sidecar = sdk_sidecar;
    report.kernel_config = kernel_config;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        eprintln!(
            "ok: guest artifact footprint is {} bytes (under {} bytes / 50 MB)",
            report.total_bytes, report.limit_bytes
        );
        for entry in &report.entries {
            eprintln!(
                "  {:<16} {} bytes  {}",
                entry.name,
                entry.bytes,
                entry.path.display()
            );
        }
        if let Some(inventory) = &report.rootfs_closure {
            eprintln!(
                "  {:<16} {} store paths  {}",
                "rootfs-closure",
                inventory.store_path_count,
                inventory.path.display()
            );
            for store_path in &inventory.store_paths {
                eprintln!("    {store_path}");
            }
        }
        if let Some(rss_bytes) = report.guest_agent_rss_bytes {
            eprintln!(
                "  {:<16} {} bytes (under {} bytes / 8 MiB)",
                "guest-agent-rss", rss_bytes, GUEST_AGENT_RSS_MAX_BYTES
            );
        }
        if let Some(entry) = &report.sdk_sidecar {
            eprintln!(
                "  {:<16} {} bytes  {} (optional; NOT counted in the base footprint above)",
                "sdk-sidecar",
                entry.bytes,
                entry.path.display()
            );
        }
        if let Some(config) = &report.kernel_config {
            eprintln!(
                "  {:<16} {} built-in symbols (budget {})  {}",
                "kernel-config",
                config.builtin_symbols,
                config.budget,
                config.path.display()
            );
        }
    }
    Ok(())
}

/// Measure the optional SDK sidecar against its own budget.
///
/// Separate from [`guest_storage_footprint_check`] on purpose: the sidecar has
/// its own ceiling and never contributes to the base total, so a growing sidecar
/// can't quietly consume the base guest's headroom and a base regression can't
/// hide behind an absent sidecar.
fn sdk_sidecar_check(path: &Path, max_bytes: u64) -> Result<FootprintEntry> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat sdk-sidecar at {}", path.display()))?;
    if !metadata.is_file() {
        bail!("sdk-sidecar at {} is not a regular file", path.display());
    }
    let bytes = metadata.len();
    if bytes > max_bytes {
        bail!(
            "SDK sidecar is {bytes} bytes — over the sidecar budget of {max_bytes} bytes (8 MiB)"
        );
    }
    Ok(FootprintEntry {
        name: "sdk-sidecar".to_string(),
        path: path.to_path_buf(),
        bytes,
    })
}

fn parse_footprint_artifacts(args: &[String]) -> Result<Vec<FootprintArtifact>> {
    let rootfs = required_path_arg(args, "--rootfs")?;
    let overlay = required_path_arg(args, "--overlay")?;
    let mut artifacts = vec![
        FootprintArtifact {
            name: "rootfs",
            path: rootfs,
        },
        FootprintArtifact {
            name: "overlay",
            path: overlay,
        },
    ];
    if let Some(path) = optional_path_arg(args, "--initramfs")? {
        artifacts.push(FootprintArtifact {
            name: "initramfs",
            path,
        });
    }
    if let Some(path) = optional_path_arg(args, "--rootfs-verity")? {
        artifacts.push(FootprintArtifact {
            name: "rootfs-verity",
            path,
        });
    }
    if let Some(path) = optional_path_arg(args, "--overlay-verity")? {
        artifacts.push(FootprintArtifact {
            name: "overlay-verity",
            path,
        });
    }
    if let Some(path) = optional_path_arg(args, "--kernel")? {
        artifacts.push(FootprintArtifact {
            name: "kernel",
            path,
        });
    }
    Ok(artifacts)
}

fn guest_storage_footprint_check(
    artifacts: &[FootprintArtifact],
    max_bytes: u64,
) -> Result<FootprintReport> {
    let entries = artifacts
        .iter()
        .map(|artifact| {
            let metadata = std::fs::metadata(&artifact.path).with_context(|| {
                format!("stat {} at {}", artifact.name, artifact.path.display())
            })?;
            if !metadata.is_file() {
                bail!(
                    "{} at {} is not a regular file",
                    artifact.name,
                    artifact.path.display()
                );
            }
            Ok(FootprintEntry {
                name: artifact.name.to_string(),
                path: artifact.path.clone(),
                bytes: metadata.len(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let total_bytes = entries.iter().map(|entry| entry.bytes).sum::<u64>();
    if total_bytes > max_bytes {
        bail!(
            "guest artifact footprint is {} bytes — over the footprint budget of {} bytes (50 MB)",
            total_bytes,
            max_bytes
        );
    }
    Ok(FootprintReport {
        limit_bytes: max_bytes,
        total_bytes,
        entries,
        rootfs_closure: None,
        guest_agent_rss_bytes: None,
        sdk_sidecar: None,
        kernel_config: None,
    })
}

fn kernel_config_summary(path: &Path) -> Result<KernelConfigSummary> {
    let config = std::fs::read_to_string(path)
        .with_context(|| format!("read kernel config at {}", path.display()))?;
    let builtin_symbols = crate::check_kernel_config_budget::count_builtins(&config);
    let budget = crate::check_kernel_config_budget::budget_for_path(&path.to_string_lossy());
    crate::check_kernel_config_budget::evaluate_budget(&config, budget)?;
    Ok(KernelConfigSummary {
        path: path.to_path_buf(),
        builtin_symbols,
        budget,
    })
}

fn guest_rss_check(rss_bytes: u64, max_bytes: u64) -> Result<()> {
    if rss_bytes > max_bytes {
        bail!(
            "guest agent RSS is {rss_bytes} bytes — over the guest-agent RSS budget of {max_bytes} bytes (8 MiB)"
        );
    }
    Ok(())
}

fn read_closure_inventory(path: &Path, max_store_paths: usize) -> Result<ClosureInventory> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("read rootfs closure inventory {}", path.display()))?;
    let mut store_paths = Vec::new();
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        if line != line.trim() || !is_hash_anchored_nix_store_path(line) {
            bail!(
                "invalid Nix store path in rootfs closure inventory {}: {line:?}",
                path.display()
            );
        }
        store_paths.push(line.to_string());
    }
    if store_paths.is_empty() {
        bail!(
            "rootfs closure inventory {} contains no store paths",
            path.display()
        );
    }
    store_paths.sort_unstable();
    if store_paths.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!(
            "rootfs closure inventory {} contains duplicate store paths",
            path.display()
        );
    }
    if store_paths.len() > max_store_paths {
        bail!(
            "rootfs closure contains {} store paths — over the closure budget of {}",
            store_paths.len(),
            max_store_paths
        );
    }
    Ok(ClosureInventory {
        path: path.to_path_buf(),
        store_path_count: store_paths.len(),
        store_paths,
    })
}

fn is_hash_anchored_nix_store_path(path: &str) -> bool {
    const NIX_BASE32_ALPHABET: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

    let Some(store_name) = path.strip_prefix("/nix/store/") else {
        return false;
    };
    let Some((hash, name)) = store_name.split_once('-') else {
        return false;
    };
    hash.len() == 32
        && hash.bytes().all(|byte| NIX_BASE32_ALPHABET.contains(&byte))
        && !name.is_empty()
        && !name.contains('/')
}

fn required_path_arg(args: &[String], flag: &str) -> Result<PathBuf> {
    optional_path_arg(args, flag)?.ok_or_else(|| anyhow::anyhow!("{flag} requires a path"))
}

fn optional_path_arg(args: &[String], flag: &str) -> Result<Option<PathBuf>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    args.get(index + 1)
        .map(|path| Some(PathBuf::from(path)))
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a path"))
}

fn optional_u64_arg(args: &[String], flag: &str) -> Result<Option<u64>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    let raw = args
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("{flag} requires a byte count"))?;
    raw.parse::<u64>()
        .map(Some)
        .with_context(|| format!("{flag} must be an unsigned byte count"))
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
    // `mvm_runtime` to invoke `start_with_mode` + measure. Substrate
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
    use crate::check_kernel_config_budget;
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
    fn guest_storage_budget_is_50_mb() {
        assert_eq!(GUEST_STORAGE_MAX_BYTES, 50_000_000);
    }

    #[test]
    fn guest_rootfs_closure_budget_is_two_store_paths() {
        assert_eq!(GUEST_ROOTFS_MAX_STORE_PATHS, 2);
    }

    #[test]
    fn guest_agent_rss_budget_is_eight_mib() {
        assert_eq!(GUEST_AGENT_RSS_MAX_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn firecracker_boot_budget_is_200ms() {
        assert_eq!(FIRECRACKER_BOOT_BUDGET, Duration::from_millis(200));
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

    #[test]
    fn footprint_check_sums_required_and_optional_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = write_sized_file(tmp.path(), "rootfs.ext4", 4);
        let overlay = write_sized_file(tmp.path(), "overlay.ext4", 5);
        let rootfs_verity = write_sized_file(tmp.path(), "rootfs.verity", 2);
        let overlay_verity = write_sized_file(tmp.path(), "overlay.verity", 3);
        let kernel = write_sized_file(tmp.path(), "vmlinux", 6);
        let artifacts = vec![
            FootprintArtifact {
                name: "rootfs",
                path: rootfs,
            },
            FootprintArtifact {
                name: "overlay",
                path: overlay,
            },
            FootprintArtifact {
                name: "rootfs-verity",
                path: rootfs_verity,
            },
            FootprintArtifact {
                name: "overlay-verity",
                path: overlay_verity,
            },
            FootprintArtifact {
                name: "kernel",
                path: kernel,
            },
        ];

        let report = guest_storage_footprint_check(&artifacts, 20).unwrap();
        assert_eq!(report.total_bytes, 20);
        assert_eq!(report.entries.len(), 5);
    }

    #[test]
    fn sdk_sidecar_is_budgeted_on_its_own_and_kept_out_of_the_base_total() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.ext4");
        let overlay = dir.path().join("overlay.ext4");
        let sidecar = dir.path().join("sdk.ext4");
        std::fs::write(&rootfs, vec![0u8; 10]).unwrap();
        std::fs::write(&overlay, vec![0u8; 4]).unwrap();
        std::fs::write(&sidecar, vec![0u8; 7]).unwrap();

        let artifacts = vec![
            FootprintArtifact {
                name: "rootfs",
                path: rootfs,
            },
            FootprintArtifact {
                name: "overlay",
                path: overlay,
            },
        ];
        let base = guest_storage_footprint_check(&artifacts, 20).unwrap();
        assert_eq!(base.total_bytes, 14);
        assert!(base.sdk_sidecar.is_none());

        // The sidecar has its own ceiling and never lands in the base total, so
        // an 8 MiB sidecar can't consume the base guest's 50 MB headroom.
        let entry = sdk_sidecar_check(&sidecar, SDK_SIDECAR_MAX_BYTES).unwrap();
        assert_eq!(entry.bytes, 7);
        assert_eq!(entry.name, "sdk-sidecar");
        let mut with_sidecar = base.clone();
        with_sidecar.sdk_sidecar = Some(entry);
        assert_eq!(
            with_sidecar.total_bytes, base.total_bytes,
            "attaching a sidecar must not change the base footprint"
        );
    }

    #[test]
    fn sdk_sidecar_over_its_own_budget_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = dir.path().join("sdk.ext4");
        std::fs::write(&sidecar, vec![0u8; 9]).unwrap();
        let err = sdk_sidecar_check(&sidecar, 8).unwrap_err();
        assert!(err.to_string().contains("over the sidecar budget"), "{err}");
    }

    #[test]
    fn sdk_sidecar_budget_matches_the_nix_allocation() {
        // The Nix derivation pre-allocates the sidecar at a fixed size; the
        // ledger's ceiling must not drift below what the build emits.
        assert_eq!(SDK_SIDECAR_MAX_BYTES, 8 * 1024 * 1024);
        let flake = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("workspace root")
                .join("nix/images/runtime-overlay/flake.nix"),
        )
        .expect("read the runtime-overlay flake");
        assert!(
            flake.contains("sdkSidecarSizeBytes = 8 * 1024 * 1024;"),
            "the flake's sidecar allocation drifted from SDK_SIDECAR_MAX_BYTES"
        );
    }

    #[test]
    fn a_missing_sdk_sidecar_path_is_an_error_not_a_silent_zero() {
        let dir = tempfile::tempdir().unwrap();
        let err =
            sdk_sidecar_check(&dir.path().join("absent.ext4"), SDK_SIDECAR_MAX_BYTES).unwrap_err();
        assert!(err.to_string().contains("stat sdk-sidecar"), "{err}");
    }

    #[test]
    fn footprint_check_rejects_over_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = write_sized_file(tmp.path(), "rootfs.ext4", 8);
        let overlay = write_sized_file(tmp.path(), "overlay.ext4", 7);
        let artifacts = vec![
            FootprintArtifact {
                name: "rootfs",
                path: rootfs,
            },
            FootprintArtifact {
                name: "overlay",
                path: overlay,
            },
        ];

        let err = guest_storage_footprint_check(&artifacts, 14).unwrap_err();
        assert!(err.to_string().contains("over the footprint budget"));
    }

    #[test]
    fn guest_rss_check_accepts_the_budget_boundary() {
        guest_rss_check(GUEST_AGENT_RSS_MAX_BYTES, GUEST_AGENT_RSS_MAX_BYTES).unwrap();
    }

    #[test]
    fn guest_rss_check_rejects_one_byte_over_budget() {
        let err =
            guest_rss_check(GUEST_AGENT_RSS_MAX_BYTES + 1, GUEST_AGENT_RSS_MAX_BYTES).unwrap_err();
        assert!(err.to_string().contains("over the guest-agent RSS budget"));
    }

    #[test]
    fn closure_inventory_accepts_two_hash_anchored_store_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rootfs-closure-paths");
        std::fs::write(
            &path,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-busybox-static\n\
             /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-mvm-setpriv-static\n",
        )
        .unwrap();

        let inventory = read_closure_inventory(&path, 2).unwrap();
        assert_eq!(inventory.store_path_count, 2);
        assert_eq!(inventory.store_paths.len(), 2);
    }

    #[test]
    fn closure_inventory_rejects_a_third_store_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rootfs-closure-paths");
        std::fs::write(
            &path,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-a\n\
             /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-b\n\
             /nix/store/cccccccccccccccccccccccccccccccc-c\n",
        )
        .unwrap();

        let err = read_closure_inventory(&path, 2).unwrap_err();
        assert!(err.to_string().contains("over the closure budget"));
    }

    #[test]
    fn closure_inventory_rejects_unanchored_input() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rootfs-closure-paths");
        std::fs::write(&path, "glibc mentioned in a derivation name\n").unwrap();

        let err = read_closure_inventory(&path, 2).unwrap_err();
        assert!(err.to_string().contains("invalid Nix store path"));
    }

    #[test]
    fn closure_inventory_rejects_duplicate_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rootfs-closure-paths");
        std::fs::write(
            &path,
            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-busybox-static\n\
             /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-busybox-static\n",
        )
        .unwrap();

        let err = read_closure_inventory(&path, 2).unwrap_err();
        assert!(err.to_string().contains("duplicate store paths"));
    }

    #[test]
    fn closure_inventory_rejects_empty_input() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("rootfs-closure-paths");
        std::fs::write(&path, "\n").unwrap();

        let err = read_closure_inventory(&path, 2).unwrap_err();
        assert!(err.to_string().contains("contains no store paths"));
    }

    #[test]
    fn parse_footprint_requires_rootfs_and_overlay() {
        let args = vec!["--rootfs".to_string(), "/tmp/rootfs.ext4".to_string()];
        let err = parse_footprint_artifacts(&args).unwrap_err();
        assert!(err.to_string().contains("--overlay"));
    }

    #[test]
    fn parse_footprint_accepts_verity_sidecars_and_kernel() {
        let args = vec![
            "--rootfs".to_string(),
            "/tmp/rootfs.ext4".to_string(),
            "--overlay".to_string(),
            "/tmp/overlay.ext4".to_string(),
            "--initramfs".to_string(),
            "/tmp/initramfs.cpio.gz".to_string(),
            "--rootfs-verity".to_string(),
            "/tmp/rootfs.verity".to_string(),
            "--overlay-verity".to_string(),
            "/tmp/overlay.verity".to_string(),
            "--kernel".to_string(),
            "/tmp/vmlinux".to_string(),
        ];
        let artifacts = parse_footprint_artifacts(&args).unwrap();
        assert_eq!(artifacts.len(), 6);
        assert_eq!(artifacts[2].name, "initramfs");
        assert_eq!(artifacts[3].name, "rootfs-verity");
        assert_eq!(artifacts[4].name, "overlay-verity");
        assert_eq!(artifacts[5].name, "kernel");
    }

    #[test]
    fn filesystem_baseline_reports_a_directory_tree() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir(tmp.path().join("etc")).unwrap();
        std::fs::write(tmp.path().join("etc/hosts"), b"127.0.0.1 localhost\n").unwrap();

        let report = filesystem_baseline(tmp.path()).unwrap();

        assert_eq!(report.nodes.files, 1);
        assert_eq!(report.nodes.directories, 1);
        assert!(report.image_size_bytes > 0);
        assert_eq!(report.image_sha256.len(), 64);
    }

    #[test]
    fn filesystem_subcommand_requires_a_root() {
        let err = filesystem_subcommand(&[]).unwrap_err();
        assert!(err.to_string().contains("--root"));
    }

    #[test]
    fn kernel_config_summary_counts_and_enforces_builtins() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("workload-config-x86_64");
        std::fs::write(
            &path,
            "CONFIG_ONE=y\nCONFIG_TWO=m\n# CONFIG_THREE is not set\n",
        )
        .unwrap();

        let summary = kernel_config_summary(&path).unwrap();

        assert_eq!(summary.path, path);
        assert_eq!(summary.builtin_symbols, 1);
        assert_eq!(
            summary.budget,
            check_kernel_config_budget::budget_for_path("x86_64")
        );
    }

    #[test]
    fn kernel_config_summary_rejects_a_budget_overflow() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("workload-config-x86_64");
        let config = (0..=check_kernel_config_budget::budget_for_path("x86_64"))
            .map(|index| format!("CONFIG_TEST_{index}=y"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&path, config).unwrap();

        let error = kernel_config_summary(&path).unwrap_err();

        assert!(error.to_string().contains("exceeds the budget"));
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
        assert_eq!(all_budgets().len(), 13);
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
    fn all_budgets_pin_guest_storage_to_constant() {
        let b = all_budgets()
            .into_iter()
            .find(|b| b.name == "guest_storage_size")
            .expect("guest_storage_size budget");
        assert_eq!(b.limit, GUEST_STORAGE_MAX_BYTES);
    }

    #[test]
    fn all_budgets_pin_guest_agent_rss_to_constant() {
        let budget = all_budgets()
            .into_iter()
            .find(|budget| budget.name == "guest_agent_rss")
            .expect("guest_agent_rss budget");
        assert_eq!(budget.limit, GUEST_AGENT_RSS_MAX_BYTES);
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
