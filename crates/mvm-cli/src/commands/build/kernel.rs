//! `mvmctl kernel` — build the custom microVM kernels.
//!
//! The builder-VM and workload microVM kernels are slim custom Linux
//! builds (`nix/images/builder-vm/kernel/base.nix` + per-variant
//! deltas). Because the
//! config is custom, `cache.nixos.org` has no substitute, so a fresh
//! machine compiles from source — the slow, memory-heavy step a first
//! `mvmctl dev up` otherwise hits implicitly. This command makes that
//! compile explicit and one-time: build the kernel once into the
//! persistent nix store, and every later `dev up` reuses it.
//!
//! `--source download` (fetch a hash-verified published prebuilt) lands
//! with the kernel-build publish workflow, which is what produces the
//! artifact to download.
//!
//! Progress: the compile path prints an elapsed-time heartbeat every
//! ~20s; `--verbose` streams the builder VM's `console.log` (the inner
//! `nix build` output) to stderr live.

#[cfg(feature = "builder-vm")]
use anyhow::Context;
use anyhow::Result;
use clap::{Args as ClapArgs, Subcommand, ValueEnum};

use super::Cli;
use mvm_core::user_config::MvmConfig;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Compile a custom microVM kernel into the local cache + nix store.
    Build(BuildArgs),
}

#[derive(ClapArgs, Debug, Clone)]
struct BuildArgs {
    /// Which kernel to build (ignored when `--all` is given).
    #[arg(long, value_enum, default_value_t = Which::Builder)]
    which: Which,

    /// Build both the builder and workload kernels.
    #[arg(long)]
    all: bool,

    /// Where the kernel comes from. `compile` builds locally via Stage 0
    /// (host arch only); `download` fetches a published prebuilt for the
    /// release; `auto` downloads if available, else compiles.
    #[arg(long, value_enum, default_value_t = Source::Compile)]
    source: Source,

    /// Target architecture. Defaults to the host arch. Only `download`
    /// can target a non-host arch (Stage 0 cannot cross-compile).
    #[arg(long, value_parser = ["aarch64", "x86_64"])]
    arch: Option<String>,

    /// After building, boot a throwaway microVM on the new kernel and confirm
    /// the in-guest agent answers over vsock — a build that links isn't proof
    /// it boots. Workload kernel only; needs a source checkout (uses
    /// `examples/sleeper`) + a working local backend.
    #[arg(long)]
    boot_check: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Builder,
    Workload,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Compile locally through the Stage 0 builder bootstrap (host arch).
    Compile,
    /// Fetch a published, SHA-256-verified prebuilt for this release.
    Download,
    /// Download if available, otherwise compile.
    Auto,
}

/// Host architecture tag — matches `builder_vm_host_arch()`. Only the
/// `builder-vm` build path consumes it (compile + cache routing).
#[cfg(feature = "builder-vm")]
fn host_arch() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        "x86_64"
    }
}

pub(in crate::commands) fn run(cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build(b) => run_build(b, cli.verbose > 0),
    }
}

#[cfg(feature = "builder-vm")]
fn run_build(args: BuildArgs, verbose: bool) -> Result<()> {
    use crate::commands::env::dev_vz::KernelVariant;
    use crate::ui;

    let arch = args.arch.clone().unwrap_or_else(|| host_arch().to_string());

    // (variant, cache-label) — the label keys the cache dir + the
    // published asset name (vmlinux-<arch>-<label>).
    let variants: Vec<(KernelVariant, &str)> = if args.all {
        vec![
            (KernelVariant::Builder, "builder"),
            (KernelVariant::Workload, "workload"),
        ]
    } else {
        match args.which {
            Which::Builder => vec![(KernelVariant::Builder, "builder")],
            Which::Workload => vec![(KernelVariant::Workload, "workload")],
        }
    };

    for (variant, label) in &variants {
        let path = acquire_kernel(args.source, *variant, label, &arch, verbose)?;
        let bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mib = bytes as f64 / (1024.0 * 1024.0);

        // Local metrics: if Stage 0 emitted the resolved `.config` next to the
        // kernel, count built-in (`=y`) symbols and persist a metrics sidecar —
        // so a config edit's effect is visible here, not only from CI.
        match emit_local_metrics(&path, label, &arch, bytes) {
            Some(y) => ui::success(&format!(
                "{label} kernel ({arch}): {} — {mib:.1} MiB, {y} built-in (=y) symbols",
                path.display()
            )),
            None => ui::success(&format!(
                "{label} kernel ({arch}): {} ({mib:.1} MiB)",
                path.display()
            )),
        }
    }

    if args.boot_check {
        run_boot_check(&variants, &arch)?;
    }
    Ok(())
}

/// JSON metrics emitted next to the cached kernel — the same shape the
/// `kernel-build` CI lane uploads (sans gz, which needs a compressor), so a
/// contributor sees `=y` count + size locally without a CI round-trip.
#[cfg(feature = "builder-vm")]
#[derive(serde::Serialize)]
struct KernelMetrics<'a> {
    arch: &'a str,
    variant: &'a str,
    y_symbol_count: usize,
    vmlinux_bytes: u64,
}

/// Count built-in (`=y`) symbols in a resolved kernel `.config` — the metric
/// the `check-kernel-config-budget` gate ratchets on. Matches CI's
/// `grep -c '=y$'`.
#[cfg(feature = "builder-vm")]
fn count_builtin_symbols(config: &str) -> usize {
    config
        .lines()
        .filter(|l| l.trim_end().ends_with("=y"))
        .count()
}

/// Read the `config` sidecar Stage 0 dropped next to `vmlinux`, count `=y`,
/// write `kernel-metrics-<arch>.json` beside it, and return the count. Returns
/// `None` when no config was emitted (e.g. `--source download`) — purely
/// additive, never an error.
#[cfg(feature = "builder-vm")]
fn emit_local_metrics(
    vmlinux: &std::path::Path,
    label: &str,
    arch: &str,
    bytes: u64,
) -> Option<usize> {
    let config = vmlinux.with_file_name("config");
    let content = std::fs::read_to_string(&config).ok()?;
    let y_symbol_count = count_builtin_symbols(&content);
    let metrics = KernelMetrics {
        arch,
        variant: label,
        y_symbol_count,
        vmlinux_bytes: bytes,
    };
    if let Ok(json) = serde_json::to_string(&metrics) {
        let dest = vmlinux.with_file_name(format!("kernel-metrics-{arch}.json"));
        let _ = std::fs::write(dest, json + "\n");
    }
    Some(y_symbol_count)
}

/// Boot a throwaway microVM on the freshly-built workload kernel and confirm
/// the agent answers. Re-execs `mvmctl` (the real `up` / `machine` paths)
/// rather than reconstructing their argument plumbing here.
#[cfg(feature = "builder-vm")]
fn run_boot_check(
    variants: &[(crate::commands::env::dev_vz::KernelVariant, &str)],
    arch: &str,
) -> Result<()> {
    use crate::commands::env::dev_vz::KernelVariant;
    use crate::ui;

    if !variants.iter().any(|(v, _)| *v == KernelVariant::Workload) {
        ui::warn(
            "--boot-check applies to the workload kernel; nothing to boot for --which builder",
        );
        return Ok(());
    }
    if !std::path::Path::new("examples/sleeper").is_dir() {
        anyhow::bail!(
            "--boot-check needs a source checkout (examples/sleeper not found in the cwd)"
        );
    }
    // Precondition: `up` builds the sleeper image, which needs the full builder
    // VM image (kernel just built into the cache isn't enough). Fail early with
    // a fixable message rather than a deep `up` error 20 min into a build.
    let builder_rootfs = mvm_build::builder_vm::builder_vm_cache_dir()
        .join(arch)
        .join("rootfs.ext4");
    if !builder_rootfs.is_file() {
        anyhow::bail!(
            "--boot-check needs the builder VM image, which isn't in the cache yet \
             ({}). Run `mvmctl dev up` once to populate it, then retry.",
            builder_rootfs.display()
        );
    }
    let exe = std::env::current_exe().context("locating mvmctl for --boot-check")?;
    let name = "kernel-bootcheck";
    let _ = run_self(&exe, &["machine", "stop", name]); // clear any stale VM

    // Force libkrun: it's available wherever `--source compile` ran (it drives
    // Stage 0), so the check is deterministic and doesn't depend on the host's
    // default workload backend (Vz on macOS 26) or its separate supervisor. The
    // kernel is backend-agnostic, so a libkrun boot proves it boots.
    ui::info("boot-check: booting a throwaway VM on the new workload kernel (libkrun)…");
    run_self(
        &exe,
        &[
            "up",
            "--flake",
            "examples/sleeper",
            "--hypervisor",
            "libkrun",
            "--name",
            name,
            "-d",
        ],
    )
    .context("boot-check: `up` failed to launch the VM")?;

    let booted = run_self(&exe, &["machine", "wait", name]);
    let _ = run_self(&exe, &["machine", "stop", name]);
    booted.context("boot-check: the guest agent never became ready")?;
    ui::success("boot-check: the new kernel boots and the agent answered over vsock");
    Ok(())
}

/// Run `mvmctl <args>` inheriting stdio; error on non-zero exit.
#[cfg(feature = "builder-vm")]
fn run_self(exe: &std::path::Path, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(exe)
        .args(args)
        .status()
        .with_context(|| format!("spawning mvmctl {}", args.join(" ")))?;
    if !status.success() {
        anyhow::bail!("mvmctl {} exited {}", args.join(" "), status);
    }
    Ok(())
}

/// Resolve a kernel by `source` into the per-arch cache, returning its path.
#[cfg(feature = "builder-vm")]
fn acquire_kernel(
    source: Source,
    variant: crate::commands::env::dev_vz::KernelVariant,
    label: &str,
    arch: &str,
    verbose: bool,
) -> Result<std::path::PathBuf> {
    let dest = kernel_cache_path(arch, label);
    match source {
        Source::Compile => compile_host_arch(variant, arch, verbose),
        Source::Download => {
            crate::update::download_kernel(arch, label, &dest)?;
            Ok(dest)
        }
        Source::Auto => match crate::update::download_kernel(arch, label, &dest) {
            Ok(()) => Ok(dest),
            Err(e) => {
                crate::ui::warn(&format!("download failed ({e}); compiling locally"));
                compile_host_arch(variant, arch, verbose)
            }
        },
    }
}

/// Compile arm — host arch only (Stage 0 cannot cross-compile).
#[cfg(feature = "builder-vm")]
fn compile_host_arch(
    variant: crate::commands::env::dev_vz::KernelVariant,
    arch: &str,
    verbose: bool,
) -> Result<std::path::PathBuf> {
    if arch != host_arch() {
        anyhow::bail!(
            "--source compile builds the host arch ({}) only; use --source download for {arch}",
            host_arch()
        );
    }
    crate::commands::env::dev_vz::build_kernel_via_stage0(variant, verbose)
}

/// Per-arch, per-variant cached kernel path. Mirrors
/// `build_kernel_via_stage0`'s output location.
#[cfg(feature = "builder-vm")]
fn kernel_cache_path(arch: &str, label: &str) -> std::path::PathBuf {
    std::path::Path::new(&mvm_core::config::mvm_cache_dir())
        .join("builder-vm")
        .join(arch)
        .join("kernels")
        .join(label)
        .join("vmlinux")
}

#[cfg(not(feature = "builder-vm"))]
fn run_build(_args: BuildArgs, _verbose: bool) -> Result<()> {
    anyhow::bail!(
        "`mvmctl kernel build` requires the `builder-vm` feature; \
         rebuild mvmctl with it enabled."
    )
}

#[cfg(all(test, feature = "builder-vm"))]
mod tests {
    use super::count_builtin_symbols;

    #[test]
    fn counts_only_lines_ending_in_y() {
        let cfg = "\
CONFIG_A=y
CONFIG_B=m
# CONFIG_C is not set
CONFIG_D=y
CONFIG_E=\"some=y string\"
CONFIG_F=42
CONFIG_G=y
";
        // A, D, G — not the =m, the comment, the quoted-value, or the number.
        assert_eq!(count_builtin_symbols(cfg), 3);
    }

    #[test]
    fn empty_config_is_zero() {
        assert_eq!(count_builtin_symbols(""), 0);
    }

    #[test]
    fn tolerates_trailing_whitespace() {
        assert_eq!(count_builtin_symbols("CONFIG_A=y \nCONFIG_B=y\t\n"), 2);
    }
}
