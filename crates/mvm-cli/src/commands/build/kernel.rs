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
        Cmd::Build(b) => run_build(b, cli.verbose),
    }
}

#[cfg(feature = "builder-vm")]
fn run_build(args: BuildArgs, verbose: bool) -> Result<()> {
    use crate::commands::env::apple_container::KernelVariant;
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

    for (variant, label) in variants {
        let path = acquire_kernel(args.source, variant, label, &arch, verbose)?;
        let mib = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as f64 / (1024.0 * 1024.0);
        ui::success(&format!(
            "{label} kernel ({arch}): {} ({mib:.1} MiB)",
            path.display()
        ));
    }
    Ok(())
}

/// Resolve a kernel by `source` into the per-arch cache, returning its path.
#[cfg(feature = "builder-vm")]
fn acquire_kernel(
    source: Source,
    variant: crate::commands::env::apple_container::KernelVariant,
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
    variant: crate::commands::env::apple_container::KernelVariant,
    arch: &str,
    verbose: bool,
) -> Result<std::path::PathBuf> {
    if arch != host_arch() {
        anyhow::bail!(
            "--source compile builds the host arch ({}) only; use --source download for {arch}",
            host_arch()
        );
    }
    crate::commands::env::apple_container::build_kernel_via_stage0(variant, verbose)
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
