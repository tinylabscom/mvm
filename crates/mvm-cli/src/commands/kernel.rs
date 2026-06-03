//! `mvmctl kernel` — build the custom microVM kernels.
//!
//! The builder-VM and workload microVM kernels are slim custom Linux
//! builds (`nix/lib/kernel/base.nix` + per-variant deltas). Because the
//! config is custom, `cache.nixos.org` has no substitute, so a fresh
//! machine compiles from source — the slow, memory-heavy step a first
//! `mvmctl dev up` otherwise hits implicitly. This command makes that
//! compile explicit and one-time: build the kernel once into the
//! persistent nix store, and every later `dev up` reuses it.
//!
//! `--source download` (fetch a hash-verified published prebuilt) lands
//! with the kernel-build publish workflow, which is what produces the
//! artifact to download.

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

    /// Where the kernel comes from. `compile` builds locally via Stage 0.
    #[arg(long, value_enum, default_value_t = Source::Compile)]
    source: Source,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Which {
    Builder,
    Workload,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Compile locally through the Stage 0 builder bootstrap.
    Compile,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    match args.cmd {
        Cmd::Build(b) => run_build(b),
    }
}

#[cfg(feature = "builder-vm")]
fn run_build(args: BuildArgs) -> Result<()> {
    use crate::commands::env::apple_container::{KernelVariant, build_kernel_via_stage0};
    use crate::ui;

    // Single source today; the binding keeps the flag wired and warns
    // here if a future variant is added without a branch.
    let Source::Compile = args.source;

    let variants: Vec<KernelVariant> = if args.all {
        vec![KernelVariant::Builder, KernelVariant::Workload]
    } else {
        match args.which {
            Which::Builder => vec![KernelVariant::Builder],
            Which::Workload => vec![KernelVariant::Workload],
        }
    };

    for variant in variants {
        let path = build_kernel_via_stage0(variant)?;
        let mib = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) as f64 / (1024.0 * 1024.0);
        ui::success(&format!(
            "Built {variant:?} kernel: {} ({mib:.1} MiB)",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(feature = "builder-vm"))]
fn run_build(_args: BuildArgs) -> Result<()> {
    anyhow::bail!(
        "`mvmctl kernel build` requires the `builder-vm` feature; \
         rebuild mvmctl with it enabled."
    )
}
