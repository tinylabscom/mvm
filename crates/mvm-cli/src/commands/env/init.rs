//! `mvmctl init` — scaffold a project (`mvm.toml` + `flake.nix`).
//!
//! Plan 40 dropped the standalone "first-time environment wizard"
//! branch this verb used to dispatch into. Run `mvmctl bootstrap`
//! for environment setup; `init` is now a pure project-scaffold
//! verb.

use anyhow::Result;
use clap::Args as ClapArgs;

use mvm_core::user_config::MvmConfig;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Project directory to scaffold (`mvm.toml` + `flake.nix`).
    #[arg(value_name = "DIR")]
    pub dir: String,
    /// Scaffold preset: `minimal` (default), `http`, `postgres`,
    /// `worker`, `python`. Mutually exclusive with `--catalog`.
    #[arg(long, conflicts_with = "catalog")]
    pub preset: Option<String>,
    /// Natural-language description of the workload. Routes
    /// through the LLM/heuristic planner (see
    /// `MVM_TEMPLATE_PROVIDER`). Mutually exclusive with `--catalog`.
    #[arg(long, conflicts_with = "catalog")]
    pub prompt: Option<String>,
    /// Scaffold from a bundled catalog entry. Run `mvmctl catalog list`
    /// to see available entries.
    #[arg(long)]
    pub catalog: Option<String>,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let preset = if let Some(catalog_name) = args.catalog.as_deref() {
        let catalog = super::super::catalog::load_bundled_catalog();
        let entry = catalog
            .find(catalog_name)
            .ok_or_else(|| anyhow::anyhow!("Catalog entry {:?} not found", catalog_name))?;
        Some(entry.profile.clone())
    } else {
        args.preset.clone()
    };

    crate::template_cmd::init(
        &args.dir,
        true,
        ".",
        preset.as_deref(),
        args.prompt.as_deref(),
    )
}
