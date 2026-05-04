//! `mvmctl manifest rm` — remove a slot from the local registry.

use anyhow::{Context, Result};
use clap::Args as ClapArgs;

use mvm_core::manifest::{canonical_key_for_path, resolve_manifest_config_path};
use mvm_core::user_config::MvmConfig;
use mvm_runtime::vm::template::lifecycle as tmpl;

use super::super::Cli;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// Manifest path (file or directory). Defaults to walking up from cwd.
    #[arg(value_name = "PATH")]
    pub path: Option<String>,
    /// Don't error if the slot doesn't exist
    #[arg(long)]
    pub force: bool,
    /// Also delete the source `mvm.toml` from disk (off by default)
    #[arg(long)]
    pub manifest_file: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let manifest_path = match args.path.as_deref() {
        Some(p) => resolve_manifest_config_path(std::path::Path::new(p))?,
        None => {
            let cwd = std::env::current_dir().context("Failed to read cwd")?;
            mvm_core::manifest::discover_manifest_from_dir(&cwd)?
                .ok_or_else(|| anyhow::anyhow!(
                    "No manifest found from cwd. Pass a path explicitly or `--force` if removing an orphaned slot by hash."
                ))?
        }
    };

    let canonical = std::fs::canonicalize(&manifest_path).with_context(|| {
        format!(
            "Failed to canonicalize manifest path {}",
            manifest_path.display()
        )
    })?;
    let slot_hash = canonical_key_for_path(&canonical)?;
    tmpl::template_delete_slot(&slot_hash, args.force)?;

    if args.manifest_file && canonical.exists() {
        std::fs::remove_file(&canonical)
            .with_context(|| format!("Failed to delete manifest file {}", canonical.display()))?;
        println!("Removed slot {} and manifest file {}", slot_hash, canonical.display());
    } else {
        println!("Removed slot {}", slot_hash);
    }

    Ok(())
}
