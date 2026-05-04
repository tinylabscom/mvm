//! `mvmctl manifest verify` — checksum verification (and, post plan 36,
//! cosign signatures) for a built slot.

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
    /// Verify a specific revision instead of the slot's current symlink.
    #[arg(long)]
    pub revision: Option<String>,
    /// Verify cosign signatures in addition to checksums. Reserved
    /// for plan 36 (sealed-signed-builder-image); today returns
    /// "not yet implemented" if passed.
    #[arg(long)]
    pub check_signature: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    if args.check_signature {
        anyhow::bail!(
            "--check-signature is reserved for plan 36 (sealed-signed-builder-image) and is not yet wired. Run without the flag for the checksum-only path."
        );
    }

    let manifest_path = match args.path.as_deref() {
        Some(p) => resolve_manifest_config_path(std::path::Path::new(p))?,
        None => {
            let cwd = std::env::current_dir().context("Failed to read cwd")?;
            mvm_core::manifest::discover_manifest_from_dir(&cwd)?
                .ok_or_else(|| anyhow::anyhow!(
                    "No manifest found from cwd. Pass a path explicitly via the positional arg."
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

    tmpl::template_verify_slot(&slot_hash, args.revision.as_deref())?;

    println!(
        "OK: slot {} ({}) verified",
        &slot_hash[..slot_hash.len().min(12)],
        canonical.display()
    );
    Ok(())
}
