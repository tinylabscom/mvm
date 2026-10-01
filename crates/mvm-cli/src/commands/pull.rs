//! `mvmctl pull` — fetch, verify, install, and pin a signed registry pack.

use anyhow::Result;
use clap::Args as ClapArgs;
use mvm_core::user_config::MvmConfig;
use serde::Serialize;

use super::Cli;
use crate::pack_registry;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    /// The pack to pull: `namespace/name`, optionally `@version`
    #[arg(value_name = "ns/name[@version]")]
    pub reference: String,
    /// Emit machine-readable JSON to stdout
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct PullJson<'a> {
    reference: &'a str,
    manifest_sha256: &'a str,
    files: usize,
    refreshed: bool,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let summary = pack_registry::pull(&args.reference)?;
    if args.json {
        return crate::json_out::emit_json(&PullJson {
            reference: &summary.reference.to_string(),
            manifest_sha256: &summary.manifest_sha256,
            files: summary.files,
            refreshed: summary.refreshed,
        });
    }
    let verb = if summary.refreshed {
        "refreshed"
    } else {
        "pulled"
    };
    println!(
        "{verb} {} ({} files, manifest {})",
        summary.reference, summary.files, summary.manifest_sha256,
    );
    Ok(())
}
