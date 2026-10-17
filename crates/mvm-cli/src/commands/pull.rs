//! `mvmctl pull` — install legacy packs or verify application metadata.

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
    let outcome = pack_registry::pull(&args.reference)?;
    let summary = match outcome {
        pack_registry::PullOutcome::Installed(summary) => summary,
        pack_registry::PullOutcome::VerifiedApplication(application) => {
            use mvm_core::registry_pack::AuthenticatedRegistryManifest;
            if args.json {
                return crate::json_out::emit_json(&serde_json::json!({
                    "reference": application.reference().to_string(),
                    "manifest_sha256": application.manifest_sha256().as_str(),
                    "status": "verified",
                    "installed": false
                }));
            }
            println!(
                "verified {} (manifest {}); application bundle not acquired or installed",
                application.reference(),
                application.manifest_sha256().as_str()
            );
            return Ok(());
        }
    };
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
