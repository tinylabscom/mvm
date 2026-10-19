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

pub(in crate::commands) fn verified_application_text(reference: &str, digest: &str) -> String {
    format!(
        "verified {reference} (manifest {digest}); application bundle not acquired or installed"
    )
}

fn verified_application_json(reference: &str, digest: &str) -> serde_json::Value {
    serde_json::json!({
        "reference": reference,
        "manifest_sha256": digest,
        "status": "verified",
        "installed": false
    })
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let outcome = pack_registry::pull(&args.reference)?;
    let summary = match outcome {
        pack_registry::PullOutcome::Installed(summary) => summary,
        pack_registry::PullOutcome::VerifiedApplication(application) => {
            use mvm_core::registry_pack::AuthenticatedRegistryManifest;
            let reference = application.reference().to_string();
            let digest = application.manifest_sha256().as_str();
            if args.json {
                return crate::json_out::emit_json(&verified_application_json(&reference, digest));
            }
            println!("{}", verified_application_text(&reference, digest));
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

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50";

    #[test]
    fn verified_application_text_says_nothing_was_installed() {
        assert_eq!(
            verified_application_text("runtime/python@1.2.3", DIGEST),
            format!(
                "verified runtime/python@1.2.3 (manifest {DIGEST}); application bundle not acquired or installed"
            )
        );
    }

    #[test]
    fn verified_application_json_is_verified_and_not_installed() {
        assert_eq!(
            verified_application_json("runtime/python@1.2.3", DIGEST),
            serde_json::json!({
                "reference": "runtime/python@1.2.3",
                "manifest_sha256": DIGEST,
                "status": "verified",
                "installed": false
            })
        );
    }
}
