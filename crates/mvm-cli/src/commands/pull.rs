//! `mvmctl pull` — verify, install and pin signed registry products.

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

pub(in crate::commands) fn installed_application_text(
    reference: &str,
    digest: &str,
    bundle_digest: &str,
) -> String {
    format!("installed {reference} (manifest {digest}, bundle {bundle_digest})")
}

fn installed_application_json(
    reference: &str,
    digest: &str,
    bundle_digest: &str,
    key_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "reference": reference,
        "manifest_sha256": digest,
        "bundle_sha256": bundle_digest,
        "key_id": key_id,
        "status": "installed",
        "installed": true
    })
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args, _cfg: &MvmConfig) -> Result<()> {
    let outcome = pack_registry::pull(&args.reference)?;
    let summary = match outcome {
        pack_registry::PullOutcome::Installed(summary) => summary,
        pack_registry::PullOutcome::InstalledApplication(installed) => {
            use mvm_core::registry_pack::AuthenticatedRegistryManifest;
            let application = installed.application();
            let reference = application.reference().to_string();
            let digest = application.manifest_sha256().as_str();
            if args.json {
                return crate::json_out::emit_json(&installed_application_json(
                    &reference,
                    digest,
                    &installed.bundle().sha256,
                    &installed.bundle().manifest.key_id.0,
                ));
            }
            println!(
                "{}",
                installed_application_text(&reference, digest, &installed.bundle().sha256)
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

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "ce1ac86f67e6a9df7a1b1a46d63384fa20a30848fdd7e5967d2293bfb5ceec50";
    const BUNDLE_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_ID: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn installed_application_text_names_the_manifest_and_bundle() {
        assert_eq!(
            installed_application_text("runtime/python@1.2.3", DIGEST, BUNDLE_DIGEST),
            format!("installed runtime/python@1.2.3 (manifest {DIGEST}, bundle {BUNDLE_DIGEST})")
        );
    }

    #[test]
    fn installed_application_json_binds_the_bundle_and_key() {
        assert_eq!(
            installed_application_json("runtime/python@1.2.3", DIGEST, BUNDLE_DIGEST, KEY_ID),
            serde_json::json!({
                "reference": "runtime/python@1.2.3",
                "manifest_sha256": DIGEST,
                "bundle_sha256": BUNDLE_DIGEST,
                "key_id": KEY_ID,
                "status": "installed",
                "installed": true
            })
        );
    }
}
