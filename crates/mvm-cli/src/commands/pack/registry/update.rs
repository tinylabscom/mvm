//! `mvmctl pack registry update`.

use anyhow::Result;

use super::UpdateArgs;
use crate::pack_registry;

pub(in crate::commands) fn run(args: UpdateArgs) -> Result<()> {
    let outcome = pack_registry::pull(&args.reference)?;
    let summary = match outcome {
        pack_registry::PullOutcome::Installed(summary) => summary,
        pack_registry::PullOutcome::VerifiedApplication(application) => {
            use mvm_core::registry_pack::AuthenticatedRegistryManifest;
            println!(
                "verified {} (manifest {}); application bundle not acquired or installed",
                application.reference(),
                application.manifest_sha256().as_str()
            );
            return Ok(());
        }
    };
    let verb = if summary.refreshed {
        "refreshed"
    } else {
        "updated"
    };
    println!(
        "{verb} {} ({} files, manifest {})",
        summary.reference, summary.files, summary.manifest_sha256,
    );
    Ok(())
}
