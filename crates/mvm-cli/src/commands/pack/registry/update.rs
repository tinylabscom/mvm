//! `mvmctl pack registry update`.

use anyhow::Result;

use super::UpdateArgs;
use crate::pack_registry;

pub(in crate::commands) fn run(args: UpdateArgs) -> Result<()> {
    let summary = pack_registry::pull(&args.reference)?;
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
