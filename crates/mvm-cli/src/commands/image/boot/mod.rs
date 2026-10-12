//! `mvmctl image boot` — inspect, compare, replace, and verify boot images.
//!
//! Three verbs over one cache: `status` says what is on disk, `check` says
//! whether it is behind the published line, and `update` replaces it. They are
//! separated by what they touch — `status` and `check` read disk and the
//! compiled lock, while `update` adds network access and a write — so a script can use exactly as much as it
//! needs. `verify` touches none of them: it checks a published image set that
//! is already on disk against the lock that pins it, offline.

use std::path::PathBuf;

use anyhow::Result;
use clap::Subcommand;

pub(crate) mod cache;
mod check;
mod status;
mod update;
mod verify;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BootAction {
    /// Show the cached boot image variants and their provenance (no network)
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Compare the cached boot image against this build's locked image set
    Check {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Fetch, verify, and atomically replace the cached boot image
    Update {
        /// Assert the exact `image-set/vX.Y.Z` release already pinned by this build
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,
        /// Replace the image even in a source checkout, where the local build
        /// is otherwise authoritative
        #[arg(long)]
        force: bool,
    },
    /// Verify a published image set offline against the lock that pins it
    Verify {
        /// The image set manifest, exactly as published
        #[arg(long, value_name = "FILE")]
        manifest: PathBuf,
        /// The detached cosign bundle published beside the manifest
        #[arg(long, value_name = "FILE")]
        bundle: PathBuf,
        /// The image lock naming the manifest digest and signing identity.
        /// Omitted, the set is checked against the pin compiled into this
        /// binary — the bytes this CLI would itself accept
        #[arg(long, value_name = "FILE")]
        lock: Option<PathBuf>,
        /// Directory holding the member artifacts to verify under their declared names
        #[arg(long, value_name = "DIR")]
        artifacts: PathBuf,
        /// Verify only this declared artifact (repeatable); unselected artifacts are not verified
        #[arg(long, value_name = "NAME")]
        artifact: Vec<String>,
        /// Also refuse a set missing any member the current release train needs
        #[arg(long)]
        require_complete: bool,
        /// Also refuse a revoked set or member, under the signed image-set
        /// revocation list applied with `mvmctl image revocations update`.
        /// Fails when no current list has been applied
        #[arg(long)]
        check_revocations: bool,
        /// Output as JSON (printed for a refusal too; the exit code still fails)
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(action: BootAction) -> Result<()> {
    match action {
        BootAction::Status { json } => status::run(json),
        BootAction::Check { json } => check::run(json),
        BootAction::Update { tag, force } => update::run(&update::UpdateRequest { tag, force }),
        BootAction::Verify {
            manifest,
            bundle,
            lock,
            artifacts,
            artifact,
            require_complete,
            check_revocations,
            json,
        } => verify::run(&verify::VerifyRequest {
            manifest,
            bundle,
            lock,
            artifacts,
            artifact,
            require_complete,
            check_revocations,
            json,
        }),
    }
}

#[cfg(test)]
mod tests;
