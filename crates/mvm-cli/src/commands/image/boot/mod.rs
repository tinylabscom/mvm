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
        /// Roll back to an older canonical image lock without rebuilding mvmctl
        #[arg(long, value_name = "FILE", conflicts_with = "tag")]
        lock: Option<PathBuf>,
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
        /// The image lock naming the manifest digest and signing identity
        #[arg(long, value_name = "FILE")]
        lock: PathBuf,
        /// Directory holding every member artifact under its declared name
        #[arg(long, value_name = "DIR")]
        artifacts: PathBuf,
        /// Also refuse a set missing any member the current release train needs
        #[arg(long)]
        require_complete: bool,
        /// Output as JSON (printed for a refusal too; the exit code still fails)
        #[arg(long)]
        json: bool,
    },
}

pub(in crate::commands) fn run(action: BootAction) -> Result<()> {
    match action {
        BootAction::Status { json } => status::run(json),
        BootAction::Check { json } => check::run(json),
        BootAction::Update { tag, lock, force } => {
            update::run(&update::UpdateRequest { tag, lock, force })
        }
        BootAction::Verify {
            manifest,
            bundle,
            lock,
            artifacts,
            require_complete,
            json,
        } => verify::run(&verify::VerifyRequest {
            manifest,
            bundle,
            lock,
            artifacts,
            require_complete,
            json,
        }),
    }
}

#[cfg(test)]
mod tests;
