//! `mvmctl image boot` — inspect, compare, and replace the cached boot image.
//!
//! Three verbs over one cache: `status` says what is on disk, `check` says
//! whether it is behind the published line, and `update` replaces it. They are
//! separated by what they touch — `status` reads disk, `check` adds the
//! network, `update` adds a write — so a script can use exactly as much as it
//! needs.

use anyhow::Result;
use clap::Subcommand;

pub(crate) mod cache;
mod check;
mod status;
mod update;

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum BootAction {
    /// Show the cached boot image variants and their provenance (no network)
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Compare the cached boot image against the latest published release
    Check {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Fetch, verify, and atomically replace the cached boot image
    Update {
        /// Pin a specific `boot-image/vX.Y.Z` release instead of the latest
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,
        /// Replace the image even in a source checkout, where the local build
        /// is otherwise authoritative
        #[arg(long)]
        force: bool,
    },
}

pub(in crate::commands) fn run(action: BootAction) -> Result<()> {
    match action {
        BootAction::Status { json } => status::run(json),
        BootAction::Check { json } => check::run(json),
        BootAction::Update { tag, force } => update::run(&update::UpdateRequest { tag, force }),
    }
}

#[cfg(test)]
mod tests;
