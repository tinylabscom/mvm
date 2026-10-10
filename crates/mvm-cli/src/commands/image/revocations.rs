//! `mvmctl image revocations` — apply and inspect the signed image-set
//! revocation list that offline image-set admission reads.
//!
//! Nothing here fetches. An operator downloads the list and its bundle from
//! the published channel and applies them; admission then reads the applied
//! copy without touching the network.

use std::path::PathBuf;

use anyhow::Result;
use chrono::{DateTime, Utc};
use clap::{Args as ClapArgs, Subcommand};
use mvm_core::image_set_revocation::{
    ImageSetRevocationCheckpoint, ImageSetRevocationStore, VerifiedImageSetRevocations,
    update_image_set_revocations,
};
use serde::Serialize;

use crate::commands::shared::read_signed_input;

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand, Debug, Clone)]
pub(in crate::commands) enum Action {
    /// Verify a signed image-set revocation list and advance the local checkpoint
    Update(UpdateArgs),
    /// Re-verify the applied image-set revocation list and report it
    Status {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(ClapArgs, Debug, Clone)]
pub(in crate::commands) struct UpdateArgs {
    /// The `revocations.json` published by the image-set revocation channel
    #[arg(long, value_name = "FILE")]
    document: PathBuf,
    /// The `revocations.json.bundle` signature bundle for those exact bytes
    #[arg(long, value_name = "FILE")]
    bundle: PathBuf,
}

pub(in crate::commands) fn run(action: Action) -> Result<()> {
    match action {
        Action::Update(args) => update(&args),
        Action::Status { json } => {
            status(&ImageSetRevocationStore::in_mvm_home(), Utc::now(), json)
        }
    }
}

fn update(args: &UpdateArgs) -> Result<()> {
    let document = read_signed_input(&args.document)?;
    let bundle = read_signed_input(&args.bundle)?;
    let checkpoint = update_image_set_revocations(&document, &bundle)?;
    println!("{}", describe_checkpoint(&checkpoint));
    Ok(())
}

fn status(store: &ImageSetRevocationStore, now: DateTime<Utc>, json: bool) -> Result<()> {
    let report = StatusReport::from(&store.load(now)?);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", report.render());
    }
    Ok(())
}

fn describe_checkpoint(checkpoint: &ImageSetRevocationCheckpoint) -> String {
    format!(
        "verified image-set revocations publication {} issued {} (sha256 {})",
        checkpoint.publication,
        checkpoint.issued_at.to_rfc3339(),
        checkpoint.sha256.as_str()
    )
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct StatusReport {
    publication: u64,
    issued_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
    sha256: String,
    signer_identity: String,
    entries: usize,
}

impl From<&VerifiedImageSetRevocations> for StatusReport {
    fn from(verified: &VerifiedImageSetRevocations) -> Self {
        let checkpoint = verified.checkpoint();
        Self {
            publication: checkpoint.publication,
            issued_at: checkpoint.issued_at,
            not_after: verified.not_after(),
            sha256: checkpoint.sha256.as_str().to_string(),
            signer_identity: verified.signer_identity().to_string(),
            entries: verified.entry_count(),
        }
    }
}

impl StatusReport {
    fn render(&self) -> String {
        format!(
            "publication: {}\nissued_at:   {}\nnot_after:   {}\nsha256:      {}\nsigner:      {}\nentries:     {}",
            self.publication,
            self.issued_at.to_rfc3339(),
            self.not_after.to_rfc3339(),
            self.sha256,
            self.signer_identity,
            self.entries
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_without_an_applied_list_refuses_and_says_how_to_apply_one() {
        let home = tempfile::tempdir().expect("tempdir");
        let store = ImageSetRevocationStore::new(home.path().join("image-set-revocations"));
        let err = status(&store, Utc::now(), false).expect_err("no list applied");
        assert!(
            format!("{err:#}").contains("mvmctl image revocations update"),
            "{err:#}"
        );
    }

    #[test]
    fn update_refuses_an_unsigned_list_and_leaves_nothing_behind() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let root = mvm_core::config::image_set_revocation_store_dir();
        let document = home.path().join("revocations.json");
        let bundle = home.path().join("revocations.json.bundle");
        std::fs::write(
            &document,
            br#"{"schema_version":1,"revocations":[],"issued_at":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z"}"#,
        )
        .expect("document");
        std::fs::write(&bundle, b"not a bundle").expect("bundle");
        let args = UpdateArgs { document, bundle };
        assert!(update(&args).is_err());
        assert!(!root.join("checkpoint.json").exists());
        assert!(!root.join("feed.json").exists());
    }
}
