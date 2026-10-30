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
use mvm_client::image_admin::revocations as client_revocations;
use mvm_core::image_set_revocation::{ImageSetRevocationCheckpoint, VerifiedImageSetRevocations};
use serde::Serialize;

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
        Action::Status { json } => status(json),
    }
}

fn update(args: &UpdateArgs) -> Result<()> {
    let checkpoint = client_revocations::update(&args.document, &args.bundle)?;
    println!("{}", describe_checkpoint(&checkpoint));
    Ok(())
}

fn status(json: bool) -> Result<()> {
    let report = StatusReport::from(&client_revocations::status()?);
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
    use crate::commands::{Cli, dispatch::TopLevelCommand};
    use clap::Parser;
    use mvm_core::user_config::MvmConfig;

    fn invoke(args: impl IntoIterator<Item = std::ffi::OsString>) -> Result<()> {
        let cli = Cli::try_parse_from(
            ["mvmctl".into(), "image".into(), "revocations".into()]
                .into_iter()
                .chain(args),
        )?;
        cli.command.clone().run(&cli, &MvmConfig::default())
    }

    fn invoke_update(document: &std::path::Path, bundle: &std::path::Path) -> Result<()> {
        invoke([
            "update".into(),
            "--document".into(),
            document.as_os_str().into(),
            "--bundle".into(),
            bundle.as_os_str().into(),
        ])
    }

    fn assert_no_applied_list_or_success_audit(home: &std::path::Path) {
        let root = mvm_core::config::image_set_revocation_store_dir();
        // The canonical store may have created its private root/lock. This is
        // not a claim that verification refusal causes zero filesystem writes.
        assert!(!root.join("checkpoint.json").exists());
        assert!(!root.join("feed.json").exists());
        assert!(!home.join("audit.jsonl").exists());
    }

    #[test]
    fn status_without_an_applied_list_refuses_and_says_how_to_apply_one() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for json in [false, true] {
            let mut args = vec![std::ffi::OsString::from("status")];
            if json {
                args.push("--json".into());
            }
            let err = invoke(args).expect_err("no list applied");
            assert!(
                format!("{err:#}").contains("mvmctl image revocations update"),
                "{err:#}"
            );
            assert_no_applied_list_or_success_audit(home.path());
        }
    }

    #[test]
    fn update_refuses_unsigned_input_without_applying_a_list_or_success_audit() {
        let home = tempfile::tempdir().expect("tempdir");
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        let document = home.path().join("revocations.json");
        let bundle = home.path().join("revocations.json.bundle");
        std::fs::write(
            &document,
            br#"{"schema_version":1,"revocations":[],"issued_at":"2026-01-01T00:00:00Z","not_after":"2026-02-01T00:00:00Z"}"#,
        )
        .expect("document");
        std::fs::write(&bundle, b"not a bundle").expect("bundle");
        assert!(invoke_update(&document, &bundle).is_err());
        assert_no_applied_list_or_success_audit(home.path());
    }

    #[test]
    fn both_input_bounds_refuse_before_opening_the_canonical_store() {
        for oversized_document in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            let document = home.path().join("document");
            let bundle = home.path().join("bundle");
            std::fs::write(&document, b"{}").unwrap();
            std::fs::write(&bundle, b"unsigned").unwrap();
            let path = if oversized_document {
                &document
            } else {
                &bundle
            };
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .unwrap()
                .set_len(1024 * 1024 + 1)
                .unwrap();
            let error = invoke_update(&document, &bundle).unwrap_err();
            assert!(format!("{error:#}").contains("1 MiB"), "{error:#}");
            assert!(!mvm_core::config::image_set_revocation_store_dir().exists());
            assert_no_applied_list_or_success_audit(home.path());
        }
    }

    #[test]
    fn missing_and_directory_inputs_refuse_before_store_effects() {
        for missing in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            let document = home.path().join("input");
            if !missing {
                std::fs::create_dir(&document).unwrap();
            }
            assert!(invoke_update(&document, &home.path().join("bundle")).is_err());
            assert!(!mvm_core::config::image_set_revocation_store_dir().exists());
            assert_no_applied_list_or_success_audit(home.path());
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_and_fifo_inputs_refuse_before_store_effects() {
        for bundle_input in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let mut env = mvm_core::util::test_env::TestEnv::new();
            env.isolate_mvm_home(home.path());
            let document = home.path().join("document");
            let bundle = home.path().join("bundle");
            std::fs::write(&document, b"{}").unwrap();
            std::fs::write(&bundle, b"unsigned").unwrap();
            let path = if bundle_input { &bundle } else { &document };
            std::fs::remove_file(path).unwrap();
            let target = home.path().join("target");
            std::fs::write(&target, b"{}").unwrap();
            std::os::unix::fs::symlink(&target, path).unwrap();
            assert!(invoke_update(&document, &bundle).is_err());
            std::fs::remove_file(path).unwrap();
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
            assert!(invoke_update(&document, &bundle).is_err());
            assert!(!mvm_core::config::image_set_revocation_store_dir().exists());
            assert_no_applied_list_or_success_audit(home.path());
        }
    }

    #[test]
    fn update_flags_remain_required_and_reject_overrides_before_effects() {
        let home = tempfile::Builder::new()
            .prefix("revocations-no-effects-")
            .tempdir()
            .unwrap();
        let mut env = mvm_core::util::test_env::TestEnv::new();
        env.isolate_mvm_home(home.path());
        for args in [
            vec!["update".into()],
            vec!["update".into(), "--document".into(), "document".into()],
            vec!["status".into(), "--issuer".into(), "override".into()],
        ] {
            let error = invoke(args).unwrap_err();
            assert!(error.downcast_ref::<clap::Error>().is_some());
        }
        let entries: Vec<_> = std::fs::read_dir(home.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert!(entries.is_empty(), "unexpected home entries: {entries:?}");
    }

    #[test]
    fn checkpoint_formatter_preserves_labels_using_metadata_only() {
        use chrono::TimeZone;
        let checkpoint = ImageSetRevocationCheckpoint {
            publication: 7,
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            sha256: mvm_core::packs::Sha256Hex::from_bytes(b"formatter fixture, not verification"),
        };
        assert_eq!(
            describe_checkpoint(&checkpoint),
            format!(
                "verified image-set revocations publication 7 issued 2026-01-01T00:00:00+00:00 (sha256 {})",
                checkpoint.sha256.as_str()
            )
        );
    }

    #[test]
    fn status_text_and_json_shapes_are_pinned_by_unverified_metadata_only() {
        use chrono::TimeZone;
        // This is a rendering fixture, deliberately not a Verified value.
        let report = StatusReport {
            publication: 7,
            issued_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            not_after: Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap(),
            sha256: "a".repeat(64),
            signer_identity: "rendering-fixture-not-authentication".into(),
            entries: 3,
        };
        assert_eq!(
            report.render(),
            format!(
                "publication: 7\nissued_at:   2026-01-01T00:00:00+00:00\nnot_after:   2026-02-01T00:00:00+00:00\nsha256:      {}\nsigner:      rendering-fixture-not-authentication\nentries:     3",
                "a".repeat(64)
            )
        );
        assert_eq!(
            serde_json::to_value(&report).unwrap(),
            serde_json::json!({
                "publication": 7, "issued_at": "2026-01-01T00:00:00Z",
                "not_after": "2026-02-01T00:00:00Z", "sha256": "a".repeat(64),
                "signer_identity": "rendering-fixture-not-authentication", "entries": 3
            })
        );
    }
}
