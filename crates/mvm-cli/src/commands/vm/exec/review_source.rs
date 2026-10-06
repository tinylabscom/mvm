//! Where a transient run's egress refusals are reviewed: the project manifest
//! its policy was read from, settled before a `--flake` is built into a slot,
//! and the offer made once the run ends.

use anyhow::Result;

use super::RunArgs;
use crate::commands::vm::denial_review::{self, JsonReviewPointer, ReviewSource};
use crate::commands::vm::egress_denials::{DenialTally, PendingWatch};

/// Build a `--flake` into a manifest slot and point the run at it, returning
/// the slot. The run's review source is settled first: once the slot replaces
/// the flake, the arguments no longer name the project directory its policy
/// was read from.
pub(in crate::commands) fn build_flake_slot(args: &mut RunArgs) -> Result<Option<String>> {
    build_flake_slot_with(args, crate::commands::build::build::build_flake_to_slot)
}

fn build_flake_slot_with(
    args: &mut RunArgs,
    build: impl FnOnce(&str, Option<&str>) -> Result<String>,
) -> Result<Option<String>> {
    if args.review_source.is_none() {
        args.review_source = Some(ReviewSource::for_launch(args)?);
    }
    let Some(flake_ref) = args.flake.take() else {
        return Ok(None);
    };
    let slot = build(&flake_ref, args.flake_profile.as_deref())?;
    args.manifest = Some(slot.clone());
    Ok(Some(slot))
}

/// Offer a finished transient run's grantable refusals for review, under the
/// name its machine was given and against the source its policy came from.
/// `None` is `--json`, which offers nothing.
pub(super) fn offer_review(
    refused: &DenialTally,
    denials: &PendingWatch,
    source: Option<&ReviewSource>,
) {
    if let Some(offer) = source.and_then(|source| denials.review_offer(source)) {
        crate::commands::vm::denial_review::offer(refused, &offer);
    }
}

/// Carry an armed run's review command into its single JSON summary.
pub(super) fn json_review_pointer(
    refused: &DenialTally,
    denials: &PendingWatch,
    source: &ReviewSource,
) -> Option<JsonReviewPointer> {
    denials
        .review_offer(source)
        .and_then(|offer| denial_review::json_review_pointer(refused, &offer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::vm::denial_review::NoManifest;
    use crate::commands::vm::egress_denials::Live;
    use crate::commands::vm::egress_denials::denial::EgressDenial;
    use crate::commands::vm::egress_denials::denial::tests::entry;

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mvm.toml"), "flake = \".\"\n").unwrap();
        dir
    }

    #[test]
    fn json_review_uses_the_armed_machine_and_the_admitted_manifest() {
        let mut env = mvm_core::util::test_env::TestEnv::new();
        let home = tempfile::tempdir().expect("isolated home");
        env.isolate_mvm_home(home.path());
        let watch = PendingWatch::new(Live::Quiet);
        let source = ReviewSource::Manifest("/project/mvm.toml".into());
        let audit = entry(
            "host.flow.denied",
            &[
                ("vm_name", "vm-json"),
                ("class", "tcp"),
                ("target", "api.example.com:443"),
                ("reason", "policy_denied"),
            ],
        );
        let mut refused = DenialTally::default();
        refused.observe(EgressDenial::from_entry(&audit, "vm-json").expect("denial"));

        assert!(json_review_pointer(&refused, &watch, &source).is_none());
        watch.arm("vm-json");
        let pointer = json_review_pointer(&refused, &watch, &source).expect("review pointer");
        assert_eq!(pointer.run, "vm-json");
        assert_eq!(
            pointer.command,
            "mvmctl explain vm-json --review --project /project/mvm.toml"
        );
    }

    /// The slot replaces the flake, so the review source has to be read
    /// before it does: afterwards the arguments name a slot hash, and the
    /// project manifest the run's policy came from can no longer be found.
    #[test]
    fn the_review_source_is_read_before_the_flake_becomes_a_slot() {
        let dir = project();
        let mut args = RunArgs {
            flake: Some(dir.path().display().to_string()),
            ..RunArgs::default()
        };

        let slot = build_flake_slot_with(&mut args, |flake, _| {
            assert_eq!(flake, dir.path().display().to_string());
            Ok("0123abcd".to_string())
        })
        .unwrap();

        assert_eq!(slot.as_deref(), Some("0123abcd"));
        assert_eq!(args.flake, None);
        assert_eq!(args.manifest.as_deref(), Some("0123abcd"));
        assert_eq!(
            args.review_source,
            Some(ReviewSource::Manifest(dir.path().join("mvm.toml")))
        );
        assert_eq!(
            ReviewSource::for_launch(&args).unwrap(),
            ReviewSource::Unavailable(NoManifest::NotNamed),
            "read after the slot replaces the flake, the project manifest is gone"
        );
    }

    /// A source an earlier step settled is the one the run keeps.
    #[test]
    fn a_settled_review_source_is_not_replaced() {
        let dir = project();
        let mut args = RunArgs {
            flake: Some(dir.path().display().to_string()),
            review_source: Some(ReviewSource::admitted_elsewhere()),
            ..RunArgs::default()
        };

        build_flake_slot_with(&mut args, |_, _| Ok("slot".to_string())).unwrap();

        assert_eq!(args.review_source, Some(ReviewSource::admitted_elsewhere()));
    }

    /// A run with no flake still settles where its policy came from.
    #[test]
    fn a_run_without_a_flake_settles_its_review_source_and_builds_nothing() {
        let mut args = RunArgs::default();

        let slot = build_flake_slot_with(&mut args, |_, _| panic!("nothing to build")).unwrap();

        assert_eq!(slot, None);
        assert_eq!(
            args.review_source,
            Some(ReviewSource::Unavailable(NoManifest::NotNamed))
        );
    }
}
