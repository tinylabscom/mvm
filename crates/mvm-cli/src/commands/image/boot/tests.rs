//! Tests for the `image boot` surface.
//!
//! Every test isolates `$HOME`/`MVM_HOME` through `TestEnv`, so the cache under
//! inspection is the one the test wrote and never the developer's real one.

use std::path::PathBuf;

use mvm_core::util::test_env::TestEnv;

use super::cache;
use super::check::{CheckVerdict, verdict};
use super::update::{self, UpdateRequest};
use crate::commands::env::builder_vm::default_microvm::DefaultMicrovmVariant;

/// Write a complete prod cache entry whose every file holds `marker` bytes,
/// with a sidecar claiming `tag`.
fn seed_prod_entry(tag: &str, marker: &[u8]) -> PathBuf {
    let dir = cache::variant_dir(DefaultMicrovmVariant::Prod);
    std::fs::create_dir_all(&dir).expect("create prod cache dir");
    for name in DefaultMicrovmVariant::Prod.required_outputs() {
        std::fs::write(dir.join(name), marker).expect("seed cache file");
    }
    let sidecar = mvm_build::builder_vm::GuestSidecar::for_oci_run("seeded", true, false);
    let sidecar = mvm_build::builder_vm::GuestSidecar {
        image_tag: tag.to_string(),
        source: "fetched".to_string(),
        ..sidecar
    };
    sidecar.write_to_dir(&dir).expect("seed sidecar");
    dir
}

#[test]
fn check_reports_behind_when_the_published_tag_is_newer() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    seed_prod_entry("image-set/v0.0.9", b"cached bytes");
    let latest = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str()
        .to_string();

    let cached = super::check::cached_tag();
    assert_eq!(cached.as_deref(), Some("image-set/v0.0.9"));
    assert_eq!(
        verdict(cached.as_deref(), Some(&latest)),
        CheckVerdict::Behind {
            cached: "image-set/v0.0.9".to_string(),
            latest: latest.clone(),
        }
    );

    let err = super::check::run(false).expect_err("behind must exit nonzero so a script can gate");
    assert!(
        err.to_string().contains("behind"),
        "the refusal must say why: {err}"
    );
}

#[test]
fn check_is_clean_when_the_cache_matches_the_lock() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let locked = mvm_core::image_set::image_train_lock()
        .image_set
        .release_tag
        .as_str();
    seed_prod_entry(locked, b"cached bytes");
    super::check::run(false).expect("a cache matching the lock is current");
}

#[test]
fn a_failed_update_leaves_the_previous_image_in_place() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());
    let original = b"the image that already works";
    let dir = seed_prod_entry("image-set/v0.0.9", original);
    let tag = "image-set/v0.2.0";

    let err = update::run(&UpdateRequest {
        tag: Some(tag.to_string()),
        force: true,
    })
    .expect_err("an image set outside the lock must not be installed");
    assert!(
        err.to_string().contains("not the build's locked image set"),
        "the refusal must name the lock mismatch: {err:#}"
    );

    for name in DefaultMicrovmVariant::Prod.required_outputs() {
        // The sidecar holds JSON rather than the marker; its survival is
        // asserted below by the tag it still records.
        if *name == mvm_build::builder_vm::SIDECAR_FILENAME {
            continue;
        }
        let bytes = std::fs::read(dir.join(name)).expect("previous image file must survive");
        assert_eq!(
            bytes, original,
            "{name} was replaced by a failed update; the cache must still hold the original bytes"
        );
    }
    let sidecar = mvm_build::builder_vm::GuestSidecar::read_from_dir(&dir)
        .expect("read sidecar")
        .expect("sidecar must survive");
    assert_eq!(
        sidecar.image_tag, "image-set/v0.0.9",
        "a failed update must not advance the recorded tag"
    );
    assert!(
        !cache::cache_root()
            .read_dir()
            .expect("read cache root")
            .flatten()
            .any(|e| e.file_name().to_string_lossy().contains("staging")),
        "the staging directory must not be left behind"
    );
}

#[test]
fn update_refuses_in_a_source_checkout_without_force() {
    // The test binary is built from this checkout, so the in-repo builder-VM
    // flake resolves and the refusal is live.
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let err = update::run(&UpdateRequest {
        tag: Some("image-set/v0.2.0".to_string()),
        force: false,
    })
    .expect_err("a source checkout's local build is authoritative");
    assert!(
        err.to_string().contains("source checkout"),
        "the refusal must name the reason: {err}"
    );
}

#[test]
fn status_reports_an_unrecorded_field_rather_than_a_blank() {
    let home = tempfile::tempdir().expect("tempdir");
    let mut env = TestEnv::new();
    env.isolate_mvm_home(home.path());

    let entries = cache::survey();
    assert_eq!(entries.len(), 2, "both variants are always reported");
    for entry in &entries {
        assert!(!entry.would_use(), "an empty cache is not usable");
        assert_eq!(entry.image_tag(), None);
        assert_eq!(entry.protocol_version(), None);
    }
    super::status::run(false).expect("status must render an empty cache");
    super::status::run(true).expect("status must render an empty cache as JSON");
}

#[test]
fn a_tag_that_cannot_be_ordered_is_not_reported_as_behind() {
    // Ordering tags as strings puts v0.10.0 before v0.9.0. Both of these
    // assertions fail under a string comparison.
    assert_eq!(
        verdict(Some("image-set/v0.10.0"), Some("image-set/v0.9.0")),
        CheckVerdict::Ahead {
            cached: "image-set/v0.10.0".to_string(),
            latest: "image-set/v0.9.0".to_string(),
        }
    );
    assert_eq!(
        verdict(Some("image-set/v0.9.0"), Some("image-set/v0.10.0")),
        CheckVerdict::Behind {
            cached: "image-set/v0.9.0".to_string(),
            latest: "image-set/v0.10.0".to_string(),
        }
    );
    assert!(matches!(
        verdict(Some("not-a-tag"), Some("image-set/v0.1.0")),
        CheckVerdict::NoCachedTag { .. }
    ));
    assert_eq!(
        verdict(Some("image-set/v0.1.0"), None),
        CheckVerdict::NoPublishedLine
    );
}

/// A fetched image must say so, even when it landed in a source checkout.
///
/// `MVM_BOOT_IMAGE=fetch` is the one case that weakens "a source checkout never
/// depends on a published artifact". The weakening is acceptable only because
/// the result is labelled: without this stamp a prebuilt sitting in a checkout
/// is indistinguishable from a build of the working tree, and the next person
/// to wonder why their flake edit had no effect has nothing to read.
#[test]
fn stamping_marks_an_acquired_image_as_fetched_without_losing_build_facts() {
    let _env = TestEnv::new();
    let dir = tempfile::tempdir().unwrap();

    // A sidecar as a producer would emit it: build facts present, acquisition
    // facts absent, because the build cannot know them.
    let produced = r#"{
        "name": "mvm-default-microvm",
        "accessible": false,
        "sealed": true,
        "entrypointKind": "command",
        "initSystem": "busybox",
        "expectedBootMs": 300,
        "agentBinary": "real",
        "rootlessEntrypoint": true,
        "hypervisor": "libkrun",
        "protocolVersion": 2,
        "generatorRev": "abc123",
        "source": "built-local"
    }"#;
    std::fs::write(
        dir.path().join(mvm_build::builder_vm::SIDECAR_FILENAME),
        produced,
    )
    .unwrap();

    super::cache::stamp_provenance(
        dir.path(),
        &super::cache::AcquiredProvenance::fetched("v0.18.0"),
    )
    .expect("stamping a well-formed sidecar must succeed");

    let after = mvm_build::builder_vm::GuestSidecar::read_from_dir(dir.path())
        .unwrap()
        .unwrap();
    assert_eq!(
        after.source, "fetched",
        "the acquisition arm must be recorded"
    );
    assert_eq!(after.image_tag, "v0.18.0");
    assert!(
        !after.built_at.is_empty(),
        "the host stamps a time the build could not"
    );
    // Build facts the producer recorded survive: stamping adds provenance, it
    // does not rewrite what the image is.
    assert_eq!(after.protocol_version, 2);
    assert_eq!(after.generator_rev, "abc123");
    assert_eq!(after.name, "mvm-default-microvm");
}
