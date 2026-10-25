#[path = "support/launch_image_fixture.rs"]
mod fixture;

use fixture::{inspect_snapshot, preparation_key};
use mvm_conformance::prepared_once::PreparedOnce;
use std::cell::Cell;
use std::io;
use std::path::Path;

const ARTIFACTS: [&str; 6] = [
    "manifest.json",
    "config.json",
    "rootfs.ext4",
    "claims.json",
    "rootfs.verity",
    "rootfs.roothash",
];

fn inspection() -> serde_json::Value {
    serde_json::json!({
        "image": {
            "reference": "docker.io/library/alpine:latest",
            "resolved_digest": "sha256:abcd",
            "manifest_path": "manifest.json",
            "config_path": "config.json",
            "rootfs_path": "rootfs.ext4",
            "claims_path": "claims.json"
        },
        "size_bytes": 42, "manifest": {}, "config": {}, "claims": {}
    })
}

fn write_artifacts(cache: &Path) -> io::Result<()> {
    for artifact in ARTIFACTS {
        std::fs::write(cache.join(artifact), "available")?;
    }
    Ok(())
}

#[test]
fn every_required_artifact_deletion_and_replacement_reprepares() {
    for artifact in ARTIFACTS {
        let home = tempfile::tempdir().unwrap();
        let once = PreparedOnce::new();
        let key = preparation_key(home.path(), "alpine").unwrap();
        let calls = Cell::new(0);
        let ensure = || {
            once.ensure_observed(
                &key,
                || inspect_snapshot(home.path(), &inspection()),
                || {
                    calls.set(calls.get() + 1);
                    write_artifacts(home.path())
                },
            )
        };
        ensure().unwrap();
        ensure().unwrap();
        assert_eq!(calls.get(), 1);
        let path = home.path().join(artifact);
        std::fs::remove_file(&path).unwrap();
        ensure().unwrap();
        assert_eq!(calls.get(), 2, "deleted {artifact}");
        let replacement = home.path().join("replacement");
        std::fs::write(&replacement, "replacement").unwrap();
        std::fs::rename(replacement, path).unwrap();
        ensure().unwrap();
        assert_eq!(calls.get(), 3, "replaced {artifact}");
    }
}

#[test]
fn missing_postprep_artifacts_are_never_memoized() {
    for artifact in ARTIFACTS {
        let home = tempfile::tempdir().unwrap();
        let once = PreparedOnce::new();
        write_artifacts(home.path()).unwrap();
        std::fs::remove_file(home.path().join(artifact)).unwrap();
        let inspect = || inspect_snapshot(home.path(), &inspection());
        assert!(once.ensure_observed("alpine", inspect, || Ok(())).is_err());
        write_artifacts(home.path()).unwrap();
        let calls = Cell::new(0);
        once.ensure_observed("alpine", inspect, || {
            calls.set(calls.get() + 1);
            Ok(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1, "{artifact}");
    }
}

#[test]
fn homes_and_images_are_independent_and_aliases_reuse() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let once = PreparedOnce::new();
    let calls = Cell::new(0);
    for (home, image) in [
        (first.path(), "alpine"),
        (first.path(), "alpine"),
        (second.path(), "alpine"),
        (first.path(), "rust"),
    ] {
        once.ensure_observed(
            &preparation_key(home, image).unwrap(),
            || inspect_snapshot(home, &inspection()),
            || {
                calls.set(calls.get() + 1);
                write_artifacts(home)
            },
        )
        .unwrap();
    }
    assert_eq!(calls.get(), 3);
    #[cfg(unix)]
    {
        let alias = second.path().join("alias");
        std::os::unix::fs::symlink(first.path(), &alias).unwrap();
        assert_eq!(
            preparation_key(&alias, "alpine").unwrap(),
            preparation_key(first.path(), "alpine").unwrap()
        );
    }
}

#[test]
fn failed_pull_and_inspection_retry_and_identity_changes_reprepare() {
    let home = tempfile::tempdir().unwrap();
    let once = PreparedOnce::new();
    let output = std::cell::RefCell::new(inspection());
    let inspect = || inspect_snapshot(home.path(), &output.borrow());
    assert!(
        once.ensure_observed("alpine", inspect, || Err(io::Error::other("pull failed")))
            .is_err()
    );
    let calls = Cell::new(0);
    let prepare = || {
        calls.set(calls.get() + 1);
        write_artifacts(home.path())
    };
    once.ensure_observed("alpine", inspect, prepare).unwrap();
    assert!(
        once.ensure_observed(
            "alpine",
            || Err(io::Error::other("inspect failed")),
            prepare
        )
        .is_err()
    );
    once.ensure_observed("alpine", inspect, prepare).unwrap();
    output.borrow_mut()["image"]["resolved_digest"] = "sha256:replacement".into();
    once.ensure_observed("alpine", inspect, prepare).unwrap();
    assert_eq!(calls.get(), 4);
}

#[test]
fn adapter_rejects_missing_fields_bad_paths_and_empty_artifacts() {
    let home = tempfile::tempdir().unwrap();
    write_artifacts(home.path()).unwrap();
    for value in [
        serde_json::Value::Null,
        "../escape".into(),
        "/absolute".into(),
    ] {
        let mut output = inspection();
        output["image"]["manifest_path"] = value;
        assert!(inspect_snapshot(home.path(), &output).is_err());
    }
    std::fs::write(home.path().join("config.json"), "").unwrap();
    assert!(inspect_snapshot(home.path(), &inspection()).is_err());
}

#[test]
fn non_ext4_roots_do_not_require_ext4_sidecars() {
    let home = tempfile::tempdir().unwrap();
    write_artifacts(home.path()).unwrap();
    let mut output = inspection();
    output["image"]["rootfs_path"] = "rootfs.squashfs".into();
    std::fs::rename(
        home.path().join("rootfs.ext4"),
        home.path().join("rootfs.squashfs"),
    )
    .unwrap();
    for sidecar in ["rootfs.verity", "rootfs.roothash"] {
        std::fs::remove_file(home.path().join(sidecar)).unwrap();
    }
    assert!(inspect_snapshot(home.path(), &output).is_ok());
}
