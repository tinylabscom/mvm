use super::*;
use std::path::{Path, PathBuf};

const SLOT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REVISION: &str = "dev-revision";

fn with_slot(test: impl FnOnce(&Path, &Path)) {
    let _lock = crate::vm::DATA_DIR_TEST_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let tmp = tempfile::tempdir().unwrap();
    let mut env = mvm_core::util::test_env::TestEnv::new();
    env.set("MVM_HOME", tmp.path());
    let revision = PathBuf::from(mvm_core::manifest::slot_revision_dir(SLOT, REVISION));
    std::fs::create_dir_all(&revision).unwrap();
    std::os::unix::fs::symlink(
        format!("artifacts/revisions/{REVISION}"),
        mvm_core::manifest::slot_current_symlink(SLOT),
    )
    .unwrap();
    test(tmp.path(), &revision);
}

fn write_checksums(revision: &Path, name: &str, digest: &str) {
    let sums = Checksums {
        schema_version: 1,
        template_id: SLOT.to_string(),
        revision_hash: REVISION.to_string(),
        files: [(name.to_string(), digest.to_string())].into(),
    };
    std::fs::write(
        revision.join("checksums.json"),
        serde_json::to_vec(&sums).unwrap(),
    )
    .unwrap();
}

fn write_metadata(revision: &Path) {
    std::fs::create_dir_all(revision).unwrap();
    let metadata = serde_json::json!({
        "revision_hash": REVISION,
        "flake_ref": ".",
        "flake_lock_hash": "lock",
        "artifact_paths": {"vmlinux": "vmlinux", "rootfs": "rootfs.ext4", "fc_base_config": "fc-base.json"},
        "built_at": "2026-01-01T00:00:00Z",
        "profile": "test",
        "vcpus": 1,
        "mem_mib": 128,
        "data_disk_mib": 0,
        "snapshot": {
            "created_at": "2026-01-01T00:00:00Z",
            "vmstate_size_bytes": 1,
            "mem_size_bytes": 1,
            "boot_args": "",
            "vcpus": 1,
            "mem_mib": 128
        }
    });
    // Prove the escaped fixture is valid metadata, not an incidental parse error.
    assert!(
        serde_json::from_value::<mvm_core::template::TemplateRevision>(metadata.clone())
            .unwrap()
            .snapshot
            .is_some()
    );
    std::fs::write(
        revision.join("revision.json"),
        serde_json::to_vec(&metadata).unwrap(),
    )
    .unwrap();
}

#[test]
fn slot_revision_validation_preserves_labels_and_rejects_paths() {
    for revision in ["dev-revision", "abc123", "release.v1"] {
        validate_slot_revision(revision).unwrap();
    }
    for revision in ["", ".", "..", "../outside", "/outside", "a/b", "a\\b"] {
        assert!(validate_slot_revision(revision).is_err(), "{revision:?}");
    }
}

#[test]
fn slot_verifier_rejects_unsafe_checksum_keys_with_existing_files() {
    with_slot(|root, revision| {
        let outside = revision.parent().unwrap().join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        let absolute = root.join("absolute");
        std::fs::write(&absolute, b"outside").unwrap();
        std::fs::write(revision.join("nested\\file"), b"outside").unwrap();
        let digest = sha256_hex(&outside).unwrap();
        for name in ["../outside", absolute.to_str().unwrap(), "nested\\file"] {
            write_checksums(revision, name, &digest);
            let error = template_verify_slot(SLOT, None).unwrap_err();
            assert!(error.to_string().contains("invalid revision artifact path"));
        }
    });
}

#[test]
fn slot_verifier_accepts_nested_files_and_internal_symlinks() {
    with_slot(|_, revision| {
        std::fs::create_dir(revision.join("nested")).unwrap();
        let file = revision.join("nested/kernel");
        std::fs::write(&file, b"kernel").unwrap();
        let digest = sha256_hex(&file).unwrap();
        write_checksums(revision, "nested/kernel", &digest);
        template_verify_slot(SLOT, Some(REVISION)).unwrap();
        std::os::unix::fs::symlink("nested/kernel", revision.join("kernel")).unwrap();
        write_checksums(revision, "kernel", &digest);
        template_verify_slot(SLOT, None).unwrap();
    });
}

#[test]
fn slot_verifier_preserves_missing_and_mismatch_diagnostics() {
    with_slot(|_, revision| {
        let error = template_verify_slot(SLOT, Some("not-built")).unwrap_err();
        assert!(error.to_string().contains("checksums are written"));
        write_checksums(revision, "kernel", "wrong");
        let error = template_verify_slot(SLOT, None).unwrap_err();
        assert!(error.to_string().contains("kernel: missing"));
        std::fs::write(revision.join("kernel"), b"kernel").unwrap();
        let error = template_verify_slot(SLOT, None).unwrap_err();
        assert!(error.to_string().contains("kernel: expected wrong, got "));
        std::fs::remove_file(revision.join("checksums.json")).unwrap();
        let error = template_verify_slot(SLOT, None).unwrap_err();
        assert!(error.to_string().starts_with("Missing "));
    });
}

#[test]
fn slot_verifier_rejects_escaping_symlinks_and_nonregular_files() {
    with_slot(|root, revision| {
        let outside = root.join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, revision.join("escape")).unwrap();
        write_checksums(revision, "escape", &sha256_hex(&outside).unwrap());
        assert!(
            template_verify_slot(SLOT, None)
                .unwrap_err()
                .to_string()
                .contains("escapes revision directory")
        );
        std::fs::create_dir(revision.join("directory")).unwrap();
        let fifo = revision.join("fifo");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the CString is a live, NUL-terminated pathname; mkfifo
        // creates a disposable test node and does not access Rust memory.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        for name in ["directory", "fifo"] {
            write_checksums(revision, name, "unused");
            assert!(
                template_verify_slot(SLOT, None)
                    .unwrap_err()
                    .to_string()
                    .contains("not a regular file")
            );
        }
    });
}

#[test]
fn slot_metadata_and_checksums_reject_escaping_file_symlinks() {
    with_slot(|root, revision| {
        let outside = root.join("outside");
        write_metadata(&outside);
        std::fs::write(outside.join("kernel"), b"kernel").unwrap();
        write_checksums(
            &outside,
            "kernel",
            &sha256_hex(&outside.join("kernel")).unwrap(),
        );
        std::fs::write(revision.join("kernel"), b"kernel").unwrap();
        for name in ["revision.json", "checksums.json"] {
            std::os::unix::fs::symlink(outside.join(name), revision.join(name)).unwrap();
        }
        assert!(template_snapshot_info_for_slot(SLOT).is_err());
        assert!(template_verify_slot(SLOT, None).is_err());
    });
}

#[test]
fn slot_snapshot_rejects_current_traversal_with_valid_escaped_metadata() {
    with_slot(|_, revision| {
        let slot = PathBuf::from(mvm_core::manifest::slot_dir(SLOT));
        let outside = slot.join("outside");
        write_metadata(&outside);
        write_checksums(&outside, "kernel", &{
            std::fs::write(outside.join("kernel"), b"kernel").unwrap();
            sha256_hex(&outside.join("kernel")).unwrap()
        });
        let current = mvm_core::manifest::slot_current_symlink(SLOT);
        std::fs::remove_file(&current).unwrap();
        std::os::unix::fs::symlink("artifacts/revisions/../../outside", &current).unwrap();
        assert!(template_snapshot_info_for_slot(SLOT).is_err());
        assert!(template_verify_slot(SLOT, None).is_err());
        assert!(template_verify_slot(SLOT, Some("../../outside")).is_err());
        // A selected single-component revision must not escape through a symlink either.
        std::os::unix::fs::symlink(&outside, revision.parent().unwrap().join("linked")).unwrap();
        assert!(template_verify_slot(SLOT, Some("linked")).is_err());
        std::fs::remove_file(&current).unwrap();
        std::os::unix::fs::symlink("artifacts/revisions/linked", &current).unwrap();
        assert!(template_snapshot_info_for_slot(SLOT).is_err());
    });
}

#[test]
fn slot_snapshot_accepts_internal_metadata_symlink_and_preserves_errors() {
    with_slot(|_, revision| {
        write_metadata(revision);
        assert!(template_snapshot_info_for_slot(SLOT).unwrap().is_some());
        std::fs::rename(
            revision.join("revision.json"),
            revision.join("metadata.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink("metadata.json", revision.join("revision.json")).unwrap();
        assert!(template_snapshot_info_for_slot(SLOT).unwrap().is_some());
        std::fs::write(revision.join("metadata.json"), b"invalid").unwrap();
        assert!(
            template_snapshot_info_for_slot(SLOT)
                .unwrap_err()
                .to_string()
                .contains("Corrupt revision.json")
        );
        std::fs::remove_file(revision.join("metadata.json")).unwrap();
        assert!(
            template_snapshot_info_for_slot(SLOT)
                .unwrap_err()
                .to_string()
                .contains("Failed to read revision.json")
        );
    });
}

#[test]
fn slot_readers_reject_escaping_revisions_directory() {
    with_slot(|root, revision| {
        write_metadata(revision);
        std::fs::write(revision.join("kernel"), b"kernel").unwrap();
        write_checksums(
            revision,
            "kernel",
            &sha256_hex(&revision.join("kernel")).unwrap(),
        );
        let revisions = revision.parent().unwrap();
        let outside = root.join("outside-revisions");
        std::fs::rename(revisions, &outside).unwrap();
        std::os::unix::fs::symlink(&outside, revisions).unwrap();
        assert!(template_snapshot_info_for_slot(SLOT).is_err());
        assert!(template_verify_slot(SLOT, None).is_err());
    });
}
