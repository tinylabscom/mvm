//! Linux-gated integration test for [`mvm_build::oci_to_rootfs::
//! seal_with_verity`].
//!
//! `veritysetup` is Linux-only and not present on macOS / Windows
//! contributor laptops by default. These tests gate on:
//!
//! 1. `#[cfg(target_os = "linux")]` — the whole file compiles only
//!    on Linux.
//! 2. `which::which("veritysetup")` — skips cleanly when
//!    `cryptsetup` (which provides `veritysetup`) isn't installed.
//!    Contributor environments without `cryptsetup` see a one-line
//!    note rather than a false failure.
//! 3. `which::which("mke2fs")` — the round-trip tests need to
//!    produce a real ext4 first (via `materialize_to_ext4`),
//!    then seal it. CI's Linux KVM lane has both binaries.

#![cfg(target_os = "linux")]

use mvm_build::oci_to_rootfs::{
    ImageStaging, MaterializedRootfs, Mke2fsOptions, OciUnpackError, StagingOptions,
    VeritysetupOptions, materialize_to_ext4, seal_with_verity,
};
use std::path::Path;
use tempfile::TempDir;

fn skip_if_no_veritysetup() -> bool {
    if which::which("veritysetup").is_err() {
        eprintln!(
            "mvm-oci verity integration test skipped: veritysetup not on $PATH \
             (install cryptsetup to run this test)"
        );
        return true;
    }
    false
}

fn skip_if_no_mke2fs() -> bool {
    if which::which("mke2fs").is_err() {
        eprintln!("mvm-oci verity integration test skipped: mke2fs not on $PATH");
        return true;
    }
    false
}

fn write_file(root: &Path, rel: &str, bytes: &[u8]) {
    let dest = root.join(rel);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(dest, bytes).unwrap();
}

/// Build a small ext4 image from a tiny staging tree and return
/// the [`MaterializedRootfs`]. Each test calls this to get a
/// fresh ext4 to seal.
fn make_small_ext4() -> (TempDir, MaterializedRootfs) {
    let staging_tmp = TempDir::new().unwrap();
    let staging = ImageStaging::new(staging_tmp.path(), StagingOptions::default()).unwrap();
    write_file(staging_tmp.path(), "etc/version", b"v1");
    write_file(staging_tmp.path(), "bin/sh", b"#!/bin/sh\necho ok\n");
    let staged = staging.finalize().unwrap();

    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("rootfs.ext4");
    // mke2fs default options use 4096-byte blocks; verity expects
    // 1024 for compatibility with mvm-verity-init. Override.
    let mke2fs_options = Mke2fsOptions {
        block_size: 1024,
        ..Mke2fsOptions::default()
    };
    let materialized =
        materialize_to_ext4(&staged, &output, &mke2fs_options).expect("materialize_to_ext4");

    // Carry the staging tmp around so the staged dir lives long
    // enough for the verity step to read the rootfs. The returned
    // tempdir owns the ext4 output too — keep it.
    (out_dir, materialized)
}

#[test]
fn seal_produces_sidecar_and_roothash_files() {
    if skip_if_no_veritysetup() || skip_if_no_mke2fs() {
        return;
    }
    let (_keep_alive, rootfs) = make_small_ext4();

    let sealed =
        seal_with_verity(&rootfs, &VeritysetupOptions::default()).expect("seal_with_verity");

    // Sidecar + roothash files exist next to the rootfs.
    assert!(
        sealed.sidecar_path.exists(),
        "verity sidecar must exist at {:?}",
        sealed.sidecar_path
    );
    assert!(
        sealed.roothash_path.exists(),
        "roothash file must exist at {:?}",
        sealed.roothash_path
    );

    // Root hash is 64 lowercase hex chars (sha256) and matches
    // the file's contents.
    assert_eq!(sealed.roothash.len(), 64, "sha256 hex must be 64 chars");
    assert!(
        sealed
            .roothash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "roothash must be lowercase hex: {:?}",
        sealed.roothash
    );
    let on_disk = std::fs::read_to_string(&sealed.roothash_path).unwrap();
    assert_eq!(on_disk.trim(), sealed.roothash);

    // Metadata fields mirror the options.
    assert_eq!(sealed.algorithm, "sha256");
    assert_eq!(sealed.data_block_size, 1024);
}

#[test]
fn seal_is_byte_deterministic_for_identical_rootfs_bytes() {
    if skip_if_no_veritysetup() || skip_if_no_mke2fs() {
        return;
    }

    // Byte-identical input must produce the same root hash and the
    // same sidecar bytes. The per-digest verity cache depends on this
    // invariant.
    //
    // We deliberately build one ext4 and copy it (not call
    // `make_small_ext4()` twice). mke2fs `-d` is not guaranteed
    // to produce byte-identical output across two independent
    // staging tempdirs — see the materialize test of the same name
    // for the readdir/dir_index explanation — so two separate
    // builds would fail the test's *precondition* (identical
    // rootfs bytes), masking what the test actually wants to
    // exercise: veritysetup's determinism on identical input.
    let (_keep, rootfs_a) = make_small_ext4();
    let rootfs_b_dir = TempDir::new().unwrap();
    let rootfs_b_path = rootfs_b_dir.path().join("rootfs.ext4");
    std::fs::copy(&rootfs_a.path, &rootfs_b_path).expect("copy rootfs bytes");
    let rootfs_b = MaterializedRootfs {
        path: rootfs_b_path,
        size_bytes: rootfs_a.size_bytes,
        label: rootfs_a.label.clone(),
        uuid: rootfs_a.uuid.clone(),
    };

    // Cross-check: the two rootfs images themselves are
    // byte-identical (the copy is the guarantee, but assert
    // it so a future refactor that drops the copy fails loudly).
    let bytes_a = std::fs::read(&rootfs_a.path).unwrap();
    let bytes_b = std::fs::read(&rootfs_b.path).unwrap();
    assert_eq!(
        bytes_a, bytes_b,
        "precondition: rootfs_b must be a byte-identical copy of rootfs_a"
    );

    let sealed_a = seal_with_verity(&rootfs_a, &VeritysetupOptions::default()).expect("seal a");
    let sealed_b = seal_with_verity(&rootfs_b, &VeritysetupOptions::default()).expect("seal b");

    assert_eq!(
        sealed_a.roothash, sealed_b.roothash,
        "ADR-050 verity-cache invariant: identical rootfs → identical roothash"
    );
    let sidecar_a = std::fs::read(&sealed_a.sidecar_path).unwrap();
    let sidecar_b = std::fs::read(&sealed_b.sidecar_path).unwrap();
    assert_eq!(
        sidecar_a, sidecar_b,
        "ADR-050 verity-cache invariant: identical rootfs → identical sidecar bytes"
    );
}

#[test]
fn seal_followed_by_veritysetup_verify_returns_zero() {
    // The canonical post-condition for a Nix-built verity artifact is
    // `veritysetup verify` returning 0. Our OCI-path sidecar must meet
    // the same bar.
    if skip_if_no_veritysetup() || skip_if_no_mke2fs() {
        return;
    }
    let (_keep, rootfs) = make_small_ext4();
    let sealed = seal_with_verity(&rootfs, &VeritysetupOptions::default()).expect("seal");

    let verify = std::process::Command::new("veritysetup")
        .arg("verify")
        .arg(&sealed.rootfs_path)
        .arg(&sealed.sidecar_path)
        .arg(&sealed.roothash)
        .output()
        .expect("spawn veritysetup verify");
    assert!(
        verify.status.success(),
        "veritysetup verify must accept the sidecar we produced; stderr={}",
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn seal_detects_post_format_rootfs_tamper() {
    // If anyone flips bytes in the rootfs after sealing,
    // `veritysetup verify` against the same root hash must
    // reject the artifact. This is the load-bearing claim 3 property
    // — the rootfs is sealed to the hash, not to a mutable filename.
    if skip_if_no_veritysetup() || skip_if_no_mke2fs() {
        return;
    }
    let (_keep, rootfs) = make_small_ext4();
    let sealed = seal_with_verity(&rootfs, &VeritysetupOptions::default()).expect("seal");

    // Flip a single byte somewhere inside the data region. The
    // first 64 KiB of an ext4 image is mostly superblock /
    // group-descriptor / inode-table territory; data blocks live
    // a few hundred KiB in. We pick offset 200 KiB to land in a
    // data block reliably for our small test image.
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&sealed.rootfs_path)
        .unwrap();
    let len = file.metadata().unwrap().len();
    let tamper_offset = (200 * 1024).min(len.saturating_sub(1));
    file.seek(SeekFrom::Start(tamper_offset)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let verify = std::process::Command::new("veritysetup")
        .arg("verify")
        .arg(&sealed.rootfs_path)
        .arg(&sealed.sidecar_path)
        .arg(&sealed.roothash)
        .output()
        .expect("spawn veritysetup verify");
    assert!(
        !verify.status.success(),
        "veritysetup verify must reject a tampered rootfs; stdout={} stderr={}",
        String::from_utf8_lossy(&verify.stdout),
        String::from_utf8_lossy(&verify.stderr)
    );
}

#[test]
fn seal_returns_error_on_missing_rootfs_file() {
    if skip_if_no_veritysetup() {
        return;
    }
    let tmp = TempDir::new().unwrap();
    let missing_path = tmp.path().join("does-not-exist.ext4");
    let rootfs = MaterializedRootfs {
        path: missing_path,
        size_bytes: 0,
        label: "mvm-rootfs".to_string(),
        uuid: "00000000-0000-0000-0000-000000000001".to_string(),
    };
    let err = seal_with_verity(&rootfs, &VeritysetupOptions::default()).unwrap_err();
    // Either the file-creation step for the sidecar fails (if
    // its parent dir is fine but veritysetup needs the data
    // device first), or veritysetup itself fails on the missing
    // data device. Both are acceptable — the property is "we
    // fail closed, not silently."
    assert!(
        matches!(
            err,
            OciUnpackError::VeritysetupFailed { .. } | OciUnpackError::Io(_)
        ),
        "expected VeritysetupFailed or Io, got {err:?}"
    );
}
