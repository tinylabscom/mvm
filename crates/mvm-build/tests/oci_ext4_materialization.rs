//! Linux-gated integration test for [`mvm_build::oci_to_rootfs::
//! materialize_to_ext4`].
//!
//! `mke2fs` is Linux-only and not present on macOS / Windows
//! contributor laptops by default. These tests run when:
//!
//! 1. The target OS is Linux (`#[cfg(target_os = "linux")]`).
//! 2. `mke2fs` is on `$PATH` at test time. If missing, the test
//!    skips cleanly with a one-line note rather than failing —
//!    contributor environments that don't have `e2fsprogs`
//!    installed shouldn't see false negatives.
//! 3. The CI lane that runs them is the same Linux KVM lane that
//!    already runs the verity regression — the host has `mke2fs`
//!    from `e2fsprogs` and the privilege bits `mke2fs -d` needs.

#![cfg(target_os = "linux")]

use mvm_build::oci_to_rootfs::{
    ImageStaging, MaterializedRootfs, Mke2fsOptions, StagingOptions, materialize_to_ext4,
};
use std::io::Cursor;
use std::path::Path;
use tempfile::TempDir;

/// Returns true when `mke2fs` is on `$PATH`. Tests that need a
/// real `mke2fs` call this and exit early on miss.
fn mke2fs_available() -> bool {
    which::which("mke2fs").is_ok()
}

fn skip_if_no_mke2fs() -> bool {
    if !mke2fs_available() {
        eprintln!(
            "mvm-oci ext4 integration test skipped: mke2fs not on $PATH \
             (install e2fsprogs to run this test)"
        );
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

fn fresh_staging() -> (TempDir, ImageStaging) {
    let tmp = TempDir::new().unwrap();
    let staging = ImageStaging::new(tmp.path(), StagingOptions::default()).unwrap();
    (tmp, staging)
}

#[test]
fn materialize_produces_a_real_ext4_image() {
    if skip_if_no_mke2fs() {
        return;
    }

    let (staging_dir, staging) = fresh_staging();
    write_file(staging_dir.path(), "etc/hello", b"hello mvm");
    write_file(staging_dir.path(), "bin/sh", b"#!/bin/sh\necho ok\n");
    let staged = staging.finalize().unwrap();

    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("rootfs.ext4");
    let mat: MaterializedRootfs = materialize_to_ext4(&staged, &output, &Mke2fsOptions::default())
        .expect("materialize_to_ext4");

    assert!(output.exists(), "ext4 file must exist on disk");
    assert_eq!(mat.path, output);
    assert!(mat.size_bytes >= 1024 * 1024);
    assert_eq!(mat.label, "mvm-rootfs");
    assert_eq!(mat.uuid, "00000000-0000-0000-0000-000000000001");

    // Confirm the on-disk size matches what we told mke2fs to
    // produce. mke2fs respects the file's preallocated length.
    let meta = std::fs::metadata(&output).unwrap();
    assert_eq!(meta.len(), mat.size_bytes);

    // First 1024 bytes of an ext4 image are the boot block (all
    // zeros for non-bootable filesystems); bytes 1024..1080 are
    // the superblock. The ext4 magic 0xef53 lives at offset
    // 0x438 within the superblock (1024 + 0x38 = 1080 + 56).
    let buf = std::fs::read(&output).unwrap();
    let magic = u16::from_le_bytes([buf[1024 + 0x38], buf[1024 + 0x39]]);
    assert_eq!(magic, 0xef53, "ext4 superblock magic must be 0xef53");
}

#[test]
fn materialize_is_byte_deterministic_for_the_same_input() {
    if skip_if_no_mke2fs() {
        return;
    }

    // The verity cache invariant: a single staging tree
    // materialised twice must produce byte-identical ext4 output.
    //
    // We deliberately reuse one staging tree across the two
    // `materialize_to_ext4` calls instead of building two
    // content-equal-but-independent tempdirs. mke2fs `-d` walks
    // the source dir via readdir(), and readdir() on freshly-
    // created ext4 directories returns entries in dir_index
    // hash-bucket order — that bucket assignment is seeded
    // per-directory, so two newly-created tempdirs with the
    // same three files can legitimately return them in different
    // orders, which then shifts mke2fs's inode allocation, which
    // then changes the output bytes. That's a property of the
    // host filesystem, not a bug in `materialize_to_ext4`. The
    // production cache only ever rehydrates the *same* staging
    // tree (the OCI digest → tarball unpack is content-addressed
    // upstream of this layer), so the same-input assertion is
    // what actually matters.
    let (staging_dir, staging) = fresh_staging();
    write_file(staging_dir.path(), "etc/version", b"v1");
    write_file(staging_dir.path(), "usr/bin/tool", b"tool-payload");
    write_file(staging_dir.path(), "usr/lib/lib.so", b"lib-bytes");
    let staged = staging.finalize().unwrap();

    let out_dir = TempDir::new().unwrap();
    let out_a = out_dir.path().join("rootfs-a.ext4");
    let out_b = out_dir.path().join("rootfs-b.ext4");
    materialize_to_ext4(&staged, &out_a, &Mke2fsOptions::default()).expect("materialize a");
    materialize_to_ext4(&staged, &out_b, &Mke2fsOptions::default()).expect("materialize b");

    let a = std::fs::read(&out_a).unwrap();
    let b = std::fs::read(&out_b).unwrap();
    assert_eq!(
        a.len(),
        b.len(),
        "byte-deterministic output must have stable size"
    );
    assert_eq!(
        a, b,
        "byte-deterministic output must produce identical bytes \
         (verity cache invariant — see ADR-050)"
    );
}

#[test]
fn materialize_through_unpack_round_trip() {
    if skip_if_no_mke2fs() {
        return;
    }

    // Build a tar in memory, unpack it via ImageStaging, then
    // materialize. Covers the unpack → materialize boundary.
    use tar::{Builder, Header};
    let mut b = Builder::new(Vec::new());
    let body = b"unpack-then-materialize\n";
    let mut h = Header::new_gnu();
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_entry_type(tar::EntryType::Regular);
    h.set_cksum();
    b.append_data(&mut h, "etc/marker", body.as_slice())
        .unwrap();
    let tar_bytes = b.into_inner().unwrap();

    let (staging_dir, mut staging) = fresh_staging();
    staging.apply_layer(Cursor::new(tar_bytes)).unwrap();
    let staged = staging.finalize().unwrap();

    let out_dir = TempDir::new().unwrap();
    let output = out_dir.path().join("rootfs.ext4");
    let mat =
        materialize_to_ext4(&staged, &output, &Mke2fsOptions::default()).expect("materialize");
    assert!(mat.size_bytes >= 1024 * 1024);
    let _ = staging_dir; // keep the staging dir alive for the duration
}
