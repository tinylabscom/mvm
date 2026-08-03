//! Regular-file materialization: mode classification (including the
//! setuid/setgid policy gate), the write path itself (both the Linux
//! `openat2`-resolved [`super::fs_ops::Rooted`] method and the
//! non-Linux path-based fallback), and the hardlink-to-copy helper
//! that [`super::fs_ops`] uses when a hardlink's target lives in a
//! lower/prior layer.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::{RefusalReason, SetidEntry, SetidPolicy, UnpackOptions, UnpackReport};

/// Tar mode bits for setuid and setgid. Sticky (`0o1000`) remains
/// stripped because only setuid/setgid passthrough is granted.
const SETID_MODE_BITS: u32 = 0o6000;

#[cfg(target_os = "linux")]
impl<'a> super::fs_ops::Rooted<'a> {
    pub(super) fn write_regular_file<R: Read>(
        &self,
        rel: &Path,
        entry: &mut tar::Entry<R>,
        raw_path: &[u8],
        options: &UnpackOptions,
        prior_layer_paths: &HashSet<PathBuf>,
        report: &mut UnpackReport,
    ) -> Result<(), RefusalReason> {
        use rustix::fs::{Mode, OFlags, ResolveFlags, openat2};
        use std::io::Write;
        use std::os::fd::AsFd;
        use std::os::unix::fs::PermissionsExt;
        use std::time::SystemTime;

        let mode = classify_regular_file_mode(entry.header().mode().unwrap_or(0o644), options)?;
        let (parent, leaf) = self
            .open_parent(rel, true)
            .map_err(super::fs_ops::map_resolve_errno)?;
        if prior_layer_paths.contains(rel) {
            super::fs_ops::remove_prior_layer_path(self, rel)?;
        }
        let resolve = ResolveFlags::IN_ROOT | ResolveFlags::NO_SYMLINKS;
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let fd = openat2(
            parent.as_fd(),
            &leaf,
            flags,
            Mode::from_raw_mode(mode),
            resolve,
        )
        .map_err(super::fs_ops::map_resolve_errno)?;
        let mut file = std::fs::File::from(fd);

        if std::io::copy(entry, &mut file).is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
        if file.flush().is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
        // `open(2)` honors umask and may clear setid bits on write, so
        // reassert the policy-classified mode through the fd.
        if file
            .set_permissions(std::fs::Permissions::from_mode(mode))
            .is_err()
        {
            return Err(RefusalReason::MalformedHeader);
        }
        record_setid_entry(report, raw_path, mode, options.setid_policy);
        if options.strip_timestamps {
            let _ = file.set_modified(SystemTime::UNIX_EPOCH);
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
impl<'a> super::fs_ops::Rooted<'a> {
    pub(super) fn write_regular_file<R: Read>(
        &self,
        rel: &Path,
        entry: &mut tar::Entry<R>,
        raw_path: &[u8],
        options: &UnpackOptions,
        prior_layer_paths: &HashSet<PathBuf>,
        report: &mut UnpackReport,
    ) -> Result<(), RefusalReason> {
        if prior_layer_paths.contains(rel) {
            super::fs_ops::remove_prior_layer_path(self.root, rel)?;
        }
        write_regular_file(entry, &self.root.join(rel), raw_path, options, report)
    }
}

/// Write a regular file from `entry` to `target`, with O_NOFOLLOW,
/// zeroed timestamps (when `options.strip_timestamps`), and setuid /
/// setgid mode bits governed by [`UnpackOptions::setid_policy`].
///
/// Returns `Ok(())` on success, or a [`RefusalReason`] for caller-
/// recorded per-entry failures. Hard I/O errors propagate via
/// `Err(RefusalReason::MalformedHeader)` for now — a future
/// sub-phase may grow a distinct `IoError` variant if the
/// granularity matters for audit, but A.1's caller treats all
/// per-entry failures equivalently.
///
/// Non-Linux fallback only — on Linux writes route through
/// [`super::fs_ops::Rooted::write_regular_file`] (openat2-resolved).
#[cfg(not(target_os = "linux"))]
fn write_regular_file<R: Read>(
    entry: &mut tar::Entry<R>,
    target: &Path,
    raw_path: &[u8],
    options: &UnpackOptions,
    report: &mut UnpackReport,
) -> Result<(), RefusalReason> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // Ensure parent directories exist. We've already verified no
    // existing parent is a symlink (safety check 5 in
    // `unpack_layer`), so `create_dir_all` here can't escape the
    // root via a planted symlink — only previously-existing host
    // directories could, and we trust the caller to give us a
    // clean `output_root`.
    if let Some(parent) = target.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return Err(RefusalReason::MalformedHeader);
        }
    }

    let mode_from_header =
        classify_regular_file_mode(entry.header().mode().unwrap_or(0o644), options)?;

    let mut opts = OpenOptions::new();
    opts.write(true)
        .create_new(true) // O_CREAT | O_EXCL — refuse to overwrite
        .mode(mode_from_header)
        .custom_flags(libc::O_NOFOLLOW);

    let mut file = match opts.open(target) {
        Ok(f) => f,
        Err(_) => return Err(RefusalReason::MalformedHeader),
    };

    if let Err(_e) = std::io::copy(entry, &mut file) {
        // The partial file is left on disk; the caller's pull
        // pipeline GCs the whole `output_root` on failure. A
        // tighter cleanup is possible but Phase A.1 keeps the
        // happy path simple.
        return Err(RefusalReason::MalformedHeader);
    }

    if let Err(_e) = file.flush() {
        return Err(RefusalReason::MalformedHeader);
    }

    // `open(2)` honors umask, and some kernels clear setuid/setgid
    // when file contents are modified. Apply the policy-classified
    // permissions after all writes through the file descriptor so the
    // on-disk result matches the tar mode without following paths.
    if file
        .set_permissions(std::fs::Permissions::from_mode(mode_from_header))
        .is_err()
    {
        return Err(RefusalReason::MalformedHeader);
    }
    record_setid_entry(report, raw_path, mode_from_header, options.setid_policy);

    if options.strip_timestamps {
        // `utimensat(AT_FDCWD, target, {0, 0})` via the `filetime`
        // crate's std-only equivalent. We use `set_file_mtime` /
        // `set_file_atime` from std-unstable / `filetime`... but
        // `filetime` isn't in our deps yet. Standard library has
        // no stable timestamp setter as of edition 2024; the
        // closest is `std::fs::File::set_modified` (stable in
        // 1.75), which takes `SystemTime`.
        use std::time::SystemTime;
        let _ = file.set_modified(SystemTime::UNIX_EPOCH);
    }

    Ok(())
}

pub(super) fn classify_regular_file_mode(
    raw_mode: u32,
    options: &UnpackOptions,
) -> Result<u32, RefusalReason> {
    let low_mode = raw_mode & 0o0777;
    let setid_bits = raw_mode & SETID_MODE_BITS;
    if setid_bits == 0 {
        return Ok(low_mode);
    }

    match options.setid_policy {
        SetidPolicy::PreserveDev | SetidPolicy::PreserveVerified => Ok(low_mode | setid_bits),
        SetidPolicy::RefuseUnsigned => Err(RefusalReason::SetuidUnsigned),
    }
}

pub(super) fn record_setid_entry(
    report: &mut UnpackReport,
    raw_path: &[u8],
    mode: u32,
    policy: SetidPolicy,
) {
    if mode & SETID_MODE_BITS == 0 {
        return;
    }

    report.setid_entries_preserved += 1;
    report.setid_entries.push(SetidEntry {
        raw_path: raw_path.to_vec(),
        mode,
        cosign_verified: policy == SetidPolicy::PreserveVerified,
    });
}

/// Copy `source` to `target` as a full file copy (used when a tar
/// hardlink entry's target lives only in lower/prior layer state, so
/// the current layer must not alias a new path back into mutable
/// pre-image state).
///
/// Non-Linux fallback only — on Linux hardlink-to-copy routes through
/// [`super::fs_ops::Rooted::materialize_hardlink`] (openat2-resolved).
#[cfg(not(target_os = "linux"))]
pub(super) fn copy_existing_regular_file(
    source: &Path,
    target: &Path,
    options: &UnpackOptions,
) -> Result<(), RefusalReason> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let source_mode = std::fs::symlink_metadata(source)
        .map_err(|_| RefusalReason::MalformedHeader)?
        .mode()
        & 0o0777;

    let mut source_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(source)
        .map_err(|_| RefusalReason::MalformedHeader)?;

    let mut target_opts = OpenOptions::new();
    target_opts
        .write(true)
        .create_new(true)
        .mode(source_mode)
        .custom_flags(libc::O_NOFOLLOW);
    let mut target_file = target_opts
        .open(target)
        .map_err(|_| RefusalReason::MalformedHeader)?;

    std::io::copy(&mut source_file, &mut target_file)
        .map_err(|_| RefusalReason::MalformedHeader)?;
    target_file
        .flush()
        .map_err(|_| RefusalReason::MalformedHeader)?;

    if options.strip_timestamps {
        use std::time::SystemTime;
        let _ = target_file.set_modified(SystemTime::UNIX_EPOCH);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::*;
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    // ── policy-controlled setuid/setgid bits ───────────

    #[test]
    fn default_setid_policy_preserves_setuid_file_with_audit_annotation() {
        use std::os::unix::fs::MetadataExt;

        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/helper", b"#!/bin/sh\n", 0o4755);
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.setid_entries_preserved, 1);
        assert_eq!(report.setid_entries.len(), 1);
        assert_eq!(report.setid_entries[0].raw_path, b"usr/bin/helper");
        assert_eq!(report.setid_entries[0].mode, 0o4755);
        assert!(!report.setid_entries[0].cosign_verified);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert_eq!(
            std::fs::symlink_metadata(tmp.path().join("usr/bin/helper"))
                .unwrap()
                .mode()
                & 0o7777,
            0o4755
        );
    }

    #[test]
    fn unsigned_production_setid_policy_refuses_setuid_file() {
        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/helper", b"#!/bin/sh\n", 0o4755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            ..UnpackOptions::default()
        };
        let report = super::super::unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts)
            .expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.setid_entries_preserved, 0);
        assert!(report.setid_entries.is_empty());
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].raw_path, b"usr/bin/helper");
        assert_eq!(report.refused[0].reason, RefusalReason::SetuidUnsigned);
        assert_eq!(
            report.refused[0].reason.audit_tag(),
            "E_OCI_SETUID_UNSIGNED"
        );
        assert!(!tmp.path().join("usr/bin/helper").exists());
    }

    #[test]
    fn unsigned_production_setid_policy_refuses_setgid_file() {
        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/group-helper", b"#!/bin/sh\n", 0o2755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            ..UnpackOptions::default()
        };
        let report = super::super::unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts)
            .expect("unpack ok");

        assert_eq!(report.files_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::SetuidUnsigned);
        assert!(!tmp.path().join("usr/bin/group-helper").exists());
    }

    #[test]
    fn verified_setid_policy_preserves_setgid_file_with_verified_annotation() {
        use std::os::unix::fs::MetadataExt;

        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/group-helper", b"#!/bin/sh\n", 0o2755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::PreserveVerified,
            ..UnpackOptions::default()
        };
        let report = super::super::unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts)
            .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.setid_entries_preserved, 1);
        assert_eq!(report.setid_entries[0].raw_path, b"usr/bin/group-helper");
        assert_eq!(report.setid_entries[0].mode, 0o2755);
        assert!(report.setid_entries[0].cosign_verified);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let mode = std::fs::symlink_metadata(tmp.path().join("usr/bin/group-helper"))
            .unwrap()
            .mode()
            & 0o7777;
        if mode & 0o2000 == 0 {
            eprintln!(
                "skipping on-disk setgid assertion: host filesystem kept {:o} instead of a setgid mode",
                mode
            );
            return;
        }
        assert_eq!(mode, 0o2755);
    }

    #[test]
    fn unsigned_production_setid_policy_allows_regular_file_without_setid_bits() {
        let tar_bytes = build_tar(|b| {
            add_file_with_mode(b, "usr/bin/tool", b"#!/bin/sh\n", 0o755);
        });

        let tmp = TempDir::new().unwrap();
        let opts = UnpackOptions {
            setid_policy: SetidPolicy::RefuseUnsigned,
            ..UnpackOptions::default()
        };
        let report = super::super::unpack_layer(Cursor::new(tar_bytes), tmp.path(), &opts)
            .expect("unpack ok");

        assert_eq!(report.files_written, 1);
        assert_eq!(report.setid_entries_preserved, 0);
        assert!(report.setid_entries.is_empty());
        assert!(report.refused.is_empty(), "{:?}", report.refused);
    }
}
