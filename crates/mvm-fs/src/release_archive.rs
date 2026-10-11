//! Shared, bounded extraction of flat published release archives.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path};

/// Hard ceiling for the total uncompressed payload of a runtime archive.
pub const MAX_EXTRACTED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Expansion budgets for one archive: a cap on any single member and a cap on
/// the aggregate payload. Both are checked against the size a member declares
/// before any of its bytes are written, so an over-budget member leaves
/// nothing behind.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseArchiveLimits {
    /// Largest accepted size of any one member.
    pub file_bytes: u64,
    /// Largest accepted sum of member sizes; still held to the hard ceiling.
    pub total_bytes: u64,
}

impl ReleaseArchiveLimits {
    /// Bound only by the hard ceiling.
    pub const CEILING: Self = Self {
        file_bytes: MAX_EXTRACTED_BYTES,
        total_bytes: MAX_EXTRACTED_BYTES,
    };

    // Canonical bundles have only a handful of flat files. 64 KiB covers
    // their headers and block padding generously; extension records are
    // refused before allocation, so no PAX/GNU metadata needs headroom.
    const TAR_FRAMING_BYTES: u64 = 64 * 1024;
}

pub const OVERLAY_MEMBERS: [&str; 9] = [
    "overlay.ext4",
    "overlay.verity",
    "overlay.roothash",
    "VERSION",
    "mvm-guest-agent",
    "mvm-guest-netinit",
    "mvm-egress-client",
    "mvm-oci-entrypoint",
    crate::overlay::CHECKSUM_MANIFEST_FILE,
];
pub const INITRAMFS_MEMBERS: [&str; 5] = [
    crate::initramfs::INITRAMFS_IMAGE_FILE,
    crate::initramfs::INITRAMFS_HASH_FILE,
    crate::initramfs::INITRAMFS_SIZE_FILE,
    crate::initramfs::VERSION_FILE,
    crate::initramfs::CHECKSUM_MANIFEST_FILE,
];
pub const SIDECAR_MEMBERS: [&str; 3] = [
    crate::sdk_sidecar::SDK_SIDECAR_IMAGE_FILE,
    crate::sdk_sidecar::SDK_SIDECAR_VERSION_FILE,
    crate::overlay::CHECKSUM_MANIFEST_FILE,
];

#[derive(Debug, thiserror::Error)]
pub enum ReleaseArchiveError {
    #[error("release archive I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid release archive: {0}")]
    Invalid(String),
}

/// Extract exactly the allow-listed regular files. Existing destinations,
/// duplicate names, links, nested/absolute paths and incomplete sets refuse.
/// The caller owns a private staging directory and discards it on failure.
pub fn extract_release_archive(
    archive_path: &Path,
    stage: &Path,
    expected: &[&str],
) -> Result<(), ReleaseArchiveError> {
    extract_release_archive_with_limits(
        archive_path,
        stage,
        expected,
        ReleaseArchiveLimits::CEILING,
    )
}

/// [`extract_release_archive`] under an explicit expansion budget.
pub fn extract_release_archive_with_limits(
    archive_path: &Path,
    stage: &Path,
    expected: &[&str],
    limits: ReleaseArchiveLimits,
) -> Result<(), ReleaseArchiveError> {
    let file = std::fs::File::open(archive_path)?;
    extract(file, stage, expected, limits)
}

fn extract(
    file: impl Read,
    stage: &Path,
    expected: &[&str],
    limits: ReleaseArchiveLimits,
) -> Result<(), ReleaseArchiveError> {
    let total_ceiling = limits.total_bytes.min(MAX_EXTRACTED_BYTES);
    let decoder = flate2::read::GzDecoder::new(file);
    // Bound the decompressed stream itself, not only the claimed member
    // sizes: a stream that never stops decoding must not decode forever.
    let mut archive =
        tar::Archive::new(decoder.take(total_ceiling + ReleaseArchiveLimits::TAR_FRAMING_BYTES));
    let mut seen = BTreeSet::new();
    let mut total = 0u64;
    // Raw iteration refuses extension records rather than allocating or
    // interpreting unbounded PAX/GNU metadata ahead of the size checks.
    for entry in archive.entries()?.raw(true) {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let mut components = path.components();
        let name = match (components.next(), components.next()) {
            (Some(Component::Normal(name)), None) => name.to_str(),
            _ => None,
        };
        let Some(name) = name.filter(|name| {
            expected.contains(name) && path.as_os_str() == std::ffi::OsStr::new(name)
        }) else {
            return Err(ReleaseArchiveError::Invalid(format!(
                "unsafe or unexpected path {}",
                path.display()
            )));
        };
        if !entry.header().entry_type().is_file() || !seen.insert(name.to_owned()) {
            return Err(ReleaseArchiveError::Invalid(format!(
                "non-regular or duplicate member {name}"
            )));
        }
        if matches!(
            name,
            "VERSION"
                | "overlay.roothash"
                | "initramfs.hash"
                | "initramfs.size"
                | "checksums-sha256.txt"
        ) && entry.size() > 64 * 1024
        {
            return Err(ReleaseArchiveError::Invalid(format!(
                "metadata member {name} exceeds limit"
            )));
        }
        if entry.size() > limits.file_bytes {
            return Err(ReleaseArchiveError::Invalid(format!(
                "archive member {name} exceeds the per-file expansion budget"
            )));
        }
        total = total
            .checked_add(entry.size())
            .filter(|n| *n <= total_ceiling)
            .ok_or_else(|| {
                ReleaseArchiveError::Invalid(
                    "archive expansion exceeds the aggregate budget".into(),
                )
            })?;
        let dest = stage.join(name);
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&dest)?;
        let size = std::io::copy(&mut entry, &mut out)?;
        if size != entry.size() {
            return Err(ReleaseArchiveError::Invalid(format!(
                "truncated member {name}"
            )));
        }
    }
    for required in expected {
        if !seen.contains(*required) {
            return Err(ReleaseArchiveError::Invalid(format!(
                "missing required archive member {required}"
            )));
        }
    }
    // Account for bytes after tar's end marker too: probing the underlying
    // reader distinguishes a real EOF from a stream truncated at the
    // expansion ceiling.
    let mut inner = archive.into_inner();
    std::io::copy(&mut inner, &mut std::io::sink())?;
    if inner.limit() == 0 && inner.get_mut().read(&mut [0u8; 1])? != 0 {
        return Err(ReleaseArchiveError::Invalid(
            "expanded tar stream budget exceeded".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_header_archive(name: &str, size: u64) -> Vec<u8> {
        use std::io::Write;
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(size);
        header.set_mode(0o644);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gzip.write_all(header.as_bytes()).unwrap();
        gzip.write_all(&[0u8; 1024]).unwrap();
        gzip.finish().unwrap()
    }

    #[test]
    fn traversal_aliases_and_oversized_headers_refuse_before_writing_payloads() {
        for (name, size) in [
            ("../payload", 0),
            ("/payload", 0),
            ("./payload", 0),
            ("payload/", 0),
            ("payload", MAX_EXTRACTED_BYTES + 1),
            ("VERSION", 65537),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let bytes = raw_header_archive(name, size);
            assert!(
                extract(
                    bytes.as_slice(),
                    dir.path(),
                    &["payload", "VERSION"],
                    ReleaseArchiveLimits::CEILING,
                )
                .is_err()
            );
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }
    }

    #[cfg(unix)]
    #[test]
    fn preexisting_symlink_is_never_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(target.path(), b"untouched").unwrap();
        std::os::unix::fs::symlink(target.path(), dir.path().join("payload")).unwrap();
        let bytes = archive(&[("payload", tar::EntryType::Regular, b"substitution")]);
        assert!(
            extract(
                bytes.as_slice(),
                dir.path(),
                &["payload"],
                ReleaseArchiveLimits::CEILING,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(target.path()).unwrap(), b"untouched");
    }

    fn archive(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut tar = tar::Builder::new(gzip);
        for (name, kind, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*kind);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_path(name).unwrap();
            header.set_cksum();
            tar.append(&header, *bytes).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn synthetic_flat_archive_accepts_only_complete_unique_regular_members() {
        let bytes = archive(&[("payload", tar::EntryType::Regular, b"synthetic")]);
        let dir = tempfile::tempdir().unwrap();
        extract(
            bytes.as_slice(),
            dir.path(),
            &["payload"],
            ReleaseArchiveLimits::CEILING,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("payload")).unwrap(),
            b"synthetic"
        );
        assert!(
            extract(
                bytes.as_slice(),
                dir.path(),
                &["payload"],
                ReleaseArchiveLimits::CEILING,
            )
            .is_err()
        );
        for entries in [
            vec![
                ("payload", tar::EntryType::Regular, b"x".as_slice()),
                ("payload", tar::EntryType::Regular, b"y"),
            ],
            vec![("nested/payload", tar::EntryType::Regular, b"x")],
            vec![("payload", tar::EntryType::Symlink, b"")],
            vec![("payload", tar::EntryType::Link, b"")],
            vec![("payload", tar::EntryType::Directory, b"")],
            vec![("payload", tar::EntryType::XHeader, b"")],
            vec![("payload", tar::EntryType::GNULongName, b"")],
            vec![],
        ] {
            let dir = tempfile::tempdir().unwrap();
            assert!(
                extract(
                    archive(&entries).as_slice(),
                    dir.path(),
                    &["payload"],
                    ReleaseArchiveLimits::CEILING,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn trailing_bytes_after_the_end_marker_are_charged_to_the_budget() {
        use std::io::Write;
        let limits = ReleaseArchiveLimits {
            file_bytes: 16,
            total_bytes: 32,
        };
        let tar_bytes = {
            let mut tar_bytes = Vec::new();
            {
                let mut builder = tar::Builder::new(&mut tar_bytes);
                let mut header = tar::Header::new_gnu();
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(4);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, "payload", b"1234".as_slice())
                    .unwrap();
                builder.finish().unwrap();
            }
            tar_bytes
        };
        let gzipped = |body: &[u8]| {
            let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            gzip.write_all(body).unwrap();
            gzip.finish().unwrap()
        };

        // A complete archive whose decompressed stream fits the budget extracts.
        let dir = tempfile::tempdir().unwrap();
        extract(
            gzipped(&tar_bytes).as_slice(),
            dir.path(),
            &["payload"],
            limits,
        )
        .unwrap();

        // A tail that pushes the decompressed stream past the budget is
        // refused rather than silently truncated.
        let mut oversized = tar_bytes.clone();
        oversized.extend_from_slice(&[0u8; 66 * 1024]);
        let dir = tempfile::tempdir().unwrap();
        let error = extract(
            gzipped(&oversized).as_slice(),
            dir.path(),
            &["payload"],
            limits,
        )
        .expect_err("trailing data beyond the budget must refuse");
        assert!(error.to_string().contains("stream budget"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("payload")).unwrap(), b"1234");
    }

    #[test]
    fn per_file_and_aggregate_budgets_bound_the_declared_payload() {
        let limits = ReleaseArchiveLimits {
            file_bytes: 4,
            total_bytes: 6,
        };
        // An exact fit on both budgets extracts.
        let dir = tempfile::tempdir().unwrap();
        let bytes = archive(&[
            ("payload", tar::EntryType::Regular, b"1234"),
            ("other", tar::EntryType::Regular, b"56"),
        ]);
        extract(bytes.as_slice(), dir.path(), &["payload", "other"], limits).unwrap();
        assert_eq!(std::fs::read(dir.path().join("payload")).unwrap(), b"1234");
        assert_eq!(std::fs::read(dir.path().join("other")).unwrap(), b"56");

        // One byte over the per-file budget refuses before any write.
        let dir = tempfile::tempdir().unwrap();
        let bytes = archive(&[
            ("payload", tar::EntryType::Regular, b"12345"),
            ("other", tar::EntryType::Regular, b"56"),
        ]);
        let error = extract(bytes.as_slice(), dir.path(), &["payload", "other"], limits)
            .expect_err("a member over the per-file budget must refuse");
        assert!(error.to_string().contains("per-file"), "{error}");
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);

        // One byte over the aggregate budget refuses; the member that fit is
        // already written, and the caller owns discarding the staging dir.
        let dir = tempfile::tempdir().unwrap();
        let bytes = archive(&[
            ("payload", tar::EntryType::Regular, b"1234"),
            ("other", tar::EntryType::Regular, b"567"),
        ]);
        let error = extract(bytes.as_slice(), dir.path(), &["payload", "other"], limits)
            .expect_err("an aggregate over the budget must refuse");
        assert!(error.to_string().contains("aggregate"), "{error}");
        assert_eq!(std::fs::read(dir.path().join("payload")).unwrap(), b"1234");
        assert!(!dir.path().join("other").exists());
    }
}
