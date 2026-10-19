//! Whether a host path sits on storage that is verified encrypted, and the
//! policy for materializing sensitive plaintext there.
//!
//! The detector is path-specific: an encrypted root disk does not establish
//! that a custom volume root on another mount is encrypted. Missing tools,
//! failed commands, unsupported layouts, and unparseable output all report
//! "not verified". What "verified" means per platform:
//!
//! - **macOS**: `diskutil info` on the APFS volume holding the path reports
//!   `FileVault: Yes` or `Encrypted: Yes`. A volume that is only hardware
//!   "encrypted at rest" (`FileVault: No (Encrypted at rest)`) does not count:
//!   its key is not bound to a user credential, so the data is readable by
//!   anyone who can boot or attach the disk.
//! - **Linux**: the path's filesystem is ext2/ext3/ext4 with no external
//!   journal, and every block device beneath it reaches a dm-crypt mapping.
//!   Other layouts are reported as unverified rather than guessed at.
//!
//! [`admit_unverified_storage`] is the single policy decision for sensitive
//! plaintext on storage that failed verification: refuse, unless the operator
//! set [`ALLOW_UNVERIFIED_STORAGE_ENV`] for local development, in which case
//! the use is written to the local audit log first and refused if that write
//! fails. `--prod` runs refuse the override outright
//! ([`refuse_override_for_production`]).

use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux", test))]
use std::process::{Command, Output};

use crate::policy::audit::{LocalAuditKind, LocalAuditLog, default_audit_log, now_event};

/// Env var that lets local development materialize sensitive volume plaintext
/// on storage that is not verified encrypted. Honoured only when set to `1`;
/// every use is audited; `--prod` refuses it.
pub const ALLOW_UNVERIFIED_STORAGE_ENV: &str = "MVM_ALLOW_UNENCRYPTED_VOLUME_STORAGE";

/// Encryption evidence and its operator-facing diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFdeStatus {
    pub enabled: bool,
    pub info: String,
}

impl HostFdeStatus {
    pub fn enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: true,
            info: info.into(),
        }
    }

    pub fn not_enabled(info: impl Into<String>) -> Self {
        Self {
            enabled: false,
            info: info.into(),
        }
    }
}

/// Require verified encrypted backing for `path`, with no override. Callers
/// that hold volume data go through [`require_volume_storage`] instead.
pub fn require_host_path_encryption(path: &Path) -> anyhow::Result<()> {
    require_status(path, detect_host_path_encryption_status(path))
}

fn require_status(path: &Path, status: HostFdeStatus) -> anyhow::Result<()> {
    if status.enabled {
        return Ok(());
    }
    anyhow::bail!(
        "{} is not on verified encrypted backing storage: {}",
        path.display(),
        status.info
    )
}

/// The storage rule for volume data at `path`: verified encrypted, or the
/// audited development override. `purpose` names the data in the refusal and
/// in the audit entry.
pub fn require_volume_storage(path: &Path, purpose: &str) -> anyhow::Result<()> {
    require_host_path_encryption(path)
        .or_else(|refusal| admit_unverified_storage(path, purpose, refusal))
}

/// The closest existing ancestor of `path` (or `path` itself).
///
/// A directory about to be created lives on the filesystem of its nearest
/// existing ancestor, so that is what a check made before creation probes.
pub fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| !candidate.as_os_str().is_empty() && candidate.exists())
        .map(Path::to_path_buf)
}

/// Whether the operator asked for the development override.
pub fn override_requested() -> bool {
    std::env::var(ALLOW_UNVERIFIED_STORAGE_ENV).as_deref() == Ok("1")
}

/// Refuse a production run that carries the development override.
///
/// A production run never accepts unverified storage, so the override is an
/// error there rather than something silently ignored.
pub fn refuse_override_for_production() -> anyhow::Result<()> {
    if std::env::var_os(ALLOW_UNVERIFIED_STORAGE_ENV).is_some() {
        anyhow::bail!(
            "--prod refuses {ALLOW_UNVERIFIED_STORAGE_ENV}: a production run never places \
             volume plaintext on storage that is not verified encrypted. Unset it, and put \
             the volume on FileVault (macOS) or dm-crypt/LUKS (Linux) storage"
        );
    }
    Ok(())
}

/// Decide what happens to sensitive plaintext bound for `path` after the
/// storage check refused it with `refusal`.
///
/// Without the override this returns the refusal, explaining why and how to
/// fix it. With the override the use is appended to the local audit log —
/// refused if that append fails, so an override never goes unrecorded — and a
/// warning is logged.
pub fn admit_unverified_storage(
    path: &Path,
    purpose: &str,
    refusal: anyhow::Error,
) -> anyhow::Result<()> {
    admit_unverified_storage_with(path, purpose, refusal, override_requested(), |detail| {
        let log = LocalAuditLog::open(Path::new(&default_audit_log()))?;
        log.append(&now_event(
            LocalAuditKind::VolumeStorageOverride,
            None,
            Some(detail.to_string()),
        ))
    })
}

fn admit_unverified_storage_with(
    path: &Path,
    purpose: &str,
    refusal: anyhow::Error,
    override_set: bool,
    audit: impl FnOnce(&str) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if !override_set {
        return Err(refusal.context(format!(
            "refusing to place {purpose} plaintext at {}: the storage is not verified \
             encrypted. Enable FileVault (macOS) or put the location on a dm-crypt/LUKS ext4 \
             filesystem (Linux), or choose a location that is. For local development only, \
             set {ALLOW_UNVERIFIED_STORAGE_ENV}=1 to proceed anyway; each use is audited and \
             --prod refuses it",
            path.display()
        )));
    }
    let detail = format!(
        "purpose={purpose} path={} reason={:#}",
        path.display(),
        refusal
    );
    audit(&detail).map_err(|error| {
        error.context(format!(
            "{ALLOW_UNVERIFIED_STORAGE_ENV} is set but its use could not be audited; \
             refusing to place {purpose} plaintext at {}",
            path.display()
        ))
    })?;
    tracing::warn!(
        path = %path.display(),
        purpose,
        "{ALLOW_UNVERIFIED_STORAGE_ENV}=1: placing plaintext on storage that is not \
         verified encrypted (development override, audited)"
    );
    Ok(())
}

/// The device node of the volume containing `path`, e.g. `/dev/disk3s5`.
///
/// `diskutil info` takes a device or a volume, not an arbitrary directory.
#[cfg(target_os = "macos")]
fn macos_containing_device(path: &Path) -> Option<String> {
    let filesystem = rustix::fs::statfs(path).ok()?;
    let device = filesystem
        .f_mntfromname
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8(device).ok().filter(|d| !d.is_empty())
}

/// Detect encryption for this path, rather than assuming root-disk encryption.
pub fn detect_host_path_encryption_status(path: &Path) -> HostFdeStatus {
    #[cfg(target_os = "macos")]
    {
        // Preserve the diagnostic fallback when containing-volume resolution
        // fails; a failed diskutil invocation still refuses the path.
        let target = macos_containing_device(path).unwrap_or_else(|| path.display().to_string());
        detect_macos(path, &target, &mut |cmd| cmd.output())
    }
    #[cfg(target_os = "linux")]
    {
        detect_linux(path, &mut |cmd| cmd.output())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        HostFdeStatus::not_enabled("unsupported platform for encrypted-volume detection")
    }
}

#[cfg(any(target_os = "macos", test))]
fn detect_macos(
    path: &Path,
    target: &str,
    run: &mut impl FnMut(&mut Command) -> std::io::Result<Output>,
) -> HostFdeStatus {
    match run(crate::env_hygiene::helper_command("diskutil")
        .arg("info")
        .arg(target))
    {
        Ok(out) if out.status.success() => {
            parse_macos_diskutil_encryption_status(path, &String::from_utf8_lossy(&out.stdout))
        }
        Ok(out) => HostFdeStatus::not_enabled(format!(
            "diskutil could not report on {target} (for {}): {}",
            path.display(),
            String::from_utf8_lossy(&out.stderr).trim(),
        )),
        Err(e) => HostFdeStatus::not_enabled(format!(
            "could not run diskutil to check {}: {e}",
            path.display()
        )),
    }
}

#[cfg(any(target_os = "linux", test))]
fn detect_linux(
    path: &Path,
    run: &mut impl FnMut(&mut Command) -> std::io::Result<Output>,
) -> HostFdeStatus {
    #[derive(serde::Deserialize)]
    struct Mount {
        source: String,
        fstype: String,
    }
    #[derive(serde::Deserialize)]
    struct Mounts {
        filesystems: Vec<Mount>,
    }
    match run(crate::env_hygiene::helper_command("findmnt")
        .args(["--json", "--output", "SOURCE,FSTYPE", "--target"])
        .arg(path))
    {
        Ok(out) if out.status.success() => {
            let Ok(mounts) = serde_json::from_slice::<Mounts>(&out.stdout) else {
                return HostFdeStatus::not_enabled(
                    "could not parse filesystem backing information",
                );
            };
            let [mount] = mounts.filesystems.as_slice() else {
                return HostFdeStatus::not_enabled("filesystem backing is missing or ambiguous");
            };
            // A filesystem can span devices not represented in lsblk's graph.
            // Admit only the known single-device ext layout, and verify that
            // its journal does not introduce another storage device.
            if !matches!(mount.fstype.as_str(), "ext2" | "ext3" | "ext4") {
                return HostFdeStatus::not_enabled(
                    "encrypted backing verification supports only ext2/ext3/ext4 \
                     with no external journal on Linux; other filesystem layouts are unverified",
                );
            }
            let dev = &mount.source;
            if !dev.starts_with("/dev/") {
                return HostFdeStatus::not_enabled("filesystem source is not a block-device path");
            }
            let internal = run(crate::env_hygiene::helper_command("tune2fs")
                .env("LC_ALL", "C")
                .args(["-l", dev]))
            .is_ok_and(|output| {
                output.status.success()
                    && ext_storage_is_self_contained(&String::from_utf8_lossy(&output.stdout))
            });
            if !internal {
                return HostFdeStatus::not_enabled(
                    "could not establish a self-contained ext filesystem and journal; \
                     tune2fs must be available and permitted to inspect the source device",
                );
            }
            // Follow backing ancestors, not devices layered on top of this
            // source. Keep the tree so every backing branch must be encrypted.
            match run(crate::env_hygiene::helper_command("lsblk").args([
                "--inverse",
                "--tree",
                "--json",
                "--output",
                "TYPE",
                "--",
                dev,
            ])) {
                Ok(types) if types.status.success() => {
                    parse_linux_backing_tree(path, dev, &String::from_utf8_lossy(&types.stdout))
                }
                _ => HostFdeStatus::not_enabled(format!(
                    "could not inspect block-device type chain for {} ({dev})",
                    path.display()
                )),
            }
        }
        _ => HostFdeStatus::not_enabled(format!(
            "could not determine backing device for {} (findmnt unavailable)",
            path.display()
        )),
    }
}

#[cfg(any(target_os = "linux", test))]
fn ext_storage_is_self_contained(info: &str) -> bool {
    let mut features = None;
    let mut journal_inode = None;
    for line in info.lines() {
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        match field.trim() {
            "Filesystem features" => {
                if features.is_some() || value.trim().is_empty() {
                    return false;
                }
                features = Some(value);
            }
            "Journal inode" => {
                if journal_inode.is_some() {
                    return false;
                }
                let Ok(inode) = value.trim().parse::<u64>() else {
                    return false;
                };
                journal_inode = Some(inode);
            }
            "Journal UUID" | "Journal device" => return false,
            _ => {}
        }
    }
    features.is_some_and(|features| {
        let flags = features.split_whitespace().collect::<Vec<_>>();
        !flags.contains(&"journal_dev")
            && (!flags.contains(&"has_journal") || journal_inode.is_some_and(|inode| inode != 0))
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_backing_tree(path: &Path, dev: &str, tree: &str) -> HostFdeStatus {
    #[derive(serde::Deserialize)]
    struct Device {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        children: Vec<Device>,
    }
    impl Device {
        fn encrypted(&self) -> bool {
            self.kind == "crypt"
                || (!self.children.is_empty() && self.children.iter().all(Self::encrypted))
        }
    }
    #[derive(serde::Deserialize)]
    struct Devices {
        blockdevices: Vec<Device>,
    }
    let encrypted = serde_json::from_str::<Devices>(tree).is_ok_and(|devices| {
        !devices.blockdevices.is_empty() && devices.blockdevices.iter().all(Device::encrypted)
    });
    if encrypted {
        HostFdeStatus::enabled(format!(
            "{} is backed by {dev}, with dm-crypt/LUKS on every backing branch",
            path.display()
        ))
    } else {
        HostFdeStatus::not_enabled(format!(
            "{} is backed by {dev}, which does NOT establish \
             dm-crypt/LUKS protection on every backing branch",
            path.display()
        ))
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_diskutil_encryption_status(path: &Path, diskutil_output: &str) -> HostFdeStatus {
    for line in diskutil_output.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().to_ascii_lowercase();
        let encrypted = value.starts_with("yes") || value.starts_with("encrypted");
        if matches!(key, "FileVault" | "Encrypted") && encrypted {
            return HostFdeStatus::enabled(format!(
                "{} is on a macOS volume reported as encrypted ({key}: {})",
                path.display(),
                value
            ));
        }
    }
    HostFdeStatus::not_enabled(format!(
        "{} is not on a macOS volume reported as encrypted by diskutil",
        path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    const EXT4_MOUNT: &str =
        r#"{"filesystems":[{"source":"/dev/mapper/synthetic","fstype":"ext4"}]}"#;
    const INTERNAL_JOURNAL: &str = "Filesystem features: has_journal extents\nJournal inode: 8\n";

    #[test]
    fn ext_topology_requires_positive_self_contained_evidence() {
        assert!(ext_storage_is_self_contained(INTERNAL_JOURNAL));
        assert!(ext_storage_is_self_contained(
            "Filesystem features: extents\n"
        ));
        for info in [
            "",
            "Journal inode: 8\n",
            "Filesystem features:\n",
            "Filesystem features: has_journal\n",
            "Filesystem features: has_journal\nJournal inode: 0\n",
            "Filesystem features: has_journal\nJournal inode: unknown\n",
            "Filesystem features: journal_dev\n",
            "Filesystem features: extents\nJournal UUID: external\n",
            "Filesystem features: has_journal\nJournal inode: 8\nJournal device: 12\n",
            "Filesystem features: has_journal\nFilesystem features: extents\n",
        ] {
            assert!(!ext_storage_is_self_contained(info), "{info}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_filesystem_topologies_are_refused_before_device_probes() {
        for fstype in ["btrfs", "xfs", "f2fs", "overlay", "unknown"] {
            let mut calls = 0;
            let status = detect_linux(Path::new("/synthetic/work"), &mut |_| {
                calls += 1;
                let mount = serde_json::json!({
                    "filesystems": [{"source": "/dev/mapper/crypt", "fstype": fstype}]
                });
                Ok(output(true, &mount.to_string(), ""))
            });
            assert_eq!(calls, 1);
            assert!(!status.enabled);
        }
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_or_external_journals_refuse_even_on_encrypted_devices() {
        for (success, journal) in [
            (false, INTERNAL_JOURNAL),
            (
                true,
                "Filesystem features: has_journal\nJournal UUID: external\n",
            ),
            (true, ""),
        ] {
            let mut calls = 0;
            let status = detect_linux(Path::new("/synthetic/work"), &mut |cmd| {
                calls += 1;
                if cmd.get_program() == "findmnt" {
                    Ok(output(true, EXT4_MOUNT, ""))
                } else {
                    assert_eq!(cmd.get_program(), "tune2fs");
                    assert!(cmd.get_envs().any(|(key, value)| {
                        key == "LC_ALL" && value == Some(std::ffi::OsStr::new("C"))
                    }));
                    Ok(output(success, journal, ""))
                }
            });
            assert_eq!(
                calls, 2,
                "lsblk must not override unsupported filesystem evidence"
            );
            assert!(!status.enabled);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_directory_resolves_to_its_containing_device() {
        // Only statfs on a test-owned directory: no diskutil or user data.
        let directory = tempfile::tempdir().unwrap();
        let device = macos_containing_device(directory.path()).expect("containing device");
        assert!(device.starts_with("/dev/"), "{device}");
        assert_eq!(
            macos_containing_device(&directory.path().join("nonexistent")),
            None
        );
    }

    #[test]
    fn linux_volume_backing_parser_requires_crypt_chain() {
        let path = Path::new("/volumes/work");
        for tree in [
            r#"{"blockdevices":[{"type":"crypt"}]}"#,
            r#"{"blockdevices":[{"type":"lvm","children":[{"type":"crypt","children":[{"type":"part"}]}]}]}"#,
            r#"{"blockdevices":[{"type":"raid1","children":[{"type":"crypt"},{"type":"crypt"}]}]}"#,
        ] {
            let status = parse_linux_backing_tree(path, "/dev/mapper/work", tree);
            assert!(status.enabled);
            assert!(status.info.contains("dm-crypt/LUKS"));
        }
        for tree in [
            "",
            "crypt\n",
            r#"{"blockdevices":[]}"#,
            r#"{"blockdevices":[{"type":"part"}]}"#,
            r#"{"blockdevices":[{"type":"lvm","children":[{"type":"part"}]}]}"#,
            r#"{"blockdevices":[{"type":"raid1","children":[{"type":"crypt"},{"type":"part"}]}]}"#,
            r#"{"blockdevices":[{"type":"crypt"},{"type":"part"}]}"#,
        ] {
            let status = parse_linux_backing_tree(path, "/dev/mapper/work", tree);
            assert!(!status.enabled);
            assert!(status.info.contains("does NOT establish"));
            assert!(require_status(path, status).is_err());
        }
    }

    #[test]
    fn macos_diskutil_parser_requires_encrypted_volume() {
        let path = Path::new("/Volumes/work");
        for value in [
            "FileVault: Yes (Unlocked)",
            "Encrypted: Yes",
            "Encrypted: Encrypted",
        ] {
            let status = parse_macos_diskutil_encryption_status(path, value);
            assert!(status.enabled);
            assert!(status.info.contains("reported as encrypted"));
            assert!(require_status(path, status).is_ok());
        }
        // The shape `diskutil info` prints for a FileVault-protected Data volume:
        // the software-encryption line says No, the FileVault line says Yes.
        let real = "File System Personality: APFS\nFileVault: Yes\nLocked: No\nEncrypted: No\n";
        assert!(parse_macos_diskutil_encryption_status(path, real).enabled);
        for value in [
            "Encrypted: No\nFileVault: No",
            // Hardware encryption at rest with no user-bound key is not enough.
            "FileVault: No (Encrypted at rest)",
            "",
            "unrecognized output",
        ] {
            let status = parse_macos_diskutil_encryption_status(path, value);
            assert!(!status.enabled);
            assert!(
                status
                    .info
                    .contains("not on a macOS volume reported as encrypted")
            );
            assert!(require_status(path, status).is_err());
        }
    }

    #[cfg(unix)]
    fn output(success: bool, stdout: &str, stderr: &str) -> Output {
        use std::os::unix::process::ExitStatusExt;
        Output {
            status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn failed_diskutil_refuses_even_with_encrypted_stdout() {
        let path = Path::new("/synthetic/work");
        let status = detect_macos(path, "/dev/synthetic", &mut |cmd| {
            assert_eq!(cmd.get_program(), "diskutil");
            assert_eq!(
                cmd.get_args().collect::<Vec<_>>(),
                ["info", "/dev/synthetic"]
            );
            Ok(output(false, "Encrypted: Yes", "Could not find disk"))
        });
        assert!(status.info.contains("Could not find disk"));
        assert!(require_status(path, status).is_err());
    }

    #[test]
    fn missing_tools_fail_closed() {
        let path = Path::new("/synthetic/work");
        let mut missing = |_: &mut Command| Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert!(require_status(path, detect_macos(path, "/dev/synthetic", &mut missing)).is_err());
        assert!(require_status(path, detect_linux(path, &mut missing)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn failed_findmnt_never_inspects_a_device() {
        let mut calls = 0;
        let status = detect_linux(Path::new("/synthetic/work"), &mut |_| {
            calls += 1;
            Ok(output(false, "/dev/mapper/synthetic", "failed"))
        });
        assert_eq!(calls, 1);
        assert!(require_status(Path::new("/synthetic/work"), status).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn successful_commands_require_positive_encryption_evidence() {
        let path = Path::new("/synthetic/work");
        let status = detect_macos(path, "/dev/synthetic", &mut |_| {
            Ok(output(true, "FileVault: Yes (Unlocked)", ""))
        });
        assert!(require_status(path, status).is_ok());
        for (types, enabled) in [
            (r#"{"blockdevices":[{"type":"crypt"}]}"#, true),
            (r#"{"blockdevices":[{"type":"part"}]}"#, false),
            ("", false),
        ] {
            let status = detect_linux(path, &mut |cmd| {
                Ok(output(
                    true,
                    if cmd.get_program() == "findmnt" {
                        EXT4_MOUNT
                    } else if cmd.get_program() == "tune2fs" {
                        INTERNAL_JOURNAL
                    } else {
                        types
                    },
                    "",
                ))
            });
            assert_eq!(require_status(path, status).is_ok(), enabled);
        }
    }

    #[cfg(unix)]
    #[test]
    fn linux_probe_uses_requested_path_and_refuses_failed_lsblk() {
        let path = Path::new("/synthetic/custom");
        let mut calls = 0;
        let status = detect_linux(path, &mut |cmd| {
            calls += 1;
            if calls == 1 {
                assert_eq!(cmd.get_program(), "findmnt");
                assert_eq!(
                    cmd.get_args().collect::<Vec<_>>(),
                    [
                        "--json",
                        "--output",
                        "SOURCE,FSTYPE",
                        "--target",
                        "/synthetic/custom",
                    ]
                );
                Ok(output(true, EXT4_MOUNT, ""))
            } else if calls == 2 {
                assert_eq!(cmd.get_program(), "tune2fs");
                assert_eq!(
                    cmd.get_args().collect::<Vec<_>>(),
                    ["-l", "/dev/mapper/synthetic"]
                );
                Ok(output(true, INTERNAL_JOURNAL, ""))
            } else {
                assert_eq!(cmd.get_program(), "lsblk");
                assert_eq!(
                    cmd.get_args().collect::<Vec<_>>(),
                    [
                        "--inverse",
                        "--tree",
                        "--json",
                        "--output",
                        "TYPE",
                        "--",
                        "/dev/mapper/synthetic",
                    ]
                );
                Ok(output(false, "crypt\n", "failed"))
            }
        });
        assert_eq!(calls, 3);
        assert!(require_status(path, status).is_err());
    }

    #[test]
    fn unverified_storage_is_refused_without_the_override_and_says_how_to_fix_it() {
        let mut audited = false;
        let error = admit_unverified_storage_with(
            Path::new("/synthetic/unlocked"),
            "managed volume",
            anyhow::anyhow!("synthetic: no dm-crypt mapping"),
            false,
            |_| {
                audited = true;
                Ok(())
            },
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(!audited, "a refusal is not an override use");
        for needle in [
            "/synthetic/unlocked",
            "not verified encrypted",
            "synthetic: no dm-crypt mapping",
            "FileVault",
            "dm-crypt/LUKS",
            ALLOW_UNVERIFIED_STORAGE_ENV,
            "--prod",
        ] {
            assert!(message.contains(needle), "missing {needle:?} in {message}");
        }
    }

    #[test]
    fn the_override_admits_only_after_its_use_is_audited() {
        let mut detail = None;
        admit_unverified_storage_with(
            Path::new("/synthetic/unlocked"),
            "managed volume",
            anyhow::anyhow!("synthetic refusal"),
            true,
            |d| {
                detail = Some(d.to_string());
                Ok(())
            },
        )
        .expect("the override admits");
        let detail = detail.expect("the override use was audited");
        assert!(detail.contains("purpose=managed volume"), "{detail}");
        assert!(detail.contains("path=/synthetic/unlocked"), "{detail}");
        assert!(detail.contains("reason=synthetic refusal"), "{detail}");
    }

    #[test]
    fn an_override_whose_audit_fails_is_refused() {
        let error = admit_unverified_storage_with(
            Path::new("/synthetic/unlocked"),
            "disk image",
            anyhow::anyhow!("synthetic refusal"),
            true,
            |_| anyhow::bail!("synthetic audit failure"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("could not be audited"), "{message}");
        assert!(message.contains("synthetic audit failure"), "{message}");
    }

    #[test]
    fn the_override_is_honoured_only_when_set_to_one_and_refused_under_prod() {
        let mut env = crate::util::test_env::TestEnv::new();
        env.remove(ALLOW_UNVERIFIED_STORAGE_ENV);
        assert!(!override_requested());
        assert!(refuse_override_for_production().is_ok());
        for value in ["0", "true", "yes", ""] {
            env.set(ALLOW_UNVERIFIED_STORAGE_ENV, value);
            assert!(!override_requested(), "{value:?} must not enable it");
            // Any value is refused under --prod: it says what the operator meant.
            assert!(refuse_override_for_production().is_err(), "{value:?}");
        }
        env.set(ALLOW_UNVERIFIED_STORAGE_ENV, "1");
        assert!(override_requested());
        let message = format!("{:#}", refuse_override_for_production().unwrap_err());
        assert!(message.contains("--prod refuses"), "{message}");
        assert!(message.contains(ALLOW_UNVERIFIED_STORAGE_ENV), "{message}");
    }

    #[test]
    fn the_override_writes_a_volume_storage_override_audit_event() {
        let home = tempfile::tempdir().unwrap();
        let mut env = crate::util::test_env::TestEnv::new();
        env.set("MVM_HOME", home.path());
        env.set(ALLOW_UNVERIFIED_STORAGE_ENV, "1");
        admit_unverified_storage(
            Path::new("/synthetic/unlocked"),
            "managed volume",
            anyhow::anyhow!("synthetic refusal"),
        )
        .expect("override admits");
        let log = std::fs::read_to_string(default_audit_log()).expect("audit log written");
        assert!(log.contains("\"volume_storage_override\""), "{log}");
        assert!(log.contains("purpose=managed volume"), "{log}");
    }

    #[test]
    fn a_check_before_creation_probes_the_nearest_existing_ancestor() {
        let scratch = tempfile::tempdir().unwrap();
        let missing = scratch.path().join("a").join("b").join("image.img");
        assert_eq!(
            nearest_existing_ancestor(&missing).as_deref(),
            Some(scratch.path())
        );
        assert_eq!(
            nearest_existing_ancestor(scratch.path()).as_deref(),
            Some(scratch.path())
        );
    }
}
