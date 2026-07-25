//! Character-device materialization: the allow-list of standard
//! pseudo-devices, the classifier that checks a tar entry's path plus
//! major/minor pair against it, and the Linux (`mknodat`) /
//! non-Linux (skip) materialization paths.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::RefusalReason;

/// Character-device allow-list, expressed as tar-relative paths plus
/// Linux major/minor pairs.
const ALLOWED_DEVICE_NODES: &[AllowedDeviceNode] = &[
    AllowedDeviceNode::new(b"dev/console", 5, 1),
    AllowedDeviceNode::new(b"dev/null", 1, 3),
    AllowedDeviceNode::new(b"dev/zero", 1, 5),
    AllowedDeviceNode::new(b"dev/random", 1, 8),
    AllowedDeviceNode::new(b"dev/urandom", 1, 9),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllowedDeviceNode {
    path: &'static [u8],
    major: u32,
    minor: u32,
}

impl AllowedDeviceNode {
    const fn new(path: &'static [u8], major: u32, minor: u32) -> Self {
        Self { path, major, minor }
    }
}

pub(super) enum DeviceNodeAction {
    #[cfg(target_os = "linux")]
    Materialized,
    #[cfg(not(target_os = "linux"))]
    Skipped,
}

#[cfg(target_os = "linux")]
impl<'a> super::fs_ops::Rooted<'a> {
    pub(super) fn materialize_device_node<R: Read>(
        &self,
        entry: &tar::Entry<R>,
        rel: &Path,
        raw_path: &[u8],
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<DeviceNodeAction, RefusalReason> {
        use rustix::fs::{FileType, Mode, makedev, mknodat};
        use std::os::fd::AsFd;

        let major = entry
            .header()
            .device_major()
            .map_err(|_| RefusalReason::MalformedHeader)?;
        let minor = entry
            .header()
            .device_minor()
            .map_err(|_| RefusalReason::MalformedHeader)?;
        let allowed = classify_device_node(entry.header().entry_type(), raw_path, major, minor)?;

        let (parent, leaf) = self
            .open_parent(rel, true)
            .map_err(super::fs_ops::map_resolve_errno)?;
        if prior_layer_paths.contains(rel) {
            super::fs_ops::remove_prior_layer_path(self, rel)?;
        }
        mknodat(
            parent.as_fd(),
            &leaf,
            FileType::CharacterDevice,
            Mode::from_raw_mode(0o666),
            makedev(allowed.major, allowed.minor),
        )
        .map_err(|_| RefusalReason::MalformedHeader)?;
        Ok(DeviceNodeAction::Materialized)
    }
}

#[cfg(not(target_os = "linux"))]
impl<'a> super::fs_ops::Rooted<'a> {
    pub(super) fn materialize_device_node<R: Read>(
        &self,
        entry: &tar::Entry<R>,
        rel: &Path,
        raw_path: &[u8],
        prior_layer_paths: &HashSet<PathBuf>,
    ) -> Result<DeviceNodeAction, RefusalReason> {
        if prior_layer_paths.contains(rel) {
            super::fs_ops::remove_prior_layer_path(self.root, rel)?;
        }
        materialize_device_node(entry, &self.root.join(rel), raw_path)
    }
}

/// Non-Linux fallback only — Linux device nodes are created via
/// [`super::fs_ops::Rooted::materialize_device_node`] (openat2-resolved
/// `mknodat`).
#[cfg(not(target_os = "linux"))]
fn materialize_device_node<R: Read>(
    entry: &tar::Entry<R>,
    target: &Path,
    raw_path: &[u8],
) -> Result<DeviceNodeAction, RefusalReason> {
    let major = entry
        .header()
        .device_major()
        .map_err(|_| RefusalReason::MalformedHeader)?;
    let minor = entry
        .header()
        .device_minor()
        .map_err(|_| RefusalReason::MalformedHeader)?;
    let allowed = classify_device_node(entry.header().entry_type(), raw_path, major, minor)?;

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|_| RefusalReason::MalformedHeader)?;
    }

    create_allowed_device_node(target, allowed)
}

fn classify_device_node(
    entry_type: tar::EntryType,
    raw_path: &[u8],
    major: Option<u32>,
    minor: Option<u32>,
) -> Result<AllowedDeviceNode, RefusalReason> {
    if entry_type != tar::EntryType::Char {
        return Err(RefusalReason::DeviceNodeRefused);
    }

    let (Some(major), Some(minor)) = (major, minor) else {
        return Err(RefusalReason::DeviceNodeRefused);
    };

    ALLOWED_DEVICE_NODES
        .iter()
        .copied()
        .find(|allowed| {
            allowed.path == raw_path && allowed.major == major && allowed.minor == minor
        })
        .ok_or(RefusalReason::DeviceNodeRefused)
}

/// Non-Linux fallback only — Linux device nodes are created via
/// [`super::fs_ops::Rooted::materialize_device_node`] (openat2-resolved
/// `mknodat`).
#[cfg(not(target_os = "linux"))]
fn create_allowed_device_node(
    _target: &Path,
    _allowed: AllowedDeviceNode,
) -> Result<DeviceNodeAction, RefusalReason> {
    Ok(DeviceNodeAction::Skipped)
}

#[cfg(test)]
mod tests {
    use super::super::UnpackOptions;
    use super::super::test_support::*;
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    // ── allow-listed device nodes ───────────────────────

    #[test]
    fn device_node_allowlist_accepts_only_expected_char_devices() {
        for allowed in ALLOWED_DEVICE_NODES {
            assert_eq!(
                classify_device_node(
                    tar::EntryType::Char,
                    allowed.path,
                    Some(allowed.major),
                    Some(allowed.minor),
                ),
                Ok(*allowed)
            );
        }

        assert_eq!(
            classify_device_node(tar::EntryType::Block, b"dev/null", Some(1), Some(3)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"dev/tty", Some(5), Some(0)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"dev/null", Some(1), Some(5)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"./dev/null", Some(1), Some(3)),
            Err(RefusalReason::DeviceNodeRefused)
        );
        assert_eq!(
            classify_device_node(tar::EntryType::Char, b"dev/null", None, Some(3)),
            Err(RefusalReason::DeviceNodeRefused)
        );
    }

    #[test]
    fn disallowed_character_device_is_refused() {
        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/tty", tar::EntryType::Char, 5, 0);
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::DeviceNodeRefused);
        assert!(!tmp.path().join("dev/tty").exists());
    }

    #[test]
    fn block_device_is_refused_even_when_path_matches_allowlist() {
        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/null", tar::EntryType::Block, 1, 3);
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::DeviceNodeRefused);
        assert!(!tmp.path().join("dev/null").exists());
    }

    #[test]
    fn allowed_device_node_under_symlinked_parent_refuses() {
        let tar_bytes = build_tar(|b| {
            add_symlink(b, "dev", "/tmp");
            add_device_node(b, "dev/null", tar::EntryType::Char, 1, 3);
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.symlinks_written, 1);
        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.refused.len(), 1, "{:?}", report.refused);
        assert_eq!(report.refused[0].reason, RefusalReason::SymlinkInParent);
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn allowlisted_device_nodes_are_skipped_on_non_linux_hosts() {
        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/console", tar::EntryType::Char, 5, 1);
            add_device_node(b, "dev/null", tar::EntryType::Char, 1, 3);
        });

        let tmp = TempDir::new().unwrap();
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 0);
        assert_eq!(report.device_nodes_skipped, 2);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        assert!(!tmp.path().join("dev/console").exists());
        assert!(!tmp.path().join("dev/null").exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allowed_device_node_materializes_when_host_permits_mknod() {
        use rustix::fs::{CWD, FileType, Mode, makedev, mknodat};
        use std::os::unix::fs::FileTypeExt;

        let tmp = TempDir::new().unwrap();
        let probe = tmp.path().join("probe-null");
        let mode = Mode::from_raw_mode(0o600);
        let dev = makedev(1, 3);
        if mknodat(CWD, &probe, FileType::CharacterDevice, mode, dev).is_err() {
            eprintln!("skipping device-node materialization assertion: mknod not permitted");
            return;
        }
        std::fs::remove_file(&probe).unwrap();

        let tar_bytes = build_tar(|b| {
            add_device_node(b, "dev/null", tar::EntryType::Char, 1, 3);
        });
        let report = super::super::unpack_layer(
            Cursor::new(tar_bytes),
            tmp.path(),
            &UnpackOptions::default(),
        )
        .expect("unpack ok");

        assert_eq!(report.device_nodes_written, 1);
        assert!(report.refused.is_empty(), "{:?}", report.refused);
        let meta = std::fs::symlink_metadata(tmp.path().join("dev/null")).unwrap();
        assert!(meta.file_type().is_char_device());
    }
}
