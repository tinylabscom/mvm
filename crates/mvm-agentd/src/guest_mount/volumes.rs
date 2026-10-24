//! Boot-time volume policy, source resolution, and mounting.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[cfg(not(target_os = "linux"))]
use super::ensure_dir;
use super::{MountError, Result};
#[cfg(any(target_os = "linux", test))]
use super::{WORKLOAD_GID, WORKLOAD_UID};
use crate::vsock::{VolumeConfig, VolumeConfigKind};

#[cfg(test)]
pub(crate) const RESERVED_MOUNTS: &[&str] =
    &["/", "/mvm", "/mvm/runtime", "/dev", "/dev/vda", "/dev/vdc"];

pub fn validate_volume_mountpoint(mountpoint: &str) -> Result<()> {
    validated_relative_mountpoint(mountpoint).map(|_| ())
}

fn validated_relative_mountpoint(mountpoint: &str) -> Result<PathBuf> {
    let normalized = mvm_core::crypto::policy::validate_mount_path(mountpoint)
        .map_err(|error| MountError::PathPolicyDenied(error.to_string()))?;
    Path::new(&normalized)
        .strip_prefix("/")
        .map(Path::to_path_buf)
        .map_err(|_| {
            MountError::PathPolicyDenied(format!(
                "volume mountpoint {mountpoint:?} is not a normalized absolute path"
            ))
        })
}

fn volume_mount_target(root: &Path, mountpoint: &str) -> Result<PathBuf> {
    Ok(root.join(validated_relative_mountpoint(mountpoint)?))
}

#[cfg(any(target_os = "linux", test))]
fn volume_mount_scaffold(root: &Path, mountpoint: &str) -> Result<Option<PathBuf>> {
    let relative = validated_relative_mountpoint(mountpoint)?;
    let mut components = relative.components();
    let Some(base) = components.next() else {
        return Err(MountError::PathPolicyDenied(format!(
            "volume mountpoint {mountpoint:?} has no allowed mount root"
        )));
    };
    if components.next().is_none() {
        return Ok(None);
    }
    Ok(Some(root.join(base.as_os_str())))
}

#[cfg(not(target_os = "linux"))]
fn ensure_volume_mount_target(
    root: &Path,
    mountpoint: &str,
    scaffolds: &mut BTreeSet<PathBuf>,
) -> Result<PathBuf> {
    let target = volume_mount_target(root, mountpoint)?;
    let first_error = match ensure_dir(&target.to_string_lossy()) {
        Ok(()) => return Ok(target),
        Err(error) => error,
    };
    if !matches!(
        &first_error,
        MountError::Syscall { source, .. } if source.raw_os_error() == Some(libc::EROFS)
    ) {
        return Err(first_error);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = scaffolds;
        Err(first_error)
    }
    #[cfg(target_os = "linux")]
    {
        let Some(scaffold) = volume_mount_scaffold(root, mountpoint)? else {
            return Err(first_error);
        };
        if !scaffolds.contains(&scaffold) {
            mount(
                "tmpfs",
                &scaffold.to_string_lossy(),
                "tmpfs",
                libc::MS_NOSUID | libc::MS_NODEV,
                "mode=0755",
            )?;
            scaffolds.insert(scaffold);
        }
        ensure_dir(&target.to_string_lossy())?;
        Ok(target)
    }
}

#[cfg(target_os = "linux")]
fn ensure_volume_mount_target(
    root: &Path,
    mountpoint: &str,
    scaffolds: &mut BTreeSet<PathBuf>,
) -> Result<crate::safe_mount_target::Target> {
    use crate::safe_mount_target::Target;
    let target = volume_mount_target(root, mountpoint)?;
    match Target::resolve(&target, true) {
        Ok(target) => return Ok(target),
        Err(error) if error.raw_os_error() == Some(libc::EROFS) => {}
        Err(error) => return Err(MountError::syscall("resolve volume mount target", error)),
    }
    let scaffold = volume_mount_scaffold(root, mountpoint)?
        .ok_or_else(|| MountError::InvalidConfig("read-only volume mount root".into()))?;
    if !scaffolds.contains(&scaffold) {
        Target::resolve(&scaffold, false)
            .and_then(|target| target.mount("tmpfs", "tmpfs", false, None, true))
            .map_err(|error| MountError::syscall("mount volume scaffold", error))?;
        scaffolds.insert(scaffold);
    }
    Target::resolve(&target, true)
        .map_err(|error| MountError::syscall("resolve volume mount target after scaffold", error))
}

/// Find the attached block device whose ext4 label is `label`.
///
/// Delegates to `flowmux_drive`, which already solved this for the FlowMux
/// identity disk: it enumerates from `/sys/class/block` rather than guessing a
/// `/dev/vd[a-z]` range, checks the ext4 magic before trusting the label field,
/// and is the same decoder the writer's stamp is tested against. A second
/// superblock parser here would be a second thing to keep in sync with the
/// on-disk format.
fn device_for_label(label: &str) -> Result<String> {
    crate::flowmux_drive::find_labeled_ext4_disk_among(
        crate::flowmux_drive::virtio_block_devices(),
        label,
    )
    .map(|path| path.to_string_lossy().into_owned())
    .ok_or_else(|| {
        MountError::InvalidConfig(format!("no block device carries volume label {label:?}"))
    })
}

fn resolve_volume_mount_source(volume: &VolumeConfig) -> Result<(String, &'static str)> {
    if volume.tag.is_empty() {
        return Err(MountError::InvalidConfig(
            "volume tag must not be empty".to_string(),
        ));
    }
    match volume.kind {
        VolumeConfigKind::VirtioFs => {
            if volume.device.is_some() {
                return Err(MountError::InvalidConfig(format!(
                    "virtio-fs volume {:?} must not carry a block device",
                    volume.tag
                )));
            }
            if volume.label.is_some() {
                return Err(MountError::InvalidConfig(format!(
                    "virtio-fs volume {:?} must not carry a volume label",
                    volume.tag
                )));
            }
            Ok((volume.tag.clone(), "virtiofs"))
        }
        VolumeConfigKind::Block => {
            let device = volume.device.as_deref().ok_or_else(|| {
                MountError::InvalidConfig(format!(
                    "block volume {:?} is missing its guest device",
                    volume.tag
                ))
            })?;
            validate_virtio_block_device(device, "block volume")?;
            // A label, when the host wrote one, wins over the node. Resolution
            // failure is fatal rather than a fallback to `device`: the host
            // asserted an identity, and mounting the slot anyway would be
            // exactly the silent wrong-image mount the label exists to stop.
            match volume.label.as_deref() {
                Some(label) => Ok((device_for_label(label)?, "ext4")),
                None => Ok((device.to_string(), "ext4")),
            }
        }
    }
}

pub(super) fn validate_virtio_block_device(device: &str, purpose: &str) -> Result<()> {
    let suffix = device.strip_prefix("/dev/vd").ok_or_else(|| {
        MountError::PathPolicyDenied(format!(
            "{purpose} device {device:?} is outside /dev/vd[a-z]"
        ))
    })?;
    if suffix.len() != 1 || !suffix.bytes().all(|byte| byte.is_ascii_lowercase()) {
        return Err(MountError::PathPolicyDenied(format!(
            "{purpose} device {device:?} is outside /dev/vd[a-z]"
        )));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn writable_block_volume_owner(volume: &VolumeConfig) -> Option<(u32, u32)> {
    (!volume.read_only && volume.kind == VolumeConfigKind::Block)
        .then_some((WORKLOAD_UID, WORKLOAD_GID))
}

pub fn mount_volumes(volumes: &[VolumeConfig], root: &Path) -> Result<()> {
    let mut scaffolds = BTreeSet::new();
    for vol in volumes {
        let (source, filesystem) = resolve_volume_mount_source(vol)?;
        #[cfg(not(target_os = "linux"))]
        let _ = (source, filesystem);
        let target = ensure_volume_mount_target(root, &vol.mountpoint, &mut scaffolds)?;
        #[cfg(not(target_os = "linux"))]
        let _ = &target;
        #[cfg(target_os = "linux")]
        {
            target
                .mount(
                    &source,
                    filesystem,
                    vol.read_only,
                    writable_block_volume_owner(vol),
                    false,
                )
                .map_err(|error| MountError::syscall("mount pinned volume", error))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires builder VM Linux mount namespace and CAP_SYS_ADMIN"]
    fn read_only_root_scaffold_supports_sibling_and_nested_mounts() {
        use crate::safe_mount_target::{Target, tests::private_mount_namespace};
        use std::ffi::CString;

        private_mount_namespace();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        Target::resolve(&root, true)
            .unwrap()
            .mount("tmpfs", "tmpfs", false, None, true)
            .unwrap();
        std::fs::create_dir(root.join("data")).unwrap();
        let root_cstring = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: the path names this test's tmpfs in its private namespace.
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    root_cstring.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REMOUNT | libc::MS_RDONLY,
                    std::ptr::null(),
                )
            },
            0
        );
        let mut scaffolds = BTreeSet::new();
        for path in ["/data/first", "/data/second", "/data/first/nested"] {
            ensure_volume_mount_target(&root, path, &mut scaffolds)
                .unwrap()
                .mount("tmpfs", "tmpfs", false, None, true)
                .unwrap();
        }
        assert_eq!(scaffolds, BTreeSet::from([root.join("data")]));
        for path in ["data/first/nested", "data/first", "data/second", "data", ""] {
            assert!(
                Target::resolve(&root.join(path), false)
                    .unwrap()
                    .unmount(false)
                    .unwrap()
            );
        }
    }

    #[test]
    fn validate_volume_mountpoint_accepts_normal_paths() {
        assert!(validate_volume_mountpoint("/data").is_ok());
        assert!(validate_volume_mountpoint("/data/app").is_ok());
        assert!(validate_volume_mountpoint("/work/nested/other").is_ok());
    }

    #[test]
    fn validate_volume_mountpoint_rejects_reserved_paths() {
        for reserved in RESERVED_MOUNTS {
            assert!(
                validate_volume_mountpoint(reserved).is_err(),
                "reserved path {reserved:?} should be rejected"
            );
            assert!(
                validate_volume_mountpoint(&format!("{reserved}/sub")).is_err(),
                "child of reserved path {reserved:?} should be rejected"
            );
        }
    }

    #[test]
    fn validate_volume_mountpoint_rejects_relative_and_empty() {
        assert!(validate_volume_mountpoint("data").is_err());
        assert!(validate_volume_mountpoint("").is_err());
        assert!(validate_volume_mountpoint("/data/../proc").is_err());
        assert!(validate_volume_mountpoint("//dev").is_err());
    }

    #[test]
    fn volume_mount_target_stays_beneath_the_staged_root() {
        assert_eq!(
            volume_mount_target(Path::new("/mnt/root"), "/data/work").unwrap(),
            PathBuf::from("/mnt/root/data/work")
        );
    }

    #[test]
    fn volume_mount_target_rejects_a_relative_mountpoint() {
        assert!(volume_mount_target(Path::new("/mnt/root"), "data").is_err());
    }

    #[test]
    fn nested_volume_mount_uses_its_allowed_root_as_a_writable_scaffold() {
        assert_eq!(
            volume_mount_scaffold(Path::new("/mnt/root"), "/data/work/cache").unwrap(),
            Some(PathBuf::from("/mnt/root/data"))
        );
        assert_eq!(
            volume_mount_scaffold(Path::new("/mnt/root"), "/data").unwrap(),
            None
        );
    }

    #[test]
    fn a_virtiofs_volume_may_not_carry_a_volume_label() {
        // A share is addressed by tag and has no filesystem to read a label
        // from, so a label here means the host built a contradictory config.
        let volume = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/mnt/data".to_string(),
            read_only: true,
            kind: VolumeConfigKind::VirtioFs,
            device: None,
            label: Some("mvmmnt0".to_string()),
        };
        assert!(resolve_volume_mount_source(&volume).is_err());
    }

    #[test]
    fn a_labelled_block_volume_that_matches_no_device_refuses() {
        // Fail closed. Falling back to the device node would mount whatever
        // landed in that slot, which is the failure the label prevents.
        let volume = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/mnt/data".to_string(),
            read_only: true,
            kind: VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
            label: Some("mvm-no-such-label".to_string()),
        };
        let err = resolve_volume_mount_source(&volume)
            .expect_err("an unmatched label must refuse rather than fall back");
        assert!(
            err.to_string().contains("mvm-no-such-label"),
            "error should name the label: {err}"
        );
    }

    #[test]
    fn volume_mount_source_distinguishes_virtiofs_and_block() {
        let share = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data/share".to_string(),
            read_only: true,
            kind: crate::vsock::VolumeConfigKind::VirtioFs,
            device: None,
            label: None,
        };
        assert_eq!(
            resolve_volume_mount_source(&share).unwrap(),
            ("uvol0".to_string(), "virtiofs")
        );

        let block = VolumeConfig {
            tag: "uvol1".to_string(),
            mountpoint: "/data/disk".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
            label: None,
        };
        assert_eq!(
            resolve_volume_mount_source(&block).unwrap(),
            ("/dev/vdb".to_string(), "ext4")
        );
    }

    #[test]
    fn volume_mount_source_rejects_invalid_kind_device_combinations() {
        let share_with_device = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data/share".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::VirtioFs,
            device: Some("/dev/vdb".to_string()),
            label: None,
        };
        assert!(resolve_volume_mount_source(&share_with_device).is_err());

        let invalid_block = VolumeConfig {
            tag: "uvol1".to_string(),
            mountpoint: "/data/disk".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/sda".to_string()),
            label: None,
        };
        assert!(resolve_volume_mount_source(&invalid_block).is_err());
    }

    #[test]
    fn sdk_sidecar_device_is_confined_to_virtio_block_nodes() {
        assert!(validate_virtio_block_device("/dev/vde", "SDK sidecar").is_ok());
        assert!(validate_virtio_block_device("/dev/sda", "SDK sidecar").is_err());
        assert!(validate_virtio_block_device("/dev/vdaa", "SDK sidecar").is_err());
        assert!(validate_virtio_block_device("../../dev/vde", "SDK sidecar").is_err());
    }

    #[test]
    fn writable_block_volume_is_owned_by_the_workload() {
        let volume = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
            label: None,
        };

        assert_eq!(
            writable_block_volume_owner(&volume),
            Some((WORKLOAD_UID, WORKLOAD_GID))
        );
    }

    #[test]
    fn read_only_and_virtiofs_volumes_keep_their_existing_owner() {
        let read_only_block = VolumeConfig {
            tag: "uvol0".to_string(),
            mountpoint: "/data".to_string(),
            read_only: true,
            kind: crate::vsock::VolumeConfigKind::Block,
            device: Some("/dev/vdb".to_string()),
            label: None,
        };
        let writable_share = VolumeConfig {
            tag: "uvol1".to_string(),
            mountpoint: "/work".to_string(),
            read_only: false,
            kind: crate::vsock::VolumeConfigKind::VirtioFs,
            device: None,
            label: None,
        };

        assert_eq!(writable_block_volume_owner(&read_only_block), None);
        assert_eq!(writable_block_volume_owner(&writable_share), None);
    }
}
