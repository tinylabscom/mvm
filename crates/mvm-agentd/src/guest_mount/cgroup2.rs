#[cfg(any(target_os = "linux", test))]
use super::MountError;
use super::Result;
#[cfg(target_os = "linux")]
use super::{chown, ensure_dir, mount};

/// Mount point for the unified cgroup hierarchy.
pub const CGROUP2_MOUNT_POINT: &str = "/sys/fs/cgroup";
/// Subtree handed to the workload, so an in-guest orchestrator (rootless
/// Kubernetes, a nested container runtime) can manage its own cgroups
/// without write access to the root cgroup.
pub const CGROUP_DELEGATION_DIR: &str = "/sys/fs/cgroup/mvm-workload";
/// Controllers enabled at the root for delegation to
/// [`CGROUP_DELEGATION_DIR`]. Each is written separately: availability
/// depends on the kernel's cgroup config, which the guest did not choose,
/// and one unavailable controller must not fail the rest.
pub const DELEGATED_CONTROLLERS: &[&str] = &["cpu", "memory", "pids", "cpuset", "io"];

/// What the cgroup2 provisioning found on this kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cgroup2Status {
    /// cgroup2 is mounted and the delegation subtree is owned by the workload.
    MountedAndDelegated,
    /// The kernel has no cgroup2 (or the mountpoint cannot host it) — a fact
    /// about the kernel, not a failure the guest can act on.
    KernelLacksCgroups,
}

/// Mount the unified cgroup hierarchy and delegate a subtree to the workload.
///
/// Best-effort by construction. The sealed workload kernel compiles cgroups
/// out entirely, where `mount(2)` fails with ENODEV — never worth refusing a
/// boot over, since a guest that never asked for cgroups must boot
/// identically. A guest on a cgroup-capable kernel gets the mount plus
/// [`CGROUP_DELEGATION_DIR`] owned by the workload uid; whether the workload
/// uses it is its own business.
///
/// Idempotent under activation retry: an existing cgroup2 mount is left
/// alone and every delegation step is harmless to repeat.
pub fn mount_and_delegate_cgroup2(workload_uid: u32, workload_gid: u32) -> Result<Cgroup2Status> {
    #[cfg(target_os = "linux")]
    {
        mount_cgroup2()?;
        delegate_cgroup2(workload_uid, workload_gid)?;
        Ok(Cgroup2Status::MountedAndDelegated)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (workload_uid, workload_gid);
        Ok(Cgroup2Status::KernelLacksCgroups)
    }
}

/// The mount half of [`mount_and_delegate_cgroup2`], split so the
/// "already mounted" arm is testable against real mount tables.
#[cfg(target_os = "linux")]
fn mount_cgroup2() -> Result<Cgroup2Status> {
    if cgroup2_is_mounted(&std::fs::read_to_string("/proc/mounts").unwrap_or_default()) {
        // Activation can retry; a second mount would fail EBUSY for a reason
        // that is not a defect.
        return Ok(Cgroup2Status::MountedAndDelegated);
    }
    ensure_dir(CGROUP2_MOUNT_POINT)?;
    match mount("cgroup2", CGROUP2_MOUNT_POINT, "cgroup2", 0, "") {
        Ok(()) => Ok(Cgroup2Status::MountedAndDelegated),
        Err(error) if cgroup2_unsupported(&error) => Ok(Cgroup2Status::KernelLacksCgroups),
        Err(error) => Err(error),
    }
}

/// The delegation half of [`mount_and_delegate_cgroup2`]: enable controllers
/// at the root for subtree delegation, create the workload subtree, and hand
/// it to the workload uid. Every step is best-effort — a kernel missing one
/// controller still yields a usable subtree for the rest.
#[cfg(target_os = "linux")]
fn delegate_cgroup2(workload_uid: u32, workload_gid: u32) -> Result<()> {
    for controller in DELEGATED_CONTROLLERS {
        // Individually: `+cpu` on a kernel without the scheduler controller
        // fails EINVAL while `+memory` beside it succeeds.
        let _ = std::fs::write(
            format!("{CGROUP2_MOUNT_POINT}/cgroup.subtree_control"),
            format!("+{controller}"),
        );
    }
    ensure_dir(CGROUP_DELEGATION_DIR)?;
    chown(CGROUP_DELEGATION_DIR, workload_uid, workload_gid)?;
    // Interface files inside a cgroup directory follow the directory owner
    // on modern kernels; where one does not, a best-effort per-file pass
    // makes the delegation usable anyway.
    if let Ok(entries) = std::fs::read_dir(CGROUP_DELEGATION_DIR) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(path) = path.to_str() else { continue };
            let _ = chown(path, workload_uid, workload_gid);
        }
    }
    Ok(())
}

/// Whether `/proc/mounts` already shows a `cgroup2` at [`CGROUP2_MOUNT_POINT`].
///
/// Split from the mount for the same reason as `devpts_is_mounted`: the
/// retry arm is the only one a host test can never reach through the syscall.
#[must_use]
#[cfg(any(target_os = "linux", test))]
fn cgroup2_is_mounted(mounts: &str) -> bool {
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let (Some(_dev), Some(target), Some(fstype)) =
            (fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        target == CGROUP2_MOUNT_POINT && fstype == "cgroup2"
    })
}

/// Whether a cgroup2 mount failure means "this kernel has no cgroup2"
/// (ENODEV/ENOENT) rather than a real defect. Distinguishing the two is what
/// keeps a boot on the sealed workload kernel — which compiles cgroups out —
/// from reading as a mount failure.
#[must_use]
#[cfg(any(target_os = "linux", test))]
fn cgroup2_unsupported(error: &MountError) -> bool {
    let Some(errno) = (match error {
        MountError::Syscall { source, .. } => source.raw_os_error(),
        _ => None,
    }) else {
        return false;
    };
    errno == libc::ENODEV || errno == libc::ENOENT
}

#[cfg(test)]
mod tests {
    use super::{
        CGROUP_DELEGATION_DIR, CGROUP2_MOUNT_POINT, Cgroup2Status, DELEGATED_CONTROLLERS,
        MountError, cgroup2_is_mounted, cgroup2_unsupported,
    };

    #[test]
    fn cgroup2_mount_detection_reads_proc_mounts() {
        let mounts = "\
/dev/vda / ext4 ro,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
";
        assert!(cgroup2_is_mounted(mounts));
        assert!(!cgroup2_is_mounted("cgroup2 /mnt/other cgroup2 rw 0 0\n"));
        assert!(!cgroup2_is_mounted("tmpfs /sys/fs/cgroup tmpfs rw 0 0\n"));
        assert!(!cgroup2_is_mounted(""));
    }

    #[test]
    fn unsupported_errno_classification_separates_kernel_gap_from_defect() {
        let enodev = MountError::syscall(
            "mount(cgroup2 -> /sys/fs/cgroup, cgroup2)",
            std::io::Error::from_raw_os_error(libc::ENODEV),
        );
        let enoent = MountError::syscall(
            "mount(cgroup2 -> /sys/fs/cgroup, cgroup2)",
            std::io::Error::from_raw_os_error(libc::ENOENT),
        );
        let eperm = MountError::syscall(
            "mount(cgroup2 -> /sys/fs/cgroup, cgroup2)",
            std::io::Error::from_raw_os_error(libc::EPERM),
        );
        let non_syscall = MountError::UnsupportedFilesystem("cgroup2".to_string());
        assert!(cgroup2_unsupported(&enodev));
        assert!(cgroup2_unsupported(&enoent));
        assert!(!cgroup2_unsupported(&eperm), "EPERM is a real defect");
        assert!(
            !cgroup2_unsupported(&non_syscall),
            "non-syscall errors carry no errno"
        );
    }

    #[test]
    fn delegation_constants_are_coherent() {
        assert!(CGROUP_DELEGATION_DIR.starts_with(CGROUP2_MOUNT_POINT));
        assert!(CGROUP_DELEGATION_DIR.len() > CGROUP2_MOUNT_POINT.len());
        assert!(!DELEGATED_CONTROLLERS.is_empty());
        for controller in DELEGATED_CONTROLLERS {
            assert!(
                controller.chars().all(|c| c.is_ascii_lowercase()),
                "controller names are written bare after a +/- sign: {controller}"
            );
        }
    }

    #[test]
    fn the_two_statuses_are_distinct() {
        assert_ne!(
            Cgroup2Status::MountedAndDelegated,
            Cgroup2Status::KernelLacksCgroups
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cgroup2_mounts_and_unmounts_where_the_host_permits() {
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("cg");
        std::fs::create_dir(&target).unwrap();
        let target_c = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        let src_c = std::ffi::CString::new("cgroup2").unwrap();
        let fs_c = std::ffi::CString::new("cgroup2").unwrap();
        // SAFETY: all three C strings are NUL-terminated and outlive the call;
        // null data is valid for a cgroup2 mount with no options.
        let rc = unsafe {
            libc::mount(
                src_c.as_ptr(),
                target_c.as_ptr(),
                fs_c.as_ptr(),
                0,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            eprintln!(
                "skipping cgroup2 mount assertion: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        // cgroup2 is a singleton hierarchy: the new mount is another view of
        // the same fs, so clean it up immediately and assert nothing further.
        // SAFETY: target_c is a live NUL-terminated C string.
        let rc = unsafe { libc::umount(target_c.as_ptr()) };
        assert_eq!(rc, 0, "umount: {}", std::io::Error::last_os_error());
    }
}
