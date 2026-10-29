//! Directory-only, descriptor-pinned volume targets.
//!
//! Linux 5.2's new mount API is required; no pathname fallback is safe here.
//! Unmount additionally requires the agent's trusted procfs at `/proc`.

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path};

    pub(crate) struct Target(OwnedFd, Option<(OwnedFd, CString)>);

    fn cstring(value: impl AsRef<[u8]>) -> io::Result<CString> {
        CString::new(value.as_ref()).map_err(io::Error::other)
    }

    fn checked(value: libc::c_long) -> io::Result<libc::c_int> {
        if value < 0 {
            Err(io::Error::last_os_error())
        } else {
            libc::c_int::try_from(value).map_err(io::Error::other)
        }
    }

    fn owned(value: libc::c_long) -> io::Result<OwnedFd> {
        let fd = checked(value)?;
        // SAFETY: successful descriptor-producing syscall transfers ownership.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    impl Target {
        /// Traverse every component without following any symlink, including
        /// the supplied root. Existing mounted directories are deliberately
        /// allowed: nested volumes and local ad-hoc directories both need them.
        pub(crate) fn resolve(path: &Path, create: bool) -> io::Result<Self> {
            if !path.is_absolute() {
                return Err(io::Error::other("mount target must be absolute"));
            }
            // SAFETY: constant C string and valid open flags.
            let mut fd = owned(
                unsafe {
                    libc::open(
                        c"/".as_ptr(),
                        libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
                    )
                }
                .into(),
            )?;
            let mut parent = None;
            for component in path.components() {
                let name = match component {
                    Component::RootDir => continue,
                    Component::Normal(name) => cstring(name.as_bytes())?,
                    _ => return Err(io::Error::other("non-normal mount target component")),
                };
                let open = || {
                    // SAFETY: live directory descriptor and NUL-terminated name.
                    unsafe {
                        libc::openat(
                            fd.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    }
                };
                let mut next = open();
                if next < 0
                    && create
                    && io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
                {
                    // SAFETY: live parent descriptor; mkdirat never follows leaf links.
                    let result = unsafe { libc::mkdirat(fd.as_raw_fd(), name.as_ptr(), 0o755) };
                    if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
                    {
                        return Err(io::Error::last_os_error());
                    }
                    next = open();
                }
                let next = owned(next.into())?;
                parent = Some((fd, name));
                fd = next;
            }
            Ok(Self(fd, parent))
        }

        /// Build a detached filesystem, adjust its own root, then attach to
        /// the pinned target. No lookup of a workload-controlled pathname
        /// occurs after target resolution.
        pub(crate) fn mount(
            &self,
            source: &str,
            filesystem: &str,
            read_only: bool,
            owner: Option<(u32, u32)>,
            scaffold: bool,
        ) -> io::Result<()> {
            let filesystem = cstring(filesystem)?;
            let source = cstring(source)?;
            // SAFETY: valid filesystem name; FSOPEN_CLOEXEC is 1.
            let context =
                owned(unsafe { libc::syscall(libc::SYS_fsopen, filesystem.as_ptr(), 1) })?;
            let config = |command: u32, key: *const libc::c_char, value: *const libc::c_char| {
                // SAFETY: context is live; strings remain live throughout call.
                checked(unsafe {
                    libc::syscall(
                        libc::SYS_fsconfig,
                        context.as_raw_fd(),
                        command,
                        key,
                        value,
                        0,
                    )
                })
                .map(|_| ())
            };
            if scaffold {
                config(1, c"mode".as_ptr(), c"0755".as_ptr())?;
            } else {
                config(1, c"source".as_ptr(), source.as_ptr())?;
            }
            if read_only {
                // Set the superblock read-only before filesystem creation,
                // not just the per-mount attribute applied by fsmount.
                config(0, c"ro".as_ptr(), std::ptr::null())?;
            }
            config(6, std::ptr::null(), std::ptr::null())?;
            let attributes: u32 = if read_only { 1 } else { 0 } | if scaffold { 2 | 4 } else { 0 };
            // SAFETY: live configured fs context; FSMOUNT_CLOEXEC is 1.
            let mounted = owned(unsafe {
                libc::syscall(libc::SYS_fsmount, context.as_raw_fd(), 1, attributes)
            })?;
            if let Some((uid, gid)) = owner {
                // SAFETY: AT_EMPTY_PATH operates on the detached mount root,
                // not on a pathname that the workload can redirect.
                checked(
                    unsafe {
                        libc::fchownat(
                            mounted.as_raw_fd(),
                            c"".as_ptr(),
                            uid,
                            gid,
                            libc::AT_EMPTY_PATH,
                        )
                    }
                    .into(),
                )?;
            }
            // SAFETY: both descriptors stay live; empty-path flags select
            // exactly those pinned objects (MOVE_MOUNT_F/T_EMPTY_PATH).
            checked(unsafe {
                libc::syscall(
                    libc::SYS_move_mount,
                    mounted.as_raw_fd(),
                    c"".as_ptr(),
                    self.0.as_raw_fd(),
                    c"".as_ptr(),
                    0x4 | 0x40,
                )
            })?;
            Ok(())
        }

        pub(crate) fn unmount(self, force: bool) -> io::Result<bool> {
            let Self(target, parent) = self;
            let (parent, name) = parent.ok_or_else(|| io::Error::other("cannot unmount root"))?;
            let mut path = format!("/proc/self/fd/{}/", parent.as_raw_fd()).into_bytes();
            path.extend_from_slice(name.as_bytes());
            let path = cstring(path)?;
            // Keeping the mount-root fd would itself make normal unmount busy.
            // Mounted directories cannot be renamed by an unprivileged workload.
            drop(target);
            // SAFETY: trusted procfs traverses the pinned parent; the kernel
            // atomically refuses leaf symlinks through UMOUNT_NOFOLLOW.
            let result = unsafe {
                libc::umount2(
                    path.as_ptr(),
                    libc::UMOUNT_NOFOLLOW | if force { libc::MNT_DETACH } else { 0 },
                )
            };
            if result == 0 {
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            if !force && error.raw_os_error() == Some(libc::EBUSY) {
                Ok(false)
            } else {
                Err(error)
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::Target;

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::Target;
    use std::os::unix::fs::symlink;

    pub(crate) fn private_mount_namespace() {
        // SAFETY: the ignored test owns its thread's new mount namespace.
        assert_eq!(
            unsafe { libc::unshare(libc::CLONE_NEWNS) },
            0,
            "requires CAP_SYS_ADMIN: {}",
            std::io::Error::last_os_error()
        );
        // SAFETY: make inherited mounts private before any test mount.
        assert_eq!(
            unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                )
            },
            0
        );
    }

    #[test]
    fn rejects_leaf_and_ancestor_redirects() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::create_dir(root.join("usr")).unwrap();
        symlink("../usr", root.join("work/redirect")).unwrap();
        assert!(Target::resolve(&root.join("work/redirect"), true).is_err());
        assert!(Target::resolve(&root.join("work/redirect/bin"), true).is_err());
        assert!(!root.join("usr/bin").exists());
        assert!(Target::resolve(&root.join("work/normal/nested"), true).is_ok());
    }

    /// Run only inside the project builder VM:
    /// cargo test -p mvm-agentd safe_mount_target::tests::mount_namespace -- --ignored --exact
    /// Missing CAP_SYS_ADMIN/new mount API is a test FAILURE, never a silent pass.
    #[test]
    #[ignore = "requires builder VM Linux mount namespace and CAP_SYS_ADMIN"]
    fn mount_namespace() {
        private_mount_namespace();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        std::fs::create_dir(root.join("work")).unwrap();
        std::fs::create_dir(root.join("usr")).unwrap();
        std::fs::create_dir(root.join("swap")).unwrap();
        let unmount_target = Target::resolve(&root.join("swap"), false).unwrap();
        std::fs::rename(root.join("swap"), root.join("old-swap")).unwrap();
        symlink("usr", root.join("swap")).unwrap();
        assert!(unmount_target.unmount(false).is_err());
        let pinned = Target::resolve(&root.join("work"), false).unwrap();
        std::fs::rename(root.join("work"), root.join("original")).unwrap();
        symlink("usr", root.join("work")).unwrap();
        pinned
            .mount("tmpfs", "tmpfs", false, Some((901, 901)), true)
            .unwrap();
        // The swapped-in symlink must not receive the mount or ownership.
        use std::os::unix::fs::MetadataExt;
        assert_ne!(std::fs::metadata(root.join("usr")).unwrap().uid(), 901);
        assert_eq!(std::fs::metadata(root.join("original")).unwrap().uid(), 901);
        assert!(Target::resolve(&root.join("work"), false).is_err());
        let mounted = Target::resolve(&root.join("original"), false).unwrap();
        symlink("../usr", root.join("original/redirect")).unwrap();
        assert!(Target::resolve(&root.join("original/redirect/bin"), true).is_err());
        let nested = Target::resolve(&root.join("original/normal"), true).unwrap();
        nested.mount("tmpfs", "tmpfs", false, None, true).unwrap();
        drop(nested);
        let busy = std::fs::File::create(root.join("original/normal/open-file")).unwrap();
        assert!(
            !Target::resolve(&root.join("original/normal"), false)
                .unwrap()
                .unmount(false)
                .unwrap()
        );
        drop(busy);
        assert!(
            Target::resolve(&root.join("original/normal"), false)
                .unwrap()
                .unmount(false)
                .unwrap()
        );
        let forced_path = root.join("original/forced");
        Target::resolve(&forced_path, true)
            .unwrap()
            .mount("tmpfs", "tmpfs", false, None, true)
            .unwrap();
        let mut held = std::fs::File::create(forced_path.join("open-file")).unwrap();
        assert!(
            Target::resolve(&forced_path, false)
                .unwrap()
                .unmount(true)
                .unwrap()
        );
        assert!(!forced_path.join("open-file").exists());
        std::io::Write::write_all(&mut held, b"still open after detach").unwrap();
        drop(held);
        let read_only = Target::resolve(&root.join("original/read-only"), true).unwrap();
        read_only.mount("tmpfs", "tmpfs", true, None, true).unwrap();
        drop(read_only);
        assert_eq!(
            std::fs::write(root.join("original/read-only/denied"), b"no")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        assert!(
            Target::resolve(&root.join("original/read-only"), false)
                .unwrap()
                .unmount(false)
                .unwrap()
        );
        assert!(mounted.unmount(false).unwrap());
    }

    struct ReadOnlyLoop {
        path: String,
    }

    impl Drop for ReadOnlyLoop {
        fn drop(&mut self) {
            match mvm_core::env_hygiene::helper_command("/sbin/losetup")
                .args(["--detach", &self.path])
                .status()
            {
                Ok(status) if status.success() => {}
                result => eprintln!("test loop-device cleanup failed: {result:?}"),
            }
        }
    }

    /// A mount-only read-only flag does not prove that filesystem creation
    /// requested a read-only superblock. Exercise an actually read-only device.
    #[test]
    #[ignore = "requires builder VM CAP_SYS_ADMIN, loop devices, /sbin/mke2fs and /sbin/losetup"]
    fn ext4_read_only_block_device() {
        use std::os::fd::AsRawFd;

        private_mount_namespace();
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("clean.ext4");
        std::fs::File::create(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let formatted = mvm_core::env_hygiene::helper_command("/sbin/mke2fs")
            .args(["-q", "-F", "-t", "ext4"])
            .arg(&image)
            .output()
            .expect("builder must provide /sbin/mke2fs");
        assert!(
            formatted.status.success(),
            "{}",
            String::from_utf8_lossy(&formatted.stderr)
        );
        let attached = mvm_core::env_hygiene::helper_command("/sbin/losetup")
            .args(["--find", "--show", "--read-only"])
            .arg(&image)
            .output()
            .expect("builder must provide /sbin/losetup and loop devices");
        assert!(
            attached.status.success(),
            "{}",
            String::from_utf8_lossy(&attached.stderr)
        );
        let device = ReadOnlyLoop {
            path: String::from_utf8(attached.stdout).unwrap().trim().into(),
        };
        assert!(device.path.starts_with("/dev/loop"));
        let block = std::fs::File::open(&device.path).unwrap();
        let mut read_only: libc::c_int = 0;
        // SAFETY: BLKROGET writes one integer into the provided live pointer.
        assert_eq!(
            unsafe { libc::ioctl(block.as_raw_fd(), 0x125e, std::ptr::addr_of_mut!(read_only)) },
            0
        );
        assert_eq!(read_only, 1, "the backing device itself must be read-only");
        drop(block);
        let target_path = temp.path().join("mounted");
        let target = Target::resolve(&target_path, true).unwrap();
        target
            .mount(&device.path, "ext4", true, None, false)
            .unwrap();
        drop(target);
        assert_eq!(
            std::fs::write(target_path.join("denied"), b"no")
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EROFS)
        );
        assert!(
            Target::resolve(&target_path, false)
                .unwrap()
                .unmount(false)
                .unwrap()
        );
    }
}
