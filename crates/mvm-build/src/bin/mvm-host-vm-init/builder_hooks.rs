//! Builder-VM lifecycle hook runner.
//!
//! Runs the `before_build` hook inside a writable copy of the workload
//! rootfs before the artifact is copied to `/out`. The hook script is
//! baked into the rootfs at `/etc/mvm/hooks/before_build.sh` by
//! `nix/lib/factories/mkFunctionService.nix`; this module is the consumer
//! that executes it in the builder VM.
//!
//! Linux-only: the runner uses `mount`, `chroot`, and `wait` syscalls.

use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::mount::{MsFlags, mount, umount};

use crate::parse_loop_device;

/// Canonical path to the before_build hook inside a workload rootfs.
const HOOK_PATH: &str = "/etc/mvm/hooks/before_build.sh";

/// Where the rootfs image is mounted while the hook runs. Lives on the
/// builder VM's tmpfs (`/tmp`) so the mount point itself is writable and
/// does not depend on any host share.
const MOUNT_POINT: &str = "/tmp/mvm-before-build-rootfs";

/// Absolute path populated by the builder image from util-linux.
const UTIL_LINUX_LOSETUP: &str = "/sbin/losetup";

/// Offline filesystem checker used to replay and seal the ext4 journal after
/// the writable hook mount has been torn down.
const E2FSCK: &str = "/sbin/e2fsck";

/// Grace period for the before_build hook. Build-time setup (DB
/// migrations, cache warming) should complete promptly; if it hangs we
/// fail the build rather than leaving a builder VM wedged.
const HOOK_GRACE: Duration = Duration::from_secs(600);

/// Poll interval while waiting for the hook process.
const HOOK_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Standard PATH inside the chroot. The hook script itself uses absolute
/// Nix store paths for `runtimeShell` and `env`; this PATH is a fallback
/// for user-supplied commands that reference bare interpreter names.
const CHROOT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin";

/// Errors surfaced when running the before_build hook.
#[derive(Debug, thiserror::Error)]
pub enum BuilderHookError {
    /// Could not create the mount point directory.
    #[error("create mount point {path}: {source}")]
    CreateMountPoint {
        path: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Could not mount the rootfs image.
    #[error("mount rootfs {rootfs} at {mount_point}: {source}")]
    MountRootfs {
        rootfs: std::path::PathBuf,
        mount_point: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Could not bind-mount a pseudo-filesystem into the chroot.
    #[error("bind-mount {src} -> {dst}: {source}")]
    BindMount {
        src: String,
        dst: String,
        #[source]
        source: std::io::Error,
    },

    /// The hook process could not be spawned.
    #[error("spawn before_build hook {hook}: {source}")]
    SpawnHook {
        hook: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// The hook ran but exited non-zero.
    #[error("before_build hook exited with code {code:?}")]
    HookNonZero { code: Option<i32> },

    /// The hook exceeded its grace deadline and was killed.
    #[error("before_build hook exceeded grace deadline {grace:?}")]
    GraceExceeded { grace: Duration },

    /// Waiting on the hook process failed unexpectedly.
    #[error("wait for hook process: {source}")]
    WaitFailed {
        #[source]
        source: std::io::Error,
    },

    /// The offline rootfs journal check could not be started.
    #[error("check rootfs journal for {rootfs}: {source}")]
    CheckRootfs {
        rootfs: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The offline checker could not leave the rootfs in a clean state.
    #[error("rootfs journal check for {rootfs} exited with code {code}: {stderr}")]
    RootfsNotClean {
        rootfs: PathBuf,
        code: i32,
        stderr: String,
    },
}

/// Mount `rootfs_path` read-write at [`MOUNT_POINT`], bind-mount
/// `/proc`, `/sys`, and `/dev` into it, then run
/// [`HOOK_PATH`] inside a chroot.
///
/// The rootfs image is modified in place at `rootfs_path`, so callers
/// should operate on a writable copy rather than the original Nix store
/// output.
///
/// Returns `Ok(())` if the hook is missing (treated as a no-op) or if it
/// exits 0. Returns [`BuilderHookError::HookNonZero`] or
/// [`BuilderHookError::GraceExceeded`] on hook failure.
pub fn run_before_build_hook(rootfs_path: &Path) -> Result<(), BuilderHookError> {
    std::fs::create_dir_all(MOUNT_POINT).map_err(|e| BuilderHookError::CreateMountPoint {
        path: MOUNT_POINT,
        source: e,
    })?;

    let mut mounted_rootfs = MountedRootfs::mount(rootfs_path)?;

    // Ensure the chroot has the target directories for bind mounts.
    // mkGuest rootfses already include them, but creating them is
    // idempotent and makes the runner tolerant of unusual images.
    for subdir in ["proc", "sys", "dev"] {
        let _ = std::fs::create_dir_all(format!("{MOUNT_POINT}/{subdir}"));
    }

    for (src, dst) in [("/proc", "proc"), ("/sys", "sys"), ("/dev", "dev")] {
        let dst_path = format!("{MOUNT_POINT}/{dst}");
        mounted_rootfs
            .bind_mount(src, &dst_path)
            .map_err(|e| BuilderHookError::BindMount {
                src: src.to_string(),
                dst: dst_path.clone(),
                source: e,
            })?;
    }

    let hook_in_chroot = format!("{MOUNT_POINT}{HOOK_PATH}");
    let hook_present = std::fs::metadata(&hook_in_chroot)
        .map(|m| m.is_file())
        .unwrap_or(false);

    let hook_result = if !hook_present {
        eprintln!("mvm-host-vm-init: no before_build hook at {HOOK_PATH}; treating as no-op");
        Ok(())
    } else {
        eprintln!(
            "mvm-host-vm-init: running before_build hook in {rootfs_path}",
            rootfs_path = rootfs_path.display()
        );
        run_hook_in_chroot()
    };

    // Drop every bind mount, the rootfs mount, and its loop device before
    // touching the image offline. If best-effort Drop cleanup ever leaves the
    // image mounted, e2fsck refuses it and the artifact is not published.
    drop(mounted_rootfs);
    let journal_result = seal_rootfs_journal(rootfs_path);
    match (hook_result, journal_result) {
        (Err(hook_error), _) => Err(hook_error),
        (Ok(()), result) => result,
    }
}

fn seal_rootfs_journal(rootfs_path: &Path) -> Result<(), BuilderHookError> {
    let output = Command::new(E2FSCK)
        .args(["-p", "-f"])
        .arg(rootfs_path)
        .output()
        .map_err(|source| BuilderHookError::CheckRootfs {
            rootfs: rootfs_path.to_path_buf(),
            source,
        })?;
    let code = output.status.code().unwrap_or(-1);
    if e2fsck_exit_code_is_clean(code) {
        return Ok(());
    }
    Err(BuilderHookError::RootfsNotClean {
        rootfs: rootfs_path.to_path_buf(),
        code,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

fn e2fsck_exit_code_is_clean(code: i32) -> bool {
    matches!(code, 0 | 1)
}

struct LoopDevice {
    path: PathBuf,
}

impl LoopDevice {
    fn attach(rootfs_path: &Path) -> Result<Self, BuilderHookError> {
        let output = Command::new(UTIL_LINUX_LOSETUP)
            .args(["--find", "--show"])
            .arg(rootfs_path)
            .output()
            .map_err(|e| BuilderHookError::MountRootfs {
                rootfs: rootfs_path.to_path_buf(),
                mount_point: MOUNT_POINT,
                source: e,
            })?;
        if !output.status.success() {
            return Err(BuilderHookError::MountRootfs {
                rootfs: rootfs_path.to_path_buf(),
                mount_point: MOUNT_POINT,
                source: std::io::Error::other(format!(
                    "losetup exited with status {}: {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
            });
        }
        let path =
            parse_loop_device(&output.stdout).map_err(|source| BuilderHookError::MountRootfs {
                rootfs: rootfs_path.to_path_buf(),
                mount_point: MOUNT_POINT,
                source,
            })?;
        Ok(Self { path })
    }
}

impl Drop for LoopDevice {
    fn drop(&mut self) {
        match Command::new(UTIL_LINUX_LOSETUP)
            .arg("--detach")
            .arg(&self.path)
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => eprintln!(
                "mvm-host-vm-init: warning: detach {} exited {status}",
                self.path.display()
            ),
            Err(error) => eprintln!(
                "mvm-host-vm-init: warning: detach {} failed: {error}",
                self.path.display()
            ),
        }
    }
}

struct MountedRootfs {
    _loop_device: LoopDevice,
    bind_mounts: Vec<String>,
}

impl MountedRootfs {
    fn mount(rootfs_path: &Path) -> Result<Self, BuilderHookError> {
        let loop_device = LoopDevice::attach(rootfs_path)?;
        mount(
            Some(loop_device.path.as_path()),
            MOUNT_POINT,
            Some("ext4"),
            MsFlags::empty(),
            None::<&str>,
        )
        .map_err(|error| BuilderHookError::MountRootfs {
            rootfs: rootfs_path.to_path_buf(),
            mount_point: MOUNT_POINT,
            source: std::io::Error::other(format!("{error}")),
        })?;
        Ok(Self {
            _loop_device: loop_device,
            bind_mounts: Vec::new(),
        })
    }

    fn bind_mount(&mut self, source: &str, target: &str) -> Result<(), std::io::Error> {
        std::fs::create_dir_all(target)?;
        mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|error| std::io::Error::other(format!("{error}")))?;
        self.bind_mounts.push(target.to_string());
        Ok(())
    }
}

impl Drop for MountedRootfs {
    fn drop(&mut self) {
        for mount_point in self.bind_mounts.iter().rev() {
            if let Err(error) = umount(mount_point.as_str()) {
                eprintln!("mvm-host-vm-init: warning: umount {mount_point} failed: {error}");
            }
        }
        if let Err(error) = umount(MOUNT_POINT) {
            eprintln!("mvm-host-vm-init: warning: umount {MOUNT_POINT} failed: {error}");
        }
    }
}

fn run_hook_in_chroot() -> Result<(), BuilderHookError> {
    let mut child = spawn_hook().map_err(|e| BuilderHookError::SpawnHook {
        hook: HOOK_PATH,
        source: e,
    })?;

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(());
                }
                return Err(BuilderHookError::HookNonZero {
                    code: status.code(),
                });
            }
            Ok(None) => {
                if start.elapsed() >= HOOK_GRACE {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(BuilderHookError::GraceExceeded { grace: HOOK_GRACE });
                }
                std::thread::sleep(HOOK_POLL_INTERVAL);
            }
            Err(e) => return Err(BuilderHookError::WaitFailed { source: e }),
        }
    }
}

fn spawn_hook() -> std::io::Result<std::process::Child> {
    let mut cmd = Command::new(HOOK_PATH);
    cmd.env("PATH", CHROOT_PATH);
    cmd.current_dir("/");

    // SAFETY: `pre_exec` runs in the forked child before `execve`.
    // It only calls async-signal-safe syscalls (`chdir`, `chroot`) and
    // modifies the child's own address space. The closure captures no
    // borrowed state from the parent.
    unsafe {
        cmd.pre_exec(|| {
            // Change into the new root before chroot so the inherited
            // working directory does not point outside the jail.
            nix::unistd::chdir(MOUNT_POINT)
                .map_err(|e| std::io::Error::other(format!("chdir {MOUNT_POINT}: {e}")))?;
            nix::unistd::chroot(MOUNT_POINT)
                .map_err(|e| std::io::Error::other(format!("chroot {MOUNT_POINT}: {e}")))?;
            nix::unistd::chdir("/").map_err(|e| std::io::Error::other(format!("chdir /: {e}")))?;
            Ok(())
        });
    }

    // `execve` resolves `HOOK_PATH` inside the chroot; the absolute path
    // string is passed through unchanged. The shebang points at a Nix
    // store path that is part of the rootfs closure.
    cmd.spawn()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_stable() {
        // These paths are part of the contract with cmd.sh callers and
        // the Nix factory. If they change, the wiring sites must update.
        assert_eq!(HOOK_PATH, "/etc/mvm/hooks/before_build.sh");
        assert_eq!(MOUNT_POINT, "/tmp/mvm-before-build-rootfs");
        assert_eq!(UTIL_LINUX_LOSETUP, "/sbin/losetup");
        assert_eq!(E2FSCK, "/sbin/e2fsck");
        assert_eq!(
            CHROOT_PATH,
            "/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin"
        );
    }

    #[test]
    fn e2fsck_clean_and_repaired_codes_are_accepted() {
        assert!(e2fsck_exit_code_is_clean(0));
        assert!(e2fsck_exit_code_is_clean(1));
        for code in [2, 4, 8, 16, 32, 128, -1] {
            assert!(!e2fsck_exit_code_is_clean(code), "code {code}");
        }
    }
}
