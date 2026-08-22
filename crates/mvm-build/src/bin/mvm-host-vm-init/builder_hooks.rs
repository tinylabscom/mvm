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
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::mount::{MsFlags, mount, umount};

/// Canonical path to the before_build hook inside a workload rootfs.
const HOOK_PATH: &str = "/etc/mvm/hooks/before_build.sh";

/// Where the rootfs image is mounted while the hook runs. Lives on the
/// builder VM's tmpfs (`/tmp`) so the mount point itself is writable and
/// does not depend on any host share.
const MOUNT_POINT: &str = "/tmp/mvm-before-build-rootfs";

/// Absolute path populated by the builder image from util-linux.
///
/// `/bin/mount` is the BusyBox applet. It does not allocate a loop device for
/// `-o loop`; it forwards `loop` to ext4 as a filesystem option instead.
const UTIL_LINUX_MOUNT: &str = "/sbin/mount";

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

    mount_rootfs(rootfs_path)?;

    // Ensure the chroot has the target directories for bind mounts.
    // mkGuest rootfses already include them, but creating them is
    // idempotent and makes the runner tolerant of unusual images.
    for subdir in ["proc", "sys", "dev"] {
        let _ = std::fs::create_dir_all(format!("{MOUNT_POINT}/{subdir}"));
    }

    let mut bind_mounts = Vec::new();
    for (src, dst) in [("/proc", "proc"), ("/sys", "sys"), ("/dev", "dev")] {
        let dst_path = format!("{MOUNT_POINT}/{dst}");
        bind_mount(src, &dst_path).map_err(|e| BuilderHookError::BindMount {
            src: src.to_string(),
            dst: dst_path.clone(),
            source: e,
        })?;
        bind_mounts.push(dst_path);
    }

    let hook_in_chroot = format!("{MOUNT_POINT}{HOOK_PATH}");
    let hook_present = std::fs::metadata(&hook_in_chroot)
        .map(|m| m.is_file())
        .unwrap_or(false);

    if !hook_present {
        eprintln!("mvm-host-vm-init: no before_build hook at {HOOK_PATH}; treating as no-op");
        cleanup_mounts(&bind_mounts);
        return Ok(());
    }

    eprintln!(
        "mvm-host-vm-init: running before_build hook in {rootfs_path}",
        rootfs_path = rootfs_path.display()
    );
    let result = run_hook_in_chroot();

    cleanup_mounts(&bind_mounts);
    result
}

fn mount_rootfs(rootfs_path: &Path) -> Result<(), BuilderHookError> {
    // util-linux mount -o loop allocates a loop device for the
    // file-backed ext4 image. The nix mount(2) syscall wrapper
    // lacks LOOP_SET_FD, so shell out.
    let status = std::process::Command::new(UTIL_LINUX_MOUNT)
        .arg("-o")
        .arg("loop")
        .arg(rootfs_path)
        .arg(MOUNT_POINT)
        .status()
        .map_err(|e| BuilderHookError::MountRootfs {
            rootfs: rootfs_path.to_path_buf(),
            mount_point: MOUNT_POINT,
            source: e,
        })?;
    if !status.success() {
        return Err(BuilderHookError::MountRootfs {
            rootfs: rootfs_path.to_path_buf(),
            mount_point: MOUNT_POINT,
            source: std::io::Error::other(format!("mount exited with status {status}")),
        });
    }
    Ok(())
}

fn bind_mount(source: &str, target: &str) -> Result<(), std::io::Error> {
    std::fs::create_dir_all(target)?;
    mount(
        Some(source),
        target,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| std::io::Error::other(format!("{e}")))
}

fn cleanup_mounts(bind_mounts: &[String]) {
    for m in bind_mounts.iter().rev() {
        if let Err(e) = umount(m.as_str()) {
            eprintln!("mvm-host-vm-init: warning: umount {m} failed: {e}");
        }
    }
    if let Err(e) = umount(MOUNT_POINT) {
        eprintln!("mvm-host-vm-init: warning: umount {MOUNT_POINT} failed: {e}");
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
        assert_eq!(UTIL_LINUX_MOUNT, "/sbin/mount");
        assert_eq!(
            CHROOT_PATH,
            "/usr/local/sbin:/usr/local/bin:/sbin:/usr/sbin:/bin:/usr/bin"
        );
    }
}
