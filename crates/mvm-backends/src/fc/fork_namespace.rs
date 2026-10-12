//! Per-child mount-namespace remapping for Firecracker `vm_full` fork restore.
//!
//! Firecracker snapshots encode absolute host paths for block devices and the
//! vsock UDS. A forked child must make those recorded parent paths resolve to
//! its own copies. The remapping is done in a private mount namespace so the
//! parent VM's live mounts are untouched.

use std::path::PathBuf;

use anyhow::Result;

#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::path::Path;

/// The mount namespace a fork's remap entered, and the way back out of it.
///
/// [`remap_paths_for_fork`] unshares the calling thread's mount namespace and
/// bind-mounts the child's copies over the parent's recorded paths. The
/// Firecracker started while this is held inherits those mounts and keeps them
/// for its whole life; the calling thread must not. A process that forks more
/// than one child — a pool refill does it once per standby — would otherwise
/// unshare each new namespace from the previous one, so every later child
/// would start out with every earlier child's mounts stacked over the parent's
/// paths. A later parent then boots on an earlier child's rootfs, and once
/// that child's state is removed its rootfs is an unlinked file the next remap
/// cannot mount over (`ENOENT`).
///
/// [`restore`](Self::restore) returns the thread to the namespace and working
/// directory it had before the remap. Dropping the value restores too, on a
/// best-effort basis, so an early return cannot leave the thread inside.
#[must_use = "the thread stays in the fork's namespace until this is restored"]
pub struct ForkMountNamespace {
    #[cfg(target_os = "linux")]
    saved: Option<SavedNamespace>,
}

impl ForkMountNamespace {
    /// Return the calling thread to the namespace it was in before the remap.
    ///
    /// Call this on the thread that called [`remap_paths_for_fork`], once the
    /// child's Firecracker has been started: the process it spawned keeps the
    /// remapped view, and nothing else should see it.
    pub fn restore(mut self) -> Result<()> {
        self.restore_inner()
    }

    #[cfg(target_os = "linux")]
    fn restore_inner(&mut self) -> Result<()> {
        match self.saved.take() {
            Some(saved) => saved.restore(),
            None => Ok(()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn restore_inner(&mut self) -> Result<()> {
        Ok(())
    }
}

impl Drop for ForkMountNamespace {
    fn drop(&mut self) {
        if let Err(error) = self.restore_inner() {
            tracing::warn!(
                error = %format!("{error:#}"),
                "could not leave a Firecracker fork's mount namespace; this thread \
                 still sees the child's remapped device paths"
            );
        }
    }
}

/// What the calling thread looked like before it entered a fork's namespace.
#[cfg(target_os = "linux")]
struct SavedNamespace {
    mount_ns: std::fs::File,
    cwd: Option<PathBuf>,
}

#[cfg(target_os = "linux")]
impl SavedNamespace {
    fn capture() -> Result<Self> {
        // The namespace is per thread once unshared, so the handle has to name
        // this thread's, not the process leader's.
        let mount_ns = std::fs::File::open("/proc/thread-self/ns/mnt")
            .context("opening this thread's mount namespace")?;
        Ok(Self {
            mount_ns,
            // A deleted working directory has no path to return to; setns then
            // leaves the thread at the namespace root, which is all it can do.
            cwd: std::env::current_dir().ok(),
        })
    }

    fn restore(self) -> Result<()> {
        nix::sched::setns(&self.mount_ns, nix::sched::CloneFlags::CLONE_NEWNS)
            .context("rejoining the original mount namespace")?;
        // Joining a mount namespace moves the thread's working directory to
        // that namespace's root.
        if let Some(cwd) = self.cwd {
            std::env::set_current_dir(&cwd)
                .with_context(|| format!("returning to working directory {}", cwd.display()))?;
        }
        Ok(())
    }
}

/// Make every `parent_path` from the snapshot resolve to the corresponding
/// `child_path` inside a new private mount namespace.
///
/// The calling thread enters the namespace and stays in it until the returned
/// [`ForkMountNamespace`] is restored or dropped; start the child's
/// Firecracker in between, so it inherits the mounts and nothing after it
/// does. The caller must have privileges to create a mount namespace and
/// perform bind mounts (CAP_SYS_ADMIN, or root on most distributions).
#[cfg(target_os = "linux")]
pub fn remap_paths_for_fork(mappings: &[(PathBuf, PathBuf)]) -> Result<ForkMountNamespace> {
    if mappings.is_empty() {
        return Ok(ForkMountNamespace { saved: None });
    }

    let saved = SavedNamespace::capture()?;
    enter_private_mount_namespace()
        .context("entering private mount namespace for fork remapping")?;
    // From here on an error drops the guard, which returns the thread to the
    // namespace it came from.
    let namespace = ForkMountNamespace { saved: Some(saved) };

    for (parent_path, child_path) in mappings {
        ensure_parent_target(parent_path, child_path)
            .with_context(|| format!("preparing remap target {}", parent_path.display()))?;
        nix::mount::mount(
            Some(child_path.as_path()),
            parent_path.as_path(),
            Option::<&str>::None,
            nix::mount::MsFlags::MS_BIND,
            Option::<&str>::None,
        )
        .with_context(|| {
            format!(
                "bind mounting {} -> {}",
                child_path.display(),
                parent_path.display()
            )
        })?;
    }

    Ok(namespace)
}

/// Non-Linux stub: Firecracker fork restore only runs on Linux hosts, but the
/// orchestration code compiles everywhere. Calling this on a non-Linux host is
/// a runtime error because the snapshot paths cannot be remapped without
/// Linux-specific mount namespace support.
#[cfg(not(target_os = "linux"))]
pub fn remap_paths_for_fork(_mappings: &[(PathBuf, PathBuf)]) -> Result<ForkMountNamespace> {
    anyhow::bail!("Firecracker vm_full fork remapping requires Linux")
}

#[cfg(target_os = "linux")]
fn enter_private_mount_namespace() -> Result<()> {
    // Unshare the mount namespace so subsequent bind mounts are isolated.
    nix::sched::unshare(nix::sched::CloneFlags::CLONE_NEWNS)
        .context("unsharing mount namespace")?;

    // Make all mounts private recursively so nothing we do propagates back to
    // the host namespace.
    nix::mount::mount(
        Some("none"),
        Path::new("/"),
        Option::<&str>::None,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        Option::<&str>::None,
    )
    .context("marking root mount as private")?;

    Ok(())
}

/// Create the parent-side path that the snapshot references, so bind-mounting
/// over it succeeds. Directories are mkdir-p'd; files are touched.
#[cfg(target_os = "linux")]
fn ensure_parent_target(parent_path: &Path, child_path: &Path) -> Result<()> {
    if let Some(parent) = parent_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir {}", parent.display()))?;
    }

    if parent_path.exists() {
        return Ok(());
    }

    if child_path.is_dir() {
        std::fs::create_dir_all(parent_path)
            .with_context(|| format!("creating directory placeholder {}", parent_path.display()))?;
    } else {
        std::fs::File::create(parent_path)
            .with_context(|| format!("creating file placeholder {}", parent_path.display()))?;
    }

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn mount_namespace() -> PathBuf {
        std::fs::read_link("/proc/thread-self/ns/mnt").unwrap()
    }

    fn running_as_root() -> bool {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    /// A pool refill forks child after child from one process. Each child's
    /// remap must start from the host's mounts: a child whose state dir was
    /// removed must not leave the next child's remap mounting over its
    /// unlinked rootfs.
    #[test]
    fn sequential_forks_do_not_inherit_a_removed_childs_remap() {
        if !running_as_root() {
            eprintln!("skipping: bind mounts in a private namespace need root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("cache/rootfs.ext4");
        std::fs::create_dir_all(parent.parent().unwrap()).unwrap();
        std::fs::write(&parent, b"image").unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for child in [&first, &second] {
            std::fs::create_dir_all(child).unwrap();
        }
        std::fs::write(first.join("rootfs.ext4"), b"first").unwrap();
        std::fs::write(second.join("rootfs.ext4"), b"second").unwrap();

        let (parent_t, first_t, second_t) = (parent.clone(), first.clone(), second.clone());
        std::thread::spawn(move || {
            let host_ns = mount_namespace();
            let first_ns =
                remap_paths_for_fork(&[(parent_t.clone(), first_t.join("rootfs.ext4"))]).unwrap();
            assert_eq!(std::fs::read(&parent_t).unwrap(), b"first");
            first_ns.restore().unwrap();
            assert_eq!(
                mount_namespace(),
                host_ns,
                "restore rejoins the host namespace"
            );
            assert_eq!(
                std::fs::read(&parent_t).unwrap(),
                b"image",
                "after the fork the thread sees the parent's own file again"
            );

            std::fs::remove_dir_all(&first_t).unwrap();
            let second_ns =
                remap_paths_for_fork(&[(parent_t.clone(), second_t.join("rootfs.ext4"))])
                    .expect("the second fork's remap must not see the first fork's mount");
            assert_eq!(std::fs::read(&parent_t).unwrap(), b"second");
            drop(second_ns);
            assert_eq!(
                mount_namespace(),
                host_ns,
                "dropping the guard restores too"
            );
            assert_eq!(std::fs::read(&parent_t).unwrap(), b"image");
        })
        .join()
        .unwrap();
    }

    #[test]
    fn a_remap_that_fails_leaves_the_thread_in_its_own_namespace() {
        if !running_as_root() {
            eprintln!("skipping: bind mounts in a private namespace need root");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("rootfs.ext4");
        std::fs::write(&parent, b"image").unwrap();
        let missing = dir.path().join("gone/rootfs.ext4");
        std::thread::spawn(move || {
            let host_ns = mount_namespace();
            assert!(remap_paths_for_fork(&[(parent, missing)]).is_err());
            assert_eq!(mount_namespace(), host_ns);
        })
        .join()
        .unwrap();
    }
}
