//! Host-wide launch/restore barrier shared with initial policy activation.
//!
//! A held shared guard keeps activation from publishing while a caller is
//! preparing or starting a workload; the coordinator holds the exclusive
//! guard across its quiescence check and durable publication. This is not an
//! effect fence or a replacement for a resident lifecycle owner.

use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;

#[cfg(unix)]
use anyhow::{Context, ensure};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
#[cfg(unix)]
use std::{
    collections::HashMap,
    fs,
    sync::{Mutex, OnceLock, Weak},
};

/// A held cross-process admission barrier; dropping it releases the lock.
pub struct ActivationBarrier {
    // Reentrant acquisitions in one process must share the *same* open file
    // description. Re-locking a different descriptor behind a queued writer
    // would deadlock the caller that already holds a shared lock.
    _file: Option<Arc<File>>,
}

#[cfg(unix)]
type HeldBarriers = Mutex<HashMap<PathBuf, (Weak<File>, bool)>>;
#[cfg(unix)]
static HELD: OnceLock<HeldBarriers> = OnceLock::new();

impl ActivationBarrier {
    /// Hold the host's shared barrier while resolving and starting a workload.
    ///
    /// # Errors
    ///
    /// Owner-only storage or the lock cannot be established.
    pub fn shared() -> Result<Self> {
        Self::acquire(&PathBuf::from(crate::config::mvm_home()), false)
    }

    /// Hold the host's exclusive barrier during initial activation.
    ///
    /// # Errors
    ///
    /// Owner-only storage or the lock cannot be established.
    pub fn exclusive() -> Result<Self> {
        Self::acquire(&PathBuf::from(crate::config::mvm_home()), true)
    }

    fn acquire(home: &Path, exclusive: bool) -> Result<Self> {
        #[cfg(unix)]
        {
            // Keep this mutex through the OS lock acquisition: another
            // thread must not open an independent descriptor in the gap.
            let mut held = HELD
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .expect("activation barrier map mutex poisoned");
            if let Some((file, held_exclusive)) = held
                .get(home)
                .and_then(|(file, held_exclusive)| file.upgrade().map(|f| (f, *held_exclusive)))
            {
                ensure!(
                    !exclusive && !held_exclusive,
                    "cannot reenter an exclusive activation barrier or change its mode"
                );
                return Ok(Self { _file: Some(file) });
            }
            crate::private_fs::create_owned_private_dir(home)
                .with_context(|| format!("securing MVM home {}", home.display()))?;
            let dir = crate::config::policy_generations_dir_at(home);
            crate::private_fs::create_owned_private_dir(&dir)
                .with_context(|| format!("securing {}", dir.display()))?;
            let path = dir.join("activation.lock");
            let file = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)
                .with_context(|| format!("opening activation barrier {}", path.display()))?;
            let meta = file.metadata()?;
            crate::private_fs::require_current_owner(&meta)?;
            ensure!(
                meta.is_file() && meta.nlink() == 1 && meta.mode() & 0o777 == 0o600,
                "activation barrier {} is not an owner-only regular file",
                path.display()
            );
            if exclusive {
                file.lock()
            } else {
                file.lock_shared()
            }
            .with_context(|| format!("acquiring activation barrier {}", path.display()))?;
            let file = Arc::new(file);
            held.retain(|_, (file, _)| file.strong_count() > 0);
            held.insert(home.to_path_buf(), (Arc::downgrade(&file), exclusive));
            Ok(Self { _file: Some(file) })
        }
        #[cfg(not(unix))]
        {
            if exclusive {
                anyhow::bail!(
                    "activation barrier is unavailable: {}",
                    crate::private_fs::unsupported_platform_error(home)
                );
            }
            // Initial activation cannot run on this host. Do not make the
            // pre-existing Windows launch paths depend on a Unix lock.
            Ok(Self { _file: None })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn shared_launches_can_overlap_but_exclusive_activation_waits() {
        let dir = tempfile::tempdir().unwrap();
        let first = ActivationBarrier::acquire(dir.path(), false).unwrap();
        let second = ActivationBarrier::acquire(dir.path(), false).unwrap();
        assert!(Arc::ptr_eq(
            first._file.as_ref().unwrap(),
            second._file.as_ref().unwrap()
        ));
        let across = std::thread::scope(|scope| {
            scope
                .spawn(|| ActivationBarrier::acquire(dir.path(), false).unwrap())
                .join()
                .unwrap()
        });
        assert!(Arc::ptr_eq(
            first._file.as_ref().unwrap(),
            across._file.as_ref().unwrap()
        ));
        assert!(ActivationBarrier::acquire(dir.path(), true).is_err());
        let path = dir.path().join("policy-generations/activation.lock");
        let contender = fs::File::open(&path).unwrap();
        assert!(
            contender.try_lock().is_err(),
            "activation must wait for both launch guards"
        );
        drop(first);
        assert!(
            contender.try_lock().is_err(),
            "a second launch still holds it"
        );
        drop(second);
        drop(across);
        contender.try_lock().unwrap();
        drop(contender);
        let _activation = ActivationBarrier::acquire(dir.path(), true).unwrap();
        assert!(
            ActivationBarrier::acquire(dir.path(), true).is_err(),
            "a second activation cannot reuse the first one's exclusive lock"
        );
        assert!(
            ActivationBarrier::acquire(dir.path(), false).is_err(),
            "a launch cannot reuse activation's exclusive lock"
        );
    }
}
