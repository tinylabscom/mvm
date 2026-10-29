//! The outstanding durability of a launch's admission record.
//!
//! Admitting a plan is two different kinds of work. Deciding it — grants, the
//! host budget, signing, verification, nonce and validity window — is CPU work
//! that finishes in a few milliseconds, and every refusal comes out of it. Making
//! the decision durable is one round of `fdatasync` on the audit chain, which on
//! a loaded rotational disk is the slowest thing on the launch path.
//!
//! Nothing the plan authorizes may run until that sync has succeeded, but the
//! VMM and guest kernel are not something the plan authorizes: a guest booted
//! from the universal initramfs refuses every verb but `ActivateEnvironment`
//! until it is activated, and activation is what mounts the root and lets
//! workload code run. So a launch may start its VMM while the sync is still in
//! flight, provided activation waits for it. [`AdmissionDurability`] is that
//! wait.
//!
//! A launch that carries no handle has nothing outstanding: its admission was
//! made durable before it was handed a config to boot, which is how every path
//! that does not opt in still behaves.

use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

use anyhow::Result;

/// A pending (or settled) sync of an admission's audit records.
///
/// Cheap to clone; every clone observes the same outcome. [`wait`](Self::wait)
/// blocks until the sync has finished and reports whether it succeeded, and
/// may be called any number of times from any clone.
#[derive(Clone)]
pub struct AdmissionDurability {
    inner: Arc<Inner>,
}

struct Inner {
    worker: Mutex<Option<JoinHandle<Result<(), String>>>>,
    outcome: OnceLock<Result<(), String>>,
}

impl AdmissionDurability {
    /// Run `sync` on its own thread and return the handle that waits for it.
    ///
    /// Fails only if the thread cannot be spawned; the caller should then run
    /// the sync inline rather than boot on an admission that was never synced.
    pub fn spawn(sync: impl FnOnce() -> Result<()> + Send + 'static) -> std::io::Result<Self> {
        let worker = std::thread::Builder::new()
            .name("admission-sync".into())
            .spawn(move || sync().map_err(|error| format!("{error:#}")))?;
        Ok(Self {
            inner: Arc::new(Inner {
                worker: Mutex::new(Some(worker)),
                outcome: OnceLock::new(),
            }),
        })
    }

    /// A handle whose sync has already finished with `outcome`.
    pub fn settled(outcome: Result<()>) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(outcome.map_err(|error| format!("{error:#}")));
        Self {
            inner: Arc::new(Inner {
                worker: Mutex::new(None),
                outcome: cell,
            }),
        }
    }

    /// Block until the sync has finished, and fail if it did.
    ///
    /// An error here means the admission was never shown to be durable, so the
    /// caller must not let the workload run.
    pub fn wait(&self) -> Result<()> {
        if self.inner.outcome.get().is_none() {
            let mut worker = self
                .inner
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(handle) = worker.take() {
                let outcome = handle
                    .join()
                    .unwrap_or_else(|_| Err("the admission sync thread panicked".to_string()));
                let _ = self.inner.outcome.set(outcome);
            }
        }
        match self.inner.outcome.get() {
            Some(Ok(())) => Ok(()),
            Some(Err(message)) => Err(anyhow::anyhow!(
                "the admission record did not reach the audit log: {message}; refusing to \
                 run a workload whose admission cannot be shown afterwards"
            )),
            None => Err(anyhow::anyhow!(
                "the admission sync finished without reporting an outcome"
            )),
        }
    }

    /// Whether the sync has finished, without waiting for it.
    pub fn is_settled(&self) -> bool {
        self.inner.outcome.get().is_some()
            || self
                .inner
                .worker
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
                .is_some_and(JoinHandle::is_finished)
    }
}

impl std::fmt::Debug for AdmissionDurability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self.inner.outcome.get() {
            Some(Ok(())) => "durable",
            Some(Err(_)) => "failed",
            None => "pending",
        };
        f.debug_struct("AdmissionDurability")
            .field("state", &state)
            .finish()
    }
}

/// Wait for `durability` when there is one; a launch without a handle has
/// nothing outstanding.
pub fn wait_for(durability: Option<&AdmissionDurability>) -> Result<()> {
    durability.map_or(Ok(()), AdmissionDurability::wait)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn wait_returns_once_the_sync_succeeds() {
        let (release, released) = mpsc::channel::<()>();
        let durability = AdmissionDurability::spawn(move || {
            released.recv().expect("released");
            Ok(())
        })
        .expect("spawn");
        assert!(!durability.is_settled(), "the sync is still held");
        release.send(()).expect("release");
        durability.wait().expect("a successful sync is durable");
        assert!(durability.is_settled());
    }

    #[test]
    fn a_failed_sync_fails_every_waiter() {
        let durability =
            AdmissionDurability::spawn(|| Err(anyhow::anyhow!("fdatasync: disk gone")))
                .expect("spawn");
        let clone = durability.clone();
        let first = durability.wait().expect_err("a failed sync is not durable");
        let second = clone.wait().expect_err("every clone sees the failure");
        assert!(format!("{first:#}").contains("fdatasync: disk gone"));
        assert_eq!(format!("{first:#}"), format!("{second:#}"));
    }

    #[test]
    fn a_panicking_sync_is_a_failure_not_a_success() {
        let durability = AdmissionDurability::spawn(|| panic!("sync worker died")).expect("spawn");
        assert!(durability.wait().is_err());
    }

    #[test]
    fn waiters_on_several_threads_all_see_the_outcome() {
        let durability = AdmissionDurability::spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(20));
            Ok(())
        })
        .expect("spawn");
        let waiters: Vec<_> = (0..4)
            .map(|_| {
                let durability = durability.clone();
                std::thread::spawn(move || durability.wait().is_ok())
            })
            .collect();
        for waiter in waiters {
            assert!(waiter.join().expect("waiter"));
        }
    }

    #[test]
    fn no_handle_means_nothing_is_outstanding() {
        wait_for(None).expect("a launch without a handle is already durable");
        assert!(wait_for(Some(&AdmissionDurability::settled(Ok(())))).is_ok());
        assert!(
            wait_for(Some(&AdmissionDurability::settled(Err(anyhow::anyhow!(
                "no"
            )))))
            .is_err()
        );
    }
}
