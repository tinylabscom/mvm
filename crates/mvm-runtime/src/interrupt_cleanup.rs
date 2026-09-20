//! Cleanups that must run if `mvmctl` is interrupted or asked to terminate.
//!
//! Work that leaves something behind which must not outlive the process — a
//! resumed guest that has not yet confirmed its reseed, decrypted snapshot
//! copies on disk — registers a cleanup with [`on_interrupt`] for as long as it
//! is in flight. The CLI's SIGINT/SIGTERM/SIGHUP handler calls [`run_all`]
//! before it exits, because that exit runs no destructors. Dropping the
//! returned [`InterruptCleanup`] withdraws the cleanup, so one runs only for
//! work the signal actually cut short.
//!
//! This replaces an earlier per-process registry of attached runtime handles
//! that nothing populated: its sweep had no live caller, so an interrupt ran
//! no cleanup at all. The resume admission and the restore staging directory
//! are the users of this module; the signal handler is its only caller of
//! [`run_all`]. A cleanup registered while `run_all` is draining stays
//! registered but does not run — the process exits right after the drain.
//!
//! Not a process supervisor: an uncatchable kill (SIGKILL, an out-of-memory
//! kill) or an abort runs nothing here. What those leave behind is found later
//! by reconcile.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// A cleanup to run if the process is interrupted, with the label it reports.
type Cleanup = (String, Box<dyn FnOnce() + Send>);

static CLEANUPS: OnceLock<Mutex<HashMap<u64, Cleanup>>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(0);

fn cleanups() -> &'static Mutex<HashMap<u64, Cleanup>> {
    CLEANUPS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A registered interrupt cleanup. Dropping it withdraws the cleanup.
#[must_use = "the cleanup is withdrawn as soon as this is dropped"]
pub struct InterruptCleanup {
    id: u64,
}

impl Drop for InterruptCleanup {
    fn drop(&mut self) {
        let mut cleanups = cleanups().lock().unwrap_or_else(|e| e.into_inner());
        cleanups.remove(&self.id);
    }
}

/// Run `cleanup` if the process is interrupted before the returned guard is
/// dropped. `label` names the work in shutdown logs.
pub fn on_interrupt(label: &str, cleanup: impl FnOnce() + Send + 'static) -> InterruptCleanup {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let mut cleanups = cleanups().lock().unwrap_or_else(|e| e.into_inner());
    cleanups.insert(id, (label.to_string(), Box::new(cleanup)));
    InterruptCleanup { id }
}

/// The labels of the cleanups currently registered.
pub fn pending() -> Vec<String> {
    let cleanups = cleanups().lock().unwrap_or_else(|e| e.into_inner());
    cleanups.values().map(|(label, _)| label.clone()).collect()
}

/// Take every registered cleanup out of the registry and run it, returning
/// their labels. Each runs at most once; the registry lock is not held while
/// they run.
pub fn run_all() -> Vec<String> {
    let taken: Vec<Cleanup> = {
        let mut cleanups = cleanups().lock().unwrap_or_else(|e| e.into_inner());
        cleanups.drain().map(|(_, cleanup)| cleanup).collect()
    };
    taken
        .into_iter()
        .map(|(label, cleanup)| {
            cleanup();
            label
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// Tests share the process-wide registry.
    static LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn an_interrupt_runs_a_registered_cleanup_once() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ran = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&ran);
        let guard = on_interrupt("resume vm-a", move || {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        assert!(pending().contains(&"resume vm-a".to_string()));
        assert!(run_all().contains(&"resume vm-a".to_string()));
        assert!(!pending().contains(&"resume vm-a".to_string()));
        assert_eq!(ran.load(Ordering::SeqCst), 1);
        drop(guard);
        let _ = run_all();
        assert_eq!(ran.load(Ordering::SeqCst), 1, "a cleanup runs at most once");
    }

    #[test]
    fn a_withdrawn_cleanup_never_runs() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let ran = Arc::new(AtomicU64::new(0));
        let counter = Arc::clone(&ran);
        drop(on_interrupt("finished work", move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }));
        assert!(!run_all().contains(&"finished work".to_string()));
        assert_eq!(ran.load(Ordering::SeqCst), 0);
    }
}
