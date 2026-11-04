//! The stop wake the HVF watchdog sends to the vCPUs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Force-exit the vCPUs, and keep doing so until the run reports it is over.
///
/// An observed SMP shutdown left a secondary in Hypervisor.framework's WFI
/// wait after the first request. A force-exit request is not completion:
/// keep requesting it until the run owner has joined every vCPU thread.
pub(super) fn wake_until_done(done: &AtomicBool, interval: Duration, mut wake: impl FnMut()) {
    while !done.load(Ordering::Acquire) {
        wake();
        if done.load(Ordering::Acquire) {
            return;
        }
        std::thread::park_timeout(interval);
    }
}

/// Marks the run as over when dropped, so a boot that returns early still
/// releases the watchdog instead of leaving it waking vCPUs that are gone.
pub(super) struct RunOver {
    done: Arc<AtomicBool>,
    watchdog: std::thread::Thread,
}

impl RunOver {
    pub(super) fn new(done: Arc<AtomicBool>, watchdog: std::thread::Thread) -> Self {
        Self { done, watchdog }
    }

    pub(super) fn complete(&self) {
        self.done.store(true, Ordering::Release);
        self.watchdog.unpark();
    }
}

impl Drop for RunOver {
    fn drop(&mut self) {
        self.complete();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Completion, not a successful wake request, ends cancellation delivery.
    #[test]
    fn the_stop_wake_is_repeated_until_the_run_is_over() {
        let done = AtomicBool::new(false);
        let wakes = AtomicUsize::new(0);
        wake_until_done(&done, Duration::from_millis(1), || {
            if wakes.fetch_add(1, Ordering::Relaxed) == 3 {
                done.store(true, Ordering::Release);
            }
        });
        assert_eq!(wakes.load(Ordering::Relaxed), 4);
    }

    #[test]
    fn a_completed_run_is_not_woken() {
        let done = AtomicBool::new(true);
        let wakes = AtomicUsize::new(0);
        wake_until_done(&done, Duration::from_secs(60), || {
            wakes.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(wakes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn completion_guard_wakes_the_parked_watchdog() {
        let done = Arc::new(AtomicBool::new(false));
        let observed_done = done.clone();
        let gate = Arc::new(std::sync::Barrier::new(2));
        let waiting = gate.clone();
        let (finished, observed) = std::sync::mpsc::sync_channel(1);
        let watchdog = std::thread::spawn(move || {
            waiting.wait();
            std::thread::park();
            finished
                .send(observed_done.load(Ordering::Acquire))
                .unwrap();
        });
        let guard = RunOver::new(done.clone(), watchdog.thread().clone());
        drop(guard);
        gate.wait();
        let completed = observed.recv_timeout(Duration::from_secs(5));
        // Ensure the fixture exits even if the guard's notification regresses.
        done.store(true, Ordering::Release);
        watchdog.thread().unpark();
        watchdog.join().unwrap();
        assert_eq!(completed, Ok(true));
    }
}
