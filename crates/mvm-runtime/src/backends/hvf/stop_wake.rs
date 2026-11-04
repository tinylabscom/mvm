//! The stop wake the HVF watchdog sends to the vCPUs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Force-exit the vCPUs, and keep doing so until the run reports it is over.
///
/// A force-exit is only seen by a vCPU that is inside `hv_vcpu_run`. One that
/// is between runs, servicing a device or an earlier heartbeat, can take the
/// single stop wake without it landing, and a guest idle in WFI then never
/// leaves the loop that checks the stop flag. Re-issuing the wake bounds that
/// window to one interval instead of leaving it open indefinitely.
pub(super) fn wake_until_done(done: &AtomicBool, interval: Duration, mut wake: impl FnMut()) {
    loop {
        wake();
        if done.load(Ordering::Acquire) {
            return;
        }
        std::thread::sleep(interval);
    }
}

/// Marks the run as over when dropped, so a boot that returns early still
/// releases the watchdog instead of leaving it waking vCPUs that are gone.
pub(super) struct RunOver(pub(super) Arc<AtomicBool>);

impl Drop for RunOver {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// A stop wake that lands while the vCPU is between runs is lost; the
    /// watchdog must therefore keep waking until the run has ended.
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
    fn a_run_that_is_already_over_is_woken_once() {
        let done = AtomicBool::new(true);
        let wakes = AtomicUsize::new(0);
        wake_until_done(&done, Duration::from_secs(60), || {
            wakes.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(wakes.load(Ordering::Relaxed), 1);
    }
}
