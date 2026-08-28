//! A source of one thread's consumed CPU time (user + system).

#[cfg(any(test, feature = "test-support"))]
use std::sync::Arc;
#[cfg(any(test, feature = "test-support"))]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// A source of one thread's consumed CPU time (user + system).
pub trait ThreadCpuClock: Send + 'static {
    /// Total CPU consumed by the thread this clock was opened on.
    fn consumed(&self) -> Duration;
}

/// A handle to another thread's CPU accounting, captured on that thread.
#[derive(Debug)]
pub struct ThreadCpuHandle {
    #[cfg(target_os = "macos")]
    port: libc::mach_port_t,
    #[cfg(not(target_os = "macos"))]
    _private: (),
}

impl ThreadCpuHandle {
    /// Capture the calling thread. Must be called *on* the thread to be
    /// measured; the returned handle is `Send` so a controller thread can
    /// read it.
    #[cfg(target_os = "macos")]
    pub fn for_current_thread() -> anyhow::Result<Self> {
        // libc's Mach bindings are deprecated in favor of the `mach2` crate,
        // but this project deliberately avoids adding that dependency. The
        // deprecation is confined to this small macOS-only block.
        #[allow(deprecated)]
        let port = unsafe { libc::mach_thread_self() };
        Ok(Self { port })
    }

    #[cfg(not(target_os = "macos"))]
    pub fn for_current_thread() -> anyhow::Result<Self> {
        Err(anyhow::anyhow!(
            "per-thread CPU accounting is only implemented on macOS"
        ))
    }
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// Deallocate a Mach port right. libc exposes the rest of the Mach surface
    /// but omits this one function, so declare it directly rather than adding
    /// a dependency on `mach2`.
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}

#[cfg(target_os = "macos")]
impl ThreadCpuClock for ThreadCpuHandle {
    fn consumed(&self) -> Duration {
        let mut info: libc::thread_basic_info = unsafe { std::mem::zeroed() };
        let mut count = libc::THREAD_BASIC_INFO_COUNT;
        // SAFETY: `info` is a valid out-param of the correct size for
        // THREAD_BASIC_INFO; `self.port` is a live send right returned by
        // mach_thread_self and owned by this handle.
        let rc = unsafe {
            libc::thread_info(
                self.port,
                libc::THREAD_BASIC_INFO as libc::thread_flavor_t,
                &mut info as *mut _ as libc::thread_info_t,
                &mut count,
            )
        };
        if rc != libc::KERN_SUCCESS {
            return Duration::ZERO;
        }
        duration_from_time_value(info.user_time)
            .saturating_add(duration_from_time_value(info.system_time))
    }
}

#[cfg(target_os = "macos")]
fn duration_from_time_value(tv: libc::time_value_t) -> Duration {
    let secs = u64::try_from(tv.seconds).unwrap_or(0);
    let micros = u64::try_from(tv.microseconds).unwrap_or(0);
    Duration::from_secs(secs) + Duration::from_micros(micros)
}

#[cfg(not(target_os = "macos"))]
impl ThreadCpuClock for ThreadCpuHandle {
    fn consumed(&self) -> Duration {
        Duration::ZERO
    }
}

#[cfg(target_os = "macos")]
impl Drop for ThreadCpuHandle {
    fn drop(&mut self) {
        // SAFETY: `self.port` is a send right returned by mach_thread_self;
        // deallocating it is required to avoid leaking the port.
        #[allow(deprecated)]
        unsafe {
            let _ = mach_port_deallocate(libc::mach_task_self(), self.port);
        }
    }
}

/// The CPU consumed by a whole machine: the sum of its vCPU threads.
///
/// A quota bounds the machine, so an SMP guest has to be charged for every vCPU
/// it is running. Reading one thread of a four-CPU guest reports a quarter of
/// what it is actually consuming, and a controller fed that number never
/// throttles — the workload runs at four times its granted share while the
/// audit record says it stayed inside it.
pub struct SummedClock<C: ThreadCpuClock> {
    threads: Vec<C>,
}

impl<C: ThreadCpuClock> SummedClock<C> {
    /// Sum `threads`. Each must have been captured on the thread it measures.
    pub fn new(threads: Vec<C>) -> Self {
        Self { threads }
    }
}

impl<C: ThreadCpuClock> ThreadCpuClock for SummedClock<C> {
    fn consumed(&self) -> Duration {
        // Saturating: a machine cannot consume more CPU than `Duration` holds,
        // but the alternative is an overflow panic on the controller thread,
        // which would leave the vCPUs held and the VM wedged.
        self.threads
            .iter()
            .map(ThreadCpuClock::consumed)
            .fold(Duration::ZERO, |total, one| total.saturating_add(one))
    }
}

/// A fake clock that always returns the same value.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone)]
pub struct FixedClock(Duration);

#[cfg(any(test, feature = "test-support"))]
impl FixedClock {
    pub fn new(value: Duration) -> Self {
        Self(value)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ThreadCpuClock for FixedClock {
    fn consumed(&self) -> Duration {
        self.0
    }
}

/// A fake clock that returns a caller-supplied sequence of readings and
/// exposes how many times it was read.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone)]
pub struct ScriptedClock {
    readings: Vec<Duration>,
    index: Arc<AtomicUsize>,
}

#[cfg(any(test, feature = "test-support"))]
impl ScriptedClock {
    pub fn new(readings: Vec<Duration>) -> Self {
        Self {
            readings,
            index: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn read_count(&self) -> usize {
        self.index.load(Ordering::SeqCst)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl ThreadCpuClock for ScriptedClock {
    fn consumed(&self) -> Duration {
        let i = self.index.fetch_add(1, Ordering::SeqCst);
        self.readings.get(i).copied().unwrap_or(Duration::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scripted_clock_counts_its_reads() {
        let clock = ScriptedClock::new(vec![
            Duration::from_millis(1),
            Duration::from_millis(2),
            Duration::from_millis(3),
        ]);
        assert_eq!(clock.consumed(), Duration::from_millis(1));
        assert_eq!(clock.consumed(), Duration::from_millis(2));
        assert_eq!(clock.read_count(), 2);
        assert_eq!(clock.consumed(), Duration::from_millis(3));
        assert_eq!(clock.read_count(), 3);
        assert_eq!(clock.consumed(), Duration::ZERO);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_captured_thread_reports_monotonically_increasing_cpu_time() {
        let clock = ThreadCpuHandle::for_current_thread().unwrap();
        let before = clock.consumed();
        let wall_before = std::time::Instant::now();

        // Burn CPU for a measurable window.
        let mut x = 0u64;
        while wall_before.elapsed() < Duration::from_millis(50) {
            x = x.wrapping_add(1);
            std::hint::black_box(x);
        }

        let after = clock.consumed();
        let wall = wall_before.elapsed();
        assert!(
            after > before,
            "CPU time must increase while the thread is busy"
        );
        let delta = after - before;
        assert!(
            delta <= wall * 10,
            "CPU delta {delta:?} should be within an order of magnitude of wall time {wall:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_thread_that_slept_is_charged_almost_nothing() {
        let clock = ThreadCpuHandle::for_current_thread().unwrap();
        let before = clock.consumed();
        std::thread::sleep(Duration::from_millis(50));
        let delta = clock.consumed() - before;
        assert!(
            delta < Duration::from_millis(5),
            "a sleeping thread should be charged almost no CPU, got {delta:?}"
        );
    }

    /// A machine's consumption is every vCPU's, added up.
    ///
    /// The number that matters for a quota: four CPUs each burning a full core
    /// for a second is four core-seconds of machine, and a controller told
    /// otherwise lets the workload run past its granted share.
    #[test]
    fn a_summed_clock_charges_every_vcpu_of_the_machine() {
        let clock = SummedClock::new(vec![
            FixedClock::new(Duration::from_millis(250)),
            FixedClock::new(Duration::from_millis(250)),
            FixedClock::new(Duration::from_millis(500)),
        ]);
        assert_eq!(clock.consumed(), Duration::from_millis(1000));
    }

    /// A one-vCPU machine reads exactly as it did before summing existed.
    #[test]
    fn a_summed_clock_over_one_thread_is_that_thread() {
        let clock = SummedClock::new(vec![FixedClock::new(Duration::from_millis(37))]);
        assert_eq!(clock.consumed(), Duration::from_millis(37));
    }

    /// Summing cannot panic the controller thread.
    ///
    /// An overflow here would leave the throttle flag set and every vCPU parked
    /// behind a controller that is no longer running — a wedged VM rather than
    /// a mis-measured one.
    #[test]
    fn a_summed_clock_saturates_rather_than_overflowing() {
        let clock = SummedClock::new(vec![
            FixedClock::new(Duration::MAX),
            FixedClock::new(Duration::MAX),
        ]);
        assert_eq!(clock.consumed(), Duration::MAX);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn capturing_a_thread_off_macos_fails_loudly_rather_than_reading_zero() {
        let err = ThreadCpuHandle::for_current_thread().unwrap_err();
        assert!(err.to_string().contains("macOS"), "{err}");
    }
}
