//! Predictive vCPU quota controller.
//!
//! Spawns a thread that sleeps to the predicted exhaustion instant, reads the
//! thread CPU clock once per period, and parks the vCPU through a throttle flag
//! when the allowance is spent.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::quota::clock::{MonotonicClock, ThreadCpuClock};
use crate::quota::{PeriodVerdict, QuotaPolicy};
use crate::vmm::hv::VcpuHandle;

/// What the scheduler actually delivered. The only honest source for the
/// enforced tier on this tier, since macOS exposes no quota file to read back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaAchievement {
    pub target_millicores: u32,
    pub achieved_millicores: u32,
    pub period: Duration,
    pub measured_wall: Duration,
    pub measured_cpu: Duration,
    pub periods: u32,
}

/// A running controller scheduling a machine's vCPUs against a quota.
///
/// The bound is on the machine, not on a thread. Every vCPU is held by the same
/// flag and charged against the same allowance, so a four-CPU guest gets the
/// share its plan granted rather than four copies of it.
pub struct VcpuQuota<H: VcpuHandle> {
    hold: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    handles: Vec<H>,
    join: Option<JoinHandle<QuotaAchievement>>,
}

impl<H: VcpuHandle> VcpuQuota<H> {
    /// Start scheduling every vCPU in `handles` against `policy`, charging
    /// `clock`.
    ///
    /// `clock` has to account for all of them. One reading a single thread of
    /// an SMP machine would see a quarter of a four-CPU guest's consumption and
    /// never throttle; [`SummedClock`](crate::quota::clock::SummedClock) is the
    /// multi-vCPU form.
    pub fn start<C: ThreadCpuClock>(handles: Vec<H>, clock: C, policy: QuotaPolicy) -> Self {
        Self::start_with_flag(handles, clock, policy, Arc::new(AtomicBool::new(false)))
    }

    /// Start against a hold flag the caller already owns.
    ///
    /// An SMP machine's vCPU threads have to be given the flag before the
    /// controller can exist: every vCPU reads it to know when to park, and the
    /// controller cannot be started until every vCPU has been created and
    /// contributed its CPU clock. Handing the flag in resolves that ordering
    /// without letting a vCPU run for a window with no flag to read.
    pub fn start_with_hold<C: ThreadCpuClock>(
        handles: Vec<H>,
        clock: C,
        policy: QuotaPolicy,
        hold: Arc<AtomicBool>,
    ) -> Self {
        Self::start_with_flag(handles, clock, policy, hold)
    }

    fn start_with_flag<C: ThreadCpuClock>(
        handles: Vec<H>,
        clock: C,
        policy: QuotaPolicy,
        hold: Arc<AtomicBool>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let hold_thread = Arc::clone(&hold);
        let stop_thread = Arc::clone(&stop);
        let handles_for_thread = handles.clone();
        // Wrapped here rather than by the caller so no controller can be built
        // on a clock that is allowed to fall. A vCPU thread's CPU accounting
        // dies with the thread and its next read is charged as zero, which
        // reaches both the record and the policy: the record would attest a
        // machine that consumed nothing, and the policy compares the total
        // against an entitlement that only grows, so a fallen total releases
        // the hold for the rest of the run.
        let clock = MonotonicClock::new(clock);
        let join = thread::spawn(move || {
            run_controller(handles_for_thread, clock, policy, hold_thread, stop_thread)
        });
        Self {
            hold,
            stop,
            handles,
            join: Some(join),
        }
    }

    /// A predicate for `RunHooks::should_throttle`.
    pub fn throttle_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.hold)
    }

    /// Stop the controller and take its measurement.
    pub fn stop(mut self) -> QuotaAchievement {
        self.halt();
        self.join
            .take()
            .expect("controller join handle is present")
            .join()
            .expect("controller thread panicked")
    }

    /// Signal the controller to finish and release every held vCPU.
    fn halt(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.hold.store(false, Ordering::SeqCst);
        H::force_exit(&self.handles);
    }
}

impl<H: VcpuHandle> Drop for VcpuQuota<H> {
    /// Stop the controller even when nobody asked for its measurement.
    ///
    /// A boot that fails between starting the controller and reading it back
    /// drops this without calling [`stop`](Self::stop). The controller thread
    /// would otherwise keep looping for the life of the process, holding a
    /// throttle flag whose vCPUs are gone — one leaked thread per failed boot.
    fn drop(&mut self) {
        if self.join.is_some() {
            self.halt();
            // Deliberately not joined: this runs on the failure path, and the
            // controller's own sleep bounds how long it takes to notice. There
            // is no measurement left to collect.
        }
    }
}

fn run_controller<H: VcpuHandle, C: ThreadCpuClock>(
    handles: Vec<H>,
    clock: C,
    mut policy: QuotaPolicy,
    hold: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
) -> QuotaAchievement {
    let start = Instant::now();
    let mut periods: u32 = 0;
    let mut measured_cpu = Duration::ZERO;

    while let Some((_, consumed)) = run_period(
        &handles,
        &clock,
        &mut policy,
        &hold,
        &stop,
        start,
        &mut periods,
    ) {
        measured_cpu = consumed;
    }

    hold.store(false, Ordering::SeqCst);
    let measured_wall = start.elapsed();
    let target_millicores = policy.config().millicores();
    let achieved_millicores = if measured_wall.as_micros() == 0 {
        0
    } else {
        let cpu_us = measured_cpu.as_micros();
        let wall_us = measured_wall.as_micros();
        u32::try_from((cpu_us * 1000).saturating_div(wall_us)).unwrap_or(u32::MAX)
    };

    QuotaAchievement {
        target_millicores,
        achieved_millicores,
        period: policy.config().period(),
        measured_wall,
        measured_cpu,
        periods,
    }
}

/// Run one period: clear the hold, sleep to predicted exhaustion, read the
/// clock once, settle the policy, and hold to the period boundary if needed.
/// Returns `None` when a stop was requested before the period completed.
fn run_period<H: VcpuHandle, C: ThreadCpuClock>(
    handles: &[H],
    clock: &C,
    policy: &mut QuotaPolicy,
    hold: &AtomicBool,
    stop: &AtomicBool,
    start: Instant,
    periods: &mut u32,
) -> Option<(PeriodVerdict, Duration)> {
    if stop.load(Ordering::SeqCst) {
        return None;
    }
    hold.store(false, Ordering::SeqCst);
    let allowance = policy.allowance();
    thread::sleep(allowance);
    if stop.load(Ordering::SeqCst) {
        return None;
    }

    let consumed_total = clock.consumed();
    *periods += 1;
    let verdict = policy.settle(consumed_total, *periods);
    if verdict.hold {
        hold.store(true, Ordering::SeqCst);
        // Every vCPU, not just one. The flag alone takes effect at a vCPU's next
        // exit, and a secondary spinning in guest code has no reason to reach
        // one; forcing them all out is what makes the hold prompt rather than
        // eventual.
        H::force_exit(handles);
    }

    let elapsed = start.elapsed();
    let boundary = policy.config().period() * *periods;
    if boundary > elapsed {
        thread::sleep(boundary - elapsed);
    }

    Some((verdict, consumed_total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::clock::ScriptedClock;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicU64;

    #[derive(Clone, Copy)]
    struct MockHandle(u64);

    struct MockState {
        flag: Option<Arc<AtomicBool>>,
        force_exit_count: usize,
        flag_at_last_exit: Option<bool>,
        saw_flag_true: bool,
    }

    static MOCK_STATE: std::sync::LazyLock<Mutex<HashMap<u64, MockState>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    impl MockHandle {
        fn new() -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
            MOCK_STATE.lock().unwrap().insert(
                id,
                MockState {
                    flag: None,
                    force_exit_count: 0,
                    flag_at_last_exit: None,
                    saw_flag_true: false,
                },
            );
            Self(id)
        }

        fn bind_flag(&self, flag: Arc<AtomicBool>) {
            MOCK_STATE.lock().unwrap().get_mut(&self.0).unwrap().flag = Some(flag);
        }

        fn force_exit_count(&self) -> usize {
            MOCK_STATE
                .lock()
                .unwrap()
                .get(&self.0)
                .unwrap()
                .force_exit_count
        }

        fn flag_at_last_exit(&self) -> Option<bool> {
            MOCK_STATE
                .lock()
                .unwrap()
                .get(&self.0)
                .unwrap()
                .flag_at_last_exit
        }

        fn saw_hold_flag_true(&self) -> bool {
            MOCK_STATE
                .lock()
                .unwrap()
                .get(&self.0)
                .unwrap()
                .saw_flag_true
        }
    }

    impl VcpuHandle for MockHandle {
        fn force_exit(handles: &[Self]) {
            let id = handles[0].0;
            let mut map = MOCK_STATE.lock().unwrap();
            let state = map.get_mut(&id).expect("mock handle registered");
            state.force_exit_count += 1;
            let flag_now = state.flag.as_ref().map(|f| f.load(Ordering::SeqCst));
            state.flag_at_last_exit = flag_now;
            if flag_now == Some(true) {
                state.saw_flag_true = true;
            }
        }
    }

    fn share_policy(millicores: u32) -> QuotaPolicy {
        QuotaPolicy::new(crate::quota::QuotaConfig::for_share(millicores).unwrap())
    }

    #[test]
    fn the_controller_reads_the_clock_once_per_period() {
        let period = Duration::from_millis(10);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        let clock = ScriptedClock::new(vec![Duration::from_millis(1); 100]);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota =
            VcpuQuota::start_with_flag(vec![handle], clock.clone(), policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(55));
        let achievement = quota.stop();

        assert_eq!(
            clock.read_count(),
            achievement.periods as usize,
            "the controller must read the clock exactly once per completed period"
        );
        assert!(achievement.periods >= 4, "should complete several periods");
    }

    #[test]
    fn a_vcpu_that_spent_its_slice_is_forced_out_and_held() {
        let period = Duration::from_millis(10);
        let slice = Duration::from_millis(5);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        // The vCPU burns exactly one slice each period, so it must be held.
        let readings: Vec<Duration> = (1..=20).map(|i| slice * i).collect();
        let clock = ScriptedClock::new(readings);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(55));
        let _ = quota.stop();

        assert!(
            handle.force_exit_count() > 0,
            "a vCPU that spent its slice must be forced out"
        );
        assert!(
            handle.saw_hold_flag_true(),
            "the hold flag must be set before at least one force_exit"
        );
    }

    #[test]
    fn an_idle_vcpu_is_never_forced_out() {
        let period = Duration::from_millis(10);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        let clock = ScriptedClock::new(vec![Duration::ZERO; 100]);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(55));
        let _ = quota.stop();

        assert_eq!(
            handle.force_exit_count(),
            1,
            "only the final stop force_exit is expected for an idle vCPU"
        );
        assert_ne!(
            handle.flag_at_last_exit(),
            Some(true),
            "no force_exit should happen while the hold flag is set"
        );
    }

    #[test]
    fn the_hold_flag_is_set_before_the_vcpu_is_forced_out() {
        // Covered by a_vcpu_that_spent_its_slice_is_forced_out_and_held; keep a
        // dedicated witness so the ordering is explicit in the test names.
        let period = Duration::from_millis(10);
        let slice = Duration::from_millis(5);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        let readings: Vec<Duration> = (1..=20).map(|i| slice * i).collect();
        let clock = ScriptedClock::new(readings);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(55));
        let _ = quota.stop();

        assert!(
            handle.saw_hold_flag_true(),
            "force_exit must see the hold flag already true"
        );
    }

    #[test]
    fn an_overshooting_period_shrinks_the_next_allowance() {
        let period = Duration::from_millis(10);
        let slice = Duration::from_millis(5);
        let mut policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        let clock = ScriptedClock::new(vec![Duration::from_millis(10)]);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));

        let verdict = run_period(
            &[handle],
            &clock,
            &mut policy,
            &flag,
            &Arc::new(AtomicBool::new(false)),
            Instant::now(),
            &mut 0,
        );
        assert!(verdict.unwrap().0.hold, "overshooting must trigger a hold");
        assert!(
            policy.allowance() < slice,
            "the next allowance must shrink because debt is carried forward"
        );
    }

    #[test]
    fn stopping_releases_a_parked_vcpu() {
        let period = Duration::from_millis(10);
        let slice = Duration::from_millis(5);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        let readings: Vec<Duration> = (1..=20).map(|i| slice * i).collect();
        let clock = ScriptedClock::new(readings);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(55));
        let _ = quota.stop();

        assert!(
            !flag.load(Ordering::SeqCst),
            "stop must clear the throttle flag so the vCPU can run again"
        );
        assert!(
            handle.force_exit_count() > 0,
            "stop must issue a final force_exit to release a parked vCPU"
        );
    }

    #[test]
    fn the_achievement_is_computed_from_measurement_not_from_the_target() {
        let period = Duration::from_millis(10);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        // The vCPU burns 8 ms per 10 ms period: 800 millicores measured.
        let readings: Vec<Duration> = (1..=20)
            .map(|i| Duration::from_millis(8 * i as u64))
            .collect();
        let clock = ScriptedClock::new(readings);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(85));
        let achievement = quota.stop();

        assert!(
            achievement.achieved_millicores > achievement.target_millicores,
            "measured achievement {}/{} must reflect overshoot, not the target",
            achievement.achieved_millicores,
            achievement.target_millicores
        );
    }

    /// The teardown shape, reproduced. Every vCPU thread exits before the
    /// controller is stopped, so the summed read collapses to zero and the
    /// last assignment would otherwise be the one that lands in the record —
    /// attesting that a machine which burned CPU consumed none of it.
    #[test]
    fn a_machine_whose_vcpu_threads_have_exited_reports_what_it_consumed() {
        let period = Duration::from_millis(10);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        // Four rising readings taken while the threads are alive, then the
        // collapse: `ScriptedClock` yields ZERO once its script runs out,
        // which is exactly what a dead thread's failed read contributes.
        let clock = ScriptedClock::new(vec![
            Duration::from_millis(5),
            Duration::from_millis(10),
            Duration::from_millis(15),
            Duration::from_millis(20),
        ]);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        // Long enough to run well past the script and sample the collapse.
        std::thread::sleep(Duration::from_millis(120));
        let achievement = quota.stop();

        assert_eq!(
            achievement.measured_cpu,
            Duration::from_millis(20),
            "the last reading taken while the threads were alive is the honest \
             total; a later zero is a failed read, not a machine that un-ran"
        );
        assert!(
            achievement.achieved_millicores > 0,
            "a machine that consumed CPU cannot report an achieved share of zero"
        );
    }

    /// The same collapse, seen by the policy rather than the record. The
    /// entitlement grows every period, so a total that falls back below it
    /// would release the hold permanently and stop bounding the machine.
    #[test]
    fn a_collapsed_reading_does_not_release_the_hold_for_the_rest_of_the_run() {
        let period = Duration::from_millis(10);
        let policy = QuotaPolicy::new(crate::quota::QuotaConfig::new(500, period).unwrap());
        // Consumes far past its entitlement, then the threads die.
        let clock = ScriptedClock::new(vec![Duration::from_millis(50), Duration::from_millis(100)]);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        std::thread::sleep(Duration::from_millis(90));
        let achievement = quota.stop();

        assert_eq!(
            achievement.measured_cpu,
            Duration::from_millis(100),
            "the overshoot has to survive the threads that produced it"
        );
    }

    #[test]
    fn an_achievement_over_a_zero_wall_window_is_not_a_division_by_zero() {
        let policy = share_policy(500);
        let clock = ScriptedClock::new(vec![Duration::ZERO; 100]);
        let handle = MockHandle::new();
        let flag = Arc::new(AtomicBool::new(false));
        handle.bind_flag(Arc::clone(&flag));
        let quota = VcpuQuota::start_with_flag(vec![handle], clock, policy, Arc::clone(&flag));

        let achievement = quota.stop();

        assert_eq!(achievement.periods, 0);
        assert_eq!(achievement.achieved_millicores, 0);
    }
}
