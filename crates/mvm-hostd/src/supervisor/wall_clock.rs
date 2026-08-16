//! The supervisor-side wall-clock timer.
//!
//! A wall-clock grant is a promise that a workload stops at a deadline. Until
//! this module existed the promise was carried in the signed plan and enforced
//! by nothing, which is worse than not making it: a reader of the plan believed
//! a bound that no code applied.
//!
//! Two halves, and both are required. The **kill** is what makes the bound
//! real. The **audit entry** is what makes it distinguishable — a workload that
//! silently disappears at its deadline reads exactly like one that crashed
//! there, so an unaudited kill leaves an operator unable to tell enforcement
//! from failure, which is the same position they were in with no enforcement at
//! all.
//!
//! The deadline is read from the plan's `resources.timeouts.exec_secs`, which
//! is the sole projection of `grants.wall_clock` and is checked against the
//! grant at admission. `0` means unbounded and arms nothing.
//!
//! ## Shape
//!
//! [`WallClockTimer::run`] is a blocking, deterministic function: it waits on a
//! channel that the workload's completion closes, and enforces only if that
//! wait times out. Nothing about it is time-of-day dependent, so both outcomes
//! — fired and not fired — are testable in milliseconds rather than by sleeping
//! through a real deadline. [`arm`] is the thin threaded wrapper the supervisor
//! binaries call.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::{Duration, Instant};

use mvm_core::plan::{ExecutionPlan, SignedExecutionPlan};

use crate::audit::emitter::AuditEmitter;

/// How a fired timer stops the workload.
///
/// A trait rather than a closure so the production implementation (which ends
/// the process, and therefore cannot be called in a test) and the test double
/// are the same shape, and so a caller cannot accidentally arm a timer with no
/// kill at all.
pub trait WorkloadKiller: Send + 'static {
    /// Stop the workload. Called at most once, and only after the audit entry
    /// has been written — a production killer ends the process, so anything
    /// sequenced after it would not run.
    fn kill(&self);
}

/// The killer the per-VM supervisor binaries use: record the timeout as the
/// workload's exit code, then end this process.
///
/// Ending the process *is* the kill on the backends that have a supervisor: the
/// supervisor owns the VMM in-process, so its exit tears the guest down. The
/// exit code is the conventional `timeout(1)` value, so a caller reading
/// `workload.exit` sees a deadline rather than an unexplained failure.
pub struct SupervisorExitKiller {
    vm_state_dir: std::path::PathBuf,
}

/// Exit code recorded for a workload its wall-clock bound stopped. Matches
/// `timeout(1)`, which is what a shell-level reader will expect.
pub const TIMEOUT_EXIT_CODE: i32 = 124;

impl SupervisorExitKiller {
    #[must_use]
    pub fn new(vm_state_dir: std::path::PathBuf) -> Self {
        Self { vm_state_dir }
    }
}

impl WorkloadKiller for SupervisorExitKiller {
    fn kill(&self) {
        let path = mvm_core::exit_capture::exit_file_path(&self.vm_state_dir);
        if let Err(err) = std::fs::write(&path, TIMEOUT_EXIT_CODE.to_string()) {
            tracing::warn!(error = %err, path = %path.display(), "recording the wall-clock timeout exit code failed");
        }
        std::process::exit(TIMEOUT_EXIT_CODE);
    }
}

/// A wall-clock bound and everything needed to enforce and record it.
pub struct WallClockTimer {
    bound: Duration,
    plan: Arc<ExecutionPlan>,
    emitter: Arc<AuditEmitter>,
    killer: Box<dyn WorkloadKiller>,
}

impl WallClockTimer {
    /// Build a timer for `plan`, or `None` when the plan declares no bound.
    ///
    /// Returning `None` rather than a timer with an infinite deadline keeps the
    /// unbounded case from spawning a thread that can never do anything, and
    /// makes "was this workload bounded?" a question the type answers.
    #[must_use]
    pub fn for_plan(
        plan: Arc<ExecutionPlan>,
        emitter: Arc<AuditEmitter>,
        killer: Box<dyn WorkloadKiller>,
    ) -> Option<Self> {
        let secs = plan.resources.timeouts.exec_secs;
        if secs == 0 {
            return None;
        }
        Some(Self {
            bound: Duration::from_secs(u64::from(secs)),
            plan,
            emitter,
            killer,
        })
    }

    /// The bound this timer enforces.
    #[must_use]
    pub fn bound(&self) -> Duration {
        self.bound
    }

    /// Block until the workload finishes or the bound elapses.
    ///
    /// `finished` is closed (or sent on) by the workload's completion path. A
    /// disconnect counts as finished: the sender is dropped when the supervisor
    /// tears down, and treating that as a timeout would kill a workload that
    /// already exited and audit a bound that never fired.
    pub fn run(self, finished: &Receiver<()>) {
        let started = Instant::now();
        match finished.recv_timeout(self.bound) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
            Err(RecvTimeoutError::Timeout) => self.enforce(started.elapsed()),
        }
    }

    /// Audit first, then kill. The production killer ends the process, so an
    /// entry written after it would never exist — and a kill with no entry is
    /// the failure mode this whole module exists to avoid.
    fn enforce(self, elapsed: Duration) {
        if let Err(err) = self
            .emitter
            .emit_wall_clock_expired(&self.plan, elapsed.as_secs())
        {
            tracing::warn!(error = %err, "auditing a wall-clock kill failed; killing anyway");
        }
        tracing::warn!(
            bound_secs = self.bound.as_secs(),
            "workload exceeded its wall-clock grant; stopping it"
        );
        self.killer.kill();
    }
}

/// A live timer. Dropping it, or calling [`WallClockGuard::finished`], stands
/// the timer down — so a workload that exits normally is never killed by a
/// deadline it beat.
pub struct WallClockGuard {
    _done: Sender<()>,
}

/// Spawn `timer` on its own thread and return the guard that stands it down.
///
/// The thread is deliberately not joined: on the firing path it never returns
/// (the killer ends the process), and on the normal path it observes the
/// dropped sender and exits on its own.
#[must_use]
pub fn arm(timer: WallClockTimer) -> WallClockGuard {
    let (done, finished) = channel();
    std::thread::Builder::new()
        .name("mvm-wall-clock".to_string())
        .spawn(move || timer.run(&finished))
        .expect("spawning the wall-clock timer thread");
    WallClockGuard { _done: done }
}

impl WallClockGuard {
    /// Stand the timer down explicitly. Equivalent to dropping the guard;
    /// spelled out at call sites where the drop would otherwise be invisible.
    pub fn finished(self) {}
}

/// What a per-VM supervisor binary knows about its own audit substrate.
///
/// Grouped rather than passed positionally because three of the four are
/// optional paths of the same shape, and a caller swapping two of them would
/// produce a timer that audits into the wrong place.
pub struct SupervisorTimerInputs<'a> {
    /// The admitted plan's **signed envelope**, in the untyped carrier shape
    /// the supervisor's JSON config uses. `None` on the legacy non-plan boot
    /// paths (Stage 0, the builder VM), which carry no grant and therefore no
    /// bound.
    ///
    /// Named for the envelope because that is what every producer sends: the
    /// admission path serialises `admitted.signed()`. Reading it as a bare
    /// plan parses nothing — the two shapes share no field — which is why the
    /// name carries the shape.
    pub signed_plan_json: Option<&'a serde_json::Value>,
    /// `~/.mvm/audit/` — where the chain-signed entry lands.
    pub audit_dir: Option<&'a std::path::Path>,
    /// `~/.mvm/keys/host-signer.ed25519` — the key the chain is signed under.
    pub signing_key_path: Option<&'a std::path::Path>,
    /// Per-VM state dir; the timeout exit code is recorded here.
    pub vm_state_dir: &'a std::path::Path,
}

/// Arm the wall-clock timer for a supervisor that is about to enter its VMM
/// run loop, or return `None` when the plan declares no bound.
///
/// Fail-closed on a declared bound it cannot audit. Booting anyway would leave
/// exactly the two states this feature exists to separate — a kill and a crash
/// — indistinguishable, and a supervisor that cannot open the chain will not
/// have been able to open it at kill time either. A plan with no bound is
/// unaffected, so the legacy non-plan boot paths never reach this.
pub fn arm_for_supervisor(
    inputs: SupervisorTimerInputs<'_>,
) -> anyhow::Result<Option<WallClockGuard>> {
    use anyhow::Context;

    let Some(value) = inputs.signed_plan_json else {
        return Ok(None);
    };
    let signed: SignedExecutionPlan = serde_json::from_value(value.clone())
        .context("decoding the admitted plan envelope for the wall-clock timer")?;
    let plan = signed
        .payload_plan()
        .context("decoding the plan inside the admitted envelope for the wall-clock timer")?;
    if plan.resources.timeouts.exec_secs == 0 {
        return Ok(None);
    }

    let audit_dir = inputs
        .audit_dir
        .context("a plan with a wall-clock bound needs an audit dir to record its kill")?;
    let key_path = inputs
        .signing_key_path
        .context("a plan with a wall-clock bound needs a signing key to record its kill")?;
    let keys_dir = key_path
        .parent()
        .context("the signing key path has no parent directory")?;
    let signer = crate::audit::host_keypair::load_or_init_at(keys_dir)
        .context("loading the host signer for the wall-clock audit entry")?;
    let emitter = Arc::new(
        AuditEmitter::with_dir(signer.signing, audit_dir)
            .context("opening the audit chain for the wall-clock timer")?,
    );

    let killer = Box::new(SupervisorExitKiller::new(inputs.vm_state_dir.to_path_buf()));
    let timer = WallClockTimer::for_plan(Arc::new(plan), emitter, killer)
        .expect("a nonzero exec_secs always yields a timer");
    tracing::info!(
        bound_secs = timer.bound().as_secs(),
        "arming the wall-clock timer"
    );
    Ok(Some(arm(timer)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Records kills instead of ending the process, so both outcomes are
    /// observable in one test binary.
    #[derive(Clone, Default)]
    struct CountingKiller(Arc<AtomicUsize>);

    impl WorkloadKiller for CountingKiller {
        fn kill(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn plan_with_bound(exec_secs: u32) -> Arc<ExecutionPlan> {
        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.resources.timeouts.exec_secs = exec_secs;
        Arc::new(plan)
    }

    fn emitter(dir: &std::path::Path) -> Arc<AuditEmitter> {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        Arc::new(AuditEmitter::with_dir(key, dir).expect("open the audit chain"))
    }

    /// The tenant's raw chain lines. Read as text rather than decoded: the
    /// envelope shape is the emitter's business, and a test that mirrored it
    /// would go red on an unrelated change to the wrapper.
    fn chain_lines(dir: &std::path::Path, tenant: &str) -> Vec<String> {
        let path = dir.join(format!("{tenant}.jsonl"));
        let Ok(body) = std::fs::read_to_string(path) else {
            return Vec::new();
        };
        body.lines().map(str::to_string).collect()
    }

    #[test]
    fn an_expired_workload_is_killed_and_the_kill_is_audited() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = plan_with_bound(1);
        let killer = CountingKiller::default();
        let kills = killer.0.clone();

        let mut timer =
            WallClockTimer::for_plan(plan.clone(), emitter(dir.path()), Box::new(killer))
                .expect("a bounded plan arms a timer");
        // Shorten the wait so the test costs milliseconds; the bound the entry
        // reports still comes off the plan, which is what a reader relies on.
        timer.bound = Duration::from_millis(30);

        let (_never_finishes, finished) = channel::<()>();
        timer.run(&finished);

        assert_eq!(
            kills.load(Ordering::SeqCst),
            1,
            "the workload must be killed"
        );
        let lines = chain_lines(dir.path(), &plan.tenant.0);
        assert!(
            lines
                .iter()
                .any(|l| l.contains(crate::audit::emitter::wall_clock_audit::EXPIRED_EVENT)),
            "the kill must be recorded in the chain, or it is indistinguishable \
             from a crash; saw {lines:?}"
        );
    }

    #[test]
    fn the_audited_kill_names_the_bound_and_the_mechanism() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = plan_with_bound(900);
        emitter(dir.path())
            .emit_wall_clock_expired(&plan, 901)
            .expect("emit");

        let body = std::fs::read_to_string(dir.path().join(format!("{}.jsonl", plan.tenant.0)))
            .expect("chain file");
        let entry: serde_json::Value =
            serde_json::from_str(body.lines().last().expect("one entry")).expect("json");
        let labels = entry
            .get("labels")
            .or_else(|| entry.get("audit_labels"))
            .unwrap_or(&entry)
            .to_string();
        assert!(labels.contains("900"), "the enforced bound: {labels}");
        assert!(labels.contains("901"), "the elapsed time: {labels}");
        assert!(
            labels.contains("supervisor:timer"),
            "the mechanism: {labels}"
        );
    }

    #[test]
    fn a_workload_within_its_bound_is_not_killed() {
        // Without this, a timer that fired the instant it was armed would pass
        // every other test in this file.
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = plan_with_bound(3600);
        let killer = CountingKiller::default();
        let kills = killer.0.clone();

        let timer = WallClockTimer::for_plan(plan.clone(), emitter(dir.path()), Box::new(killer))
            .expect("a bounded plan arms a timer");

        let (done, finished) = channel::<()>();
        done.send(()).expect("the workload reports completion");
        timer.run(&finished);

        assert_eq!(
            kills.load(Ordering::SeqCst),
            0,
            "a workload that finished inside its bound must not be killed"
        );
        assert!(
            chain_lines(dir.path(), &plan.tenant.0).is_empty(),
            "nothing fired, so nothing may be recorded as having fired"
        );
    }

    #[test]
    fn a_dropped_sender_is_a_finish_not_a_timeout() {
        // The supervisor drops the guard on teardown. Reading that as a
        // deadline would kill a workload that already exited.
        let dir = tempfile::tempdir().expect("tempdir");
        let killer = CountingKiller::default();
        let kills = killer.0.clone();
        let timer =
            WallClockTimer::for_plan(plan_with_bound(3600), emitter(dir.path()), Box::new(killer))
                .expect("timer");

        let (done, finished) = channel::<()>();
        drop(done);
        timer.run(&finished);

        assert_eq!(kills.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn an_unbounded_plan_arms_no_timer() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            WallClockTimer::for_plan(
                plan_with_bound(0),
                emitter(dir.path()),
                Box::new(CountingKiller::default()),
            )
            .is_none(),
            "exec_secs 0 is unbounded; there is nothing to enforce"
        );
    }

    #[test]
    fn the_bound_comes_from_the_plan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let timer = WallClockTimer::for_plan(
            plan_with_bound(42),
            emitter(dir.path()),
            Box::new(CountingKiller::default()),
        )
        .expect("timer");
        assert_eq!(timer.bound(), Duration::from_secs(42));
    }

    /// Exactly what the launch path puts on the wire: `plan_admission` writes
    /// `serde_json::to_string(admitted.signed())` onto `VmStartConfig.plan_json`,
    /// the spec map re-parses that string into the `PlanBinding`, and the
    /// libkrun/HVF relays hand it to the supervisor verbatim. A fixture that
    /// hands the timer a bare plan tests a shape no producer emits.
    fn admitted_plan_on_the_wire(exec_secs: u32) -> serde_json::Value {
        let signed = mvm_core::plan::test_support::PlanFixture::new()
            .exec_secs(exec_secs)
            .build_signed();
        serde_json::to_value(&signed).expect("the envelope serialises")
    }

    #[test]
    fn a_bounded_admitted_plan_arms_the_timer() {
        let home = tempfile::tempdir().expect("tempdir");
        let audit_dir = home.path().join("audit");
        let keys_dir = home.path().join("keys");
        std::fs::create_dir_all(&audit_dir).expect("audit dir");
        std::fs::create_dir_all(&keys_dir).expect("keys dir");
        let wire = admitted_plan_on_the_wire(900);

        let guard = arm_for_supervisor(SupervisorTimerInputs {
            signed_plan_json: Some(&wire),
            audit_dir: Some(&audit_dir),
            signing_key_path: Some(&keys_dir.join("host-signer.ed25519")),
            vm_state_dir: home.path(),
        })
        .expect("the supervisor must be able to read the plan it was admitted under");

        assert!(
            guard.is_some(),
            "a plan admitted with a 900s bound must arm a timer; None here means the \
             bound is inert"
        );
    }

    #[test]
    fn an_unbounded_admitted_plan_boots_without_a_timer() {
        // The regression this pairs with: the decode used to run before the
        // `exec_secs == 0` early return, so an unbounded plan — the common
        // case — was refused too. Asserting `Ok(None)` and not merely "no
        // error" pins both halves.
        let home = tempfile::tempdir().expect("tempdir");
        let wire = admitted_plan_on_the_wire(0);

        let guard = arm_for_supervisor(SupervisorTimerInputs {
            signed_plan_json: Some(&wire),
            audit_dir: None,
            signing_key_path: None,
            vm_state_dir: home.path(),
        })
        .expect("an unbounded workload must boot");

        assert!(
            guard.is_none(),
            "exec_secs 0 is unbounded; arming a timer for it would kill a workload \
             that was never bounded"
        );
    }

    #[test]
    fn arming_and_standing_down_kills_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let killer = CountingKiller::default();
        let kills = killer.0.clone();
        let timer =
            WallClockTimer::for_plan(plan_with_bound(3600), emitter(dir.path()), Box::new(killer))
                .expect("timer");
        arm(timer).finished();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(kills.load(Ordering::SeqCst), 0);
    }
}
