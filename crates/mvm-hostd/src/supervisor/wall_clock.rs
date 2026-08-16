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

use mvm_core::plan::ExecutionPlan;

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
    /// The admitted `ExecutionPlan`, as the supervisor received it. `None` on
    /// the legacy non-plan boot paths (Stage 0, the builder VM), which carry no
    /// grant and therefore no bound.
    pub plan_json: Option<&'a serde_json::Value>,
    /// `~/.mvm/audit/` — where the chain-signed entry lands.
    pub audit_dir: Option<&'a std::path::Path>,
    /// `~/.mvm/keys/host-signer.ed25519` — the key the chain is signed under.
    pub signing_key_path: Option<&'a std::path::Path>,
    /// Per-VM state dir; the timeout exit code is recorded here.
    pub vm_state_dir: &'a std::path::Path,
}

/// Decode what the launch path actually put on `plan_json`.
///
/// It is the **signed** plan: `vm/exec.rs`, `session.rs` and `invoke.rs` all
/// build it from `admitted.signed()`, and `SignedExecutionPlan` is a newtype
/// over `SignedPayload`, so the plan's own fields sit inside `payload` rather
/// than at the top level. Decoding the envelope directly as an `ExecutionPlan`
/// can never succeed, and since the caller refuses to boot a bound it cannot
/// read, that failure took every admitted workload down with it.
///
/// The bare form is still accepted. Not every producer goes through the
/// admission path — the checkpoint restore path and the attach path build this
/// value themselves — and a decoder that understands only one shape would just
/// move the failure rather than remove it. Anything that is neither still
/// errors, so an unreadable bound keeps failing closed.
fn decode_admitted_plan(value: &serde_json::Value) -> anyhow::Result<ExecutionPlan> {
    use anyhow::anyhow;

    let signed_err =
        match serde_json::from_value::<mvm_core::plan::SignedExecutionPlan>(value.clone()) {
            Ok(signed) => match serde_json::from_slice::<ExecutionPlan>(&signed.0.payload) {
                Ok(plan) => return Ok(plan),
                Err(e) => anyhow!("signed envelope carried an undecodable payload: {e}"),
            },
            Err(e) => anyhow!("not a signed plan: {e}"),
        };

    match serde_json::from_value::<ExecutionPlan>(value.clone()) {
        Ok(plan) => Ok(plan),
        // Both causes, because "not a signed plan" alone sends a reader looking
        // at the wrong half of the problem.
        Err(bare_err) => Err(anyhow!("{signed_err}; and not a bare plan: {bare_err}")),
    }
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

    let Some(value) = inputs.plan_json else {
        return Ok(None);
    };
    let plan = decode_admitted_plan(value)
        .context("decoding the admitted plan for the wall-clock timer")?;
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

    /// The launch path sends a **signed** plan: `vm/exec.rs` builds
    /// `plan_json` from `admitted.signed()`, and `session.rs` / `invoke.rs` do
    /// the same. `arm_for_supervisor` has to accept exactly that.
    ///
    /// It did not, and because the caller fails closed on an un-decodable
    /// bound, every admitted workload refused to boot on libkrun and HVF with
    /// "refusing to boot a bounded workload it cannot audit".
    #[test]
    fn a_signed_plan_from_the_launch_path_arms_the_timer() {
        let dir = tempfile::tempdir().unwrap();
        let audit_dir = dir.path().join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        let keys_dir = dir.path().join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        let mut plan = mvm_core::plan::test_support::PlanFixture::new().build();
        plan.resources.timeouts.exec_secs = 5;
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = mvm_core::plan::sign_plan(&plan, &key, "host-signer");
        // Byte-for-byte what the launch path puts on the wire.
        let wire: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();

        let guard = arm_for_supervisor(SupervisorTimerInputs {
            plan_json: Some(&wire),
            audit_dir: Some(audit_dir.as_path()),
            signing_key_path: Some(keys_dir.join("host-signer.ed25519").as_path()),
            vm_state_dir: dir.path(),
        })
        .expect("a signed plan carrying a bound must arm, not refuse the boot");

        assert!(
            guard.is_some(),
            "a nonzero exec_secs must produce an armed timer"
        );
    }

    /// A signed plan with no bound is not an error — it simply arms nothing.
    #[test]
    fn a_signed_plan_without_a_bound_arms_no_timer() {
        let dir = tempfile::tempdir().unwrap();
        let plan = mvm_core::plan::test_support::PlanFixture::new().build();
        assert_eq!(plan.resources.timeouts.exec_secs, 0);
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let signed = mvm_core::plan::sign_plan(&plan, &key, "host-signer");
        let wire = serde_json::to_value(&signed).unwrap();

        let guard = arm_for_supervisor(SupervisorTimerInputs {
            plan_json: Some(&wire),
            audit_dir: None,
            signing_key_path: None,
            vm_state_dir: dir.path(),
        })
        .expect("an unbounded signed plan is not an error");
        assert!(guard.is_none());
    }

    /// Garbage must still fail closed: the caller turns an error here into a
    /// refusal to boot, which is the right posture for a bound that could not
    /// be read.
    #[test]
    fn an_undecodable_plan_still_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let wire = serde_json::json!({"not": "a plan"});
        assert!(
            arm_for_supervisor(SupervisorTimerInputs {
                plan_json: Some(&wire),
                audit_dir: None,
                signing_key_path: None,
                vm_state_dir: dir.path(),
            })
            .is_err(),
            "an unreadable bound must refuse, not silently run unbounded"
        );
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
