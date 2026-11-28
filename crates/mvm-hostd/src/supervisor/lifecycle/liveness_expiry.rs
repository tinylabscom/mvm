//! The supervisor-side owner of a unit's liveness expiry and cell digest.
//!
//! A unit whose admitted topology declares a liveness period has a deadline on
//! the host (`crate::liveness`). The per-VM supervisor owns the guest for its
//! whole life, so it is the process that runs the expiry check for its own
//! unit: it sleeps until the stored deadline, re-reads it on waking because a
//! signal moves it, and fences the unit's epoch through the policy coordinator
//! once it has passed.
//!
//! The same supervisor digests the cells its unit writes
//! (`crate::state_cells::digest`), once a period. Both run on one thread that
//! waits for whichever is due first, so a unit with both costs one thread and
//! one wakeup per due time, not two.
//!
//! A supervisor whose plan names no topology, or whose unit declares no period
//! and writes no cell, starts nothing: no thread and no file read after this
//! check.
//!
//! The fenced guest is left running. Every gate refuses its epoch from the
//! fence on, so nothing it sends is accepted, and choosing and starting a
//! successor is failover's job, not this one's.
//!
//! The thread also watches for the host being suspended across a wait: the
//! wall clock, which the deadline is held on, keeps running while the host
//! sleeps, and the monotonic clock does not. A deadline that passed while the
//! host slept still fences (the deadline is not extended, so a unit that hung
//! just before the suspend is not given extra time), and the expiry entry
//! records how long the host was seen suspended. A forward step of the wall
//! clock larger than [`SUSPEND_TOLERANCE`] looks the same and is recorded the
//! same; the label says what was measured, not why.

use mvm_contract::timestamp::UtcTimestamp;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::workload::{WorkloadChange, WorkloadCommit, WorkloadLedger};
use mvm_core::plan::{TenantId, WorkloadId};
use mvm_core::time::{Clock, SystemClock};

use super::wall_clock::{SupervisorTimerInputs, decode_admitted_plan, supervisor_emitter};
use crate::audit::emitter::AuditEmitter;
use crate::containment::{CoordinatorWorkloads, WorkloadAuthority};
use crate::liveness::{LivenessCaller, LivenessDeadlines, liveness_period};
use crate::state_cells::digest::{CELL_DIGEST_PERIOD, CellDigest};

/// How far the wall clock may run ahead of the monotonic clock across one wait
/// before the gap is taken for a suspend. Both clocks see the same scheduling
/// delay, so the gap is the wall clock's own movement: time-sync daemons slew
/// small offsets and step only on a large one, and two seconds stays above a
/// routine step while far below any real suspend.
pub const SUSPEND_TOLERANCE: Duration = Duration::from_secs(2);

/// Time since an arbitrary origin, from a clock that does not advance while
/// the host is suspended.
pub trait Monotonic: Send + Sync {
    fn elapsed(&self) -> Duration;
}

/// The standard library's monotonic clock: `CLOCK_MONOTONIC` on Linux and
/// `CLOCK_UPTIME_RAW` on macOS, neither of which counts a suspend.
pub struct SystemMonotonic(Instant);

impl SystemMonotonic {
    #[must_use]
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for SystemMonotonic {
    fn default() -> Self {
        Self::new()
    }
}

impl Monotonic for SystemMonotonic {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
}

/// The policy coordinator of `home`, started on the first commit only, so a
/// watcher whose unit never expires never spawns or dials it.
pub struct CoordinatorOnDemand {
    home: PathBuf,
}

impl WorkloadAuthority for CoordinatorOnDemand {
    fn ledger(&self) -> Result<WorkloadLedger> {
        Ok(WorkloadLedger::load_at(&self.home)?)
    }

    fn commit(&self, change: &WorkloadChange) -> Result<WorkloadCommit> {
        let socket = crate::policy_generation::coordinator::ensure(&self.home)?;
        CoordinatorWorkloads::new(socket).commit(change)
    }
}

/// One unit's expiry watch.
pub struct LivenessWatch {
    pub tenant: TenantId,
    pub unit: WorkloadId,
    pub epoch: ExecutionEpoch,
    /// Retry interval after a failed pass.
    pub period: Duration,
    pub host_signer_keys_dir: Option<PathBuf>,
    pub emitter: Arc<AuditEmitter>,
    pub clock: Arc<dyn Clock>,
    pub authority: Box<dyn WorkloadAuthority + Send + Sync>,
}

impl LivenessWatch {
    /// One pass over this unit. Returns when the next is due.
    pub fn pass(&self) -> Result<Option<UtcTimestamp>> {
        self.pass_noting(None)
    }

    /// One pass, recording `suspended` in an expiry it commits.
    fn pass_noting(&self, suspended: Option<Duration>) -> Result<Option<UtcTimestamp>> {
        let deadlines = LivenessDeadlines {
            host_signer_keys_dir: self.host_signer_keys_dir.as_deref(),
            emitter: &self.emitter,
            clock: self.clock.as_ref(),
        };
        let pass = deadlines.expire_unit_noting(
            &LivenessCaller {
                tenant: &self.tenant,
                unit: &self.unit,
                epoch: self.epoch,
            },
            self.authority.as_ref(),
            suspended,
        )?;
        if let Some(expiry) = &pass.expired {
            tracing::warn!(
                unit = %expiry.unit.0,
                fenced_epoch = expiry.fenced.get(),
                epoch = expiry.current.get(),
                "liveness deadline passed; the unit's epoch is fenced and the guest is left running"
            );
        }
        Ok(pass.next)
    }
}

/// A supervisor's unit timer: its liveness watch, its cell digest, or both.
pub struct UnitTimer {
    pub liveness: Option<LivenessWatch>,
    pub digest: Option<CellDigest>,
    pub monotonic: Arc<dyn Monotonic>,
}

impl UnitTimer {
    /// Run whatever is due, then `wait` until the next thing is, until there is
    /// nothing left to do or `wait` returns `false` (the supervisor stood it
    /// down). The digest runs at once on start, so a change made while no
    /// owner ran is recorded without waiting a period.
    pub fn run(&self, mut wait: impl FnMut(Duration) -> bool) {
        let mut liveness = self.liveness.as_ref();
        // When the next liveness pass is due on the wall clock; `None` is now.
        let mut liveness_at = None;
        // When the next digest is due on the monotonic clock.
        let mut digest_at = self.monotonic.elapsed();
        // Suspend seen since the last liveness pass that completed.
        let mut suspended = Duration::ZERO;
        loop {
            if let Some(digest) = &self.digest
                && self.monotonic.elapsed() >= digest_at
            {
                if let Err(e) = digest.pass() {
                    tracing::warn!(error = %format!("{e:#}"), unit = %digest.unit.0, "cell digest pass failed; retrying in one period");
                }
                digest_at = self.monotonic.elapsed() + digest.period;
            }
            if let Some(watch) = liveness
                && liveness_at.is_none_or(|at| watch.clock.now() >= at)
            {
                let noted = (!suspended.is_zero()).then_some(suspended);
                match watch.pass_noting(noted) {
                    Ok(Some(next)) => {
                        liveness_at = Some(next);
                        suspended = Duration::ZERO;
                    }
                    Ok(None) => liveness = None,
                    Err(e) => {
                        tracing::warn!(error = %format!("{e:#}"), unit = %watch.unit.0, "liveness expiry pass failed; retrying in one period");
                        let now = watch.clock.now();
                        liveness_at = Some(now.checked_add(watch.period).unwrap_or(now));
                    }
                }
            }
            let liveness_pause = liveness.map(|watch| {
                liveness_at.map_or(Duration::ZERO, |at| {
                    at.duration_since(watch.clock.now())
                        .unwrap_or(Duration::ZERO)
                })
            });
            let digest_pause = self
                .digest
                .as_ref()
                .map(|_| digest_at.saturating_sub(self.monotonic.elapsed()));
            let Some(pause) = [liveness_pause, digest_pause].into_iter().flatten().min() else {
                return;
            };
            let before = liveness.map(|watch| (watch.clock.now(), self.monotonic.elapsed()));
            if !wait(pause.max(Duration::from_millis(1))) {
                return;
            }
            if let (Some(watch), Some((wall, mono))) = (liveness, before)
                && let Some(gap) =
                    suspend_gap(wall, watch.clock.now(), mono, self.monotonic.elapsed())
            {
                tracing::warn!(unit = %watch.unit.0, gap_ms = gap.as_millis(), "the host was suspended, or its wall clock stepped forward, during a liveness wait");
                suspended = suspended.saturating_add(gap);
            }
        }
    }

    /// [`Self::run`] on a thread of its own, until there is nothing left to do
    /// or the returned sender is dropped.
    ///
    /// # Errors
    ///
    /// The thread could not be spawned.
    pub fn spawn(self) -> std::io::Result<(Sender<()>, JoinHandle<()>)> {
        let (stop, stopped) = channel::<()>();
        let thread = std::thread::Builder::new()
            .name("mvm-unit-timer".to_string())
            .spawn(move || {
                self.run(|pause| {
                    matches!(stopped.recv_timeout(pause), Err(RecvTimeoutError::Timeout))
                });
            })?;
        Ok((stop, thread))
    }
}

/// How far the wall clock ran ahead of the monotonic clock between two
/// readings, if beyond [`SUSPEND_TOLERANCE`].
fn suspend_gap(
    wall_before: UtcTimestamp,
    wall_after: UtcTimestamp,
    mono_before: Duration,
    mono_after: Duration,
) -> Option<Duration> {
    // A wall clock that went backwards ran ahead of nothing.
    let wall = wall_after.duration_since(wall_before)?;
    let gap = wall.saturating_sub(mono_after.saturating_sub(mono_before));
    (gap > SUSPEND_TOLERANCE).then_some(gap)
}

/// A running timer. Dropping it stands the timer down.
pub struct LivenessGuard {
    _stop: Sender<()>,
}

/// Start the unit timer for a supervisor about to enter its VMM run loop, or
/// return `None` when its unit declares no liveness period and writes no cell.
///
/// # Errors
///
/// The plan or its topology cannot be read, or a unit with a period or a
/// written cell has no audit chain to record its expiry or digest in: a
/// declared deadline nobody watches is refused, as a wall-clock bound that
/// cannot be audited is.
pub fn arm_for_supervisor(inputs: &SupervisorTimerInputs<'_>) -> Result<Option<LivenessGuard>> {
    let Some(value) = inputs.plan_json else {
        return Ok(None);
    };
    let plan = decode_admitted_plan(value).context("decoding the admitted plan")?;
    let Some(binding) = plan.topology else {
        return Ok(None);
    };
    let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
    let keys_dir = inputs.signing_key_path.and_then(Path::parent);
    let topology =
        crate::topology_admission::last_admitted_topology(&home, &plan.tenant, keys_dir)?;
    let Some(topology) = topology else {
        return Ok(None);
    };
    let period = liveness_period(&topology, &binding.unit);
    let writes_cells = topology.cells.iter().any(|c| c.writer == binding.unit);
    if period.is_none() && !writes_cells {
        return Ok(None);
    }
    let emitter = supervisor_emitter(inputs).context(
        "a unit with a liveness period or a written cell needs an audit chain to record its \
         expiry or digest",
    )?;
    let keys_dir = keys_dir.map(Path::to_path_buf);
    let liveness = match period {
        Some(period) => Some(LivenessWatch {
            tenant: plan.tenant.clone(),
            unit: binding.unit.clone(),
            epoch: ExecutionEpoch::new(plan.execution_epoch)
                .context("the plan's execution epoch")?,
            period: Duration::from_millis(u64::from(period.get())),
            host_signer_keys_dir: keys_dir.clone(),
            emitter: emitter.clone(),
            clock: Arc::new(SystemClock),
            authority: Box::new(CoordinatorOnDemand { home }),
        }),
        None => None,
    };
    let digest = writes_cells.then(|| CellDigest {
        tenant: plan.tenant,
        unit: binding.unit,
        host_signer_keys_dir: keys_dir,
        emitter,
        period: CELL_DIGEST_PERIOD,
    });
    let timer = UnitTimer {
        liveness,
        digest,
        monotonic: Arc::new(SystemMonotonic::new()),
    };
    let (stop, _thread) = timer.spawn().context("spawning the unit timer thread")?;
    Ok(Some(LivenessGuard { _stop: stop }))
}
