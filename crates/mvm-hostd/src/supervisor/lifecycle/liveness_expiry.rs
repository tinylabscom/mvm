//! The supervisor-side owner of a unit's liveness expiry.
//!
//! A unit whose admitted topology declares a liveness period has a deadline on
//! the host (`crate::liveness`). The per-VM supervisor owns the guest for its
//! whole life, so it is the process that runs the expiry check for its own
//! unit: one thread that sleeps until the stored deadline, re-reads it on
//! waking because a signal moves it, and fences the unit's epoch through the
//! policy coordinator once it has passed.
//!
//! A supervisor whose plan names no topology, or whose unit declares no
//! period, starts nothing: no thread and no file read after this check.
//!
//! The fenced guest is left running. Every gate refuses its epoch from the
//! fence on, so nothing it sends is accepted, and choosing and starting a
//! successor is failover's job, not this one's.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::time::Duration;

use anyhow::{Context, Result};
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::host_interface::workload::{WorkloadChange, WorkloadCommit, WorkloadLedger};
use mvm_core::plan::{TenantId, WorkloadId};
use mvm_core::time::{Clock, SystemClock};

use super::wall_clock::{SupervisorTimerInputs, decode_admitted_plan, supervisor_emitter};
use crate::audit::emitter::AuditEmitter;
use crate::containment::{CoordinatorWorkloads, WorkloadAuthority};
use crate::liveness::{LivenessCaller, LivenessDeadlines, liveness_period};

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
    /// Pass, then `wait` until the next one is due, until there is nothing
    /// left to watch or `wait` returns `false` (the supervisor stood it down).
    pub fn run(&self, mut wait: impl FnMut(Duration) -> bool) {
        loop {
            let pause = match self.pass() {
                Ok(Some(next)) => (next - self.clock.now())
                    .to_std()
                    .unwrap_or(Duration::ZERO)
                    .max(Duration::from_millis(1)),
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(error = %format!("{e:#}"), unit = %self.unit.0, "liveness expiry pass failed; retrying in one period");
                    self.period
                }
            };
            if !wait(pause) {
                return;
            }
        }
    }

    /// One pass over this unit. Returns when the next is due.
    pub fn pass(&self) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
        let deadlines = LivenessDeadlines {
            host_signer_keys_dir: self.host_signer_keys_dir.as_deref(),
            emitter: &self.emitter,
            clock: self.clock.as_ref(),
        };
        let pass = deadlines.expire_unit(
            &LivenessCaller {
                tenant: &self.tenant,
                unit: &self.unit,
                epoch: self.epoch,
            },
            self.authority.as_ref(),
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

/// A running watch. Dropping it stands the watch down.
pub struct LivenessGuard {
    _stop: Sender<()>,
}

/// Start the liveness expiry watch for a supervisor about to enter its VMM run
/// loop, or return `None` when its unit declares no liveness period.
///
/// # Errors
///
/// The plan or its topology cannot be read, or a unit with a period has no
/// audit chain to record its expiry in: a declared deadline nobody watches is
/// refused, as a wall-clock bound that cannot be audited is.
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
    let Some(period) = topology
        .as_ref()
        .and_then(|t| liveness_period(t, &binding.unit))
    else {
        return Ok(None);
    };
    let watch = LivenessWatch {
        tenant: plan.tenant,
        unit: binding.unit,
        epoch: ExecutionEpoch::new(plan.execution_epoch).context("the plan's execution epoch")?,
        period: Duration::from_millis(u64::from(period.get())),
        host_signer_keys_dir: keys_dir.map(Path::to_path_buf),
        emitter: supervisor_emitter(inputs)
            .context("a unit with a liveness period needs an audit chain to record its expiry")?,
        clock: Arc::new(SystemClock),
        authority: Box::new(CoordinatorOnDemand { home }),
    };
    let (stop, stopped) = channel::<()>();
    std::thread::Builder::new()
        .name("mvm-liveness".to_string())
        .spawn(move || {
            watch
                .run(|pause| matches!(stopped.recv_timeout(pause), Err(RecvTimeoutError::Timeout)));
        })
        .context("spawning the liveness expiry thread")?;
    Ok(Some(LivenessGuard { _stop: stop }))
}
