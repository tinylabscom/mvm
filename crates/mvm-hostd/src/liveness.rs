//! Host-held liveness deadlines.
//!
//! A unit whose admitted topology declares a liveness period has one deadline
//! on the host. An explicit liveness signal from the unit's current epoch, as
//! the epoch gate decides it, resets the deadline to one period from now. A
//! pass the host runs on a timer, [`LivenessDeadlines::expire`], fences every
//! unit whose deadline has passed, and [`LivenessDeadlines::expire_unit`] does
//! the same for one unit, for the host process that owns it: it commits a replacement of the watched
//! epoch to the workload ledger, the record the gate reads, so every service
//! that asks the gate refuses that epoch from then on, and writes
//! `liveness.epoch_replaced` to the tenant's chain. Expiry fences and reports;
//! it starts, promotes and selects nothing.
//!
//! The deadlines live in one file per tenant under `<mvm_home>/liveness`,
//! as absolute times, so a restarted host process keeps every deadline that
//! was running rather than starting it again: a host process that keeps
//! restarting can never postpone an expiry. A deadline is first armed by the
//! epoch's first accepted signal. The file holds a deadline only for a unit
//! the tenant's admitted topology declares a period for, at most
//! [`MAX_LIVENESS_UNITS`] of them.
//!
//! The deadline is compared with the injected wall clock, so it can be kept
//! across a restart. A forward step or a suspend expires early, which fences
//! in the safe direction. A clock found behind the last signal counts as
//! expired, so a backward step delays an expiry by less than one period.
//!
//! Every signal and every pass holds the tenant's lock from before it asks the
//! gate until its write is durable, so a signal and an expiry of the same
//! tenant never interleave and two passes never both commit. The commit is
//! conditional on the watched epoch, so it cannot happen twice even so. An
//! expiry is recorded as in progress before the commit and the deadline is
//! removed after the chain entry, so a pass interrupted in between finishes
//! the report on the next pass; the entry is written at least once.
//!
//! Refused signals are written to the tenant's chain. Accepted ones are not.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use mvm_contract::plan::topology::Topology;
use mvm_contract::plan::topology::requirements::MAX_LIVENESS_UNITS;
use mvm_contract::protocol::mailbox::ExecutionEpoch;
use mvm_core::atomic_io::{self, FileLock};
use mvm_core::host_interface::Denial;
use mvm_core::host_interface::epoch_gate::CommandGate;
use mvm_core::host_interface::workload::WorkloadChange;
use mvm_core::plan::{TenantId, WorkloadId};
use mvm_core::time::Clock;
use serde::{Deserialize, Serialize};

use crate::audit::emitter::AuditEmitter;
use crate::containment::WorkloadAuthority;

/// Chain event for a deadline that passed and fenced its epoch.
pub const LIVENESS_EPOCH_REPLACED_EVENT: &str = "liveness.epoch_replaced";
/// Chain event for a refused liveness signal.
pub const LIVENESS_SIGNAL_REFUSED_EVENT: &str = "liveness.signal_refused";

/// The largest deadline file this host reads: [`MAX_LIVENESS_UNITS`] records
/// with room for long unit names.
const MAX_FILE_BYTES: u64 = 256 * 1024;

/// A liveness signal the host refused. The returned error's root cause, so a
/// caller can `downcast_ref` it even when the refusal's audit write failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LivenessRefusal {
    #[error("no admitted topology of this tenant declares a liveness period for unit {}", .unit.0)]
    NoPeriod { unit: WorkloadId },
    #[error("unit {} may not signal: {denial}", .unit.0)]
    Epoch { unit: WorkloadId, denial: Denial },
    #[error("the liveness deadline of unit {} has passed", .unit.0)]
    DeadlinePassed { unit: WorkloadId },
}

/// Who is signalling. The unit and epoch are the ones the caller's channel
/// was admitted under.
#[derive(Debug, Clone, Copy)]
pub struct LivenessCaller<'a> {
    pub tenant: &'a TenantId,
    pub unit: &'a WorkloadId,
    pub epoch: ExecutionEpoch,
}

/// A deadline that passed and the replacement that fenced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expiry {
    pub tenant: TenantId,
    pub unit: WorkloadId,
    /// The epoch the deadline watched, refused by the gate from now on.
    pub fenced: ExecutionEpoch,
    /// The unit's current epoch in the ledger after the fence.
    pub current: ExecutionEpoch,
}

/// What a pass over one unit did, and when to look at it again.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct UnitPass {
    /// The fence this pass committed, if the unit's deadline had passed.
    pub expired: Option<Expiry>,
    /// When the next pass is due: the unit's stored deadline, or one period
    /// from now while no deadline is armed. `None` once the caller's epoch can
    /// never act again (replaced or quarantined) or the admitted topology
    /// declares no period for the unit, so there is nothing left to watch.
    pub next: Option<DateTime<Utc>>,
}

/// What one expiry pass did.
#[derive(Debug, Default)]
pub struct ExpiryPass {
    pub expired: Vec<Expiry>,
    /// Tenants the pass could not finish, each retried by the next pass.
    pub failures: Vec<(TenantId, anyhow::Error)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Watching,
    /// The deadline passed and the fence may have been committed.
    Fencing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Deadline {
    epoch: ExecutionEpoch,
    last_signal: DateTime<Utc>,
    deadline: DateTime<Utc>,
    state: State,
}

impl Deadline {
    fn has_passed(&self, now: DateTime<Utc>) -> bool {
        self.state == State::Fencing || now >= self.deadline || now < self.last_signal
    }
}

/// One tenant's deadlines, keyed by unit.
type Deadlines = BTreeMap<String, Deadline>;

/// The host's liveness deadlines.
pub struct LivenessDeadlines<'a> {
    /// Where the host signer lives; `None` for the default keys directory.
    pub host_signer_keys_dir: Option<&'a Path>,
    pub emitter: &'a AuditEmitter,
    pub clock: &'a dyn Clock,
}

impl LivenessDeadlines<'_> {
    /// Reset the caller's deadline to one period from now.
    ///
    /// # Errors
    ///
    /// A [`LivenessRefusal`] for a unit that declares no period, an epoch the
    /// gate refuses, or a deadline that has already passed; otherwise any
    /// failure to read the topology, the gate's record or the deadlines.
    pub fn signal(&self, caller: &LivenessCaller<'_>) -> Result<()> {
        let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
        let topology = crate::topology_admission::last_admitted_topology(
            &home,
            caller.tenant,
            self.host_signer_keys_dir,
        )?;
        let Some(period) = topology
            .as_ref()
            .and_then(|t| liveness_period(t, caller.unit))
        else {
            return Err(self.refuse(
                caller,
                LivenessRefusal::NoPeriod {
                    unit: caller.unit.clone(),
                },
            ));
        };
        let path = tenant_path(&home, caller.tenant);
        let _lock = lock(&path)?;
        let gate = CommandGate::load_at(&home).context("loading the epoch gate's record")?;
        if let Err(denial) = gate.admit(&caller.unit.0, caller.epoch) {
            return Err(self.refuse(
                caller,
                LivenessRefusal::Epoch {
                    unit: caller.unit.clone(),
                    denial,
                },
            ));
        }
        let now = self.clock.now();
        let mut deadlines = load(&path)?;
        // A deadline the gate still admits watches the caller's own epoch; one
        // it refuses belongs to an epoch already replaced.
        let passed = deadlines
            .get(&caller.unit.0)
            .is_some_and(|d| gate.admit(&caller.unit.0, d.epoch).is_ok() && d.has_passed(now));
        if passed {
            return Err(self.refuse(
                caller,
                LivenessRefusal::DeadlinePassed {
                    unit: caller.unit.clone(),
                },
            ));
        }
        let deadline = now
            .checked_add_signed(chrono::Duration::milliseconds(i64::from(period.get())))
            .context("the liveness deadline overflows the clock")?;
        if let Some(topology) = &topology {
            retain_declared(&mut deadlines, topology);
        }
        deadlines.insert(
            caller.unit.0.clone(),
            Deadline {
                epoch: caller.epoch,
                last_signal: now,
                deadline,
                state: State::Watching,
            },
        );
        store(&path, &deadlines)
    }

    /// Fence every unit whose deadline has passed, in every tenant.
    ///
    /// # Errors
    ///
    /// Only a liveness directory that cannot be listed; a tenant that fails
    /// is reported in [`ExpiryPass::failures`] and the pass goes on.
    pub fn expire(&self, authority: &dyn WorkloadAuthority) -> Result<ExpiryPass> {
        let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
        let dir = mvm_core::config::liveness_dir_at(&home);
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ExpiryPass::default());
            }
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        let mut pass = ExpiryPass::default();
        for entry in entries {
            let path = entry
                .with_context(|| format!("reading {}", dir.display()))?
                .path();
            if path.extension().is_none_or(|e| e != "json") {
                continue;
            }
            let Some(tenant) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let tenant = TenantId(tenant.to_string());
            if let Err(e) = self.expire_tenant(&home, &tenant, None, authority, &mut pass.expired) {
                pass.failures.push((tenant, e));
            }
        }
        Ok(pass)
    }

    /// Fence the caller's unit if its deadline has passed, under the same lock
    /// and with the same exactly-once commit as [`Self::expire`], and say when
    /// to pass again.
    ///
    /// # Errors
    ///
    /// Any failure to read the topology, the deadlines or the gate's record,
    /// to commit the fence or to audit it; the next pass retries.
    pub fn expire_unit(
        &self,
        caller: &LivenessCaller<'_>,
        authority: &dyn WorkloadAuthority,
    ) -> Result<UnitPass> {
        let home = mvm_core::config::mvm_home_strict().context("resolving the mvm home")?;
        let mut expired = Vec::new();
        let (topology, deadlines) = self.expire_tenant(
            &home,
            caller.tenant,
            Some(&caller.unit.0),
            authority,
            &mut expired,
        )?;
        let expired = expired.pop();
        let Some(period) = topology
            .as_ref()
            .and_then(|t| liveness_period(t, caller.unit))
        else {
            return Ok(UnitPass {
                expired,
                next: None,
            });
        };
        let gate = CommandGate::load_at(&home).context("loading the epoch gate's record")?;
        // A standby epoch not yet promoted may still become current; any other
        // refusal is final for the caller's epoch.
        let ended = matches!(
            gate.admit(&caller.unit.0, caller.epoch),
            Err(denial) if !matches!(denial, Denial::EpochNotPromoted { .. })
        );
        let next = if ended {
            None
        } else {
            match deadlines.get(&caller.unit.0) {
                Some(d) => Some(d.deadline),
                None => self
                    .clock
                    .now()
                    .checked_add_signed(chrono::Duration::milliseconds(i64::from(period.get()))),
            }
        };
        Ok(UnitPass { expired, next })
    }

    /// Expire `only` the named unit, or every unit, of `tenant`. Returns the
    /// topology it read and the deadlines left after the pass.
    fn expire_tenant(
        &self,
        home: &Path,
        tenant: &TenantId,
        only: Option<&str>,
        authority: &dyn WorkloadAuthority,
        expired: &mut Vec<Expiry>,
    ) -> Result<(Option<Topology>, Deadlines)> {
        let topology = crate::topology_admission::last_admitted_topology(
            home,
            tenant,
            self.host_signer_keys_dir,
        )?;
        let path = tenant_path(home, tenant);
        let _lock = lock(&path)?;
        let mut deadlines = load(&path)?;
        let before = deadlines.len();
        match &topology {
            Some(topology) => retain_declared(&mut deadlines, topology),
            None => deadlines.clear(),
        }
        if deadlines.len() != before {
            store(&path, &deadlines)?;
        }
        let now = self.clock.now();
        let gate = CommandGate::load_at(home).context("loading the epoch gate's record")?;
        let overdue: Vec<String> = deadlines
            .iter()
            .filter(|(unit, d)| only.is_none_or(|o| o == unit.as_str()) && d.has_passed(now))
            .map(|(unit, _)| unit.clone())
            .collect();
        for unit in overdue {
            let watched = deadlines[&unit].clone();
            let current = match gate.admit(&unit, watched.epoch) {
                Ok(_) => {
                    deadlines.insert(
                        unit.clone(),
                        Deadline {
                            state: State::Fencing,
                            ..watched.clone()
                        },
                    );
                    store(&path, &deadlines)?;
                    authority
                        .commit(&WorkloadChange::Replace {
                            workload: unit.clone(),
                            from_epoch: watched.epoch,
                        })
                        .with_context(|| format!("fencing unit {unit}"))?
                        .entry
                        .epoch
                }
                // Fenced by an earlier pass that stopped before its report.
                Err(Denial::StaleEpoch { .. }) if watched.state == State::Fencing => {
                    gate.current(&unit)
                }
                // Replaced by someone else; the new epoch arms its own deadline.
                Err(Denial::StaleEpoch { .. }) => {
                    deadlines.remove(&unit);
                    store(&path, &deadlines)?;
                    continue;
                }
                // Quarantined, so already refused everything: a replacement
                // would lift the quarantine. Kept until the operator acts.
                Err(_) => continue,
            };
            let expiry = Expiry {
                tenant: tenant.clone(),
                unit: WorkloadId(unit.clone()),
                fenced: watched.epoch,
                current,
            };
            self.audit_expiry(&expiry, &watched)?;
            deadlines.remove(&unit);
            store(&path, &deadlines)?;
            expired.push(expiry);
        }
        Ok((topology, deadlines))
    }

    fn audit_expiry(&self, expiry: &Expiry, watched: &Deadline) -> Result<()> {
        self.emitter.emit_topology_decision(
            &expiry.tenant,
            LIVENESS_EPOCH_REPLACED_EVENT,
            [
                ("unit".to_string(), expiry.unit.0.clone()),
                ("fenced_epoch".to_string(), expiry.fenced.get().to_string()),
                ("epoch".to_string(), expiry.current.get().to_string()),
                ("last_signal".to_string(), watched.last_signal.to_rfc3339()),
                ("deadline".to_string(), watched.deadline.to_rfc3339()),
            ],
        )
    }

    fn refuse(&self, caller: &LivenessCaller<'_>, refusal: LivenessRefusal) -> anyhow::Error {
        let audit = self.emitter.emit_topology_decision(
            caller.tenant,
            LIVENESS_SIGNAL_REFUSED_EVENT,
            [
                ("unit".to_string(), caller.unit.0.clone()),
                ("epoch".to_string(), caller.epoch.get().to_string()),
                ("reason".to_string(), refusal.to_string()),
            ],
        );
        match audit {
            Ok(()) => refusal.into(),
            Err(e) => anyhow::Error::new(refusal).context(format!(
                "the refusal could not be written to the audit chain: {e:#}"
            )),
        }
    }
}

/// The liveness period `topology` declares for `unit`, if any.
#[must_use]
pub fn liveness_period(topology: &Topology, unit: &WorkloadId) -> Option<std::num::NonZeroU32> {
    topology
        .units
        .iter()
        .find(|u| u.workload == *unit)
        .and_then(|u| u.liveness_period_ms)
}

/// Keep only deadlines of units `topology` still declares a period for, so
/// the file never holds more than the admitted topology allows.
fn retain_declared(deadlines: &mut Deadlines, topology: &Topology) {
    deadlines.retain(|unit, _| {
        topology
            .units
            .iter()
            .any(|u| u.workload.0 == *unit && u.liveness_period_ms.is_some())
    });
}

fn tenant_path(home: &Path, tenant: &TenantId) -> PathBuf {
    mvm_core::config::liveness_dir_at(home).join(format!("{}.json", tenant.0))
}

fn load(path: &Path) -> Result<Deadlines> {
    let len = match std::fs::metadata(path) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Deadlines::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    anyhow::ensure!(
        len <= MAX_FILE_BYTES,
        "{} holds {len} bytes, more than the {MAX_FILE_BYTES} a deadline file may",
        path.display()
    );
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let deadlines: Deadlines =
        serde_json::from_slice(&bytes).with_context(|| format!("decoding {}", path.display()))?;
    anyhow::ensure!(
        deadlines.len() <= MAX_LIVENESS_UNITS,
        "{} holds {} deadlines, more than the {MAX_LIVENESS_UNITS} a topology may declare",
        path.display(),
        deadlines.len()
    );
    Ok(deadlines)
}

/// The tenant's lock, beside its file in a directory created private first.
fn lock(path: &Path) -> Result<FileLock> {
    let dir = path.parent().context("a deadline file has a parent")?;
    mvm_core::config::create_private_dir(dir)
        .with_context(|| format!("creating {} privately", dir.display()))?;
    FileLock::acquire(path)
}

fn store(path: &Path, deadlines: &Deadlines) -> Result<()> {
    let bytes = serde_json::to_vec(deadlines).context("encoding the deadlines")?;
    atomic_io::atomic_write_durable(path, &bytes)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests;
