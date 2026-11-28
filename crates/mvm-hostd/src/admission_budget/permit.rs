//! Durable capacity holds. Unknown execution keeps its capacity reserved.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use mvm_contract::grants::budget::{HostBudget, MachineCharge};
use mvm_core::atomic_io;
use mvm_core::plan::ExecutionPlan;
use serde::{Deserialize, Serialize};

use super::charge_for;

const MAX_LEDGER_BYTES: usize = 4 * 1024 * 1024;
const MAX_RESERVATIONS: usize = 8192;

#[cfg(unix)]
#[path = "platforms/unix.rs"]
mod platform;
#[cfg(not(unix))]
#[path = "platforms/unsupported.rs"]
mod platform;

pub(crate) use platform::{acquire_lock, read_private};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    version: u32,
    reservations: BTreeMap<String, Reservation>,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            version: 1,
            reservations: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reservation {
    vm_name: String,
    charge: MachineCharge,
    owner: String,
    ownership: Ownership,
    plan: Option<String>,
    phase: Phase,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Prepared,
    Dispatching,
    NoDispatch,
    Running { process: String },
    OrdinaryStopped,
    Terminal { result_digest: String },
}

impl Phase {
    fn is_charged(&self) -> bool {
        !matches!(self, Self::OrdinaryStopped | Self::Terminal { .. })
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Ownership {
    Ordinary,
    Coordinator { request_digest: String },
}

/// A host-held reservation, never a guest-provided readiness assertion.
///
/// The ledger lock protects only accounting transitions, not VM boot.
/// Dropping an ordinary undispatched permit attempts to release it; coordinated
/// or possibly dispatched reservations require explicit reconciliation.
#[derive(Debug)]
pub struct HostBudgetPermit {
    home: PathBuf,
    id: String,
    drop_policy: DropPolicy,
    mode: PermitMode,
}

#[derive(Debug)]
enum PermitMode {
    Tracked,
    UnboundedOrdinary { charge: MachineCharge },
}

#[derive(Debug)]
enum DropPolicy {
    ReleasePrepared,
    Retain,
}

/// Accounting outcome after original-owner cleanup, separate from native stop.
#[derive(Debug, PartialEq, Eq)]
pub enum HostBudgetRelease {
    Released,
    CoordinatorRetained,
}

impl HostBudgetPermit {
    /// Ordinary launches need no pending journal when no host ceiling is set.
    pub(crate) fn reserve_ordinary(vm_name: &str, charge: MachineCharge) -> Result<Self> {
        let home = PathBuf::from(mvm_core::config::mvm_home());
        let budget = budget_at(&home)?;
        if budget.is_configured() {
            return Self::reserve_at(&home, &budget, vm_name, charge);
        }
        Ok(Self {
            home,
            id: uuid::Uuid::new_v4().to_string(),
            drop_policy: DropPolicy::Retain,
            mode: PermitMode::UnboundedOrdinary { charge },
        })
    }

    /// Reserve the host's configured capacity before deriving an actor plan.
    pub fn reserve(vm_name: &str, charge: MachineCharge) -> Result<Self> {
        let home = PathBuf::from(mvm_core::config::mvm_home());
        Self::reserve_at(&home, &budget_at(&home)?, vm_name, charge)
    }

    fn reserve_at(
        home: &Path,
        budget: &HostBudget,
        vm_name: &str,
        charge: MachineCharge,
    ) -> Result<Self> {
        validate_name(vm_name)?;
        let owner = platform::current_owner()?;
        let permit = Self {
            home: home.to_owned(),
            id: uuid::Uuid::new_v4().to_string(),
            drop_policy: DropPolicy::ReleasePrepared,
            mode: PermitMode::Tracked,
        };
        permit.update(|ledger| {
            let retired: Vec<_> = ledger
                .reservations
                .iter()
                .filter_map(|(id, record)| {
                    let dead = match (&record.ownership, &record.phase) {
                        (Ownership::Ordinary, Phase::OrdinaryStopped) => true,
                        (Ownership::Ordinary, Phase::Prepared) => {
                            platform::owner_is_confirmed_dead(&record.owner)
                        }
                        (Ownership::Ordinary, Phase::Running { process }) => {
                            platform::owner_is_confirmed_dead(process)
                        }
                        _ => false,
                    };
                    dead.then(|| id.clone())
                })
                .collect();
            for id in retired {
                let record = &ledger.reservations[&id];
                if matches!(record.phase, Phase::Running { .. }) {
                    remove_legacy_charge(home, record)?;
                }
                ledger.reservations.remove(&id);
            }
            ensure!(
                ledger.reservations.len() < MAX_RESERVATIONS,
                "host reservation ledger is full"
            );
            let mut total = legacy_committed(home, ledger)?;
            for record in ledger
                .reservations
                .values()
                .filter(|r| r.phase.is_charged())
            {
                total = total.plus(record.charge);
            }
            super::admits(budget, total, charge)?;
            ledger.reservations.insert(
                permit.id.clone(),
                Reservation {
                    vm_name: vm_name.to_owned(),
                    charge,
                    owner,
                    ownership: Ownership::Ordinary,
                    plan: None,
                    phase: Phase::Prepared,
                },
            );
            Ok(())
        })?;
        Ok(permit)
    }

    /// Opaque identity to bind into the host coordinator's durable decision.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Reopen a coordinator hold for observation or terminal reconciliation.
    /// This does not authorize a second dispatch.
    pub fn reopen(id: &str, request_digest: &str) -> Result<Self> {
        ensure!(
            uuid::Uuid::parse_str(id).is_ok(),
            "invalid host reservation identifier"
        );
        validate_digest(request_digest)?;
        let permit = Self {
            home: PathBuf::from(mvm_core::config::mvm_home()),
            id: id.to_owned(),
            drop_policy: DropPolicy::Retain,
            mode: PermitMode::Tracked,
        };
        permit.mutate(|record| {
            ensure!(
                record.ownership
                    == Ownership::Coordinator {
                        request_digest: request_digest.to_owned()
                    },
                "host reservation coordinator binding differs"
            );
            Ok(())
        })?;
        Ok(permit)
    }

    /// Retain this hold across coordinator failure, before reserving actor scope.
    pub fn bind_coordinator(&self, request_digest: &str) -> Result<()> {
        ensure!(
            matches!(self.mode, PermitMode::Tracked),
            "coordinators require a tracked host hold"
        );
        validate_digest(request_digest)?;
        self.mutate(|record| {
            ensure!(
                record.phase == Phase::Prepared,
                "host reservation is not prepared"
            );
            if let Ownership::Coordinator {
                request_digest: previous,
            } = &record.ownership
            {
                ensure!(
                    previous == request_digest,
                    "host reservation coordinator binding differs"
                );
            }
            record.ownership = Ownership::Coordinator {
                request_digest: request_digest.to_owned(),
            };
            Ok(())
        })
    }

    /// Bind the exact admitted plan without charging capacity a second time.
    pub fn bind_plan(&self, plan: &ExecutionPlan) -> Result<()> {
        if matches!(self.mode, PermitMode::UnboundedOrdinary { .. }) {
            return self.verify_plan_resources(plan);
        }
        self.mutate(|record| {
            ensure!(
                record.phase == Phase::Prepared,
                "host reservation is not prepared"
            );
            let charge = charge_for(
                plan.resources.mem_mib,
                plan.grants.as_ref().unwrap_or(&Default::default()),
            );
            ensure!(
                record.charge == charge,
                "host reservation does not match admitted machine resources"
            );
            ensure!(
                record.plan.as_deref().is_none_or(|id| id == plan.plan_id.0),
                "host reservation is bound to another plan"
            );
            record.plan = Some(plan.plan_id.0.clone());
            Ok(())
        })
    }

    /// Check the real prepared hold before the host signs the proposed plan.
    pub fn verify_plan_resources(&self, plan: &ExecutionPlan) -> Result<()> {
        if let PermitMode::UnboundedOrdinary { charge } = self.mode {
            ensure!(
                charge
                    == charge_for(
                        plan.resources.mem_mib,
                        plan.grants.as_ref().unwrap_or(&Default::default())
                    ),
                "ordinary host charge differs from plan"
            );
            return Ok(());
        }
        self.mutate(|record| {
            ensure!(
                record.phase == Phase::Prepared,
                "host reservation is not prepared"
            );
            let charge = charge_for(
                plan.resources.mem_mib,
                plan.grants.as_ref().unwrap_or(&Default::default()),
            );
            ensure!(
                record.charge == charge,
                "host reservation does not match proposed plan resources"
            );
            Ok(())
        })
    }

    /// Spend the bound permit before any backend start may execute.
    pub fn mark_dispatching(&self, plan: &ExecutionPlan) -> Result<()> {
        self.mark_dispatching_for(plan, &plan.workload.0)
    }

    /// Freeze the physical instance name at the original dispatch boundary.
    pub fn mark_dispatching_for(&self, plan: &ExecutionPlan, vm_name: &str) -> Result<()> {
        validate_name(vm_name)?;
        if matches!(self.mode, PermitMode::UnboundedOrdinary { .. }) {
            ensure!(
                !budget_at(&self.home)?.is_configured(),
                "host ceiling changed; re-admit with a tracked reservation"
            );
            return self.verify_plan_resources(plan);
        }
        self.update(|ledger| {
            let budget = budget_at(&self.home)?;
            let mut total = legacy_committed(&self.home, ledger)?;
            for record in ledger
                .reservations
                .values()
                .filter(|record| record.phase.is_charged())
            {
                total = total.plus(record.charge);
            }
            super::admits(&budget, total, MachineCharge::default())?;
            ensure!(
                !ledger.reservations.iter().any(|(id, record)| id != &self.id
                    && record.vm_name == vm_name
                    && matches!(record.phase, Phase::Dispatching | Phase::Running { .. })),
                "another host reservation may already execute this machine"
            );
            let record = ledger
                .reservations
                .get_mut(&self.id)
                .context("host reservation is absent")?;
            ensure!(
                record.phase == Phase::Prepared && record.plan.as_deref() == Some(&plan.plan_id.0),
                "host reservation cannot authorize this dispatch"
            );
            if matches!(record.ownership, Ownership::Coordinator { .. }) {
                ensure!(
                    record.vm_name == vm_name,
                    "coordinated host reservation names another machine"
                );
            }
            record.vm_name = vm_name.to_owned();
            record.phase = Phase::Dispatching;
            Ok(())
        })
    }

    /// Persist the legacy charge while retaining the authoritative hold.
    pub fn record_started(&self, vm_name: &str) -> Result<()> {
        validate_name(vm_name)?;
        if let PermitMode::UnboundedOrdinary { charge } = self.mode {
            return super::record_charge_at(&self.home, vm_name, charge);
        }
        self.mutate(|record| {
            ensure!(
                record.phase == Phase::Dispatching,
                "host reservation does not match the started machine"
            );
            if matches!(record.ownership, Ownership::Coordinator { .. }) {
                ensure!(
                    record.vm_name == vm_name,
                    "coordinated host reservation names another machine"
                );
            }
            record.vm_name = vm_name.to_owned();
            super::record_charge_at(&self.home, vm_name, record.charge)?;
            if let Some(process) =
                platform::machine_identity(&mvm_core::config::vm_state_dir_at(&self.home, vm_name))?
            {
                record.phase = Phase::Running { process };
            }
            Ok(())
        })
    }

    /// Release a known pre-effect failure; never releases a dispatched hold.
    pub fn release_pre_dispatch(self) -> Result<()> {
        if matches!(self.mode, PermitMode::UnboundedOrdinary { .. }) {
            return Ok(());
        }
        self.update(|ledger| {
            let record = ledger
                .reservations
                .get(&self.id)
                .context("host reservation is absent")?;
            ensure!(
                record.phase == Phase::Prepared,
                "possibly executed host reservation cannot be released"
            );
            ledger.reservations.remove(&self.id);
            Ok(())
        })
    }

    /// Reconcile a stopped ordinary launch through its original native owner.
    ///
    /// The host caller must have successfully stopped its original runtime,
    /// released its resources, and verified there are no managed lease keys.
    /// Never substitute a name/PID lookup for the original-owner callback.
    /// Coordinated actors remain charged for their terminal-result owner.
    #[doc(hidden)]
    pub fn reconcile_ordinary_stopped(
        &self,
        stop_and_release: impl FnOnce() -> Result<()>,
    ) -> Result<HostBudgetRelease> {
        // Accounting failure must never prevent original-owner native cleanup.
        stop_and_release()?;
        if matches!(self.mode, PermitMode::UnboundedOrdinary { .. }) {
            return Ok(HostBudgetRelease::Released);
        }
        self.update(|ledger| {
            let record = ledger
                .reservations
                .get_mut(&self.id)
                .context("host reservation is absent")?;
            if matches!(record.ownership, Ownership::Coordinator { .. }) {
                return Ok(HostBudgetRelease::CoordinatorRetained);
            }
            ensure!(
                record.plan.is_some(),
                "ordinary owned cleanup requires a bound host hold"
            );
            remove_legacy_charge(&self.home, record)?;
            record.phase = Phase::OrdinaryStopped;
            Ok(HostBudgetRelease::Released)
        })
    }

    /// Settle an ordinary hold whose launch failed, by the ledger's own
    /// liveness rule: a launch that never dispatched holds nothing, a machine
    /// that cannot be running ([`may_be_live`]) is released, and one that may
    /// be keeps its charge, upgraded to `Running` when its process is provably
    /// ours so the usual reconciliation retires it once that process dies.
    pub fn settle_failed_launch(&self, vm_name: &str) -> Result<()> {
        if matches!(self.mode, PermitMode::UnboundedOrdinary { .. }) {
            return Ok(());
        }
        validate_name(vm_name)?;
        let directory = mvm_core::config::vm_state_dir_at(&self.home, vm_name);
        self.update(|ledger| {
            let Some(record) = ledger.reservations.get_mut(&self.id) else {
                return Ok(());
            };
            ensure!(
                record.ownership == Ownership::Ordinary,
                "coordinated host reservation requires terminal reconciliation"
            );
            match record.phase {
                Phase::Prepared => {
                    ledger.reservations.remove(&self.id);
                    return Ok(());
                }
                Phase::OrdinaryStopped | Phase::Terminal { .. } => return Ok(()),
                Phase::NoDispatch => anyhow::bail!("ordinary host reservation has no dispatch"),
                Phase::Dispatching | Phase::Running { .. } => {}
            }
            ensure!(
                record.vm_name == vm_name,
                "host reservation names another machine"
            );
            if !may_be_live(&directory, vm_name) {
                remove_legacy_charge(&self.home, record)?;
                record.phase = Phase::OrdinaryStopped;
            } else if let Ok(Some(process)) = platform::machine_identity(&directory) {
                record.phase = Phase::Running { process };
            }
            Ok(())
        })
    }

    /// Record original runtime refusal before any helper/native dispatch.
    /// Coordinated holds remain charged until their owner durably cancels them.
    pub(crate) fn record_runtime_no_dispatch(
        &self,
        proof: &mvm_runtime::actor_teardown::ActorNoDispatchProof,
        vm_name: &str,
        plan: &ExecutionPlan,
        emitter: &crate::audit::emitter::AuditEmitter,
    ) -> Result<()> {
        use sha2::{Digest, Sha256};
        ensure!(
            proof.matches_launch(vm_name, plan),
            "runtime no-dispatch proof names another admitted attempt"
        );
        let audit = || {
            emitter.emit(
                plan,
                "plan.cancelled",
                [
                    ("reason".into(), "runtime_never_dispatched".into()),
                    ("host_reservation".into(), self.id.clone()),
                    ("vm_name".into(), vm_name.to_owned()),
                ],
            )
        };
        if matches!(self.mode, PermitMode::UnboundedOrdinary { .. }) {
            return audit();
        }
        let cancellation_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&(
            plan,
            vm_name,
            "runtime_never_dispatched",
        ))?));
        self.mutate(|record| {
            ensure!(
                record.vm_name == vm_name && record.plan.as_deref() == Some(&plan.plan_id.0),
                "host hold does not match the refused runtime dispatch"
            );
            if let Phase::Terminal { result_digest } = &record.phase {
                ensure!(
                    record.ownership == Ownership::Ordinary
                        && result_digest == &cancellation_digest,
                    "host cancellation terminal evidence differs"
                );
                return Ok(());
            }
            ensure!(
                matches!(record.phase, Phase::Dispatching | Phase::NoDispatch),
                "host hold is not awaiting runtime cancellation"
            );
            audit()?;
            record.phase = match record.ownership {
                Ownership::Ordinary => Phase::Terminal {
                    result_digest: cancellation_digest,
                },
                Ownership::Coordinator { .. } => Phase::NoDispatch,
            };
            Ok(())
        })
    }

    /// Retain a digest-bound tombstone for a coordinator's pre-dispatch cancellation.
    ///
    /// The coordinator must durably record cleanup and its terminal result first.
    /// No plan is required, but a possibly dispatched hold cannot use this path.
    pub fn reconcile_never_dispatched(&self, result_digest: &str) -> Result<()> {
        ensure!(
            matches!(self.mode, PermitMode::Tracked),
            "pre-dispatch reconciliation requires a tracked host hold"
        );
        validate_digest(result_digest)?;
        self.mutate(|record| {
            ensure!(
                matches!(record.ownership, Ownership::Coordinator { .. }),
                "pre-dispatch reconciliation requires a coordinator-bound hold"
            );
            match &record.phase {
                Phase::Prepared | Phase::NoDispatch => {
                    record.phase = Phase::Terminal {
                        result_digest: result_digest.to_owned(),
                    };
                }
                Phase::Terminal {
                    result_digest: previous,
                } => {
                    ensure!(
                        previous == result_digest,
                        "host reservation terminal result differs"
                    );
                }
                Phase::Dispatching | Phase::Running { .. } | Phase::OrdinaryStopped => {
                    anyhow::bail!(
                        "possibly dispatched host hold cannot use pre-dispatch reconciliation"
                    );
                }
            }
            Ok(())
        })
    }

    /// Record terminal reconciliation by the trusted original lifecycle owner.
    ///
    /// The caller must have confirmed death and host-resource cleanup and
    /// durably committed this terminal result. For a coordinated hold, missing
    /// PID files, failed starts and best-effort audit writes are not that
    /// evidence; an ordinary failed launch is settled instead by
    /// [`Self::settle_failed_launch`].
    pub fn reconcile_terminal(&self, result_digest: &str) -> Result<()> {
        ensure!(
            matches!(self.mode, PermitMode::Tracked),
            "terminal reconciliation requires a tracked host hold"
        );
        validate_digest(result_digest)?;
        self.mutate(|record| {
            if let Phase::Terminal {
                result_digest: previous,
            } = &record.phase
            {
                ensure!(
                    previous == result_digest,
                    "host reservation terminal result differs"
                );
            } else {
                ensure!(
                    record.plan.is_some(),
                    "unbound host hold requires pre-dispatch release"
                );
                remove_legacy_charge(&self.home, record)?;
                record.phase = Phase::Terminal {
                    result_digest: result_digest.to_owned(),
                };
            }
            Ok(())
        })
    }

    fn mutate(&self, apply: impl FnOnce(&mut Reservation) -> Result<()>) -> Result<()> {
        self.update(|ledger| {
            apply(
                ledger
                    .reservations
                    .get_mut(&self.id)
                    .context("host reservation is absent")?,
            )
        })
    }

    fn update<T>(&self, apply: impl FnOnce(&mut Ledger) -> Result<T>) -> Result<T> {
        if !self.home.try_exists()? {
            mvm_core::config::create_private_dir(&self.home)?;
        }
        let root = self.home.join("admission-budget");
        platform::prepare_directory(&root)?;
        let path = root.join("reservations.json");
        let _lock = super::acquire_lock(&path.with_extension("lock"))?;
        let mut ledger: Ledger = match super::read_private(&path, MAX_LEDGER_BYTES)? {
            Some(bytes) => {
                serde_json::from_slice(&bytes).context("invalid host reservation ledger")?
            }
            None => Ledger::default(),
        };
        ensure!(
            ledger.version == 1 && ledger.reservations.len() <= MAX_RESERVATIONS,
            "unsupported or oversized host reservation ledger"
        );
        for (id, record) in &ledger.reservations {
            ensure!(
                uuid::Uuid::parse_str(id).is_ok(),
                "invalid host reservation identifier"
            );
            validate_name(&record.vm_name)?;
            platform::validate_owner(&record.owner)?;
            if let Ownership::Coordinator { request_digest } = &record.ownership {
                validate_digest(request_digest)?;
            }
            if let Phase::Running { process } = &record.phase {
                platform::validate_owner(process)?;
            }
            if let Phase::Terminal { result_digest } = &record.phase {
                validate_digest(result_digest)?;
            }
            ensure!(
                record.phase == Phase::Prepared
                    || record.plan.is_some()
                    || (matches!(record.phase, Phase::Terminal { .. })
                        && matches!(record.ownership, Ownership::Coordinator { .. })),
                "unbound dispatched reservation"
            );
            ensure!(
                !matches!(record.phase, Phase::OrdinaryStopped)
                    || record.ownership == Ownership::Ordinary,
                "coordinated host reservation has an ordinary release"
            );
        }
        let result = apply(&mut ledger)?;
        let bytes = serde_json::to_vec(&ledger)?;
        ensure!(
            bytes.len() <= MAX_LEDGER_BYTES,
            "host reservation ledger exceeds byte limit"
        );
        atomic_io::atomic_write_durable(&path, &bytes)?;
        Ok(result)
    }
}

impl Drop for HostBudgetPermit {
    fn drop(&mut self) {
        if matches!(self.drop_policy, DropPolicy::Retain) {
            return;
        }
        if let Err(error) = self.update(|ledger| {
            if ledger.reservations.get(&self.id).is_some_and(|record| {
                record.phase == Phase::Prepared && record.ownership == Ownership::Ordinary
            }) {
                ledger.reservations.remove(&self.id);
            }
            Ok(())
        }) {
            tracing::warn!(%error, "host reservation cleanup unconfirmed; retaining capacity");
        }
    }
}

fn budget_at(home: &Path) -> Result<HostBudget> {
    let config = home.join("config").join("config.toml");
    let Some(bytes) = platform::read_legacy(&config, 1024 * 1024)? else {
        return Ok(HostBudget::default());
    };
    Ok(mvm_core::user_config::parse(std::str::from_utf8(&bytes)?)?.host_budget())
}

fn validate_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            && name != "."
            && name != "..",
        "invalid host reservation machine name"
    );
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    ensure!(
        digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid host reservation digest"
    );
    Ok(())
}

fn legacy_committed(home: &Path, ledger: &Ledger) -> Result<MachineCharge> {
    let directory = mvm_core::config::vms_dir_at(home);
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(MachineCharge::default());
        }
        Err(error) => return Err(error.into()),
    };
    // Sums saturate: a charge too large to add claims the whole host, which the
    // headroom check then refuses as such.
    let mut total = MachineCharge::default();
    for entry in entries {
        let entry = entry?;
        // A stray file (a Finder `.DS_Store`, say) is not a machine.
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        // A charged hold already counts its machine, whatever its legacy
        // record says.
        let held = ledger
            .reservations
            .values()
            .any(|record| record.vm_name == name && record.phase.is_charged());
        if held || !may_be_live(&entry.path(), &name) {
            continue;
        }
        if let Some(charge) = super::machine_charge(&entry.path(), |path| {
            platform::read_legacy(path, MAX_MACHINE_EVIDENCE_BYTES)
        }) {
            total = total.plus(charge);
        }
    }
    Ok(total)
}

/// Upper bound on a charge record or persisted plan read for accounting.
const MAX_MACHINE_EVIDENCE_BYTES: usize = 1024 * 1024;

/// Whether a state dir's pid markers leave its machine possibly running.
///
/// No marker is no machine. A live-handoff child's marker is a link to the
/// marker of the standby parent whose VMM it took over, which the owner-only
/// reader refuses to follow; the shared liveness probe judges the process that
/// marker names, and a dangling link names none. Any marker that cannot be
/// read safely (a link to anything but a small regular file, or a malformed
/// marker in a dir with no link) proves nothing either way, so that machine
/// stays counted: over-counting one machine costs headroom, refusing on it
/// would cost every boot.
fn may_be_live(directory: &Path, name: &str) -> bool {
    use mvm_vmm::host::process_liveness::{
        PID_FILE_NAMES, read_pid_marker, state_dir_has_live_process,
    };
    let markers: Vec<_> = PID_FILE_NAMES
        .iter()
        .map(|file| directory.join(file))
        .filter_map(|path| path.symlink_metadata().ok().map(|meta| (path, meta)))
        .collect();
    if markers.is_empty() {
        return false;
    }
    let unreadable = |error: &dyn std::fmt::Display| {
        super::warn_once(
            name,
            format!(
                "unreadable machine PID evidence; counting this machine as possibly live: {error:#}"
            ),
        );
        true
    };
    let links: Vec<_> = markers
        .iter()
        .filter(|(_, meta)| meta.file_type().is_symlink())
        .collect();
    if !links.is_empty() {
        if let Some(error) = links
            .iter()
            .find_map(|(path, _)| read_pid_marker(path).err())
        {
            return unreadable(&error);
        }
        return state_dir_has_live_process(directory);
    }
    match platform::machine_is_confirmed_dead(directory) {
        Ok(dead) => !dead,
        Err(error) => unreadable(&error),
    }
}

/// Remove a retiring hold's legacy record, but only one that is provably its.
///
/// A record that differs or cannot be read may belong to a later machine of the
/// same name, so it is left for [`legacy_committed`] to judge by that machine's
/// own evidence.
fn remove_legacy_charge(home: &Path, record: &Reservation) -> Result<()> {
    let path = super::charge_path_at(home, &record.vm_name);
    let legacy = platform::read_legacy(&path, MAX_MACHINE_EVIDENCE_BYTES).and_then(|bytes| {
        bytes
            .map(|bytes| serde_json::from_slice::<MachineCharge>(&bytes).map_err(Into::into))
            .transpose()
    });
    match legacy {
        Ok(None) => {}
        Ok(Some(charge)) if charge == record.charge => {
            std::fs::remove_file(&path)?;
            atomic_io::sync_dir(path.parent().context("charge parent missing")?)?;
        }
        Ok(Some(_)) => tracing::warn!(
            machine = record.vm_name,
            "legacy charge differs from the retiring hold; leaving it in place"
        ),
        Err(error) => tracing::warn!(
            machine = record.vm_name,
            "unreadable legacy charge left in place for the retiring hold: {error:#}"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
