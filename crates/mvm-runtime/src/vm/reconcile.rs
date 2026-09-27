//! Reconcile-on-entry convergence.
//!
//! The VM name registry (`VmNameRegistry`, `{mvm_share_dir}/vm-names.json`)
//! is the source of truth; this module converges on-disk runtime reality to
//! it. A record whose supervisor process is dead has its leftover state torn
//! down and the record dropped — never adopted: an orphan process that lost
//! its admission context must not be resurrected outside the signed-admission
//! path. State dirs with no record are reaped; records whose
//! state has vanished are dropped. Convergence is idempotent — running it
//! twice is a no-op.
//!
//! Pure-logic-first, mirroring `mvm_hostd::supervisor::reaper::sweep`:
//! [`classify`] and [`sweep`] take an injected [`RuntimeView`] /
//! [`ReconcileActions`] and need no real backend, clock, or filesystem.
//! [`converge`] is the thin real-filesystem adapter the CLI entry path calls.
//!
//! **Cheapness is a hard constraint.** Liveness is a `kill(pid, 0)`
//! stat against the recorded supervisor pid files only — never `pgrep` / `ps`
//! (which spawn subprocesses), never a VM boot, never Nix. The heavier
//! helper-PID argv sweep stays in `mvmctl cache prune` (on by default). This
//! reuses the live-vs-orphan discrimination from `mvm-cli`'s
//! `env::builder_vm` reaper rather than reinventing the policy; the bare
//! syscall is restated here only because the lower `mvm` crate can't depend on
//! `mvm-cli`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::vm::name_registry::{VmNameRegistry, VmRegistration};

/// Options controlling a convergence pass.
#[derive(Debug, Clone, Default)]
pub struct ConvergeOpts {
    /// Classify and report drift but perform no teardown, reap, or
    /// deregister — the on-disk registry and state dirs are left untouched.
    pub dry_run: bool,
}

/// One unit of drift between the registry and on-disk runtime reality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drift {
    /// Record with a live supervisor process, or an intentionally-paused
    /// record. Nothing to do.
    Live { name: String },
    /// Record present with runtime state on disk, but the supervisor
    /// process is dead. Tear down the leftover state and drop the record.
    DeadProcessLeftState { name: String },
    /// Record present but its runtime state dir has vanished. Drop the
    /// stale record (today this surfaces as a stale `pause` against a
    /// vanished VM).
    RecordNoState { name: String },
    /// A runtime state dir on disk with no registry record and no live
    /// owning process. Reap it.
    OrphanStateNoRecord { dir: String },
    /// A paused record whose Firecracker is running with no pause marker: a
    /// resume restored it and resumed its vCPUs, then ended before the guest
    /// confirmed it reseeded (the resuming process was killed or crashed).
    /// The guest is running on random state it has already used. Stop it and
    /// keep the record paused; its sealed snapshot is untouched.
    UnadmittedResume { name: String },
}

/// Cheap, side-effect-free observations convergence makes. The real impl
/// ([`FsRuntimeView`]) is filesystem stat + `kill(pid, 0)`; tests inject a
/// synthetic view so [`classify`] / [`sweep`] run with no real backend.
pub trait RuntimeView {
    /// Does this record's on-disk runtime state still exist?
    fn state_present(&self, reg: &VmRegistration) -> bool;
    /// Is the supervisor process recorded in that state alive? Consulted
    /// only when [`RuntimeView::state_present`] is true.
    fn process_alive(&self, reg: &VmRegistration) -> bool;
    /// Whether the machine `name` has a live Firecracker that neither a pause
    /// nor an admission accounts for — the state a resume leaves between
    /// resuming vCPUs and admitting the guest. Consulted only for paused
    /// records. Backends other than Firecracker never have it.
    fn unadmitted_resume(&self, _name: &str) -> bool {
        false
    }
    /// Basenames of runtime state dirs on disk that have no record in
    /// `known` **and** no live owning process — i.e. true orphans, safe to
    /// reap. A dir with a live process is an in-flight or specially-managed
    /// VM (e.g. the dev VM) and is deliberately excluded.
    fn orphan_dirs(&self, known: &BTreeSet<String>) -> Vec<String>;
}

/// The mutating side of convergence, injected so [`sweep`] stays testable.
pub trait ReconcileActions {
    /// Tear down a dead-process record's leftover runtime state.
    fn tear_down(&self, name: &str, reg: &VmRegistration) -> Result<(), String>;
    /// Reap an orphan state dir (basename) that has no record. `Ok(false)`
    /// when it turned out not to be an orphan: a lifecycle operation on the
    /// machine (a restore filling the directory before its supervisor is up)
    /// owns it, or a supervisor came up since it was classified.
    fn reap_orphan(&self, dir: &str) -> Result<bool, String>;
    /// Stop the Firecracker of a resume that was never admitted. `Ok(false)`
    /// when there is nothing to stop after all: a resume of `name` is still in
    /// progress in another process, which owns the outcome, or the state has
    /// changed since it was classified.
    fn stop_unadmitted(&self, name: &str) -> Result<bool, String>;
}

/// What a convergence pass observed and did. Serializable for
/// `mvmctl reconcile --json`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ConvergeReport {
    /// Records left untouched — live or intentionally paused.
    pub live: Vec<String>,
    /// Dead-process records whose leftover state was torn down + dropped.
    pub dead_process_reaped: Vec<String>,
    /// Records whose state had vanished; the stale record was dropped.
    pub stale_record_dropped: Vec<String>,
    /// Orphan state dirs (no record) that were reaped.
    pub orphan_state_reaped: Vec<String>,
    /// Paused records whose never-admitted resumed guest was stopped.
    pub unadmitted_resume_stopped: Vec<String>,
    /// Non-fatal errors. Fail-open: recorded here, never returned, so a
    /// bookkeeping hiccup can't block the command that triggered the sweep.
    pub errors: Vec<String>,
}

impl ConvergeReport {
    /// Total drift healed: records dropped plus orphan dirs reaped.
    pub fn reconciled_count(&self) -> usize {
        self.dead_process_reaped.len()
            + self.stale_record_dropped.len()
            + self.orphan_state_reaped.len()
            + self.unadmitted_resume_stopped.len()
    }

    /// No drift healed and no errors — reality already matched the registry.
    pub fn is_clean(&self) -> bool {
        self.reconciled_count() == 0 && self.errors.is_empty()
    }
}

/// Pure classification: cross-check every record against runtime reality and
/// enumerate orphan state dirs. No mutation, no I/O of its own — drives off
/// the injected [`RuntimeView`]. Deterministic order (records sorted by name,
/// then orphan dirs sorted).
pub fn classify(registry: &VmNameRegistry, view: &dyn RuntimeView) -> Vec<Drift> {
    let mut drifts = Vec::new();

    let mut names: Vec<&String> = registry.vms.keys().collect();
    names.sort();
    for name in names {
        let reg = &registry.vms[name];
        // An intentionally-paused record (sealed snapshot awaiting
        // `mvmctl resume`) has a dead process by design — never reap it.
        // A paused record whose VMM is running unpaused is a resume that
        // never finished admitting its guest.
        if reg.paused && view.unadmitted_resume(name) {
            drifts.push(Drift::UnadmittedResume { name: name.clone() });
            continue;
        }
        if reg.paused {
            drifts.push(Drift::Live { name: name.clone() });
            continue;
        }
        if !view.state_present(reg) {
            drifts.push(Drift::RecordNoState { name: name.clone() });
        } else if view.process_alive(reg) {
            drifts.push(Drift::Live { name: name.clone() });
        } else {
            drifts.push(Drift::DeadProcessLeftState { name: name.clone() });
        }
    }

    let known: BTreeSet<String> = registry.vms.keys().cloned().collect();
    let mut orphans = view.orphan_dirs(&known);
    orphans.sort();
    orphans.dedup();
    for dir in orphans {
        drifts.push(Drift::OrphanStateNoRecord { dir });
    }

    drifts
}

/// Apply convergence to an in-memory registry: tear down dead-process
/// records, drop stale records, reap orphan dirs, and deregister the
/// reconciled records. Pure of filesystem I/O beyond the injected
/// `actions` — testable with a fake backend. Mirrors
/// `mvm_hostd::supervisor::reaper::sweep`.
///
/// Idempotent: a second `sweep` over the post-sweep registry + reality
/// finds no drift (every dropped record is gone, every reaped dir is gone),
/// so it reports only `Live` and mutates nothing. A failed action keeps its
/// record so the next pass retries (fail-open — recorded in
/// `report.errors`, never returned).
pub fn sweep(
    registry: &mut VmNameRegistry,
    view: &dyn RuntimeView,
    actions: &dyn ReconcileActions,
    opts: &ConvergeOpts,
) -> ConvergeReport {
    let mut report = ConvergeReport::default();
    let mut to_deregister = Vec::new();

    for drift in classify(registry, view) {
        match drift {
            Drift::Live { name } => report.live.push(name),
            Drift::RecordNoState { name } => {
                if !opts.dry_run {
                    to_deregister.push(name.clone());
                }
                report.stale_record_dropped.push(name);
            }
            Drift::DeadProcessLeftState { name } => {
                if opts.dry_run {
                    report.dead_process_reaped.push(name);
                    continue;
                }
                let reg = registry.vms[&name].clone();
                match actions.tear_down(&name, &reg) {
                    Ok(()) => {
                        to_deregister.push(name.clone());
                        report.dead_process_reaped.push(name);
                    }
                    Err(e) => report.errors.push(format!("tear down {name}: {e}")),
                }
            }
            Drift::UnadmittedResume { name } => {
                if opts.dry_run {
                    report.unadmitted_resume_stopped.push(name);
                    continue;
                }
                match actions.stop_unadmitted(&name) {
                    Ok(true) => report.unadmitted_resume_stopped.push(name),
                    Ok(false) => report.live.push(name),
                    Err(e) => report
                        .errors
                        .push(format!("stop unadmitted resume {name}: {e}")),
                }
            }
            Drift::OrphanStateNoRecord { dir } => {
                if opts.dry_run {
                    report.orphan_state_reaped.push(dir);
                    continue;
                }
                match actions.reap_orphan(&dir) {
                    Ok(true) => report.orphan_state_reaped.push(dir),
                    Ok(false) => {}
                    Err(e) => report.errors.push(format!("reap orphan {dir}: {e}")),
                }
            }
        }
    }

    for name in to_deregister {
        registry.deregister(&name);
    }
    report
}

use mvm_vmm::host::process_liveness::state_dir_has_live_process;

/// Remove a machine's state dir unless something still owns it, holding the
/// machine's lifecycle lock across the removal. `Ok(true)` when the directory
/// is gone afterwards (including when there was none); `Ok(false)` when an
/// owner kept it in place.
///
/// A restore creates the state dir and fills it before its supervisor
/// publishes a pid, so for that whole window the dir has no live owner and no
/// registry record, which is exactly what an orphan looks like. The restore
/// holds the machine's lifecycle lock for that window; taking the same lock
/// here, and keeping it until the directory is gone, is what stops a stop or a
/// reconcile in another process from deleting it underneath the restore. A
/// restore that starts after this returns blocks on the lock until the
/// removal has finished, so it never clones into a half-deleted directory.
///
/// Liveness is checked again under the lock: a restore that completed between
/// the caller's classification and here has left a running supervisor behind.
pub fn reap_unowned_state_dir(state_dir: &Path, instance_dir: &Path) -> Result<bool, String> {
    // Nothing to remove, and no reason to create a lock file for a machine
    // that has no state.
    if !state_dir.exists() {
        return Ok(true);
    }
    let lock = crate::vm::instance_snapshot::try_lock_resume_in(instance_dir)
        .map_err(|e| format!("{e:#}"))?;
    let Some(_lifecycle) = lock else {
        return Ok(false);
    };
    if state_dir_has_live_process(state_dir) {
        return Ok(false);
    }
    remove_runtime_dirs(state_dir).map(|()| true)
}

/// Remove a machine's state dir *and* the directory its sockets live in.
///
/// Those are not always the same place. When the state dir is deep enough that
/// a socket path would overflow macOS's `sun_path` limit, `vm_socket_dir_at`
/// puts the sockets under a short hashed namespace instead. Removing only the
/// state dir then leaves the substitution socket behind, and the next launch
/// under that name dies binding it with "Address already in use".
///
/// Absent directories are not an error. The caller owns the decision that
/// nothing is still running out of them.
pub fn remove_runtime_dirs(state_dir: &Path) -> Result<(), String> {
    let socket_dir = mvm_core::config::vm_socket_dir_at(state_dir);
    if socket_dir != state_dir {
        remove_state_dir(&socket_dir)?;
    }
    remove_state_dir(state_dir)
}

/// Best-effort recursive removal of a state dir. The dead-process
/// discrimination already ran in [`classify`], so there is no live process
/// to signal here — only leftover sockets / pid files / `console.log`.
fn remove_state_dir(dir: &Path) -> Result<(), String> {
    if !dir.exists() {
        return Ok(());
    }
    std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))
}

/// Real-filesystem [`RuntimeView`] rooted at a `vms` directory
/// (`{mvm_home}/vms`). State presence is a `stat`; liveness is
/// `kill(pid, 0)` on the recorded supervisor pid files — no subprocess
/// spawn, no VM boot (the cheapness budget).
pub struct FsRuntimeView {
    vms_root: PathBuf,
}

impl FsRuntimeView {
    pub fn new(vms_root: impl Into<PathBuf>) -> Self {
        Self {
            vms_root: vms_root.into(),
        }
    }
}

impl RuntimeView for FsRuntimeView {
    fn state_present(&self, reg: &VmRegistration) -> bool {
        Path::new(&reg.vm_dir).is_dir()
    }
    fn process_alive(&self, reg: &VmRegistration) -> bool {
        state_dir_has_live_process(Path::new(&reg.vm_dir))
    }
    fn unadmitted_resume(&self, name: &str) -> bool {
        // The markers live in the machine's state directory, derived from its
        // name. The record's `vm_dir` is not used: some registrations leave it
        // empty, which would probe paths relative to the working directory.
        crate::vm::admission::is_unaccounted(&self.vms_root.join(name))
    }
    fn orphan_dirs(&self, known: &BTreeSet<String>) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.vms_root) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            // Canonical layout is `vms/<name>`, so the dir basename is the
            // registry key. A dir with a live owner is an in-flight or
            // specially-managed VM (e.g. the dev VM) — never an orphan.
            if known.contains(name) || state_dir_has_live_process(&path) {
                continue;
            }
            out.push(name.to_string());
        }
        out
    }
}

/// Stops a machine's Firecracker given its state directory.
pub type StopVmm = fn(&Path) -> anyhow::Result<()>;

/// The production [`StopVmm`]: the restore teardown, which stops the process
/// only if it is the Firecracker serving this state directory's API socket.
fn stop_firecracker_in(state_dir: &Path) -> anyhow::Result<()> {
    use crate::vm::instance_snapshot::{FirecrackerIO, SnapshotIO};
    FirecrackerIO::new(state_dir.join("fc.socket")).teardown_paused()
}

/// Real-filesystem [`ReconcileActions`] rooted at the same `vms` dir.
pub struct FsReconcileActions {
    vms_root: PathBuf,
    /// Where each machine's lifecycle lock lives: the `instances` dir beside
    /// `vms_root`, both being children of the same mvm home.
    instances_root: PathBuf,
    /// The registry an unadmitted-resume stop re-reads once it holds the
    /// machine's resume lock. `None` skips that re-read.
    registry_path: Option<PathBuf>,
    stop_vmm: StopVmm,
}

impl FsReconcileActions {
    /// `vms_root` is `<mvm_home>/vms`; the lifecycle locks an orphan reap
    /// defers to are read from `<mvm_home>/instances`.
    pub fn new(vms_root: impl Into<PathBuf>) -> Self {
        let vms_root = vms_root.into();
        let mvm_home = vms_root.parent().unwrap_or(&vms_root);
        let instances_root = mvm_core::config::instances_root_at(mvm_home);
        Self {
            vms_root,
            instances_root,
            registry_path: None,
            stop_vmm: stop_firecracker_in,
        }
    }

    /// Re-read `registry_path` before stopping an unadmitted resume.
    pub fn with_registry(mut self, registry_path: impl Into<PathBuf>) -> Self {
        self.registry_path = Some(registry_path.into());
        self
    }

    /// Stop Firecracker with `stop_vmm` instead of the real teardown.
    pub fn with_stop_vmm(mut self, stop_vmm: StopVmm) -> Self {
        self.stop_vmm = stop_vmm;
        self
    }

    /// Whether the registry still records `name` as paused.
    fn still_paused(&self, name: &str) -> Result<bool, String> {
        let Some(path) = &self.registry_path else {
            return Ok(true);
        };
        let registry = VmNameRegistry::load(path).map_err(|e| format!("{e:#}"))?;
        Ok(registry.lookup(name).is_some_and(|record| record.paused))
    }
}

impl ReconcileActions for FsReconcileActions {
    fn tear_down(&self, _name: &str, reg: &VmRegistration) -> Result<(), String> {
        remove_state_dir(Path::new(&reg.vm_dir))
    }
    fn reap_orphan(&self, dir: &str) -> Result<bool, String> {
        reap_unowned_state_dir(&self.vms_root.join(dir), &self.instances_root.join(dir))
    }
    fn stop_unadmitted(&self, name: &str) -> Result<bool, String> {
        use crate::vm::instance_snapshot::try_lock_resume;
        // A resume in progress holds this lock for its whole admission; its
        // own outcome decides whether the guest keeps running.
        let Some(_resuming) = try_lock_resume(name).map_err(|e| format!("{e:#}"))? else {
            return Ok(false);
        };
        // The classification ran before the lock was taken. A resume may have
        // admitted its guest and released the lock since, so check again now
        // that no resume can change the answer.
        let state_dir = self.vms_root.join(name);
        if !self.still_paused(name)? || !crate::vm::admission::is_unaccounted(&state_dir) {
            return Ok(false);
        }
        (self.stop_vmm)(&state_dir).map_err(|e| format!("{e:#}"))?;
        Ok(true)
    }
}

/// Filesystem adapter over explicit paths — the testable seam under
/// [`converge`]. Loads the registry, sweeps it against `vms_root`, and
/// (unless `dry_run`) saves it back when records were dropped. Fail-open:
/// a load/save error is recorded in the report and the pass still returns
/// — never an `Err` that could block the calling command.
///
/// Does not emit audit; that belongs to the real entry point [`converge`]
/// so this stays free of process-global state and hermetically testable.
pub fn converge_at(registry_path: &Path, vms_root: &Path, opts: &ConvergeOpts) -> ConvergeReport {
    // Held for the whole pass, so a record changed by another process between
    // this load and the save below is not overwritten with a stale copy.
    let _registry_lock = match crate::vm::name_registry::acquire_registry_lock(registry_path) {
        Ok(lock) => lock,
        Err(e) => {
            let mut report = ConvergeReport::default();
            report
                .errors
                .push(format!("lock registry {}: {e:#}", registry_path.display()));
            return report;
        }
    };
    let mut registry = match VmNameRegistry::load(registry_path) {
        Ok(r) => r,
        Err(e) => {
            let mut report = ConvergeReport::default();
            report
                .errors
                .push(format!("load registry {}: {e}", registry_path.display()));
            return report;
        }
    };

    let view = FsRuntimeView::new(vms_root);
    let actions = FsReconcileActions::new(vms_root).with_registry(registry_path);
    let mut report = sweep(&mut registry, &view, &actions, opts);

    let registry_changed =
        !report.dead_process_reaped.is_empty() || !report.stale_record_dropped.is_empty();
    if !opts.dry_run
        && registry_changed
        && let Err(e) = registry.save(registry_path)
    {
        // The in-memory reconcile already happened; only persistence
        // failed. Record it and keep going — fail-open.
        report
            .errors
            .push(format!("save registry {}: {e}", registry_path.display()));
    }
    report
}

/// Reconcile the default on-disk registry — the cheap convergence pass the
/// CLI entry path runs for state-touching commands, and the body of
/// `mvmctl reconcile`. Never returns an error: drift-healing must never
/// block the requested command (fail-open). On the non-dry-run
/// path emits a `RegistryReconcile` audit line per healed item so the
/// self-heal is observable and `audit verify` still chains.
pub fn converge(opts: &ConvergeOpts) -> ConvergeReport {
    let registry_path = crate::vm::name_registry::registry_path();
    let vms_root = mvm_core::config::vms_dir();
    let report = converge_at(&registry_path, &vms_root, opts);
    if !opts.dry_run {
        emit_audit(&report);
        remove_abandoned_restore_staging(&registry_path);
    }
    report
}

/// Remove restore staging abandoned by a process that died mid-restore, for
/// every registered machine: each holds decrypted guest memory.
fn remove_abandoned_restore_staging(registry_path: &Path) {
    let Ok(registry) = VmNameRegistry::load(registry_path) else {
        return;
    };
    for name in registry.vms.keys() {
        crate::vm::instance_snapshot::remove_abandoned_staging(&mvm_core::config::instance_dir(
            name,
        ));
    }
}

/// Reap only *orphan* state dirs under the default `vms` root: dirs with no
/// live owning process and no registry record. Unlike [`converge`] it never
/// drops records, tears down dead-process records, or drives any resume/boot,
/// so the throwaway transient-run path — which opts out of full convergence to
/// avoid auto-resuming unrelated machines — can still clean up a state dir a
/// killed or crashed prior run left behind (a SIGKILL or a closed terminal
/// skips teardown). `protect` shields the caller's in-flight VM name, whose dir
/// may exist before its supervisor comes up. Fail-open: returns the reaped
/// basenames, empty on any error, and audits each reap for observability.
pub fn reap_orphan_state_dirs(protect: Option<&str>) -> Vec<String> {
    let registry_path = crate::vm::name_registry::registry_path();
    let vms_root = mvm_core::config::vms_dir();
    let reaped = reap_orphan_state_dirs_at(&registry_path, &vms_root, protect);
    for dir in &reaped {
        mvm_core::audit_emit!(RegistryReconcile, vm: dir.as_str(), "action=orphan_state_no_record");
    }
    reaped
}

/// Path-explicit, audit-free seam for [`reap_orphan_state_dirs`] — the
/// hermetically testable core. Reads the registry only to shield registered
/// names; a registry that fails to load reaps nothing (fail-safe: never reap a
/// registered VM's dir on a transient read error).
pub fn reap_orphan_state_dirs_at(
    registry_path: &Path,
    vms_root: &Path,
    protect: Option<&str>,
) -> Vec<String> {
    let mut known: BTreeSet<String> = match VmNameRegistry::load(registry_path) {
        Ok(registry) => registry.vms.keys().cloned().collect(),
        Err(_) => return Vec::new(),
    };
    if let Some(name) = protect {
        known.insert(name.to_string());
    }
    let view = FsRuntimeView::new(vms_root);
    let actions = FsReconcileActions::new(vms_root);
    let mut reaped = Vec::new();
    for dir in view.orphan_dirs(&known) {
        if matches!(actions.reap_orphan(&dir), Ok(true)) {
            reaped.push(dir);
        }
    }
    reaped.sort();
    reaped
}

/// Emit one `RegistryReconcile` audit line per healed item. Best-effort
/// (the audit layer swallows write failures); consistent with the Stage 0
/// audit-emit contract.
fn emit_audit(report: &ConvergeReport) {
    for name in &report.dead_process_reaped {
        mvm_core::audit_emit!(RegistryReconcile, vm: name.as_str(), "action=dead_process_left_state");
    }
    for name in &report.stale_record_dropped {
        mvm_core::audit_emit!(RegistryReconcile, vm: name.as_str(), "action=record_no_state");
    }
    for dir in &report.orphan_state_reaped {
        mvm_core::audit_emit!(RegistryReconcile, vm: dir.as_str(), "action=orphan_state_no_record");
    }
    for name in &report.unadmitted_resume_stopped {
        mvm_core::audit_emit!(
            ResumeRefused,
            vm: name.as_str(),
            "stopped a resumed guest that never confirmed a reseed: its resume ended \
             before admitting it; the machine stays paused and its sealed snapshot is kept"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::vm::name_registry::RegisterParams;
    use mvm_core::util::test_env::TestEnv;
    use std::cell::RefCell;
    use std::path::Path;

    /// Create `<vms_root>/<name>/` and return its absolute path. With
    /// `pid` set, write a `libkrun.pid` pointing at that pid.
    fn make_state_dir(vms_root: &Path, name: &str, pid: Option<i32>) -> String {
        let dir = vms_root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(pid) = pid {
            std::fs::write(dir.join("libkrun.pid"), pid.to_string()).unwrap();
        }
        dir.to_string_lossy().into_owned()
    }

    /// In-memory [`RuntimeView`] for hermetic classification tests.
    #[derive(Default)]
    struct FakeView {
        /// VM names whose state dir is present.
        present: BTreeSet<String>,
        /// VM names whose supervisor process is alive.
        alive: BTreeSet<String>,
        /// State-dir basenames on disk (the orphan-scan source set).
        on_disk: BTreeSet<String>,
        /// Basenames the view considers to have a live owner (excluded
        /// from orphan reaping).
        live_dirs: BTreeSet<String>,
    }

    impl RuntimeView for FakeView {
        fn state_present(&self, reg: &VmRegistration) -> bool {
            self.present.contains(&reg.vm_dir)
        }
        fn process_alive(&self, reg: &VmRegistration) -> bool {
            self.alive.contains(&reg.vm_dir)
        }
        fn orphan_dirs(&self, known: &BTreeSet<String>) -> Vec<String> {
            self.on_disk
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .filter(|d| !self.live_dirs.contains(d.as_str()))
                .cloned()
                .collect()
        }
    }

    fn registry_with(names_and_dirs: &[(&str, &str)]) -> VmNameRegistry {
        let mut reg = VmNameRegistry::default();
        for (name, dir) in names_and_dirs {
            reg.register_with_metadata(RegisterParams::minimal(name, dir, "default"))
                .unwrap();
        }
        reg
    }

    #[test]
    fn classify_live_record_when_state_present_and_process_alive() {
        let reg = registry_with(&[("vm1", "/s/vm1")]);
        let view = FakeView {
            present: ["/s/vm1".to_string()].into(),
            alive: ["/s/vm1".to_string()].into(),
            ..Default::default()
        };
        assert_eq!(
            classify(&reg, &view),
            vec![Drift::Live {
                name: "vm1".to_string()
            }]
        );
    }

    #[test]
    fn classify_dead_process_when_state_present_but_process_dead() {
        let reg = registry_with(&[("vm1", "/s/vm1")]);
        let view = FakeView {
            present: ["/s/vm1".to_string()].into(),
            ..Default::default()
        };
        assert_eq!(
            classify(&reg, &view),
            vec![Drift::DeadProcessLeftState {
                name: "vm1".to_string()
            }]
        );
    }

    #[test]
    fn classify_record_no_state_when_state_dir_vanished() {
        let reg = registry_with(&[("vm1", "/s/vm1")]);
        let view = FakeView::default();
        assert_eq!(
            classify(&reg, &view),
            vec![Drift::RecordNoState {
                name: "vm1".to_string()
            }]
        );
    }

    #[test]
    fn classify_orphan_state_dir_with_no_record() {
        let reg = VmNameRegistry::default();
        let view = FakeView {
            on_disk: ["ghost".to_string()].into(),
            ..Default::default()
        };
        assert_eq!(
            classify(&reg, &view),
            vec![Drift::OrphanStateNoRecord {
                dir: "ghost".to_string()
            }]
        );
    }

    #[test]
    fn classify_skips_orphan_dir_with_live_owner() {
        // A live, unregistered dir (e.g. the dev VM) is not an orphan.
        let reg = VmNameRegistry::default();
        let view = FakeView {
            on_disk: ["mvm-dev".to_string()].into(),
            live_dirs: ["mvm-dev".to_string()].into(),
            ..Default::default()
        };
        assert!(classify(&reg, &view).is_empty());
    }

    #[test]
    fn classify_treats_paused_record_as_live() {
        // A paused record's process is dead by design — must never be
        // reaped even though its state is present and process is absent.
        let mut reg = registry_with(&[("vm1", "/s/vm1")]);
        reg.set_paused("vm1", true).unwrap();
        let view = FakeView {
            present: ["/s/vm1".to_string()].into(),
            ..Default::default()
        };
        assert_eq!(
            classify(&reg, &view),
            vec![Drift::Live {
                name: "vm1".to_string()
            }]
        );
    }

    /// Mutable fake serving both [`RuntimeView`] and [`ReconcileActions`]
    /// off one shared world, so a `tear_down` / `reap_orphan` is visible to
    /// the next `classify` — the setup needed to assert idempotency.
    #[derive(Default)]
    struct FakeWorld {
        present: RefCell<BTreeSet<String>>,
        alive: RefCell<BTreeSet<String>>,
        on_disk: RefCell<BTreeSet<String>>,
        live_dirs: RefCell<BTreeSet<String>>,
        torn_down: RefCell<Vec<String>>,
        reaped: RefCell<Vec<String>>,
        /// vm_dirs whose teardown should fail (drives the retry path).
        fail_teardown: BTreeSet<String>,
        /// vm_dirs whose Firecracker runs unpaused under a paused record.
        unadmitted: RefCell<BTreeSet<String>>,
        /// VM names with a resume in progress in another process.
        resuming: BTreeSet<String>,
        /// vm_dirs whose unadmitted guest was stopped.
        stopped: RefCell<Vec<String>>,
    }

    impl RuntimeView for FakeWorld {
        fn state_present(&self, reg: &VmRegistration) -> bool {
            self.present.borrow().contains(&reg.vm_dir)
        }
        fn process_alive(&self, reg: &VmRegistration) -> bool {
            self.alive.borrow().contains(&reg.vm_dir)
        }
        fn unadmitted_resume(&self, name: &str) -> bool {
            self.unadmitted.borrow().contains(name)
        }
        fn orphan_dirs(&self, known: &BTreeSet<String>) -> Vec<String> {
            self.on_disk
                .borrow()
                .iter()
                .filter(|d| !known.contains(d.as_str()))
                .filter(|d| !self.live_dirs.borrow().contains(d.as_str()))
                .cloned()
                .collect()
        }
    }

    impl ReconcileActions for FakeWorld {
        fn tear_down(&self, _name: &str, reg: &VmRegistration) -> Result<(), String> {
            if self.fail_teardown.contains(&reg.vm_dir) {
                return Err("backend down".to_string());
            }
            self.present.borrow_mut().remove(&reg.vm_dir);
            self.torn_down.borrow_mut().push(reg.vm_dir.clone());
            Ok(())
        }
        fn reap_orphan(&self, dir: &str) -> Result<bool, String> {
            self.on_disk.borrow_mut().remove(dir);
            self.reaped.borrow_mut().push(dir.to_string());
            Ok(true)
        }
        fn stop_unadmitted(&self, name: &str) -> Result<bool, String> {
            if self.resuming.contains(name) {
                return Ok(false);
            }
            self.unadmitted.borrow_mut().remove(name);
            self.stopped.borrow_mut().push(name.to_string());
            Ok(true)
        }
    }

    fn paused_registry(name: &str, dir: &str) -> VmNameRegistry {
        let mut reg = registry_with(&[(name, dir)]);
        reg.set_paused(name, true).unwrap();
        reg
    }

    /// A paused record whose Firecracker runs unpaused is a resume that
    /// never admitted its guest (the resuming process died): the guest is
    /// stopped, the record kept paused, and a second pass finds nothing.
    #[test]
    fn sweep_stops_a_resumed_guest_that_was_never_admitted() {
        let mut reg = paused_registry("vm1", "/s/vm1");
        let world = FakeWorld {
            present: RefCell::new(["/s/vm1".to_string()].into()),
            alive: RefCell::new(["/s/vm1".to_string()].into()),
            unadmitted: RefCell::new(["vm1".to_string()].into()),
            ..Default::default()
        };
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert_eq!(report.unadmitted_resume_stopped, vec!["vm1".to_string()]);
        assert_eq!(*world.stopped.borrow(), vec!["vm1".to_string()]);
        let record = reg.lookup("vm1").expect("the record is kept");
        assert!(record.paused, "and stays paused");
        let again = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert!(again.unadmitted_resume_stopped.is_empty(), "idempotent");
    }

    /// A resume still admitting its guest in another process is left to
    /// that process.
    #[test]
    fn sweep_leaves_a_resume_in_progress_alone() {
        let mut reg = paused_registry("vm1", "/s/vm1");
        let world = FakeWorld {
            unadmitted: RefCell::new(["vm1".to_string()].into()),
            resuming: ["vm1".to_string()].into(),
            ..Default::default()
        };
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert!(report.unadmitted_resume_stopped.is_empty());
        assert_eq!(report.live, vec!["vm1".to_string()]);
        assert!(world.stopped.borrow().is_empty());
    }

    #[test]
    fn a_dry_run_reports_an_unadmitted_resume_without_stopping_it() {
        let mut reg = paused_registry("vm1", "/s/vm1");
        let world = FakeWorld {
            unadmitted: RefCell::new(["vm1".to_string()].into()),
            ..Default::default()
        };
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts { dry_run: true });
        assert_eq!(report.unadmitted_resume_stopped, vec!["vm1".to_string()]);
        assert!(world.stopped.borrow().is_empty());
    }

    /// The filesystem view probes the machine's state directory under the
    /// `vms` root, by name. A registration with an empty `vm_dir` (as some
    /// write) must not send it probing the working directory.
    #[test]
    fn the_fs_view_probes_the_state_dir_by_name_not_the_record_vm_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vm_dir = dir.path().join("vm1");
        std::fs::create_dir(&vm_dir).unwrap();
        let reg = paused_registry("vm1", "");
        let view = FsRuntimeView::new(dir.path());
        assert!(!view.unadmitted_resume("vm1"), "no VMM at all");
        // This test's own process stands in for a live Firecracker.
        std::fs::write(vm_dir.join("fc.pid"), std::process::id().to_string()).unwrap();
        assert!(view.unadmitted_resume("vm1"));
        let drifts = classify(&reg, &view);
        assert_eq!(
            drifts,
            vec![Drift::UnadmittedResume {
                name: "vm1".to_string()
            }]
        );
        crate::vm::admission::record_admitted(&vm_dir).unwrap();
        assert!(
            !view.unadmitted_resume("vm1"),
            "an admitted guest is not a resume"
        );
    }

    /// Serializes the tests below, which point `MVM_HOME` at a temporary
    /// directory because the resume lock lives under it.
    struct IsolatedHome {
        _lock: std::sync::MutexGuard<'static, ()>,
        _env: TestEnv,
        dir: tempfile::TempDir,
    }

    impl IsolatedHome {
        fn new() -> Self {
            let lock = crate::vm::DATA_DIR_TEST_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let dir = tempfile::tempdir().expect("tempdir");
            let mut env = TestEnv::new();
            env.set("MVM_HOME", dir.path());
            Self {
                _lock: lock,
                _env: env,
                dir,
            }
        }

        /// A paused record for `vm1` whose state dir holds a live, unaccounted
        /// `fc.pid`, and the actions over it with a recording stop.
        fn unadmitted_vm1(&self) -> (PathBuf, FsReconcileActions) {
            let vms_root = self.dir.path().join("vms");
            let state_dir = vms_root.join("vm1");
            std::fs::create_dir_all(&state_dir).unwrap();
            std::fs::write(state_dir.join("fc.pid"), std::process::id().to_string()).unwrap();
            let registry_path = self.dir.path().join("vm-names.json");
            paused_registry("vm1", "").save(&registry_path).unwrap();
            let actions = FsReconcileActions::new(&vms_root)
                .with_registry(&registry_path)
                .with_stop_vmm(record_stop);
            (registry_path, actions)
        }
    }

    thread_local! {
        static STOPPED: RefCell<Vec<PathBuf>> = const { RefCell::new(Vec::new()) };
    }

    fn record_stop(state_dir: &Path) -> anyhow::Result<()> {
        STOPPED.with(|stopped| stopped.borrow_mut().push(state_dir.to_path_buf()));
        Ok(())
    }

    fn stops() -> Vec<PathBuf> {
        STOPPED.with(|stopped| std::mem::take(&mut *stopped.borrow_mut()))
    }

    #[test]
    fn an_unadmitted_resume_is_stopped_through_the_real_lock() {
        let home = IsolatedHome::new();
        let (_, actions) = home.unadmitted_vm1();
        let _ = stops();
        assert_eq!(actions.stop_unadmitted("vm1"), Ok(true));
        assert_eq!(stops().len(), 1);
    }

    /// A resume in progress in another process holds the machine's resume
    /// lock; reconcile must not stop the guest that resume is admitting.
    #[test]
    fn a_held_resume_lock_keeps_reconcile_away() {
        let home = IsolatedHome::new();
        let (_, actions) = home.unadmitted_vm1();
        let _ = stops();
        let resuming = crate::vm::instance_snapshot::lock_resume("vm1").expect("lock");
        assert_eq!(actions.stop_unadmitted("vm1"), Ok(false));
        assert!(stops().is_empty(), "nothing is stopped under a held lock");
        drop(resuming);
    }

    /// A resume that admitted its guest after the classification: the
    /// re-check under the lock sees the admission and stops nothing.
    #[test]
    fn a_guest_admitted_after_classification_is_not_stopped() {
        let home = IsolatedHome::new();
        let (registry_path, actions) = home.unadmitted_vm1();
        let _ = stops();
        crate::vm::admission::record_admitted(&home.dir.path().join("vms").join("vm1")).unwrap();
        assert_eq!(actions.stop_unadmitted("vm1"), Ok(false));
        std::fs::remove_file(home.dir.path().join("vms/vm1/fc.admitted")).unwrap();
        crate::vm::name_registry::update_registry(&registry_path, |reg| {
            reg.set_paused("vm1", false)
        })
        .unwrap();
        assert_eq!(
            actions.stop_unadmitted("vm1"),
            Ok(false),
            "no longer paused"
        );
        assert!(stops().is_empty());
    }

    #[test]
    fn sweep_tears_down_dead_process_record_and_deregisters() {
        let mut reg = registry_with(&[("vm1", "/s/vm1")]);
        let world = FakeWorld {
            present: RefCell::new(["/s/vm1".to_string()].into()),
            ..Default::default()
        };
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert_eq!(report.dead_process_reaped, vec!["vm1".to_string()]);
        assert_eq!(*world.torn_down.borrow(), vec!["/s/vm1".to_string()]);
        assert!(reg.lookup("vm1").is_none(), "record must be deregistered");
    }

    #[test]
    fn sweep_drops_stale_record_without_a_teardown_call() {
        let mut reg = registry_with(&[("vm1", "/s/vm1")]);
        let world = FakeWorld::default(); // nothing present on disk
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert_eq!(report.stale_record_dropped, vec!["vm1".to_string()]);
        assert!(world.torn_down.borrow().is_empty());
        assert!(reg.lookup("vm1").is_none());
    }

    #[test]
    fn sweep_reaps_orphan_dir() {
        let mut reg = VmNameRegistry::default();
        let world = FakeWorld {
            on_disk: RefCell::new(["ghost".to_string()].into()),
            ..Default::default()
        };
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert_eq!(report.orphan_state_reaped, vec!["ghost".to_string()]);
        assert_eq!(*world.reaped.borrow(), vec!["ghost".to_string()]);
    }

    #[test]
    fn sweep_dry_run_reports_but_mutates_nothing() {
        let mut reg = registry_with(&[("dead", "/s/dead"), ("gone", "/s/gone")]);
        let world = FakeWorld {
            present: RefCell::new(["/s/dead".to_string()].into()),
            on_disk: RefCell::new(["orphan".to_string()].into()),
            ..Default::default()
        };
        let opts = ConvergeOpts { dry_run: true };
        let report = sweep(&mut reg, &world, &world, &opts);
        assert_eq!(report.dead_process_reaped, vec!["dead".to_string()]);
        assert_eq!(report.stale_record_dropped, vec!["gone".to_string()]);
        assert_eq!(report.orphan_state_reaped, vec!["orphan".to_string()]);
        // Nothing actually happened.
        assert!(world.torn_down.borrow().is_empty());
        assert!(world.reaped.borrow().is_empty());
        assert!(reg.lookup("dead").is_some());
        assert!(reg.lookup("gone").is_some());
    }

    #[test]
    fn sweep_run_twice_is_a_no_op() {
        let mut reg = registry_with(&[
            ("live", "/s/live"),
            ("dead", "/s/dead"),
            ("gone", "/s/gone"),
        ]);
        let world = FakeWorld {
            present: RefCell::new(["/s/live".to_string(), "/s/dead".to_string()].into()),
            alive: RefCell::new(["/s/live".to_string()].into()),
            on_disk: RefCell::new(["orphan".to_string()].into()),
            ..Default::default()
        };

        let first = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert_eq!(first.reconciled_count(), 3, "first pass heals all drift");

        // Second pass over the converged world finds nothing to do.
        let second = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert!(second.is_clean(), "second pass must be a no-op: {second:?}");
        assert_eq!(second.live, vec!["live".to_string()]);
        assert!(second.dead_process_reaped.is_empty());
        assert!(second.stale_record_dropped.is_empty());
        assert!(second.orphan_state_reaped.is_empty());
    }

    #[test]
    fn sweep_keeps_record_and_records_error_when_teardown_fails() {
        let mut reg = registry_with(&[("vm1", "/s/vm1")]);
        let world = FakeWorld {
            present: RefCell::new(["/s/vm1".to_string()].into()),
            fail_teardown: ["/s/vm1".to_string()].into(),
            ..Default::default()
        };
        let report = sweep(&mut reg, &world, &world, &ConvergeOpts::default());
        assert!(report.dead_process_reaped.is_empty());
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert!(report.errors[0].contains("backend down"));
        // Fail-open + retry-next-pass: the record survives.
        assert!(reg.lookup("vm1").is_some());
    }

    // -------- FsRuntimeView / FsReconcileActions (real filesystem) --------

    #[test]
    fn fs_view_marks_record_live_only_when_pid_is_alive() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        // Our own pid is guaranteed alive; pid 2^31-1 is guaranteed dead.
        let live_dir = make_state_dir(root, "live", Some(std::process::id() as i32));
        let dead_dir = make_state_dir(root, "dead", Some(i32::MAX));

        let view = FsRuntimeView::new(root);
        let live = RegisterParams::minimal("live", &live_dir, "default");
        let dead = RegisterParams::minimal("dead", &dead_dir, "default");
        let mut reg = VmNameRegistry::default();
        reg.register_with_metadata(live).unwrap();
        reg.register_with_metadata(dead).unwrap();

        assert!(view.state_present(reg.lookup("live").unwrap()));
        assert!(view.process_alive(reg.lookup("live").unwrap()));
        assert!(view.state_present(reg.lookup("dead").unwrap()));
        assert!(!view.process_alive(reg.lookup("dead").unwrap()));
    }

    #[test]
    fn fs_view_record_no_state_when_dir_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let view = FsRuntimeView::new(tmp.path());
        let reg = RegisterParams::minimal("ghost", "/nonexistent/ghost", "default");
        let mut registry = VmNameRegistry::default();
        registry.register_with_metadata(reg).unwrap();
        assert!(!view.state_present(registry.lookup("ghost").unwrap()));
    }

    #[test]
    fn fs_view_orphan_dirs_excludes_known_and_live() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        make_state_dir(root, "registered", Some(i32::MAX));
        make_state_dir(root, "orphan", Some(i32::MAX)); // dead pid
        make_state_dir(root, "live-unregistered", Some(std::process::id() as i32));

        let view = FsRuntimeView::new(root);
        let known: BTreeSet<String> = ["registered".to_string()].into();
        let orphans = view.orphan_dirs(&known);
        assert_eq!(orphans, vec!["orphan".to_string()]);
    }

    #[test]
    fn fs_view_recognizes_live_hvf_supervisor_pid() {
        // Regression: the HVF backend records liveness in `hvf.pid`. The
        // reconciler must treat that as a live owner — otherwise every CLI
        // entry (which runs convergence) reaps a running HVF machine's state
        // dir, so `machine ls` reports it stopped and `machine shell` can't
        // find its agent socket.
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = root.join("hvf-vm");
        std::fs::create_dir_all(&dir).unwrap();
        // Only hvf.pid present (no libkrun.pid / fc.pid), pointing at us.
        std::fs::write(dir.join("hvf.pid"), std::process::id().to_string()).unwrap();

        let view = FsRuntimeView::new(root);
        let dir_str = dir.to_string_lossy().into_owned();
        let reg = RegisterParams::minimal("hvf-vm", &dir_str, "default");
        let mut registry = VmNameRegistry::default();
        registry.register_with_metadata(reg).unwrap();
        assert!(
            view.process_alive(registry.lookup("hvf-vm").unwrap()),
            "a live hvf.pid must count as a live supervisor"
        );
        assert!(
            view.orphan_dirs(&BTreeSet::new()).is_empty(),
            "a dir owned by a live hvf supervisor must not be reaped as an orphan"
        );
    }

    #[test]
    fn fs_view_recognizes_live_firecracker_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = root.join("firecracker-vm");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("fc.pid"), std::process::id().to_string()).unwrap();

        let view = FsRuntimeView::new(root);
        let dir_str = dir.to_string_lossy().into_owned();
        let reg = RegisterParams::minimal("firecracker-vm", &dir_str, "default");
        let mut registry = VmNameRegistry::default();
        registry.register_with_metadata(reg).unwrap();
        assert!(
            view.process_alive(registry.lookup("firecracker-vm").unwrap()),
            "a live fc.pid must count as a live Firecracker owner"
        );
        assert!(
            view.orphan_dirs(&BTreeSet::new()).is_empty(),
            "a dir owned by live Firecracker must not be reaped as an orphan"
        );
    }

    #[test]
    fn shared_liveness_rule_recognizes_qemu_pid() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("qemu.pid"), std::process::id().to_string()).unwrap();

        assert_eq!(
            mvm_vmm::host::process_liveness::live_process_pid_file(tmp.path()),
            Some(tmp.path().join("qemu.pid"))
        );
    }

    #[test]
    fn fs_actions_tear_down_removes_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let dir = make_state_dir(root, "vm1", Some(i32::MAX));
        let actions = FsReconcileActions::new(root);
        let reg = RegisterParams::minimal("vm1", &dir, "default");
        let mut registry = VmNameRegistry::default();
        registry.register_with_metadata(reg).unwrap();
        actions
            .tear_down("vm1", registry.lookup("vm1").unwrap())
            .unwrap();
        assert!(!Path::new(&dir).exists());
    }

    #[test]
    fn fs_actions_reap_orphan_removes_dir_under_root() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vms");
        make_state_dir(&root, "orphan", None);
        let actions = FsReconcileActions::new(&root);
        assert!(actions.reap_orphan("orphan").unwrap());
        assert!(!root.join("orphan").exists());
    }

    /// A restore fills the state dir before its supervisor is up, so for that
    /// window the dir has no pid and no record. The machine's lifecycle lock is
    /// the only thing that tells it apart from an orphan; a reconcile in
    /// another process must leave it alone while the lock is held.
    #[test]
    fn fs_actions_reap_orphan_leaves_a_dir_whose_lifecycle_lock_is_held() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vms");
        make_state_dir(&root, "restoring", None);
        let instance_dir = mvm_core::config::instances_root_at(tmp.path()).join("restoring");
        let _restore = crate::vm::instance_snapshot::try_lock_resume_in(&instance_dir)
            .unwrap()
            .expect("nothing else holds the lock");

        let actions = FsReconcileActions::new(&root);

        assert!(!actions.reap_orphan("restoring").unwrap());
        assert!(root.join("restoring").exists(), "the restore keeps its dir");
    }

    #[test]
    fn reap_unowned_state_dir_keeps_a_dir_with_a_live_supervisor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("vms");
        let dir = make_state_dir(&root, "restored", Some(std::process::id() as i32));

        let reaped = reap_unowned_state_dir(Path::new(&dir), &tmp.path().join("restored"));

        assert_eq!(reaped, Ok(false));
        assert!(Path::new(&dir).exists());
    }

    /// A deep state dir keeps its sockets under a short hashed namespace; a
    /// reap that removed only the state dir would leave a socket the next
    /// launch under the same name fails to bind.
    #[test]
    fn reap_unowned_state_dir_removes_a_dead_dir_and_its_separate_socket_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let vms_root = tmp.path().join("d".repeat(120)).join("vms");
        let dir = PathBuf::from(make_state_dir(&vms_root, "stopped", None));
        let socket_dir = mvm_core::config::vm_socket_dir_at(&dir);
        assert_ne!(socket_dir, dir, "the fixture must keep its sockets apart");
        std::fs::create_dir_all(&socket_dir).unwrap();
        std::fs::write(socket_dir.join("substitution-endpoint.sock"), b"").unwrap();

        let reaped = reap_unowned_state_dir(&dir, &tmp.path().join("instances").join("stopped"));

        assert_eq!(reaped, Ok(true));
        assert!(!dir.exists());
        assert!(!socket_dir.exists());
    }

    #[test]
    fn reap_unowned_state_dir_takes_no_lock_for_a_machine_with_no_state() {
        let tmp = tempfile::tempdir().unwrap();
        let instance_dir = tmp.path().join("instances").join("never-started");

        let reaped =
            reap_unowned_state_dir(&tmp.path().join("vms").join("never-started"), &instance_dir);

        assert_eq!(reaped, Ok(true));
        assert!(!instance_dir.exists());
    }

    #[test]
    fn a_held_lifecycle_lock_shields_a_dir_from_reap_orphan_state_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let vms_root = tmp.path().join("vms");
        make_state_dir(&vms_root, "restoring", None);
        make_state_dir(&vms_root, "dead-orphan", None);
        let registry_path = tmp.path().join("registry.json");
        VmNameRegistry::default().save(&registry_path).unwrap();
        let instance_dir = mvm_core::config::instances_root_at(tmp.path()).join("restoring");
        let _restore = crate::vm::instance_snapshot::try_lock_resume_in(&instance_dir)
            .unwrap()
            .expect("nothing else holds the lock");

        let reaped = reap_orphan_state_dirs_at(&registry_path, &vms_root, None);

        assert_eq!(reaped, vec!["dead-orphan".to_string()]);
        assert!(vms_root.join("restoring").exists());
    }

    #[test]
    fn reap_orphan_state_dirs_reaps_only_dead_unprotected_orphans() {
        let tmp = tempfile::tempdir().unwrap();
        let vms_root = tmp.path().join("vms");
        std::fs::create_dir_all(&vms_root).unwrap();

        // A registered VM with a dead process is a *record*, not an orphan: the
        // narrow reap leaves registry records untouched (tearing them down is
        // converge's job, not this side-effect-free sweep).
        let registered_dir = make_state_dir(&vms_root, "registered-dead", None);
        let registry_path = tmp.path().join("registry.json");
        let mut registry = VmNameRegistry::default();
        registry
            .register_with_metadata(RegisterParams::minimal(
                "registered-dead",
                &registered_dir,
                "default",
            ))
            .unwrap();
        registry.save(&registry_path).unwrap();

        // A live orphan (no record, live supervisor) — shielded by liveness.
        make_state_dir(&vms_root, "live-orphan", Some(std::process::id() as i32));
        // The in-flight run's own dir (dead, no record) — shielded by `protect`.
        make_state_dir(&vms_root, "current-run", None);
        // A dead orphan (no record, no live process, unprotected) — reaped.
        make_state_dir(&vms_root, "dead-orphan", Some(i32::MAX));

        let reaped = reap_orphan_state_dirs_at(&registry_path, &vms_root, Some("current-run"));

        assert_eq!(reaped, vec!["dead-orphan".to_string()]);
        assert!(!vms_root.join("dead-orphan").exists(), "dead orphan reaped");
        assert!(
            vms_root.join("registered-dead").exists(),
            "a registry record is not an orphan"
        );
        assert!(
            vms_root.join("live-orphan").exists(),
            "live orphan shielded"
        );
        assert!(
            vms_root.join("current-run").exists(),
            "the protected in-flight run is shielded"
        );
    }

    #[test]
    fn reap_orphan_state_dirs_reaps_nothing_when_the_registry_is_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        let vms_root = tmp.path().join("vms");
        std::fs::create_dir_all(&vms_root).unwrap();
        make_state_dir(&vms_root, "would-be-orphan", None);
        // A corrupt registry fails safe: reap nothing rather than risk a
        // registered VM's dir on a transient read error.
        let registry_path = tmp.path().join("registry.json");
        std::fs::write(&registry_path, b"not valid json {").unwrap();

        let reaped = reap_orphan_state_dirs_at(&registry_path, &vms_root, None);

        assert!(reaped.is_empty());
        assert!(vms_root.join("would-be-orphan").exists());
    }

    #[test]
    fn fs_actions_tear_down_absent_dir_is_ok() {
        let tmp = tempfile::tempdir().unwrap();
        let actions = FsReconcileActions::new(tmp.path());
        let reg = RegisterParams::minimal("gone", "/nonexistent/gone", "default");
        let mut registry = VmNameRegistry::default();
        registry.register_with_metadata(reg).unwrap();
        // Idempotent: tearing down already-gone state is a clean no-op.
        actions
            .tear_down("gone", registry.lookup("gone").unwrap())
            .unwrap();
    }

    // -------- converge (default-path entry + audit emission) --------

    #[test]
    fn converge_default_heals_drift_and_emits_audit() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("mvm-root");
        std::fs::create_dir_all(root.join("vms")).unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", root.to_str().unwrap());

        // A dead-process record under the relocated vms root + its registry.
        let vms_root = root.join("vms");
        let dead_dir = make_state_dir(&vms_root, "dead", Some(i32::MAX));
        let mut reg = VmNameRegistry::default();
        reg.register_with_metadata(RegisterParams::minimal("dead", &dead_dir, "default"))
            .unwrap();
        reg.save(&crate::vm::name_registry::registry_path())
            .unwrap();

        let report = converge(&ConvergeOpts::default());
        assert_eq!(report.dead_process_reaped, vec!["dead".to_string()]);

        // Record deregistered on disk.
        let reloaded = VmNameRegistry::load(&crate::vm::name_registry::registry_path()).unwrap();
        assert!(reloaded.lookup("dead").is_none());

        // Audit line emitted to the local log (default path under state dir).
        let audit = std::fs::read_to_string(root.join("state/log/audit.jsonl")).unwrap_or_default();
        assert!(
            audit.contains("registry_reconcile") && audit.contains("dead_process_left_state"),
            "expected a registry_reconcile audit line, got: {audit}"
        );
    }

    #[test]
    fn converge_default_is_clean_with_empty_registry() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let mut env = TestEnv::new();
        env.set("MVM_HOME", tmp.path().join("mvm-root").to_str().unwrap());
        // No registry file, no vms dir — fail-open, clean report, no panic.
        let report = converge(&ConvergeOpts::default());
        assert!(report.is_clean(), "{report:?}");
    }

    // -------- converge_at (registry load/save adapter) --------

    #[test]
    fn converge_at_heals_drift_and_persists_registry() {
        let tmp = tempfile::tempdir().unwrap();
        let vms_root = tmp.path().join("vms");
        std::fs::create_dir_all(&vms_root).unwrap();
        let registry_path = tmp.path().join("vm-names.json");

        let live_dir = make_state_dir(&vms_root, "live", Some(std::process::id() as i32));
        let dead_dir = make_state_dir(&vms_root, "dead", Some(i32::MAX));
        make_state_dir(&vms_root, "orphan", Some(i32::MAX)); // dead, no record

        let mut reg = VmNameRegistry::default();
        reg.register_with_metadata(RegisterParams::minimal("live", &live_dir, "default"))
            .unwrap();
        reg.register_with_metadata(RegisterParams::minimal("dead", &dead_dir, "default"))
            .unwrap();
        reg.register_with_metadata(RegisterParams::minimal(
            "gone",
            "/nonexistent/gone",
            "default",
        ))
        .unwrap();
        reg.save(&registry_path).unwrap();

        let report = converge_at(&registry_path, &vms_root, &ConvergeOpts::default());
        assert_eq!(report.live, vec!["live".to_string()]);
        assert_eq!(report.dead_process_reaped, vec!["dead".to_string()]);
        assert_eq!(report.stale_record_dropped, vec!["gone".to_string()]);
        assert_eq!(report.orphan_state_reaped, vec!["orphan".to_string()]);

        // Persisted: only the live record remains; orphan + dead state gone.
        let reloaded = VmNameRegistry::load(&registry_path).unwrap();
        assert_eq!(reloaded.names(), vec!["live"]);
        assert!(!Path::new(&dead_dir).exists());
        assert!(!vms_root.join("orphan").exists());
        assert!(Path::new(&live_dir).exists());

        // Idempotent on disk: a second pass is clean and rewrites nothing.
        let again = converge_at(&registry_path, &vms_root, &ConvergeOpts::default());
        assert!(
            again.is_clean(),
            "second converge_at must be clean: {again:?}"
        );
    }

    #[test]
    fn converge_at_dry_run_leaves_registry_and_disk_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let vms_root = tmp.path().join("vms");
        std::fs::create_dir_all(&vms_root).unwrap();
        let registry_path = tmp.path().join("vm-names.json");
        let dead_dir = make_state_dir(&vms_root, "dead", Some(i32::MAX));
        let mut reg = VmNameRegistry::default();
        reg.register_with_metadata(RegisterParams::minimal("dead", &dead_dir, "default"))
            .unwrap();
        reg.save(&registry_path).unwrap();

        let report = converge_at(&registry_path, &vms_root, &ConvergeOpts { dry_run: true });
        assert_eq!(report.dead_process_reaped, vec!["dead".to_string()]);
        // Disk + registry untouched.
        assert!(Path::new(&dead_dir).exists());
        assert!(
            VmNameRegistry::load(&registry_path)
                .unwrap()
                .lookup("dead")
                .is_some()
        );
    }

    #[test]
    fn converge_at_fails_open_on_unreadable_registry() {
        let tmp = tempfile::tempdir().unwrap();
        // A directory where a registry file is expected → read_to_string errors.
        let registry_path = tmp.path().join("vm-names.json");
        std::fs::create_dir_all(&registry_path).unwrap();
        let report = converge_at(&registry_path, tmp.path(), &ConvergeOpts::default());
        assert_eq!(report.errors.len(), 1, "{report:?}");
        assert!(report.errors[0].contains("load registry"));
        // Fail-open: no panic, returns a report.
        assert!(report.live.is_empty());
    }

    #[test]
    fn classify_is_deterministic_across_record_and_orphan_order() {
        let reg = registry_with(&[("beta", "/s/beta"), ("alpha", "/s/alpha")]);
        let view = FakeView {
            present: ["/s/alpha".to_string(), "/s/beta".to_string()].into(),
            alive: ["/s/alpha".to_string(), "/s/beta".to_string()].into(),
            on_disk: ["zeta".to_string(), "gamma".to_string()].into(),
            ..Default::default()
        };
        assert_eq!(
            classify(&reg, &view),
            vec![
                Drift::Live {
                    name: "alpha".to_string()
                },
                Drift::Live {
                    name: "beta".to_string()
                },
                Drift::OrphanStateNoRecord {
                    dir: "gamma".to_string()
                },
                Drift::OrphanStateNoRecord {
                    dir: "zeta".to_string()
                },
            ]
        );
    }
}
