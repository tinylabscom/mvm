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
//! helper-PID argv sweep stays in `mvmctl cache prune --reap-orphans`. This
//! reuses the live-vs-orphan discrimination from `mvm-cli`'s
//! `env::dev_vz` reaper rather than reinventing the policy; the bare
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
    /// Reap an orphan state dir (basename) that has no record.
    fn reap_orphan(&self, dir: &str) -> Result<(), String>;
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
            Drift::OrphanStateNoRecord { dir } => {
                if opts.dry_run {
                    report.orphan_state_reaped.push(dir);
                    continue;
                }
                match actions.reap_orphan(&dir) {
                    Ok(()) => report.orphan_state_reaped.push(dir),
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

/// Supervisor pid-file names a per-VM state dir may carry. `pid` is the
/// Apple-Container dev-VM owner file; `libkrun.pid` / `vz.pid` are the
/// workload-supervisor files. The first one that exists and points at a
/// live process marks the dir as having a live owner.
const PID_FILE_NAMES: &[&str] = &["libkrun.pid", "vz.pid", "pid"];

/// `kill(pid, 0)` existence probe — delivers no signal, just checks the
/// process is alive. The cheap half of the live-vs-orphan discrimination
/// (see module docs); the heavier argv/ppid sweep stays in `cache prune`.
fn pid_is_alive(pid: i32) -> bool {
    // SAFETY: kill with signal 0 performs only a permission/existence
    // check and never delivers a signal.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn read_pid_file(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 1)
}

/// Does `dir` carry a supervisor pid file pointing at a live process?
fn dir_has_live_process(dir: &Path) -> bool {
    PID_FILE_NAMES
        .iter()
        .filter_map(|f| read_pid_file(&dir.join(f)))
        .any(pid_is_alive)
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
/// (`{mvm_data_dir}/vms`). State presence is a `stat`; liveness is
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
        dir_has_live_process(Path::new(&reg.vm_dir))
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
            if known.contains(name) || dir_has_live_process(&path) {
                continue;
            }
            out.push(name.to_string());
        }
        out
    }
}

/// Real-filesystem [`ReconcileActions`] rooted at the same `vms` dir.
pub struct FsReconcileActions {
    vms_root: PathBuf,
}

impl FsReconcileActions {
    pub fn new(vms_root: impl Into<PathBuf>) -> Self {
        Self {
            vms_root: vms_root.into(),
        }
    }
}

impl ReconcileActions for FsReconcileActions {
    fn tear_down(&self, _name: &str, reg: &VmRegistration) -> Result<(), String> {
        remove_state_dir(Path::new(&reg.vm_dir))
    }
    fn reap_orphan(&self, dir: &str) -> Result<(), String> {
        remove_state_dir(&self.vms_root.join(dir))
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
    let actions = FsReconcileActions::new(vms_root);
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
    let vms_root = PathBuf::from(mvm_core::config::mvm_data_dir()).join("vms");
    let report = converge_at(&registry_path, &vms_root, opts);
    if !opts.dry_run {
        emit_audit(&report);
    }
    report
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::name_registry::RegisterParams;
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
    }

    impl RuntimeView for FakeWorld {
        fn state_present(&self, reg: &VmRegistration) -> bool {
            self.present.borrow().contains(&reg.vm_dir)
        }
        fn process_alive(&self, reg: &VmRegistration) -> bool {
            self.alive.borrow().contains(&reg.vm_dir)
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
        fn reap_orphan(&self, dir: &str) -> Result<(), String> {
            self.on_disk.borrow_mut().remove(dir);
            self.reaped.borrow_mut().push(dir.to_string());
            Ok(())
        }
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
        let root = tmp.path();
        make_state_dir(root, "orphan", None);
        let actions = FsReconcileActions::new(root);
        actions.reap_orphan("orphan").unwrap();
        assert!(!root.join("orphan").exists());
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

    /// RAII env-var setter that restores the previous value on drop, so a
    /// panicking assertion can't leak `MVM_*` overrides into sibling tests.
    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }
    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var(key).ok();
            // SAFETY: tests under this block hold DATA_DIR_TEST_LOCK, so no
            // other thread mutates these vars concurrently.
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn converge_default_heals_drift_and_emits_audit() {
        let _lock = crate::vm::DATA_DIR_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let share = tmp.path().join("share");
        let data = tmp.path().join("data");
        let state = tmp.path().join("state");
        std::fs::create_dir_all(data.join("vms")).unwrap();
        let _g1 = EnvGuard::set("MVM_SHARE_DIR", share.to_str().unwrap());
        let _g2 = EnvGuard::set("MVM_DATA_DIR", data.to_str().unwrap());
        let _g3 = EnvGuard::set("MVM_STATE_DIR", state.to_str().unwrap());

        // A dead-process record under the relocated vms root + its registry.
        let vms_root = data.join("vms");
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
        let audit = std::fs::read_to_string(state.join("log/audit.jsonl")).unwrap_or_default();
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
        let _g1 = EnvGuard::set("MVM_SHARE_DIR", tmp.path().join("share").to_str().unwrap());
        let _g2 = EnvGuard::set("MVM_DATA_DIR", tmp.path().join("data").to_str().unwrap());
        let _g3 = EnvGuard::set("MVM_STATE_DIR", tmp.path().join("state").to_str().unwrap());
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
