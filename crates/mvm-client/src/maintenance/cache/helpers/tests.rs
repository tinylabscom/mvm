use super::*;
use mvm_vmm::host::process_liveness::GuardedSignal;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// Entirely local observations: fixture PIDs never reach a host probe or signal.
pub(super) struct ProcessObservations {
    alive: HashSet<i32>,
    signals: RefCell<Vec<i32>>,
    outcome: SignalOutcome,
}

#[derive(Clone, Copy)]
enum SignalOutcome {
    Sent,
    SentStillAlive,
    Exited,
    Refused,
    PermissionDenied,
}

impl ProcessObservations {
    pub(super) fn is_alive(&self, pid: i32) -> bool {
        self.alive.contains(&pid)
            && (matches!(
                self.outcome,
                SignalOutcome::SentStillAlive
                    | SignalOutcome::Refused
                    | SignalOutcome::PermissionDenied
            ) || !self.signals.borrow().contains(&pid))
    }

    pub(super) fn signal(&self, pid: i32) -> std::io::Result<GuardedSignal> {
        self.signals.borrow_mut().push(pid);
        match self.outcome {
            SignalOutcome::Sent | SignalOutcome::SentStillAlive => Ok(GuardedSignal::Sent),
            SignalOutcome::Exited => Ok(GuardedSignal::Exited),
            SignalOutcome::Refused => Ok(GuardedSignal::Refused(None)),
            SignalOutcome::PermissionDenied => {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            }
        }
    }
}

fn fixture(parents: HashMap<i32, i32>, cmds: Vec<(i32, String)>) -> ProcSnapshot {
    let alive = parents.keys().copied().collect();
    ProcSnapshot {
        parents,
        cmds,
        executables: Default::default(),
        observations: Some(ProcessObservations {
            alive,
            signals: Default::default(),
            outcome: SignalOutcome::Sent,
        }),
    }
}

fn signals(snapshot: &ProcSnapshot) -> Vec<i32> {
    snapshot
        .observations
        .as_ref()
        .unwrap()
        .signals
        .borrow()
        .clone()
}

fn scope(root: &std::path::Path, workload: bool) -> ReapScope<'_> {
    ReapScope {
        vms_root: root,
        sidecars: if workload {
            WORKLOAD_SIDECARS
        } else {
            BUILDER_SIDECARS
        },
        remove_dead_dirs: true,
        all_dirs_managed: workload,
        dry_run: false,
    }
}

fn vm(root: &std::path::Path, name: &str, marker: &str, pid: i32) -> std::path::PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(marker), format!("{pid}\n")).unwrap();
    dir
}

#[test]
fn reap_picks_up_orphaned_builder_state_dir_regardless_of_prefix() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let builder_dir = vm(
        tmp.path(),
        "mvm-builder-unrecognised-prefix-abc12345",
        "builder.pid",
        42,
    );
    // The marker is real; the injected observation says that owner is dead.
    // Directory naming must not restrict discovery or cleanup.
    let snapshot = fixture(Default::default(), Vec::new());
    let outcome = reap_orphaned_vm_helpers_at(&scope(tmp.path(), false), &snapshot)
        .expect("reap should succeed");
    assert_eq!(
        outcome.removed_dirs, 1,
        "builder state dir should be reaped whatever its prefix"
    );
    assert!(
        !builder_dir.exists(),
        "builder state dir should be gone on disk"
    );
    assert!(signals(&snapshot).is_empty());
}

#[test]
fn missing_vms_root_is_empty_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("does-not-exist");
    let snapshot = fixture(Default::default(), Vec::new());
    let out = reap_orphaned_vm_helpers_at(&scope(&root, false), &snapshot).unwrap();
    assert_eq!(out.killed, 0);
    assert_eq!(out.removed_dirs, 0);
    assert_eq!(out.freed_bytes, 0);
    assert!(signals(&snapshot).is_empty());
}

#[test]
fn dead_pids_get_their_dirs_swept() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(
        root.path(),
        "mvm-stage0-99999-1234567890",
        "builder.pid",
        42,
    );
    std::fs::write(vm.join("payload"), vec![0u8; 1024]).unwrap();
    std::fs::write(
        vm.join("builder-egress-runtime.json"),
        br#"{"state":"bound","socket_path":"/tmp/vsock-5253.sock"}"#,
    )
    .unwrap();
    let snapshot = fixture(Default::default(), Vec::new());
    let out = reap_orphaned_vm_helpers_at(&scope(root.path(), false), &snapshot).unwrap();
    assert_eq!(out.killed, 0, "no live PID, so nothing to kill");
    assert_eq!(out.removed_dirs, 1, "dir should be removed");
    assert!(
        out.freed_bytes >= 1024,
        "payload and evidence sidecars should be counted"
    );
    assert!(!vm.exists(), "dir should be gone");
    assert!(signals(&snapshot).is_empty());
}

#[test]
fn live_owner_preserves_dir_in_dry_run_and_real() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(root.path(), "mvm-stage0-pid-of-self", "builder.pid", 42);
    let snapshot = fixture([(42, 41)].into(), Vec::new());
    for dry_run in [true, false] {
        let mut scope = scope(root.path(), false);
        scope.dry_run = dry_run;
        let out = reap_orphaned_vm_helpers_at(&scope, &snapshot).unwrap();
        assert_eq!(out.killed, 0, "live owner should not be killed");
        assert_eq!(out.removed_dirs, 0, "dir preserved while owner alive");
        assert!(vm.exists(), "dir should still be on disk");
        assert!(snapshot.is_alive(42));
        assert!(signals(&snapshot).is_empty());
    }
}

#[test]
fn workload_root_preserves_dir_with_dead_pid() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(
        root.path(),
        "mvm-workload-reaptest-7f3a9c-deadpid",
        "libkrun.pid",
        42,
    );
    std::fs::write(vm.join("config"), vec![0u8; 512]).unwrap();
    let mut scope = scope(root.path(), true);
    scope.remove_dead_dirs = false;
    let out =
        reap_orphaned_vm_helpers_at(&scope, &fixture(Default::default(), Vec::new())).unwrap();
    assert_eq!(out.killed, 0, "dead PID, nothing to kill");
    assert_eq!(out.removed_dirs, 0, "workload dir must never be removed");
    assert!(vm.exists(), "workload VM state dir must survive the sweep");
    assert!(vm.join("config").exists(), "persistent state untouched");
}

#[test]
fn a_finished_builder_job_under_the_workload_root_is_pruned() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(
        root.path(),
        &mvm_core::naming::builder_shell_vm_name("4242-9999"),
        "hvf.pid",
        42,
    );
    std::fs::write(vm.join("payload"), vec![0u8; 2048]).unwrap();
    let out = reap_orphaned_vm_helpers_at(
        &scope(root.path(), true),
        &fixture(Default::default(), Vec::new()),
    )
    .unwrap();
    assert_eq!(out.removed_dirs, 1, "a dead per-job builder dir is garbage");
    assert!(!vm.exists(), "the job dir should be gone");
    assert!(out.freed_bytes >= 2048);
}

#[test]
fn the_persistent_builder_dir_is_never_pruned() {
    let root = tempfile::tempdir().unwrap();
    let name = mvm_core::naming::persistent_builder_vm_name(
        mvm_core::naming::BuilderVmSlot::Hvf,
        "session",
    );
    let vm = vm(root.path(), &name, "hvf.pid", 42);
    let out = reap_orphaned_vm_helpers_at(
        &scope(root.path(), true),
        &fixture(Default::default(), Vec::new()),
    )
    .unwrap();
    assert_eq!(out.removed_dirs, 0);
    assert!(vm.exists(), "the warm store must survive a prune");
}

#[test]
fn granting_builder_prune_does_not_reach_a_stopped_machine() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(root.path(), "web", "libkrun.pid", 42);
    let out = reap_orphaned_vm_helpers_at(
        &scope(root.path(), true),
        &fixture(Default::default(), Vec::new()),
    )
    .unwrap();
    assert_eq!(out.removed_dirs, 0);
    assert!(vm.exists(), "a stopped machine keeps its state dir");
}

#[test]
fn dry_run_does_not_mutate() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(root.path(), "mvm-stage0-dryrun-test", "builder.pid", 42);
    std::fs::write(vm.join("payload"), vec![0u8; 256]).unwrap();
    let mut scope = scope(root.path(), false);
    scope.dry_run = true;
    let snapshot = fixture(Default::default(), Vec::new());
    let out = reap_orphaned_vm_helpers_at(&scope, &snapshot).unwrap();
    assert_eq!(out.removed_dirs, 1);
    assert!(vm.exists(), "dry-run must not remove the dir");
    assert!(vm.join("builder.pid").exists(), "pid file untouched");
    assert!(signals(&snapshot).is_empty());
}

fn assert_managed_supervisor_spared(name: &str, marker: &str, workload: bool) {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(root.path(), name, marker, 42);
    let snapshot = fixture([(42, 1)].into(), Vec::new());
    let out = reap_orphaned_vm_helpers_at(&scope(root.path(), workload), &snapshot).unwrap();
    assert_eq!(out.killed, 0, "live VM supervisor must not be signalled");
    assert_eq!(out.removed_dirs, 0, "live VM dir must be preserved");
    assert!(vm.exists());
    assert!(
        snapshot.is_alive(42),
        "live VM supervisor was wrongly killed"
    );
    assert!(signals(&snapshot).is_empty());
}

#[test]
fn reap_spares_live_persistent_dev_vm_under_launchd() {
    assert_managed_supervisor_spared("mvm-persistent-builder-hvf-dev", "builder.pid", false);
}

#[test]
fn reap_spares_live_named_workload_under_launchd() {
    assert_managed_supervisor_spared("mvm-workload-livetest-3b1f-running", "libkrun.pid", true);
}

#[test]
fn reap_spares_live_hvf_workload_under_launchd() {
    assert_managed_supervisor_spared("mvm-workload-livetest-hvf-running", "hvf.pid", true);
}

fn assert_workload_helper_spared(name: &str, marker: &str) {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(root.path(), name, marker, 42);
    let snapshot = fixture(
        [(42, 1), (43, 1)].into(),
        vec![(43, format!("/fixture/helper --state {}", vm.display()))],
    );
    let mut scope = scope(root.path(), true);
    scope.remove_dead_dirs = false;
    let out = reap_orphaned_vm_helpers_at(&scope, &snapshot).unwrap();
    assert_eq!(out.killed, 0, "a live supervisor must protect its helper");
    assert!(
        snapshot.is_alive(43),
        "helper of live VM was wrongly killed"
    );
    assert!(signals(&snapshot).is_empty());
}

#[test]
fn reap_spares_live_qemu_workload_under_launchd() {
    assert_workload_helper_spared("mvm-workload-livetest-qemu-running", "qemu.pid");
}

#[test]
fn reap_spares_live_firecracker_workload_under_launchd() {
    assert_workload_helper_spared("mvm-workload-livetest-fc-running", "fc.pid");
}

#[test]
fn reap_still_kills_orphaned_ephemeral_builder_under_launchd() {
    let root = tempfile::tempdir().unwrap();
    vm(root.path(), "mvm-builder-hvf-abc12345", "builder.pid", 42);
    let snapshot = fixture([(42, 1)].into(), Vec::new());
    let out = reap_orphaned_vm_helpers_at(&scope(root.path(), false), &snapshot).unwrap();
    assert_eq!(out.killed, 1, "orphaned ephemeral builder must be reaped");
    assert_eq!(signals(&snapshot), [42]);
}

#[test]
fn reap_spares_live_helper_of_live_workload() {
    assert_workload_helper_spared("mvm-workload-livehelper-9c2a-running", "libkrun.pid");
}

#[test]
fn reap_kills_leaked_helper_of_dead_workload() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(
        root.path(),
        "mvm-workload-deadhelper-4e7b-stopped",
        "libkrun.pid",
        42,
    );
    let snapshot = fixture(
        [(43, 1)].into(),
        vec![(43, format!("/fixture/helper --state {}", vm.display()))],
    );
    let mut scope = scope(root.path(), true);
    scope.remove_dead_dirs = false;
    let out = reap_orphaned_vm_helpers_at(&scope, &snapshot).unwrap();
    assert_eq!(
        out.killed, 1,
        "leaked helper of a stopped VM must be reaped"
    );
    assert_eq!(signals(&snapshot), [43]);
}

#[test]
fn prune_spares_stopped_persistent_builder_store() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(
        root.path(),
        "mvm-persistent-builder-hvf-dev",
        "builder.pid",
        42,
    );
    std::fs::write(vm.join("store"), vec![0u8; 4096]).unwrap();
    let out = reap_orphaned_vm_helpers_at(
        &scope(root.path(), false),
        &fixture(Default::default(), Vec::new()),
    )
    .unwrap();
    assert_eq!(
        out.removed_dirs, 0,
        "persistent builder dir must not be pruned"
    );
    assert!(
        vm.exists(),
        "persistent builder store dir must survive prune"
    );
    assert!(vm.join("store").exists(), "warm store payload untouched");
}

#[test]
fn prune_still_reclaims_dead_ephemeral_builder() {
    let root = tempfile::tempdir().unwrap();
    let vm = vm(root.path(), "mvm-builder-hvf-deadjob1", "builder.pid", 42);
    let out = reap_orphaned_vm_helpers_at(
        &scope(root.path(), false),
        &fixture(Default::default(), Vec::new()),
    )
    .unwrap();
    assert_eq!(
        out.removed_dirs, 1,
        "dead ephemeral builder dir must be reclaimed"
    );
    assert!(!vm.exists(), "ephemeral builder dir should be gone");
}

#[test]
fn startup_reaps_builder_egress_supervisor_from_another_worktree() {
    let snapshot = fixture(
        [(42, 1)].into(),
        vec![(42, "/tmp/other-worktree/target/debug/mvmctl __builder-egress-supervisor --endpoint /tmp/other-worktree/target/debug/mvm-network-endpoint".into())],
    );
    assert_eq!(
        reap_orphaned_builder_egress_supervisors(true, &snapshot),
        1,
        "a launchd-parented builder egress wrapper is orphaned regardless of worktree"
    );
    assert!(signals(&snapshot).is_empty(), "preview must never signal");
    assert_eq!(
        reap_orphaned_builder_egress_supervisors(false, &snapshot),
        1
    );
    assert_eq!(signals(&snapshot), [42]);
}

#[test]
fn startup_spares_owned_or_unrelated_mvmctl_processes() {
    for (parent, command) in [
        (
            42,
            "/tmp/worktree/target/debug/mvmctl __builder-egress-supervisor --endpoint /tmp/endpoint",
        ),
        (1, "/tmp/worktree/target/debug/mvmctl machine ls"),
        (
            1,
            "/tmp/worktree/target/debug/not-mvmctl __builder-egress-supervisor",
        ),
        (
            1,
            "/tmp/worktree/target/debug/mvmctl machine run __builder-egress-supervisor",
        ),
    ] {
        let snapshot = fixture([(43, parent)].into(), vec![(43, command.into())]);
        assert_eq!(reap_orphaned_builder_egress_supervisors(true, &snapshot), 0);
        assert_eq!(
            reap_orphaned_builder_egress_supervisors(false, &snapshot),
            0
        );
        assert!(signals(&snapshot).is_empty());
    }
}

#[test]
fn guarded_signal_outcomes_control_reconciliation() {
    for (outcome, killed, removed) in [
        (SignalOutcome::Sent, 1, 1),
        (SignalOutcome::SentStillAlive, 1, 0),
        (SignalOutcome::Exited, 0, 1),
        (SignalOutcome::Refused, 0, 0),
        (SignalOutcome::PermissionDenied, 0, 0),
    ] {
        let root = tempfile::tempdir().unwrap();
        let vm = vm(root.path(), "mvm-builder-vm-fixture", "builder.pid", 42);
        let mut snapshot = fixture([(42, 1)].into(), Vec::new());
        snapshot.observations.as_mut().unwrap().outcome = outcome;
        let out = reap_orphaned_vm_helpers_at(&scope(root.path(), false), &snapshot).unwrap();
        assert_eq!(out.killed, killed);
        assert_eq!(out.removed_dirs, removed);
        assert_eq!(vm.exists(), removed == 0);
        assert_eq!(signals(&snapshot), [42]);
    }
}
