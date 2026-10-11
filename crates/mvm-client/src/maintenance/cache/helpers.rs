use anyhow::Result;

pub(crate) use reap_orphaned_vm_helpers as reap;

/// Outcome of [`reap_orphaned_vm_helpers`]. Counts
/// orphaned helper PIDs that were signalled and per-VM cache dirs
/// removed, plus the bytes freed by removing those dirs. Pruner-side
/// caller uses this to print a clean one-line summary.
#[derive(Debug, Default)]
pub struct ReapOutcome {
    pub killed: u64,
    pub removed_dirs: u64,
    pub freed_bytes: u64,
}

/// Reap orphaned per-VM helpers left behind by killed
/// mvmctl runs. Covers each backend's supervisor
/// (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`).
///
/// mvmctl spawns the active backend's supervisor binary, which in turn
/// may spawn auxiliary per-VM helpers. If mvmctl exits abnormally (^C,
/// SIGKILL, crash), supervisor + helpers are reparented to launchd PID 1
/// and outlive mvmctl indefinitely. This is the "clean up after the fact"
/// side, distinct from the prevention path.
///
/// The dir traversal below is **prefix-agnostic**: it iterates every
/// subdirectory of `~/.mvm/cache/builder-vm/vms/` regardless of naming, so
/// `mvm-builder-vm-<job_id>` (libkrun) and HVF builder state dirs are picked
/// up by the same loop, and the sidecar PID names (`builder.pid` /
/// `stage0.pid`) are shared across backends. The
/// `reap_picks_up_orphaned_builder_state_dir_regardless_of_prefix` test pins
/// that: a future refactor narrowing the traversal or renaming the sidecar
/// must update it.
///
/// The persistent builder egress wrapper is the one exception to root-scoped
/// discovery. Its exact argv identifies an internal process whose owner is
/// always a live `BuilderVsockEgressEndpoint` guard. A wrapper reparented to
/// init/launchd is therefore unambiguously orphaned, so the same snapshot also
/// finds and reaps those wrappers across worktree-specific `MVM_HOME` roots.
///
/// A microVM is several processes: the supervisor (the VMM-host that
/// owns the guest) plus dependent helpers (for example a
/// `tail -F console.log` reader). The supervisor is the authoritative
/// liveness signal, so the sweep runs in two phases per dir:
///
/// 1. **Supervisor phase.** Read the supervisor sidecars (`builder.pid` /
///    `stage0.pid` / `libkrun.pid` / `hvf.pid`: see
///    [`is_supervisor_sidecar`]). On a managed dir (the persistent dev
///    builder `mvm-persistent-builder-*`, or any named workload under
///    `~/.mvm/vms/`) an alive supervisor is the running VM, spared:
///    those supervisors are detached under launchd by design to
///    outlive the spawning CLI, so `parent == launchd` is their steady
///    state, not an orphan signal. They are stopped only by explicit
///    `dev down` / `stop <name>`. On an ephemeral per-job builder dir,
///    an alive launchd-parented supervisor is a build whose CLI crashed
///    and should be SIGTERM'd. Without the managed carve-out the startup
///    sweep kills the live dev VM on every `cache prune` / `image pull`.
/// 2. **Helper phase.** Any argv-scanned grandchildren whose argv
///    carries the dir's unique basename. A helper's fate follows its
///    supervisor: if Phase 1 found the VM live every helper is spared;
///    once the supervisor is gone a still-running launchd-parented
///    helper is a leak and is SIGTERM'd.
///
/// Per PID the verdict ([`classify_pid_for_dir`]) is dead => ignore;
/// alive non-launchd parent => live owner, spared; alive launchd parent
/// => leak, SIGTERM'd, unless `protected` for that phase.
///
/// Then an ephemeral per-job builder dir with no live owner is removed
/// (cache-prune semantics). That is intentionally whole-dir removal, not
/// per-file cleanup: every per-run evidence sidecar under the dir
/// (including `builder-egress-runtime.json`) disappears atomically with the
/// dead builder state. A managed dir is never auto-removed: the persistent
/// dev builder's dir is its warm Nix store and a named workload's dir is
/// restartable state. Both are torn down only by explicit `dev down` /
/// `stop` / manual removal, not by routine prune.
pub fn reap_orphaned_vm_helpers(dry_run: bool) -> Result<ReapOutcome> {
    reap_orphaned_vm_helpers_both_roots(/* remove_builder_dirs = */ true, dry_run)
}

/// Best-effort orphan-helper sweep run at the start of `mvmctl image pull`
/// and the OCI run-image path. The next launch reaps the previous run's
/// corpses: startup is the robust trigger because an abnormal exit (^C, SIGKILL,
/// crash, the libkrun `krun_start_enter` `exit()`) is exactly when the CLI
/// can't self-clean and reparents its helpers to launchd.
///
/// Reclaims dead ephemeral builder state as well as signalling orphaned
/// helpers, using the same classification as explicit cache maintenance.
/// Quiet on the happy path and swallows errors because a sweep failure
/// must never block a launch.
pub fn sweep_orphaned_vm_helpers_on_startup() {
    match reap_orphaned_vm_helpers(false) {
        Ok(o) if o.killed > 0 => tracing::info!(
            "Reaped {} orphaned VM helper(s) left by a prior run.",
            o.killed
        ),
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(error = %e, "startup orphan-helper sweep failed (non-fatal)")
        }
    }
}

/// Reap orphaned helpers once, immediately before this process may spawn a
/// builder VM of its own.
///
/// The sweep needs a native snapshot of the host process table, whose cost
/// scales with how busy the host is. A launch that resolves
/// every artifact from cache never spawns a helper, so running the sweep
/// unconditionally charges the prepared launch path for cleanup that cannot
/// benefit it. Calling this at the spawn sites keeps the guarantee the startup
/// sweep was added for — no orphan accumulation across runs that do spawn —
/// without putting a process-table walk in front of a launch that does not.
///
/// Idempotent: several branches can reach a materializer in one run, and the
/// second sweep would find nothing the first left behind.
pub fn sweep_orphaned_vm_helpers_before_spawn() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(sweep_orphaned_vm_helpers_on_startup);
}

/// Sidecar PID file names a builder VM dir carries (libkrun + HVF).
pub(crate) const BUILDER_SIDECARS: &[&str] = &["builder.pid", "stage0.pid"];

/// Sidecar PID file names a workload VM dir under `~/.mvm/vms/<name>/`.
///
/// The shared liveness markers, not a copy of them: this list decides whether
/// a VM dir has a live owner, and a backend missing from it reads as dead —
/// so the reaper would SIGTERM the helpers of a guest that is still running.
pub(crate) const WORKLOAD_SIDECARS: &[&str] = mvm_vmm::host::process_liveness::PID_FILE_NAMES;

fn reap_orphaned_vm_helpers_both_roots(
    remove_builder_dirs: bool,
    dry_run: bool,
) -> Result<ReapOutcome> {
    let builder_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm/vms");
    let workload_root = mvm_core::config::vms_dir();
    super::directory(std::path::Path::new(&mvm_core::config::mvm_home()))?;
    super::directory(std::path::Path::new(&mvm_core::config::mvm_cache_dir()))?;
    super::directory(
        &std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm"),
    )?;
    let snapshot = ProcSnapshot::capture();

    let mut out = reap_orphaned_vm_helpers_at(
        &ReapScope {
            vms_root: &builder_root,
            sidecars: BUILDER_SIDECARS,
            remove_dead_dirs: remove_builder_dirs,
            all_dirs_managed: false,
            dry_run,
        },
        &snapshot,
    )?;
    // `remove_builder_dirs` rather than a flat `false`: everything under the
    // workload root is managed except a per-job builder dir, so this grants
    // exactly the authority to prune finished builds that stage there, and
    // the kill-only startup sweep (which passes `false`) still removes nothing.
    let workload = reap_orphaned_vm_helpers_at(
        &ReapScope {
            vms_root: &workload_root,
            sidecars: WORKLOAD_SIDECARS,
            remove_dead_dirs: remove_builder_dirs,
            all_dirs_managed: true,
            dry_run,
        },
        &snapshot,
    )?;
    out.killed += workload.killed;
    out.removed_dirs += workload.removed_dirs;
    out.freed_bytes += workload.freed_bytes;
    out.killed += reap_orphaned_builder_egress_supervisors(dry_run, &snapshot);
    Ok(out)
}

const BUILDER_EGRESS_SUPERVISOR_SUBCOMMAND: &str = "__builder-egress-supervisor";

fn is_builder_egress_supervisor(command: &str) -> bool {
    let mut fields = command.split_whitespace();
    let Some(executable) = fields.next() else {
        return false;
    };
    std::path::Path::new(executable)
        .file_name()
        .is_some_and(|name| name == "mvmctl")
        && fields.next() == Some(BUILDER_EGRESS_SUPERVISOR_SUBCOMMAND)
}

fn reap_orphaned_builder_egress_supervisors(dry_run: bool, snapshot: &ProcSnapshot) -> u64 {
    let victims: Vec<i32> = snapshot
        .cmds
        .iter()
        .filter(|(pid, command)| {
            snapshot.parent(*pid) == Some(1) && is_builder_egress_supervisor(command)
        })
        .map(|(pid, _)| *pid)
        .collect();

    let mut killed = 0;
    for pid in victims {
        if dry_run
            || matches!(
                signal_snapshot_process(pid, snapshot),
                Ok(mvm_vmm::host::process_liveness::GuardedSignal::Sent)
            )
        {
            killed += 1;
        }
    }
    killed
}

/// Which VM state directories one reap pass walks, and what it may do there.
struct ReapScope<'a> {
    /// Directory whose children are per-VM state dirs.
    pub vms_root: &'a std::path::Path,
    /// Sidecar PID file names that mark a state dir as having a live owner.
    pub sidecars: &'a [&'a str],
    /// Remove a state dir once nothing in it is alive.
    pub remove_dead_dirs: bool,
    /// Every child of `vms_root` is a dir this reaper manages, rather than
    /// only the per-job builder dirs.
    pub all_dirs_managed: bool,
    /// Report what would be signalled and removed without doing it.
    pub dry_run: bool,
}

/// Reap the orphaned helpers under one VM root, against a process table
/// captured once for the whole sweep.
fn reap_orphaned_vm_helpers_at(
    scope: &ReapScope<'_>,
    snapshot: &ProcSnapshot,
) -> Result<ReapOutcome> {
    let ReapScope {
        vms_root,
        sidecars,
        remove_dead_dirs,
        all_dirs_managed,
        dry_run,
    } = *scope;
    let mut outcome = ReapOutcome {
        killed: 0,
        removed_dirs: 0,
        freed_bytes: 0,
    };
    if !super::directory(vms_root)? {
        return Ok(outcome);
    }

    for entry in std::fs::read_dir(vms_root)? {
        let entry = entry?;
        let dir = entry.path();
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(dir_basename) = dir.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        // A per-job builder dir is ephemeral wherever it sits. The HVF
        // builder family stages its jobs under the workload root, so without
        // this the blanket `all_dirs_managed` there would treat a finished
        // build's leftovers as restartable machine state and keep them
        // forever — and now that the inventory no longer lists builder VMs,
        // nothing would show they had accumulated.
        let managed = !mvm_core::naming::is_ephemeral_builder_vm_name(dir_basename)
            && (all_dirs_managed || mvm_core::naming::is_builder_owned_vm_name(dir_basename));

        let mut dir_has_live_owner = false;
        let mut killed_in_dir = 0u64;
        let mut seen_pids: std::collections::HashSet<i32> = std::collections::HashSet::new();

        for sidecar in sidecars.iter().filter(|s| is_supervisor_sidecar(s)) {
            let Some(pid) = read_pid_file(&dir.join(sidecar)) else {
                continue;
            };
            if !seen_pids.insert(pid) {
                continue;
            }
            reap_or_track(
                pid,
                managed,
                dry_run,
                snapshot,
                &mut dir_has_live_owner,
                &mut killed_in_dir,
            );
        }

        let helper_pids = sidecars
            .iter()
            .filter(|s| !is_supervisor_sidecar(s))
            .filter_map(|s| read_pid_file(&dir.join(s)))
            .chain(snapshot.pids_referencing(&dir.to_string_lossy()));
        for pid in helper_pids {
            if !seen_pids.insert(pid) {
                continue;
            }
            reap_or_track(
                pid,
                dir_has_live_owner,
                dry_run,
                snapshot,
                &mut dir_has_live_owner,
                &mut killed_in_dir,
            );
        }

        outcome.killed += killed_in_dir;
        if dir_has_live_owner || !remove_dead_dirs || managed {
            continue;
        }

        let size = dir_size_bytes(&dir);
        if !dry_run {
            std::fs::remove_dir_all(&dir)?;
        }
        outcome.removed_dirs += 1;
        outcome.freed_bytes += size;
    }

    Ok(outcome)
}

enum PidClassification {
    Dead,
    LiveOwned,
    Orphan,
}

fn classify_pid(pid: i32, snapshot: &ProcSnapshot) -> PidClassification {
    if !snapshot.is_alive(pid) {
        return PidClassification::Dead;
    }
    match snapshot.parent(pid) {
        Some(1) => PidClassification::Orphan,
        _ => PidClassification::LiveOwned,
    }
}

fn classify_pid_for_dir(pid: i32, protected: bool, snapshot: &ProcSnapshot) -> PidClassification {
    match classify_pid(pid, snapshot) {
        PidClassification::Orphan if protected => PidClassification::LiveOwned,
        other => other,
    }
}

fn reap_or_track(
    pid: i32,
    protected: bool,
    dry_run: bool,
    snapshot: &ProcSnapshot,
    dir_has_live_owner: &mut bool,
    killed_in_dir: &mut u64,
) {
    match classify_pid_for_dir(pid, protected, snapshot) {
        PidClassification::Dead => {}
        PidClassification::LiveOwned => *dir_has_live_owner = true,
        PidClassification::Orphan => {
            if dry_run {
                *killed_in_dir += 1;
            } else {
                use mvm_vmm::host::process_liveness::GuardedSignal;
                match signal_snapshot_process(pid, snapshot) {
                    Ok(GuardedSignal::Sent) => {
                        *killed_in_dir += 1;
                        // Delivery is not exit confirmation. Preserve the state until
                        // a later reconciliation observes that the process is gone.
                        *dir_has_live_owner |= snapshot.is_alive(pid);
                    }
                    Ok(GuardedSignal::Exited) => {}
                    Ok(GuardedSignal::Refused(_)) | Err(_) => *dir_has_live_owner = true,
                }
            }
        }
    }
}

fn signal_snapshot_process(
    pid: i32,
    snapshot: &ProcSnapshot,
) -> std::io::Result<mvm_vmm::host::process_liveness::GuardedSignal> {
    use mvm_vmm::host::process_liveness::{GuardedSignal, signal_if_executable};
    #[cfg(test)]
    if let Some(observations) = &snapshot.observations {
        return observations.signal(pid);
    }
    let Some(expected) = snapshot.executables.get(&pid) else {
        return Ok(GuardedSignal::Refused(None));
    };
    let Some((_, command)) = snapshot
        .cmds
        .iter()
        .find(|(candidate, _)| *candidate == pid)
    else {
        return Ok(GuardedSignal::Refused(None));
    };
    let argv_executable = command.split_whitespace().next().map(std::path::Path::new);
    if argv_executable.and_then(std::path::Path::file_name) != expected.file_name() {
        return Ok(GuardedSignal::Refused(Some(expected.clone())));
    }
    // Keep signalling on the guarded native provider: sysinfo's kill wrappers
    // can launch external tools on some platforms.
    signal_if_executable(pid, libc::SIGTERM, &|actual| actual == expected)
}

/// Whether a sidecar name identifies the process that owns the VM, as opposed
/// to a helper attached to it. An owner marker protects the dir; a helper one
/// does not. Both marker sets are read from where they are defined.
fn is_supervisor_sidecar(name: &str) -> bool {
    BUILDER_SIDECARS.contains(&name)
        || mvm_vmm::host::process_liveness::PID_FILE_NAMES.contains(&name)
}

struct ProcSnapshot {
    parents: std::collections::HashMap<i32, i32>,
    cmds: Vec<(i32, String)>,
    executables: std::collections::HashMap<i32, std::path::PathBuf>,
    #[cfg(test)]
    observations: Option<tests::ProcessObservations>,
}

impl ProcSnapshot {
    #[tracing::instrument(name = "proc_snapshot.capture", skip_all)]
    fn capture() -> Self {
        // Reported here rather than at the callers: this is the function that
        // pays for the snapshot, and a caller that forgot to report would make
        // a launch look cheaper than it was.
        mvm_core::launch_trace::record_process_table_scan();
        let mut parents = std::collections::HashMap::new();
        let mut cmds = Vec::new();
        let mut executables = std::collections::HashMap::new();
        let system =
            sysinfo::System::new_with_specifics(sysinfo::RefreshKind::new().with_processes(
                sysinfo::ProcessRefreshKind::new().with_cmd(sysinfo::UpdateKind::Always),
            ));
        for (native_pid, process) in system.processes() {
            let Ok(pid) = i32::try_from(native_pid.as_u32()) else {
                continue;
            };
            if let Some(parent) = process
                .parent()
                .and_then(|p| i32::try_from(p.as_u32()).ok())
            {
                parents.insert(pid, parent);
            }
            if pid > 1 {
                // Match guarded revalidation, including unlinked Linux binaries.
                if let Some(path) = mvm_vmm::host::process_liveness::process_executable(pid) {
                    executables.insert(pid, path);
                }
                if !process.cmd().is_empty() {
                    cmds.push((pid, process.cmd().join(" ")));
                }
            }
        }
        Self {
            parents,
            cmds,
            executables,
            #[cfg(test)]
            observations: None,
        }
    }

    #[cfg(test)]
    fn from_parts(parents: std::collections::HashMap<i32, i32>, cmds: Vec<(i32, String)>) -> Self {
        Self {
            parents,
            cmds,
            executables: std::collections::HashMap::new(),
            observations: None,
        }
    }

    fn is_alive(&self, pid: i32) -> bool {
        #[cfg(test)]
        if let Some(observations) = &self.observations {
            return observations.is_alive(pid);
        }
        pid_is_alive(pid)
    }

    fn parent(&self, pid: i32) -> Option<i32> {
        self.parents.get(&pid).copied()
    }

    fn pids_referencing(&self, needle: &str) -> Vec<i32> {
        self.cmds
            .iter()
            .filter(|(_, cmd)| cmd.contains(needle))
            .map(|(pid, _)| *pid)
            .collect()
    }
}

// The reaper's notion of "still alive" is the shared one. Its own copy read a
// bare `kill(pid, 0) == 0`, which reports a supervisor owned by another uid —
// a root-owned Firecracker under the jailer — as dead, and would then reap the
// helpers of a running guest.
pub(crate) use mvm_vmm::host::process_liveness::{pid_is_alive, read_pid_file};

/// Disk the reaper would return by dropping a per-VM dir. Shared with the
/// rest of `cache prune` so one command never quotes two different numbers.
fn dir_size_bytes(path: &std::path::Path) -> u64 {
    mvm_core::disk_usage::tree_bytes(path)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod safety_tests {
    use super::*;

    #[test]
    fn native_snapshot_observes_this_process_without_an_external_tool() {
        let snapshot = ProcSnapshot::capture();
        let pid = i32::try_from(std::process::id()).unwrap();
        assert!(snapshot.parent(pid).is_some());
        assert!(snapshot.cmds.iter().any(|(candidate, _)| *candidate == pid));
        assert!(snapshot.is_alive(pid));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let expected = std::env::current_exe().unwrap().canonicalize().unwrap();
            let observed = snapshot.executables.get(&pid).unwrap();
            assert_eq!(observed.canonicalize().unwrap(), expected);
            assert_eq!(
                Some(observed),
                mvm_vmm::host::process_liveness::process_executable(pid).as_ref()
            );
        }
    }

    #[test]
    fn missing_identity_refuses_signal_and_preserves_state() {
        let pid = i32::try_from(std::process::id()).unwrap();
        let snapshot = ProcSnapshot::from_parts([(pid, 1)].into(), Vec::new());
        let mut live = false;
        let mut killed = 0;
        reap_or_track(pid, false, false, &snapshot, &mut live, &mut killed);
        assert!(live, "uncertain identity must retain the state directory");
        assert_eq!(killed, 0);
        assert!(pid_is_alive(pid));
    }

    #[test]
    fn preview_never_signals_and_repeated_apply_reclaims_only_dead_state() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("mvm-builder-vm-fixture");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("payload"), b"fixture").unwrap();
        let snapshot = ProcSnapshot::from_parts(Default::default(), Vec::new());
        let mut scope = ReapScope {
            vms_root: root.path(),
            sidecars: BUILDER_SIDECARS,
            remove_dead_dirs: true,
            all_dirs_managed: false,
            dry_run: true,
        };
        assert_eq!(
            reap_orphaned_vm_helpers_at(&scope, &snapshot)
                .unwrap()
                .removed_dirs,
            1
        );
        assert!(dir.exists());
        scope.dry_run = false;
        assert_eq!(
            reap_orphaned_vm_helpers_at(&scope, &snapshot)
                .unwrap()
                .removed_dirs,
            1
        );
        assert!(!dir.exists());
        assert_eq!(
            reap_orphaned_vm_helpers_at(&scope, &snapshot)
                .unwrap()
                .removed_dirs,
            0
        );
    }

    #[test]
    #[cfg(unix)]
    fn symlink_roots_refuse_and_child_links_are_not_traversed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("keep"), b"keep").unwrap();
        let link = root.path().join("mvm-builder-vm-link");
        std::os::unix::fs::symlink(outside.path(), &link).unwrap();
        let snapshot = ProcSnapshot::from_parts(Default::default(), Vec::new());
        let mut scope = ReapScope {
            vms_root: root.path(),
            sidecars: BUILDER_SIDECARS,
            remove_dead_dirs: true,
            all_dirs_managed: false,
            dry_run: false,
        };
        assert_eq!(
            reap_orphaned_vm_helpers_at(&scope, &snapshot)
                .unwrap()
                .removed_dirs,
            0
        );
        scope.vms_root = &link;
        assert!(reap_orphaned_vm_helpers_at(&scope, &snapshot).is_err());
        assert!(outside.path().join("keep").exists());
    }

    #[test]
    fn argv_discovery_requires_the_root_bound_directory_not_just_a_basename() {
        let snapshot = ProcSnapshot::from_parts(
            Default::default(),
            vec![(
                42,
                "tail -F /other/root/mvm-builder-vm-fixture/console.log".into(),
            )],
        );
        assert!(
            snapshot
                .pids_referencing("/configured/root/mvm-builder-vm-fixture")
                .is_empty()
        );
    }
}
