use super::*;

/// Outcome of [`reap_orphaned_vm_helpers`]. Counts
/// orphaned helper PIDs that were signalled and per-VM cache dirs
/// removed, plus the bytes freed by removing those dirs. Pruner-side
/// caller uses this to print a clean one-line summary.
pub(in crate::commands) struct ReapOutcome {
    pub killed: u64,
    pub removed_dirs: u64,
    pub freed_bytes: u64,
}

/// Reap orphaned per-VM helpers left behind by killed
/// `mvmctl dev up` runs. Covers each backend's supervisor
/// (`mvm-libkrun-supervisor`, `mvm-hvf-supervisor`).
///
/// mvmctl spawns the active backend's supervisor binary, which in turn
/// may spawn auxiliary per-VM helpers. If mvmctl exits abnormally (^C,
/// SIGKILL, crash), supervisor + helpers are reparented to launchd PID 1
/// and outlive mvmctl indefinitely. This is the "clean up after the fact"
/// side, distinct from the prevention path.
///
/// The dir traversal below is **prefix-agnostic**: it iterates every
/// subdirectory of `~/.cache/mvm/builder-vm/vms/`, so both
/// `mvm-builder-vm-<job_id>` (libkrun) and `mvm-builder-vz-<job_id>`
/// (Vz) state dirs are picked up by the same loop, and the sidecar PID
/// names (`builder.pid` / `stage0.pid`) are shared across backends. The
/// `reap_picks_up_orphaned_vz_builder_state_dir` test pins this: a
/// future refactor that narrows the traversal or renames the sidecar
/// must update that test.
///
/// A microVM is several processes: the supervisor (the VMM-host that
/// owns the guest) plus dependent helpers (for example a
/// `tail -F console.log` reader). The supervisor is the authoritative
/// liveness signal, so the sweep runs in two phases per dir:
///
/// 1. **Supervisor phase.** Read the supervisor sidecars (`builder.pid` /
///    `stage0.pid` / `vz.pid` / `libkrun.pid`: see
///    [`is_supervisor_sidecar`]). On a managed dir (the persistent dev
///    builder `mvm-persistent-builder-*`, or any named workload under
///    `~/.mvm/vms/`) an alive supervisor is the running VM, spared:
///    those supervisors are detached under launchd by design to
///    outlive the spawning CLI, so `parent == launchd` is their steady
///    state, not an orphan signal. They are stopped only by explicit
///    `dev down` / `stop <name>`. On an ephemeral per-job builder dir,
///    an alive launchd-parented supervisor is a build whose CLI crashed
///    and should be SIGTERM'd. Without the managed carve-out the startup
///    sweep kills the live dev VM on every `up` / `dev up` / `ls`.
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
pub(in crate::commands) fn reap_orphaned_vm_helpers(dry_run: bool) -> Result<ReapOutcome> {
    reap_orphaned_vm_helpers_both_roots(/* remove_builder_dirs = */ true, dry_run)
}

/// Best-effort orphan-helper sweep run at the start of `mvmctl dev up`
/// / `mvmctl up`. The next launch reaps the previous run's corpses:
/// startup is the robust trigger because an abnormal exit (^C, SIGKILL,
/// crash, the libkrun `krun_start_enter` `exit()`) is exactly when the CLI
/// can't self-clean and reparents its helpers to launchd.
///
/// Kill-only: it signals provably-orphaned helpers but removes no
/// directories, so it never deletes host bytes and carries no audit
/// obligation. Directory pruning stays the job of `mvmctl cache prune`.
/// Quiet on the happy path and swallows errors because a sweep failure
/// must never block a launch.
pub(in crate::commands) fn sweep_orphaned_vm_helpers_on_startup() {
    match reap_orphaned_vm_helpers(false) {
        Ok(o) if o.killed > 0 => crate::ui::info(&format!(
            "Reaped {} orphaned VM helper(s) left by a prior run.",
            o.killed
        )),
        Ok(_) => {}
        Err(e) => {
            tracing::debug!(error = %e, "startup orphan-helper sweep failed (non-fatal)")
        }
    }
}

/// Sidecar PID file names a builder VM dir carries (libkrun + Vz).
pub(super) const BUILDER_SIDECARS: &[&str] = &["builder.pid", "stage0.pid"];

/// Sidecar PID file names a workload VM dir under `~/.mvm/vms/<name>/`.
pub(super) const WORKLOAD_SIDECARS: &[&str] = &["libkrun.pid", "vz.pid"];

/// Dir-name prefix of the persistent dev builder VM.
const PERSISTENT_BUILDER_DIR_PREFIX: &str = "mvm-persistent-builder-";

fn reap_orphaned_vm_helpers_both_roots(
    remove_builder_dirs: bool,
    dry_run: bool,
) -> Result<ReapOutcome> {
    let builder_root =
        std::path::PathBuf::from(mvm_core::config::mvm_cache_dir()).join("builder-vm/vms");
    let workload_root = std::path::PathBuf::from(mvm_core::config::mvm_data_dir()).join("vms");
    let snapshot = ProcSnapshot::capture();

    let mut out = reap_orphaned_vm_helpers_at_with_snapshot(
        &builder_root,
        BUILDER_SIDECARS,
        remove_builder_dirs,
        false,
        dry_run,
        &snapshot,
    )?;
    let workload = reap_orphaned_vm_helpers_at_with_snapshot(
        &workload_root,
        WORKLOAD_SIDECARS,
        false,
        true,
        dry_run,
        &snapshot,
    )?;
    out.killed += workload.killed;
    out.removed_dirs += workload.removed_dirs;
    out.freed_bytes += workload.freed_bytes;
    Ok(out)
}

#[cfg(test)]
pub(super) fn reap_orphaned_vm_helpers_at(
    vms_root: &std::path::Path,
    sidecars: &[&str],
    remove_dead_dirs: bool,
    all_dirs_managed: bool,
    dry_run: bool,
) -> Result<ReapOutcome> {
    let snapshot = ProcSnapshot::capture();
    reap_orphaned_vm_helpers_at_with_snapshot(
        vms_root,
        sidecars,
        remove_dead_dirs,
        all_dirs_managed,
        dry_run,
        &snapshot,
    )
}

pub(super) fn reap_orphaned_vm_helpers_at_with_snapshot(
    vms_root: &std::path::Path,
    sidecars: &[&str],
    remove_dead_dirs: bool,
    all_dirs_managed: bool,
    dry_run: bool,
    snapshot: &ProcSnapshot,
) -> Result<ReapOutcome> {
    let mut outcome = ReapOutcome {
        killed: 0,
        removed_dirs: 0,
        freed_bytes: 0,
    };
    if !vms_root.is_dir() {
        return Ok(outcome);
    }

    for entry in std::fs::read_dir(vms_root)?.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let Some(dir_basename) = dir.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let managed = all_dirs_managed || dir_basename.starts_with(PERSISTENT_BUILDER_DIR_PREFIX);

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
            .chain(snapshot.pids_referencing(dir_basename));
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
            let _ = std::fs::remove_dir_all(&dir);
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
    if !pid_is_alive(pid) {
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
            if !dry_run {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
            *killed_in_dir += 1;
        }
    }
}

fn is_supervisor_sidecar(name: &str) -> bool {
    matches!(
        name,
        "builder.pid" | "stage0.pid" | "vz.pid" | "libkrun.pid"
    )
}

pub(super) struct ProcSnapshot {
    parents: std::collections::HashMap<i32, i32>,
    cmds: Vec<(i32, String)>,
}

impl ProcSnapshot {
    fn capture() -> Self {
        let mut parents = std::collections::HashMap::new();
        let mut cmds = Vec::new();
        let Ok(out) = std::process::Command::new("ps")
            .args(["-axww", "-o", "pid=,ppid=,command="])
            .output()
        else {
            return Self { parents, cmds };
        };
        if !out.status.success() {
            return Self { parents, cmds };
        }
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let rest = line.trim_start();
            let Some((pid_s, rest)) = rest.split_once(char::is_whitespace) else {
                continue;
            };
            let Ok(pid) = pid_s.parse::<i32>() else {
                continue;
            };
            let rest = rest.trim_start();
            let Some((ppid_s, cmd)) = rest.split_once(char::is_whitespace) else {
                continue;
            };
            let Ok(ppid) = ppid_s.parse::<i32>() else {
                continue;
            };
            parents.insert(pid, ppid);
            if pid > 1 {
                cmds.push((pid, cmd.trim_start().to_string()));
            }
        }
        Self { parents, cmds }
    }

    #[cfg(test)]
    pub(super) fn from_parts(
        parents: std::collections::HashMap<i32, i32>,
        cmds: Vec<(i32, String)>,
    ) -> Self {
        Self { parents, cmds }
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

fn read_pid_file(path: &std::path::Path) -> Option<i32> {
    std::fs::read_to_string(path)
        .ok()?
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|&p| p > 1)
}

pub(super) fn pid_is_alive(pid: i32) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}

fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(path) else {
        return total;
    };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_file() {
            total += p.metadata().map(|m| m.len()).unwrap_or(0);
        } else if p.is_dir() {
            total += dir_size_bytes(&p);
        }
    }
    total
}
