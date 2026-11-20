//! Stop every host process a scenario left running against a home it owned.
//!
//! A live scenario boots its microVM through `mvmctl`, and on Linux that
//! starts Firecracker as `sudo setsid nohup sh -c '…; exec firecracker …'`.
//! The VMM is deliberately detached: it outlives the `mvmctl` that started it,
//! it is not a child of the test process, and it runs as root. So when a
//! scenario fails before its own `machine stop` step, nothing in the test
//! process's tree owns that VMM any more. Dropping the scenario's temporary
//! home then deletes the pid marker and the state directory under a VMM that
//! keeps running — on the shared KVM runner, for days.
//!
//! The reaper finds those processes the only way that still works after the
//! fact: by the paths their command lines name. Every per-VM process `mvmctl`
//! starts names either the VM's state directory under the home, or the short
//! socket directory that state directory falls back to when its path is too
//! long for a Unix socket. Both are derived here from the home alone, so a
//! process is only ever signalled while its command line names a path the
//! scenario owned — a recycled PID belonging to someone else is never touched.
//!
//! A process the test user cannot signal (the root-owned VMM) is signalled
//! through `sudo -n`, the same privilege its launch used.
//!
//! HVF supervisors are never raw-signalled. Home-local runtime evidence
//! selects an isolated `mvmctl machine stop` child; only the existing backend
//! authenticates shutdown and authorizes finalization cleanup. Missing evidence,
//! refusal, timeout, or a newly observed supervisor leaves cleanup unknown.

use mvm_core::env_hygiene::helper_command;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::IsolatedHome;

/// Cleanup could not establish an authenticated HVF stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupUnknown {
    /// No home-local runtime candidate accounted for the supervisor.
    MissingVm,
    /// Home-local runtime evidence could not be enumerated safely.
    DiscoveryUnavailable,
    /// The stop command refused or exited unsuccessfully.
    StopRefused,
    /// The stop command exceeded its deadline.
    StopTimedOut,
    /// The CLI could not be located, started, or waited on.
    StopUnavailable,
    /// A supervisor appeared after the authenticated-stop pass.
    NewSupervisor,
    /// A supervisor remained observable after the stop pass.
    SupervisorSurvived,
    /// The host process table could not be read.
    ProcessTableUnavailable,
}

/// Bounded, secret-free cleanup diagnostic. No command output or identity bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownCleanup {
    pub pid: Option<u32>,
    pub category: CleanupUnknown,
}

/// One host process whose command line names a path the scenario owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProcess {
    pub pid: u32,
    pub args: String,
}

/// What a reap found and what it could not stop.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReapReport {
    /// Processes that were still running when the reap started.
    pub found: Vec<OwnedProcess>,
    /// Processes still running after SIGTERM and SIGKILL.
    pub survivors: Vec<OwnedProcess>,
    /// Unconfirmed cleanup, retained even when a later scan finds no process.
    pub unknown: Vec<UnknownCleanup>,
}

impl ReapReport {
    /// Whether nothing the scenario started outlived the reap.
    pub fn is_clean(&self) -> bool {
        self.survivors.is_empty() && self.unknown.is_empty()
    }

    /// Describe failure without dumping runtime identity or subprocess output.
    pub fn describe_failure(&self) -> String {
        format!(
            "{}\nunknown cleanup: {:?}",
            Self::describe(&self.survivors),
            self.unknown
        )
    }

    /// A one-line-per-process description for a failure message or a log.
    pub fn describe(processes: &[OwnedProcess]) -> String {
        processes
            .iter()
            .map(|process| format!("  pid {}", process.pid))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// One row of the host process table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRow {
    pub pid: u32,
    pub ppid: u32,
    pub args: String,
}

/// Paths whose appearance in a command line marks a process as started
/// against `home`: the home itself, and the short socket directory each VM
/// state directory under it falls back to.
pub fn owned_markers(home: &Path) -> Vec<String> {
    let mut markers = vec![with_trailing_slash(home)];
    let vms = mvm_core::config::vms_dir_at(home);
    if let Ok(entries) = std::fs::read_dir(&vms) {
        for entry in entries.flatten() {
            let state_dir = entry.path();
            let socket_dir = mvm_core::config::vm_socket_dir_at(&state_dir);
            if !socket_dir.starts_with(home) {
                markers.push(with_trailing_slash(&socket_dir));
            }
        }
    }
    markers
}

fn with_trailing_slash(path: &Path) -> String {
    let mut marker = path.display().to_string();
    if !marker.ends_with('/') {
        marker.push('/');
    }
    marker
}

/// Parse `ps -ww -eo pid=,ppid=,args=` output. Lines that do not start with
/// two numbers (a kernel thread with empty args, a header) are skipped.
pub fn parse_process_table(output: &str) -> Vec<ProcessRow> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.trim_start().splitn(2, char::is_whitespace);
            let pid = fields.next()?.parse().ok()?;
            let rest = fields.next()?.trim_start();
            let mut fields = rest.splitn(2, char::is_whitespace);
            let ppid = fields.next()?.parse().ok()?;
            let args = fields.next().unwrap_or("").trim().to_string();
            Some(ProcessRow { pid, ppid, args })
        })
        .collect()
}

/// `pid` and every process above it. Their command lines may name the home
/// (a shell that runs the suite with `MVM_HOME` in its argv), and signalling
/// them would kill the run that is doing the reaping.
pub fn ancestry(rows: &[ProcessRow], pid: u32) -> HashSet<u32> {
    let parents: HashMap<u32, u32> = rows.iter().map(|row| (row.pid, row.ppid)).collect();
    let mut chain = HashSet::new();
    let mut current = pid;
    while current > 1 && chain.insert(current) {
        match parents.get(&current) {
            Some(&parent) => current = parent,
            None => break,
        }
    }
    chain
}

/// The rows whose command line names one of `markers`, minus `spare`.
pub fn select_owned(
    rows: &[ProcessRow],
    markers: &[String],
    spare: &HashSet<u32>,
) -> Vec<OwnedProcess> {
    rows.iter()
        .filter(|row| !spare.contains(&row.pid))
        .filter(|row| markers.iter().any(|marker| row.args.contains(marker)))
        .map(|row| OwnedProcess {
            pid: row.pid,
            args: row.args.clone(),
        })
        .collect()
}

fn process_table() -> Result<Vec<ProcessRow>, CleanupUnknown> {
    let output = helper_command("ps")
        .args(["-ww", "-eo", "pid=,ppid=,args="])
        .output()
        .map_err(|_| CleanupUnknown::ProcessTableUnavailable)?;
    if !output.status.success() {
        return Err(CleanupUnknown::ProcessTableUnavailable);
    }
    Ok(parse_process_table(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Signal `pid` as the test user, and through `sudo -n` when that is refused:
/// the detached VMM runs as root because its launch went through `sudo`.
fn signal(pid: u32, signal: &str) {
    let pid = pid.to_string();
    let direct = helper_command("kill")
        .args(["-s", signal, &pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    if !direct {
        let _ = helper_command("sudo")
            .args(["-n", "kill", "-s", signal, &pid])
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn is_hvf(process: &OwnedProcess) -> bool {
    is_hvf_with_override(
        process,
        std::env::var_os("MVM_HVF_SUPERVISOR_PATH").as_deref(),
    )
}

fn is_hvf_with_override(process: &OwnedProcess, configured: Option<&std::ffi::OsStr>) -> bool {
    // Deliberately conservative: an ambiguous wrapper must not raw-kill HVF.
    process.args.contains("mvm-hvf-supervisor")
        || configured
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|path| !path.is_empty() && process.args.contains(path))
}

fn hvf_candidates(homes: &[&Path]) -> Result<Vec<(PathBuf, String)>, CleanupUnknown> {
    let mut candidates = Vec::new();
    for home in homes {
        let entries = match std::fs::read_dir(mvm_core::config::vms_dir_at(home)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return Err(CleanupUnknown::DiscoveryUnavailable),
        };
        for entry in entries {
            let entry = entry.map_err(|_| CleanupUnknown::DiscoveryUnavailable)?;
            let kind = entry
                .file_type()
                .map_err(|_| CleanupUnknown::DiscoveryUnavailable)?;
            if kind.is_symlink() {
                return Err(CleanupUnknown::DiscoveryUnavailable);
            }
            if !kind.is_dir() {
                continue;
            }
            let dir = entry.path();
            let mut evidence = false;
            for marker in [
                "hvf-launch.lock",
                "hvf.pid",
                "hvf-instance.json",
                "hvf-finalized.json",
                "hvf-stop.sock",
            ] {
                match std::fs::symlink_metadata(dir.join(marker)) {
                    Ok(_) => evidence = true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => return Err(CleanupUnknown::DiscoveryUnavailable),
                }
            }
            if evidence {
                let name = entry.file_name();
                let vm = name.to_str().ok_or(CleanupUnknown::DiscoveryUnavailable)?;
                mvm_core::naming::validate_vm_name(vm)
                    .map_err(|_| CleanupUnknown::DiscoveryUnavailable)?;
                candidates.push((home.to_path_buf(), vm.to_owned()));
            }
        }
    }
    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn stop_command(binary: &Path, home: &Path, vm: &str) -> std::process::Command {
    let mut command = crate::command_for_binary(binary);
    command
        .isolated_home(home)
        .args(["machine", "stop", vm, "--yes"]);
    command
}

trait ReapOps {
    fn scan(&mut self, homes: &[&Path]) -> Result<Vec<OwnedProcess>, CleanupUnknown>;
    fn stop(&mut self, home: &Path, vm: &str) -> Result<(), CleanupUnknown>;
    fn signal(&mut self, pid: u32, signal: &str);
    fn grace(&mut self, duration: Duration);
}

#[derive(Default)]
struct HostOps {
    markers: HashSet<String>,
}

impl ReapOps for HostOps {
    fn scan(&mut self, homes: &[&Path]) -> Result<Vec<OwnedProcess>, CleanupUnknown> {
        // Stop can remove a VM directory; retain its short-socket marker while
        // also discovering directories a detached refill created in this round.
        self.markers
            .extend(homes.iter().flat_map(|home| owned_markers(home)));
        let rows = process_table()?;
        let spare = ancestry(&rows, std::process::id());
        Ok(select_owned(
            &rows,
            &self.markers.iter().cloned().collect::<Vec<_>>(),
            &spare,
        ))
    }

    fn stop(&mut self, home: &Path, vm: &str) -> Result<(), CleanupUnknown> {
        use mvm_core::bounded_run::{BoundedRunError, RunBounds, run_bounded};
        let binary = crate::mvmctl_path().map_err(|_| CleanupUnknown::StopUnavailable)?;
        // Only the CLI child is killed on timeout, never its detached supervisor.
        // Diagnostics are categorical: arbitrary CLI output can contain secrets.
        let output = run_bounded(
            stop_command(&binary, home, vm),
            RunBounds::new(Duration::from_secs(45), 0),
        )
        .map_err(|error| match error {
            BoundedRunError::TimedOut(_) => CleanupUnknown::StopTimedOut,
            BoundedRunError::Spawn(_) | BoundedRunError::Wait(_) => CleanupUnknown::StopUnavailable,
        })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(CleanupUnknown::StopRefused)
        }
    }

    fn signal(&mut self, pid: u32, kind: &str) {
        signal(pid, kind);
    }

    fn grace(&mut self, duration: Duration) {
        // Detached external processes have no owned child event to wait on.
        std::thread::sleep(duration);
    }
}

/// Stop HVF through authenticated CLI shutdown; TERM/KILL only other helpers.
/// Each sweep reclassifies supervisors, including ones born during cleanup.
/// Unknown HVF cleanup remains a failure across later calls for the same home.
pub fn reap_home(home: &Path) -> ReapReport {
    reap_homes(&[home])
}

/// [`reap_home`] over several homes with one process-table scan per round.
pub fn reap_homes(homes: &[&Path]) -> ReapReport {
    let mut report = reap_with(homes, &mut HostOps::default());
    // A later Drop scan cannot turn refusal into permission to delete evidence.
    let mut uncertain = UNCERTAIN_HOMES
        .lock()
        .expect("cleanup evidence lock poisoned");
    retain_unknown(homes, &mut report, &mut uncertain);
    report
}

fn retain_unknown(
    homes: &[&Path],
    report: &mut ReapReport,
    uncertain: &mut HashMap<PathBuf, Vec<UnknownCleanup>>,
) {
    for home in homes {
        if let Some(previous) = uncertain.get(*home) {
            for unknown in previous {
                if !report.unknown.contains(unknown) {
                    report.unknown.push(unknown.clone());
                }
            }
        }
    }
    if !report.unknown.is_empty() {
        for home in homes {
            uncertain.insert(home.to_path_buf(), report.unknown.clone());
        }
    }
}

static UNCERTAIN_HOMES: std::sync::LazyLock<
    std::sync::Mutex<HashMap<PathBuf, Vec<UnknownCleanup>>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn reap_with(homes: &[&Path], ops: &mut impl ReapOps) -> ReapReport {
    if homes.is_empty() {
        return ReapReport::default();
    }
    let mut report = ReapReport::default();
    let mut protected = HashSet::new();
    let mut seen_hvf = HashSet::new();
    let mut protected_markers = HashSet::new();
    let mut attempted = HashSet::new();
    // Authenticated stops may take seconds. Rescan before the first raw signal
    // rather than acting on the helper PIDs observed before those stops.
    for round in 0..4 {
        let processes = match ops.scan(homes) {
            Ok(processes) => processes,
            Err(category) => {
                report.unknown.push(UnknownCleanup {
                    pid: None,
                    category,
                });
                break;
            }
        };
        if round == 0 {
            report.found = processes.clone();
        }
        let candidates = match hvf_candidates(homes) {
            Ok(candidates) => candidates,
            Err(category) => {
                report.unknown.push(UnknownCleanup {
                    pid: None,
                    category,
                });
                break;
            }
        };
        // Production supervisors take config on stdin, not argv. Discover every
        // home-local runtime candidate even when ps names only the executable.
        for (home, vm) in &candidates {
            // A configured supervisor can have an arbitrary filename. Without
            // argv identity, raw cleanup cannot safely distinguish it from a
            // helper in this home, even after the stop child returns.
            protected_markers.extend(owned_markers(home));
            if attempted.insert((home.clone(), vm.clone())) {
                let result = if round == 0 {
                    ops.stop(home, vm)
                } else {
                    Err(CleanupUnknown::NewSupervisor)
                };
                if let Err(category) = result {
                    report.unknown.push(UnknownCleanup {
                        pid: None,
                        category,
                    });
                }
            }
        }
        for process in &processes {
            let in_hvf_home = protected_markers
                .iter()
                .any(|marker| process.args.contains(marker));
            if in_hvf_home && protected.insert(process.pid) && round != 0 {
                report.unknown.push(UnknownCleanup {
                    pid: Some(process.pid),
                    category: CleanupUnknown::NewSupervisor,
                });
            }
            if is_hvf(process) && seen_hvf.insert(process.pid) {
                protected.insert(process.pid);
                let result = if round != 0 {
                    Err(CleanupUnknown::NewSupervisor)
                } else if in_hvf_home {
                    Ok(())
                } else {
                    Err(CleanupUnknown::MissingVm)
                };
                if let Err(category) = result {
                    let unknown = UnknownCleanup {
                        pid: Some(process.pid),
                        category,
                    };
                    if !report.unknown.contains(&unknown) {
                        report.unknown.push(unknown);
                    }
                }
            }
        }
        if round == 1 || round == 2 {
            for process in &processes {
                if !is_hvf(process) && !protected.contains(&process.pid) {
                    ops.signal(process.pid, if round == 1 { "TERM" } else { "KILL" });
                }
            }
        }
        report.survivors = processes;
        if round == 3 {
            for process in &report.survivors {
                if protected.contains(&process.pid)
                    && !report
                        .unknown
                        .iter()
                        .any(|unknown| unknown.pid == Some(process.pid))
                {
                    report.unknown.push(UnknownCleanup {
                        pid: Some(process.pid),
                        category: CleanupUnknown::SupervisorSurvived,
                    });
                }
            }
        }
        if report.survivors.is_empty() && (round != 0 || candidates.is_empty()) {
            break;
        }
        if round == 1 || round == 2 {
            ops.grace(Duration::from_secs(if round == 1 { 5 } else { 2 }));
        }
    }
    report
}

/// Homes a live step has launched `mvmctl` against during this run.
static LAUNCHED_HOMES: std::sync::Mutex<std::collections::BTreeSet<PathBuf>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

/// Record that a step is about to launch `mvmctl` against `home`, so a run
/// interrupted mid-step can still stop what it started.
///
/// The per-scenario teardown cannot cover that case: a job that hits its
/// timeout, or is cancelled, signals the runner process while a step is still
/// blocked, and nothing after that step — the `after` hook, the world's
/// destructor — ever runs.
pub fn register_launched_home(home: &Path) {
    if let Ok(mut homes) = LAUNCHED_HOMES.lock() {
        homes.insert(home.to_path_buf());
    }
}

/// [`reap_homes`] over every home [`register_launched_home`] recorded.
pub fn reap_launched_homes() -> ReapReport {
    let homes: Vec<PathBuf> = LAUNCHED_HOMES
        .lock()
        .map(|homes| homes.iter().cloned().collect())
        .unwrap_or_default();
    let homes: Vec<&Path> = homes.iter().map(PathBuf::as_path).collect();
    reap_homes(&homes)
}

/// Reaps `home` when dropped, including while unwinding from a failed step.
///
/// Hold it next to the `TempDir` that owns the home and declare it so it drops
/// first: the reap needs the state directories to derive the socket fallback
/// paths, and the processes must be gone before their files are deleted.
#[derive(Debug)]
pub struct ReapOnDrop {
    home: PathBuf,
    temporary: Option<tempfile::TempDir>,
    finished: bool,
}

impl ReapOnDrop {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self {
            home: home.into(),
            temporary: None,
            finished: false,
        }
    }

    /// Own a temporary home so failed cleanup retains its evidence.
    pub fn temporary(home: tempfile::TempDir) -> Self {
        Self {
            home: home.path().to_owned(),
            temporary: Some(home),
            finished: false,
        }
    }

    pub fn path(&self) -> &Path {
        &self.home
    }

    /// Finish explicitly so the caller can fail on an unconfirmed cleanup.
    pub fn finish(self) -> ReapReport {
        self.finish_with(reap_home)
    }

    fn finish_with(mut self, reap: impl FnOnce(&Path) -> ReapReport) -> ReapReport {
        let report = reap(&self.home);
        self.complete(&report);
        report
    }

    fn complete(&mut self, report: &ReapReport) {
        if !report.is_clean()
            && let Some(home) = self.temporary.take()
        {
            let _ = home.keep();
        }
        self.finished = true;
    }
}

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let report = reap_home(&self.home);
        self.complete(&report);
        if !report.found.is_empty() {
            eprintln!(
                "[bdd] found {} process(es) left running against {}:\n{}",
                report.found.len(),
                self.home.display(),
                ReapReport::describe(&report.found)
            );
        }
        if !report.is_clean() {
            eprintln!("[bdd] could not stop:\n{}", report.describe_failure());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "live: explicit private standby fixture and authenticated-reaper opt-in required"]
    fn native_authenticated_hvf_reap() {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(std::env::var("MVM_E2E_AUTH_REAPER").as_deref(), Ok("1"));
        let home = PathBuf::from(
            std::env::var_os("MVM_E2E_STANDBY_ROOT").expect("explicit standby fixture root"),
        );
        let configured = PathBuf::from(std::env::var_os("MVM_HOME").expect("explicit MVM_HOME"));
        assert!(home.is_absolute(), "fixture root must be absolute");
        assert_eq!(home, configured, "fixture root must equal MVM_HOME");
        let metadata = std::fs::symlink_metadata(&home).expect("existing fixture root");
        assert!(
            metadata.is_dir(),
            "fixture root must be a real directory, not a symlink"
        );
        assert_eq!(
            metadata.permissions().mode() & 0o077,
            0,
            "fixture root must be private"
        );
        let binary = PathBuf::from(
            std::env::var_os("CARGO_BIN_EXE_mvmctl").expect("explicit source-built CLI path"),
        );
        assert!(
            binary.is_absolute() && binary.is_file(),
            "CLI override must name an existing absolute binary"
        );
        assert_eq!(crate::mvmctl_path().unwrap(), binary);
        let expected_vm =
            std::env::var("MVM_E2E_EXPECTED_VM").expect("explicit expected fixture VM");
        mvm_core::naming::validate_vm_name(&expected_vm).expect("valid expected VM name");
        assert_eq!(
            hvf_candidates(&[&home]).unwrap(),
            [(home.clone(), expected_vm)],
            "fixture must contain exactly the expected HVF runtime candidate"
        );

        // The parent witness owns launch and any fallback. This invokes only
        // the real reaper and never owns or deletes the caller's fixture root.
        let report = reap_home(&home);
        assert!(
            report.is_clean(),
            "native reaper cleanup unknown:\n{}",
            report.describe_failure()
        );
        assert!(home.is_dir(), "reaper must retain the caller's root");
    }

    fn row(pid: u32, ppid: u32, args: &str) -> ProcessRow {
        ProcessRow {
            pid,
            ppid,
            args: args.to_string(),
        }
    }

    #[derive(Default)]
    struct FakeOps {
        scans: std::collections::VecDeque<Vec<OwnedProcess>>,
        stops: Vec<(PathBuf, String)>,
        signals: Vec<(u32, String)>,
        refusal: Option<CleanupUnknown>,
    }

    impl ReapOps for FakeOps {
        fn scan(&mut self, _: &[&Path]) -> Result<Vec<OwnedProcess>, CleanupUnknown> {
            Ok(self.scans.pop_front().unwrap_or_default())
        }
        fn stop(&mut self, home: &Path, vm: &str) -> Result<(), CleanupUnknown> {
            self.stops.push((home.to_owned(), vm.to_owned()));
            self.refusal.map_or(Ok(()), Err)
        }
        fn signal(&mut self, pid: u32, kind: &str) {
            self.signals.push((pid, kind.to_owned()));
        }
        fn grace(&mut self, _: Duration) {}
    }

    fn hvf_fixture(home: &Path, vm: &str, pid: u32) -> OwnedProcess {
        let dir = mvm_core::config::vms_dir_at(home).join(vm);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("hvf-instance.json"),
            serde_json::to_vec(&mvm_core::protocol::hvf_control::HvfInstance {
                vm_id: vm.into(),
                boot_nonce: [1; 32],
            })
            .unwrap(),
        )
        .unwrap();
        OwnedProcess {
            pid,
            // Production passes JSON on stdin and no VM arguments.
            args: home.join("bin/mvm-hvf-supervisor").display().to_string(),
        }
    }

    #[test]
    fn production_stdin_config_argv_needs_no_home_or_vm_argument() {
        let home = tempfile::tempdir().unwrap();
        hvf_fixture(home.path(), "resident", 42);
        // Native cold/restore spawning passes the helper executable alone.
        let rows = [row(42, 1, "/opt/mvm/libexec/mvm-hvf-supervisor")];
        let selected = select_owned(&rows, &owned_markers(home.path()), &HashSet::new());
        assert!(
            selected.is_empty(),
            "argv alone cannot attribute this supervisor"
        );
        let mut ops = FakeOps {
            scans: [selected, vec![]].into(),
            ..Default::default()
        };
        let report = reap_with(&[home.path()], &mut ops);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(ops.stops, [(home.path().to_owned(), "resident".into())]);
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn other_shards_supervisors_do_not_fail_this_home() {
        let home = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        hvf_fixture(other.path(), "resident", 42);
        let rows = [
            row(
                42,
                1,
                &other
                    .path()
                    .join("bin/mvm-hvf-supervisor")
                    .display()
                    .to_string(),
            ),
            row(43, 1, "/opt/mvm/libexec/mvm-hvf-supervisor"),
        ];
        let processes = select_owned(&rows, &owned_markers(home.path()), &HashSet::new());
        assert!(processes.is_empty());
        let mut ops = FakeOps {
            scans: [processes].into(),
            ..Default::default()
        };
        assert!(reap_with(&[home.path()], &mut ops).is_clean());
        assert!(ops.stops.is_empty());
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn another_requested_homes_candidate_cannot_account_for_missing_evidence() {
        let valid_home = tempfile::tempdir().unwrap();
        let unknown_home = tempfile::tempdir().unwrap();
        let valid = hvf_fixture(valid_home.path(), "resident", 42);
        let unknown = OwnedProcess {
            pid: 43,
            args: unknown_home
                .path()
                .join("bin/mvm-hvf-supervisor")
                .display()
                .to_string(),
        };
        let mut ops = FakeOps {
            scans: [vec![valid, unknown], vec![]].into(),
            ..Default::default()
        };
        let report = reap_with(&[valid_home.path(), unknown_home.path()], &mut ops);
        assert!(!report.is_clean());
        assert_eq!(
            report.unknown,
            [UnknownCleanup {
                pid: Some(43),
                category: CleanupUnknown::MissingVm
            }]
        );
        assert_eq!(
            ops.stops,
            [(valid_home.path().to_owned(), "resident".into())]
        );
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn custom_named_supervisor_in_hvf_home_never_receives_raw_signals() {
        for refusal in [None, Some(CleanupUnknown::StopRefused)] {
            let home = tempfile::tempdir().unwrap();
            hvf_fixture(home.path(), "resident", 42);
            let process = OwnedProcess {
                pid: 42,
                args: home.path().join("bin/custom-runner").display().to_string(),
            };
            let mut ops = FakeOps {
                scans: [
                    vec![process.clone()],
                    vec![process.clone()],
                    vec![process.clone()],
                    vec![process],
                ]
                .into(),
                refusal,
                ..Default::default()
            };
            let report = reap_with(&[home.path()], &mut ops);
            assert!(
                !report.is_clean(),
                "even a CLI success cannot hide a survivor"
            );
            assert!(ops.signals.is_empty());
            assert_eq!(ops.stops.len(), 1);
        }
    }

    #[test]
    fn configured_custom_filename_is_an_exclusion_not_stop_authority() {
        let process = OwnedProcess {
            pid: 42,
            args: "/fixture/home/bin/custom-runner".into(),
        };
        assert!(is_hvf_with_override(
            &process,
            Some(std::ffi::OsStr::new("/fixture/home/bin/custom-runner"))
        ));
        assert!(!is_hvf_with_override(&process, None));
    }

    #[test]
    fn new_custom_named_process_in_hvf_home_keeps_cleanup_unknown() {
        let home = tempfile::tempdir().unwrap();
        hvf_fixture(home.path(), "resident", 42);
        let process = OwnedProcess {
            pid: 43,
            args: home.path().join("bin/custom-runner").display().to_string(),
        };
        let mut ops = FakeOps {
            scans: [vec![], vec![process], vec![]].into(),
            ..Default::default()
        };
        let report = reap_with(&[home.path()], &mut ops);
        assert!(!report.is_clean());
        assert_eq!(report.unknown[0].category, CleanupUnknown::NewSupervisor);
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn pid_marker_without_identity_still_requires_canonical_stop() {
        let home = tempfile::tempdir().unwrap();
        let dir = mvm_core::config::vms_dir_at(home.path()).join("resident");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("hvf.pid"), "not-a-trusted-pid").unwrap();
        let mut ops = FakeOps {
            refusal: Some(CleanupUnknown::StopRefused),
            ..Default::default()
        };
        let report = reap_with(&[home.path()], &mut ops);
        assert!(!report.is_clean());
        assert_eq!(ops.stops, [(home.path().to_owned(), "resident".into())]);
        assert!(dir.join("hvf.pid").exists());
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn fifo_identity_is_discovered_without_opening_it() {
        let home = tempfile::tempdir().unwrap();
        let dir = mvm_core::config::vms_dir_at(home.path()).join("resident");
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("hvf-instance.json");
        assert!(
            Command::new("/usr/bin/mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let mut ops = FakeOps {
            refusal: Some(CleanupUnknown::StopTimedOut),
            ..Default::default()
        };
        let report = reap_with(&[home.path()], &mut ops);
        assert!(!report.is_clean());
        assert_eq!(report.unknown[0].category, CleanupUnknown::StopTimedOut);
        assert!(fifo.exists());
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn explicit_finish_retains_failed_home_and_returns_the_only_cleanup_report() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().to_owned();
        hvf_fixture(&path, "resident", 42);
        let mut ops = FakeOps {
            refusal: Some(CleanupUnknown::StopRefused),
            ..Default::default()
        };
        let report = ReapOnDrop::temporary(home).finish_with(|home| reap_with(&[home], &mut ops));
        assert!(!report.is_clean());
        assert_eq!(ops.stops.len(), 1);
        assert!(path.join("vms/resident/hvf-instance.json").exists());
        assert!(ops.signals.is_empty());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn explicit_finish_cleans_a_confirmed_temporary_home() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().to_owned();
        let report = ReapOnDrop::temporary(home).finish_with(|_| ReapReport::default());
        assert!(report.is_clean());
        assert!(!path.exists());
    }

    #[test]
    fn authenticated_stop_uses_isolated_cli_and_never_signals_hvf() {
        let home = tempfile::tempdir().unwrap();
        let process = hvf_fixture(home.path(), "parent", 42);
        let mut ops = FakeOps {
            scans: [vec![process], vec![]].into(),
            ..Default::default()
        };
        let report = reap_with(&[home.path()], &mut ops);
        assert!(report.is_clean(), "{report:?}");
        assert_eq!(ops.stops, [(home.path().to_owned(), "parent".into())]);
        assert!(ops.signals.is_empty());
        let command = stop_command(Path::new("/test/mvmctl"), home.path(), "parent");
        assert_eq!(command.get_program(), "/test/mvmctl");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            ["machine", "stop", "parent", "--yes"]
        );
        assert!(
            command
                .get_envs()
                .any(|(key, value)| key == "MVM_HOME" && value == Some(home.path().as_os_str()))
        );
    }

    #[test]
    fn refusals_and_invalid_identity_keep_evidence_even_after_process_disappears() {
        for failure in [CleanupUnknown::StopRefused, CleanupUnknown::StopTimedOut] {
            let home = tempfile::tempdir().unwrap();
            let process = hvf_fixture(home.path(), "parent", 42);
            let identity =
                mvm_core::config::vms_dir_at(home.path()).join("parent/hvf-instance.json");
            std::fs::write(&identity, "malformed secret").unwrap();
            let before = std::fs::read(&identity).unwrap();
            let mut ops = FakeOps {
                scans: [vec![process], vec![]].into(),
                refusal: Some(failure),
                ..Default::default()
            };
            let report = reap_with(&[home.path()], &mut ops);
            assert!(!report.is_clean());
            assert_eq!(report.unknown[0].category, failure);
            assert!(ops.signals.is_empty());
            assert_eq!(std::fs::read(&identity).unwrap(), before);
            assert!(!report.describe_failure().contains("secret"));
        }
    }

    #[test]
    fn missing_identity_and_unmatched_supervisors_are_never_raw_killed() {
        let home = tempfile::tempdir().unwrap();
        let missing = hvf_fixture(home.path(), "parent", 42);
        std::fs::remove_file(
            mvm_core::config::vms_dir_at(home.path()).join("parent/hvf-instance.json"),
        )
        .unwrap();
        let unmatched = OwnedProcess {
            pid: 43,
            args: format!(
                "mvm-hvf-supervisor {}/unknown/config",
                home.path().display()
            ),
        };
        let mut ops = FakeOps {
            scans: [vec![missing, unmatched], vec![]].into(),
            ..Default::default()
        };
        let report = reap_with(&[home.path()], &mut ops);
        assert_eq!(
            report
                .unknown
                .iter()
                .map(|u| u.category)
                .collect::<Vec<_>>(),
            [CleanupUnknown::MissingVm, CleanupUnknown::MissingVm]
        );
        assert!(!report.is_clean());
        assert!(ops.stops.is_empty());
        assert!(ops.signals.is_empty());
    }

    #[test]
    fn each_sweep_excludes_new_hvf_and_keeps_non_hvf_escalation() {
        for arrival in [1, 2, 3] {
            let home = tempfile::tempdir().unwrap();
            let helper = OwnedProcess {
                pid: 11,
                args: "helper".into(),
            };
            let hvf = hvf_fixture(home.path(), "refill", 42);
            let mut scans = vec![
                vec![helper.clone()],
                vec![helper.clone()],
                vec![helper],
                vec![],
            ];
            scans[arrival].push(hvf);
            let mut ops = FakeOps {
                scans: scans.into(),
                ..Default::default()
            };
            let report = reap_with(&[home.path()], &mut ops);
            assert!(!report.is_clean(), "{report:?}");
            assert_eq!(report.unknown[0].category, CleanupUnknown::NewSupervisor);
            assert_eq!(ops.signals, [(11, "TERM".into()), (11, "KILL".into())]);
            assert_eq!(ops.stops.len(), 1);
        }
    }

    #[test]
    fn later_empty_drop_scan_does_not_clear_unknown() {
        let home = Path::new("/fixture/home");
        let mut uncertain = HashMap::new();
        let mut refused = ReapReport {
            unknown: vec![UnknownCleanup {
                pid: Some(42),
                category: CleanupUnknown::StopRefused,
            }],
            ..Default::default()
        };
        retain_unknown(&[home], &mut refused, &mut uncertain);
        let mut later = ReapReport::default();
        retain_unknown(&[home], &mut later, &mut uncertain);
        assert!(!later.is_clean());
        assert_eq!(later.unknown, refused.unknown);
        let mut unrelated = ReapReport::default();
        retain_unknown(
            &[Path::new("/fixture/other")],
            &mut unrelated,
            &mut uncertain,
        );
        assert!(unrelated.is_clean());
    }

    #[test]
    fn the_process_table_parses_pid_ppid_and_full_args() {
        let rows = parse_process_table(
            "    1     0 /sbin/init\n\
             2876658 2876657 firecracker --api-sock /tmp/.tmp5fKeaH/vms/bdd/fc.socket\n\
             \x20  12     2 \n\
             garbage line\n",
        );
        assert_eq!(
            rows,
            vec![
                row(1, 0, "/sbin/init"),
                row(
                    2876658,
                    2876657,
                    "firecracker --api-sock /tmp/.tmp5fKeaH/vms/bdd/fc.socket"
                ),
                row(12, 2, ""),
            ]
        );
    }

    #[test]
    fn only_processes_naming_an_owned_path_are_selected() {
        let rows = vec![
            row(10, 1, "firecracker --api-sock /tmp/home-a/vms/x/fc.socket"),
            row(11, 1, "firecracker --api-sock /tmp/home-ab/vms/x/fc.socket"),
            row(12, 1, "firecracker --api-sock /tmp/mvm-sock-abc/fc.socket"),
            row(13, 1, "sleep 100"),
        ];
        let markers = vec!["/tmp/home-a/".to_string(), "/tmp/mvm-sock-abc/".to_string()];
        let owned: Vec<u32> = select_owned(&rows, &markers, &HashSet::new())
            .into_iter()
            .map(|p| p.pid)
            .collect();
        // `/tmp/home-ab` shares a prefix with `/tmp/home-a` but is not under it.
        assert_eq!(owned, vec![10, 12]);
    }

    #[test]
    fn the_reaping_process_and_its_parents_are_spared() {
        let rows = vec![
            row(1, 0, "/sbin/init"),
            row(50, 1, "bash -c MVM_HOME=/tmp/home-a/ run"),
            row(60, 50, "conformance /tmp/home-a/"),
            row(70, 1, "firecracker --api-sock /tmp/home-a/vms/x/fc.socket"),
        ];
        let spare = ancestry(&rows, 60);
        assert_eq!(spare, HashSet::from([50, 60]));
        let owned: Vec<u32> = select_owned(&rows, &["/tmp/home-a/".to_string()], &spare)
            .into_iter()
            .map(|p| p.pid)
            .collect();
        assert_eq!(owned, vec![70]);
    }

    #[test]
    fn a_long_state_dir_adds_its_socket_fallback_directory() {
        // Root the home at a short path: a runner whose TMPDIR is already
        // near the socket limit would earn the home itself a fallback entry
        // and break the two-marker expectation.
        let home = tempfile::Builder::new()
            .prefix("mvm-reaper-test-")
            .tempdir_in("/tmp")
            .expect("create short home fixture directory");
        let long_name = "m".repeat(90);
        let state_dir = mvm_core::config::vms_dir_at(home.path()).join(&long_name);
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(mvm_core::config::vms_dir_at(home.path()).join("short")).unwrap();

        let markers = owned_markers(home.path());
        let fallback = mvm_core::config::vm_socket_dir_at(&state_dir);
        assert!(
            !fallback.starts_with(home.path()),
            "fixture must exceed the socket path limit"
        );
        assert_eq!(markers.len(), 2, "{markers:?}");
        assert_eq!(markers[0], with_trailing_slash(home.path()));
        assert_eq!(markers[1], with_trailing_slash(&fallback));
    }

    /// Start a process the way the Firecracker launch does: detached from the
    /// caller (its parent exits at once, so it is re-parented to init and is
    /// not in the test's process tree) with a home path in its command line.
    /// Returns its pid.
    fn spawn_detached_naming(path: &Path) -> u32 {
        let output = Command::new("sh")
            .arg("-c")
            .arg("( while :; do sleep 1; done ) </dev/null >/dev/null 2>&1 & echo $!")
            .arg(path)
            .output()
            .expect("spawn detached process");
        String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("detached pid")
    }

    fn is_running(pid: u32) -> bool {
        process_table().unwrap().iter().any(|row| row.pid == pid)
    }

    #[test]
    fn a_scenario_that_fails_midway_leaves_no_detached_process_behind() {
        let home = tempfile::tempdir().unwrap();
        let state_dir = mvm_core::config::vms_dir_at(home.path()).join("bdd-fails-midway");
        std::fs::create_dir_all(&state_dir).unwrap();
        let socket = state_dir.join("fc.socket");

        let pid = std::sync::Mutex::new(None);
        let outcome = std::panic::catch_unwind(|| {
            let _reaper = ReapOnDrop::new(home.path());
            *pid.lock().unwrap() = Some(spawn_detached_naming(&socket));
            panic!("a step failed before the scenario's own stop step");
        });
        assert!(outcome.is_err(), "the simulated step must fail");
        let pid = pid.lock().unwrap().expect("detached process started");

        assert!(
            !is_running(pid),
            "pid {pid} naming {} outlived the failed scenario",
            socket.display()
        );
        assert!(reap_home(home.path()).found.is_empty());
    }

    #[test]
    fn an_interrupted_run_stops_what_its_launched_homes_started() {
        let home = tempfile::tempdir().unwrap();
        let pid = spawn_detached_naming(&home.path().join("vms/interrupted/fc.socket"));
        register_launched_home(home.path());

        let report = reap_launched_homes();
        assert!(report.found.iter().any(|p| p.pid == pid), "{report:?}");
        assert!(report.is_clean(), "{report:?}");
        assert!(!is_running(pid));
    }

    #[test]
    fn a_reap_stops_only_what_names_the_home() {
        let home = tempfile::tempdir().unwrap();
        let other = tempfile::tempdir().unwrap();
        let mine = spawn_detached_naming(&home.path().join("vms/a/fc.socket"));
        let theirs = spawn_detached_naming(&other.path().join("vms/a/fc.socket"));

        let report = reap_home(home.path());
        let found: Vec<u32> = report.found.iter().map(|p| p.pid).collect();
        assert_eq!(found, vec![mine]);
        assert!(report.is_clean(), "{report:?}");
        assert!(!is_running(mine));
        assert!(
            is_running(theirs),
            "a process under another home was signalled"
        );

        let cleanup = reap_home(other.path());
        assert!(cleanup.is_clean(), "{cleanup:?}");
        assert!(!is_running(theirs));
    }
}
