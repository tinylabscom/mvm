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

use mvm_core::env_hygiene::helper_command;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
}

impl ReapReport {
    /// Whether nothing the scenario started outlived the reap.
    pub fn is_clean(&self) -> bool {
        self.survivors.is_empty()
    }

    /// A one-line-per-process description for a failure message or a log.
    pub fn describe(processes: &[OwnedProcess]) -> String {
        processes
            .iter()
            .map(|process| format!("  pid {}: {}", process.pid, process.args))
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

fn process_table() -> Vec<ProcessRow> {
    helper_command("ps")
        .args(["-ww", "-eo", "pid=,ppid=,args="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| parse_process_table(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

fn scan(markers: &[String]) -> Vec<OwnedProcess> {
    let rows = process_table();
    let spare = ancestry(&rows, std::process::id());
    select_owned(&rows, markers, &spare)
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

fn wait_until_gone(markers: &[String], timeout: Duration) -> Vec<OwnedProcess> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = scan(markers);
        if remaining.is_empty() || Instant::now() >= deadline {
            return remaining;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Stop every process still running against `home`: SIGTERM, a grace period,
/// then SIGKILL. Each signal is re-aimed from a fresh scan, so a PID is only
/// signalled while its command line still names a path under the home.
pub fn reap_home(home: &Path) -> ReapReport {
    reap_homes(&[home])
}

/// [`reap_home`] over several homes with one process-table scan per round.
pub fn reap_homes(homes: &[&Path]) -> ReapReport {
    let markers: Vec<String> = homes.iter().flat_map(|home| owned_markers(home)).collect();
    if markers.is_empty() {
        return ReapReport::default();
    }
    let found = scan(&markers);
    if found.is_empty() {
        return ReapReport::default();
    }
    for process in &found {
        signal(process.pid, "TERM");
    }
    let mut remaining = wait_until_gone(&markers, Duration::from_secs(5));
    if !remaining.is_empty() {
        for process in &remaining {
            signal(process.pid, "KILL");
        }
        remaining = wait_until_gone(&markers, Duration::from_secs(2));
    }
    ReapReport {
        found,
        survivors: remaining,
    }
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
}

impl ReapOnDrop {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }
}

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        let report = reap_home(&self.home);
        if !report.found.is_empty() {
            eprintln!(
                "[bdd] stopped {} process(es) left running against {}:\n{}",
                report.found.len(),
                self.home.display(),
                ReapReport::describe(&report.found)
            );
        }
        if !report.is_clean() {
            eprintln!(
                "[bdd] could not stop:\n{}",
                ReapReport::describe(&report.survivors)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn row(pid: u32, ppid: u32, args: &str) -> ProcessRow {
        ProcessRow {
            pid,
            ppid,
            args: args.to_string(),
        }
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
        process_table().iter().any(|row| row.pid == pid)
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
