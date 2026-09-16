//! `mvmctl env uninstall` — remove an installation made by `install.sh`.
//!
//! The removal itself is `uninstall.sh`, embedded here and run with the
//! arguments this verb was given, so the published script and the verb cannot
//! drift apart. The script owns the install layout it shares with `install.sh`.
//! This binary owns the two questions the script must not answer with a copy of
//! our logic — whether a machine is running, and whether a recorded daemon PID
//! still names an installed daemon — and the script asks them through the
//! hidden `--quiesce` mode before it removes anything.
//!
//! The verb runs before CLI startup creates configuration, signing keys or the
//! command audit envelope, so neither mode creates the state directory it may
//! be about to remove.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Args as ClapArgs;

use crate::install_layout::{LIB_MARKER, release_dirs, versioned_lib_dir_of};
use crate::ui;

use mvm_vmm::host::broker_services_spawn::resolve_subprocess_bin;
use mvm_vmm::host::host_agent_spawn::{DAEMON_PID_FILE, HOST_AGENT_BIN};
use mvm_vmm::host::process_exit::{ProcessExitObserver, wait_for_pid_exit};
use mvm_vmm::host::process_liveness::{
    GuardedSignal, pid_is_alive, process_executable, read_pid_file, signal_if_executable,
};

use super::cleanup::running_vms_at;

/// The uninstaller published beside `install.sh`.
const UNINSTALL_SCRIPT: &str = include_str!("../../../../../uninstall.sh");

/// How long a host-agent daemon gets to exit after SIGTERM.
const DAEMON_EXIT_TIMEOUT: Duration = Duration::from_secs(10);

/// Env var naming the library directory, read by the script and by `--quiesce`.
const LIB_DIR_ENV: &str = "MVM_INSTALL_LIB_DIR";
/// Env var naming the mvmctl the script asks to run `--quiesce`.
const CHECKER_ENV: &str = "MVM_UNINSTALL_CHECKER";

#[derive(ClapArgs, Debug, Clone, PartialEq, Eq)]
pub(in crate::commands) struct Args {
    /// Also remove the mvm state directory (~/.mvm, or MVM_HOME) without asking
    #[arg(long)]
    pub purge: bool,
    /// Print what would be removed without removing anything
    #[arg(long)]
    pub dry_run: bool,
    /// Skip the running-machine check and host-agent daemon shutdown
    #[arg(long)]
    pub force: bool,
    /// Refuse if a machine is running, then stop the host-agent daemons after
    /// confirming each recorded PID runs an installed daemon binary. The
    /// uninstall script calls this before it removes anything.
    #[arg(long, hide = true, conflicts_with_all = ["purge", "force"])]
    pub quiesce: bool,
}

pub(in crate::commands) fn run(args: &Args) -> Result<()> {
    if args.quiesce {
        return quiesce(args.dry_run);
    }
    run_script(args)
}

/// The flags the script receives for these arguments.
fn script_flags(args: &Args) -> Vec<&'static str> {
    [
        (args.purge, "--purge"),
        (args.dry_run, "--dry-run"),
        (args.force, "--force"),
    ]
    .into_iter()
    .filter_map(|(set, flag)| set.then_some(flag))
    .collect()
}

/// The environment the script needs from the running binary: itself as the
/// checker, and the library directory it was installed into unless the caller
/// already named one. An unversioned binary names no location: a plain
/// `mvmctl` file could as well belong to a package manager, whose files this
/// uninstaller must never take.
fn script_env(exe: &Path, lib_dir_already_set: bool) -> Vec<(&'static str, PathBuf)> {
    let mut env = vec![(CHECKER_ENV, exe.to_path_buf())];
    if !lib_dir_already_set && let Some(lib) = versioned_lib_dir_of(exe) {
        env.push((LIB_DIR_ENV, lib));
    }
    env
}

fn env_is_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn run_script(args: &Args) -> Result<()> {
    let exe = std::env::current_exe().context("locating this mvmctl binary")?;
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(UNINSTALL_SCRIPT)
        .arg("uninstall.sh")
        .args(script_flags(args))
        .envs(script_env(&exe, env_is_set(LIB_DIR_ENV)))
        .status()
        .context("running the uninstall script with sh")?;
    if !status.success() {
        bail!("uninstall did not complete ({status})");
    }
    // Recorded only once the uninstall has happened, and only where a kept
    // state directory will still hold the entry.
    if !args.dry_run && Path::new(&mvm_core::config::mvm_home()).is_dir() {
        mvm_core::audit_emit!(Uninstall);
    }
    Ok(())
}

fn quiesce(dry_run: bool) -> Result<()> {
    let running = running_vms_at(&mvm_core::config::vms_dir());
    if !running.is_empty() {
        bail!("{}", running_machines_refusal(&running));
    }

    let identity = DaemonIdentity::installed(installed_lib_dir());
    let records = host_agent_daemons_at(&mvm_core::config::host_agent_root(), &identity);
    let pids = daemon_pids_to_stop(&records)?;
    if dry_run {
        for pid in &pids {
            ui::info(&format!("Would stop the host-agent daemon (pid {pid})"));
        }
        return Ok(());
    }
    for pid in pids {
        stop_daemon(pid, &identity)?;
        ui::info(&format!("Stopped the host-agent daemon (pid {pid})"));
    }
    Ok(())
}

/// The library directory being uninstalled: the one the script names, else
/// the one this binary runs from.
fn installed_lib_dir() -> Option<PathBuf> {
    std::env::var_os(LIB_DIR_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|lib| lib.join(LIB_MARKER).is_file())
        .or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| versioned_lib_dir_of(&exe))
        })
}

fn running_machines_refusal(running: &[String]) -> String {
    let stops = running
        .iter()
        .map(|name| format!("mvmctl machine stop {name}"))
        .collect::<Vec<_>>()
        .join("; ");
    format!(
        "{} running: {}. Stop {} first: {stops}",
        if running.len() == 1 {
            "a machine is"
        } else {
            "machines are"
        },
        running.join(", "),
        if running.len() == 1 { "it" } else { "them" },
    )
}

/// The daemon executables an uninstall may signal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct DaemonIdentity {
    /// Canonical paths of installed `mvm-host-agent` binaries.
    binaries: Vec<PathBuf>,
    /// The canonical library directory, when the install is versioned.
    lib_dir: Option<PathBuf>,
}

impl DaemonIdentity {
    /// The daemon binary this mvmctl would spawn, plus the one in every release
    /// directory of the library being uninstalled.
    fn installed(lib_dir: Option<PathBuf>) -> Self {
        let lib_dir = lib_dir.and_then(|lib| std::fs::canonicalize(lib).ok());
        let spawned = resolve_subprocess_bin(HOST_AGENT_BIN, "MVM_HOST_AGENT_PATH").ok();
        let released = lib_dir
            .iter()
            .flat_map(|lib| release_dirs(lib))
            .map(|release| release.join(HOST_AGENT_BIN));
        let binaries = spawned
            .into_iter()
            .chain(released)
            .filter_map(|path| std::fs::canonicalize(path).ok())
            .collect();
        Self { binaries, lib_dir }
    }

    /// Whether a process running `executable` is an installed daemon. The path
    /// must be one of the installed binaries. A daemon started from a release
    /// that has since been pruned runs a file that no longer exists; that one
    /// is accepted only when it sat directly inside a release directory of this
    /// library under the daemon's name.
    fn accepts(&self, executable: &Path) -> bool {
        if let Ok(canonical) = std::fs::canonicalize(executable) {
            return self.binaries.contains(&canonical);
        }
        executable.file_name() == Some(std::ffi::OsStr::new(HOST_AGENT_BIN))
            && self.lib_dir.is_some()
            && executable.parent().and_then(Path::parent) == self.lib_dir.as_deref()
    }
}

/// What a recorded host-agent daemon PID turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonPid {
    /// No live process holds the PID; there is nothing to stop.
    Stale,
    /// The PID is a live process running an installed daemon binary.
    Daemon(i32),
    /// The PID is live but cannot be shown to be the daemon, so signalling it
    /// could hit an unrelated process that inherited the number.
    Ambiguous { pid: i32, reason: String },
}

/// Decide what a recorded PID is from its liveness and the executable the
/// kernel reports for it.
fn classify_recorded_pid(
    pid: i32,
    alive: bool,
    executable: Option<&Path>,
    identity: &DaemonIdentity,
) -> DaemonPid {
    if !alive {
        return DaemonPid::Stale;
    }
    match executable {
        None => DaemonPid::Ambiguous {
            pid,
            reason: "its executable cannot be read".to_string(),
        },
        Some(path) if identity.accepts(path) => DaemonPid::Daemon(pid),
        Some(path) => DaemonPid::Ambiguous {
            pid,
            reason: format!(
                "it is running {}, not an installed {HOST_AGENT_BIN}",
                path.display()
            ),
        },
    }
}

fn inspect_pid(pid: i32, identity: &DaemonIdentity) -> DaemonPid {
    let alive = pid_is_alive(pid);
    let executable = if alive { process_executable(pid) } else { None };
    classify_recorded_pid(pid, alive, executable.as_deref(), identity)
}

/// One tenant's daemon PID file and what its PID turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DaemonRecord {
    pid_file: PathBuf,
    pid: DaemonPid,
}

/// Every host-agent daemon PID file under `root` that records a PID, sorted by
/// path. A missing root or an unparseable file records nothing to signal.
fn host_agent_daemons_at(root: &Path, identity: &DaemonIdentity) -> Vec<DaemonRecord> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let mut records: Vec<DaemonRecord> = entries
        .flatten()
        .map(|entry| entry.path().join(DAEMON_PID_FILE))
        .filter_map(|pid_file| {
            let pid = read_pid_file(&pid_file)?;
            Some(DaemonRecord {
                pid: inspect_pid(pid, identity),
                pid_file,
            })
        })
        .collect();
    records.sort_by(|a, b| a.pid_file.cmp(&b.pid_file));
    records
}

/// The daemon PIDs to stop, or an error naming every PID that could not be
/// confirmed. All-or-nothing: one ambiguous PID means nothing is signalled.
fn daemon_pids_to_stop(records: &[DaemonRecord]) -> Result<Vec<i32>> {
    let ambiguous: Vec<String> = records
        .iter()
        .filter_map(|record| match &record.pid {
            DaemonPid::Ambiguous { pid, reason } => Some(format!(
                "{} records pid {pid}, but {reason}",
                record.pid_file.display()
            )),
            DaemonPid::Stale | DaemonPid::Daemon(_) => None,
        })
        .collect();
    if !ambiguous.is_empty() {
        bail!(
            "refusing to signal a process that may not be the host-agent daemon: {}. \
             Check those processes, stop the daemon yourself or delete the stale PID \
             file, then run the uninstall again",
            ambiguous.join("; ")
        );
    }
    Ok(records
        .iter()
        .filter_map(|record| match record.pid {
            DaemonPid::Daemon(pid) => Some(pid),
            DaemonPid::Stale | DaemonPid::Ambiguous { .. } => None,
        })
        .collect())
}

/// SIGTERM one confirmed daemon and wait for it to exit. The identity is
/// checked again as part of sending the signal, so a daemon that exited since
/// it was inspected is not mistaken for whatever took its PID.
fn stop_daemon(pid: i32, identity: &DaemonIdentity) -> Result<()> {
    let observer = ProcessExitObserver::arm(pid).ok();
    let outcome = signal_if_executable(pid, libc::SIGTERM, &|path| identity.accepts(path))
        .with_context(|| format!("signal the host-agent daemon (pid {pid})"))?;
    match outcome {
        GuardedSignal::Exited => return Ok(()),
        GuardedSignal::Refused(executable) => bail!(
            "refusing to signal pid {pid}: {}",
            executable.map_or_else(
                || "its executable cannot be read".to_string(),
                |path| format!("it is running {}", path.display()),
            )
        ),
        GuardedSignal::Sent => {}
    }
    if !wait_for_pid_exit(pid, Instant::now() + DAEMON_EXIT_TIMEOUT, observer.as_ref()) {
        bail!(
            "the host-agent daemon (pid {pid}) did not exit within {}s of SIGTERM",
            DAEMON_EXIT_TIMEOUT.as_secs()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::install_layout::RELEASE_MARKER;

    fn args() -> Args {
        Args {
            purge: false,
            dry_run: false,
            force: false,
            quiesce: false,
        }
    }

    fn identity_of(binary: &Path) -> DaemonIdentity {
        DaemonIdentity {
            binaries: vec![std::fs::canonicalize(binary).unwrap()],
            lib_dir: None,
        }
    }

    /// A marked library `<root>/lib` with release `1-v1` holding the daemon.
    fn versioned_install() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let release = root.path().join("lib").join("1-v1");
        std::fs::create_dir_all(&release).unwrap();
        std::fs::write(root.path().join("lib").join(LIB_MARKER), "").unwrap();
        std::fs::write(release.join(RELEASE_MARKER), "complete\n").unwrap();
        std::fs::write(release.join(HOST_AGENT_BIN), "").unwrap();
        std::fs::write(release.join("mvmctl"), "").unwrap();
        root
    }

    #[test]
    fn the_embedded_script_is_the_published_uninstaller() {
        assert!(UNINSTALL_SCRIPT.starts_with("#!/bin/sh\n# mvmctl uninstaller."));
        assert!(UNINSTALL_SCRIPT.contains("env uninstall \"$@\""));
        assert!(UNINSTALL_SCRIPT.contains(CHECKER_ENV));
        assert!(UNINSTALL_SCRIPT.contains(LIB_DIR_ENV));
    }

    #[test]
    fn script_flags_forward_exactly_the_flags_given() {
        assert!(script_flags(&args()).is_empty());
        let all = Args {
            purge: true,
            dry_run: true,
            force: true,
            quiesce: false,
        };
        assert_eq!(script_flags(&all), ["--purge", "--dry-run", "--force"]);
    }

    #[test]
    fn the_script_asks_this_binary_and_is_told_its_library() {
        let root = versioned_install();
        let exe = root.path().join("lib/1-v1/mvmctl");
        let lib = std::fs::canonicalize(root.path().join("lib")).unwrap();
        assert_eq!(
            script_env(&exe, false),
            vec![(CHECKER_ENV, exe.clone()), (LIB_DIR_ENV, lib)]
        );
        assert_eq!(
            script_env(&exe, true),
            vec![(CHECKER_ENV, exe)],
            "a library the caller named is not overridden"
        );
    }

    #[test]
    fn an_unversioned_binary_names_no_install_location() {
        let root = tempfile::tempdir().unwrap();
        let exe = root.path().join("mvmctl");
        std::fs::write(&exe, "").unwrap();
        assert_eq!(script_env(&exe, false), vec![(CHECKER_ENV, exe)]);
    }

    #[test]
    fn a_dead_pid_is_stale_whatever_it_once_ran() {
        let identity = DaemonIdentity::default();
        assert_eq!(
            classify_recorded_pid(4242, false, None, &identity),
            DaemonPid::Stale
        );
        assert_eq!(
            classify_recorded_pid(4242, false, Some(Path::new("/bin/sleep")), &identity),
            DaemonPid::Stale
        );
    }

    #[test]
    fn a_live_pid_running_an_installed_daemon_binary_is_the_daemon() {
        let root = versioned_install();
        let binary = root.path().join("lib/1-v1").join(HOST_AGENT_BIN);
        assert_eq!(
            classify_recorded_pid(4242, true, Some(&binary), &identity_of(&binary)),
            DaemonPid::Daemon(4242)
        );
        let installed = DaemonIdentity::installed(Some(root.path().join("lib")));
        assert!(
            installed.accepts(&binary),
            "every release directory's daemon binary is installed: {installed:?}"
        );
    }

    #[test]
    fn a_daemon_name_outside_the_install_is_ambiguous() {
        let root = versioned_install();
        let installed = root.path().join("lib/1-v1").join(HOST_AGENT_BIN);
        let elsewhere = root.path().join("elsewhere").join(HOST_AGENT_BIN);
        std::fs::create_dir_all(elsewhere.parent().unwrap()).unwrap();
        std::fs::write(&elsewhere, "").unwrap();
        let DaemonPid::Ambiguous { pid, reason } =
            classify_recorded_pid(4242, true, Some(&elsewhere), &identity_of(&installed))
        else {
            panic!("a binary merely named like the daemon is not the daemon");
        };
        assert_eq!(pid, 4242);
        assert!(reason.contains("elsewhere"), "{reason}");
        assert!(matches!(
            classify_recorded_pid(
                4242,
                true,
                Some(Path::new("/bin/sleep")),
                &identity_of(&installed)
            ),
            DaemonPid::Ambiguous { .. }
        ));
    }

    #[test]
    fn a_pruned_release_daemon_is_accepted_only_inside_the_library() {
        let root = versioned_install();
        let lib = std::fs::canonicalize(root.path().join("lib")).unwrap();
        let identity = DaemonIdentity {
            binaries: Vec::new(),
            lib_dir: Some(lib.clone()),
        };
        assert!(identity.accepts(&lib.join("0-v0").join(HOST_AGENT_BIN)));
        assert!(!identity.accepts(&lib.join("0-v0").join("mvm-other")));
        assert!(!identity.accepts(&lib.join("0-v0/nested").join(HOST_AGENT_BIN)));
        assert!(!identity.accepts(&root.path().join("gone").join(HOST_AGENT_BIN)));
        assert!(
            !DaemonIdentity::default().accepts(&lib.join("0-v0").join(HOST_AGENT_BIN)),
            "without a library there is nothing to have been pruned from"
        );
    }

    #[test]
    fn a_live_pid_whose_executable_cannot_be_read_is_ambiguous() {
        assert!(matches!(
            classify_recorded_pid(4242, true, None, &DaemonIdentity::default()),
            DaemonPid::Ambiguous { .. }
        ));
    }

    #[test]
    fn daemon_records_are_read_from_each_tenant_directory() {
        let root = tempfile::tempdir().unwrap();
        let own_pid = std::process::id().to_string();
        for (tenant, body) in [
            ("acme", own_pid.as_str()),
            ("junk", "not-a-pid"),
            ("init", "1"),
        ] {
            let dir = root.path().join(tenant);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(DAEMON_PID_FILE), body).unwrap();
        }
        std::fs::create_dir_all(root.path().join("no-pid-file")).unwrap();

        let records = host_agent_daemons_at(root.path(), &DaemonIdentity::default());
        assert_eq!(records.len(), 1, "{records:?}");
        assert_eq!(
            records[0].pid_file,
            root.path().join("acme").join(DAEMON_PID_FILE)
        );
        // This test process is live and is not an installed daemon binary.
        assert!(matches!(records[0].pid, DaemonPid::Ambiguous { .. }));
        assert!(
            host_agent_daemons_at(&root.path().join("absent"), &DaemonIdentity::default())
                .is_empty()
        );
    }

    #[test]
    fn one_ambiguous_record_means_nothing_is_signalled() {
        let records = vec![
            DaemonRecord {
                pid_file: PathBuf::from("/m/host-agent/a/daemon.pid"),
                pid: DaemonPid::Daemon(10),
            },
            DaemonRecord {
                pid_file: PathBuf::from("/m/host-agent/b/daemon.pid"),
                pid: DaemonPid::Ambiguous {
                    pid: 11,
                    reason: "it is running /bin/sleep".to_string(),
                },
            },
        ];
        let error = daemon_pids_to_stop(&records).unwrap_err().to_string();
        assert!(error.contains("/m/host-agent/b/daemon.pid"), "{error}");
        assert!(error.contains("pid 11"), "{error}");
    }

    #[test]
    fn confirmed_daemons_are_stopped_and_stale_records_skipped() {
        let records = vec![
            DaemonRecord {
                pid_file: PathBuf::from("/m/host-agent/a/daemon.pid"),
                pid: DaemonPid::Daemon(10),
            },
            DaemonRecord {
                pid_file: PathBuf::from("/m/host-agent/b/daemon.pid"),
                pid: DaemonPid::Stale,
            },
        ];
        assert_eq!(daemon_pids_to_stop(&records).unwrap(), vec![10]);
    }

    #[test]
    fn the_refusal_names_every_running_machine_and_how_to_stop_it() {
        let one = running_machines_refusal(&["web".to_string()]);
        assert!(one.starts_with("a machine is running: web."), "{one}");
        assert!(one.contains("mvmctl machine stop web"), "{one}");
        let two = running_machines_refusal(&["api".to_string(), "web".to_string()]);
        assert!(two.starts_with("machines are running: api, web."), "{two}");
        assert!(two.contains("mvmctl machine stop api; mvmctl machine stop web"));
    }
}
