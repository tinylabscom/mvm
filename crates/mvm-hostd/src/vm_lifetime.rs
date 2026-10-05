//! Keep a per-VM endpoint serving for exactly as long as its VM runs.
//!
//! `mvm-network-endpoint` arms [`crate::parent_death`] first thing: it holds a
//! workload's secrets in the clear and must not keep serving once nobody is
//! responsible for it. That watch is on the process that spawned it, which is
//! right when the spawner owns the VM and wrong for a detached machine.
//! `mvmctl machine start` returns while the VM keeps running, and the endpoint
//! went with it, leaving the guest's egress socket and the host's
//! tool-decision socket bound to nothing.
//!
//! The keeper sits between the two. A launcher that wants the endpoint to live
//! as long as the VM starts the binary in keeper mode (`--vm-state-dir <dir>`);
//! the keeper starts the real endpoint as its own child, so the endpoint's
//! parent-death watch now follows the keeper, and the keeper stays until the
//! launcher has gone *and* no VM process is recorded live in the VM's state
//! directory. Everything that already signals the endpoint by its pid file —
//! the stop path, a failed launch's rollback — signals the keeper, whose death
//! takes the endpoint with it.
//!
//! The keeper reads nothing from stdin and holds no secret. The endpoint
//! inherits the launcher's pipes directly, and the keeper points its own copies
//! at `/dev/null` so the launcher still sees end-of-file when the endpoint
//! exits.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::Duration;

use anyhow::{Context, Result, bail};

pub use mvm_vmm::host::network_endpoint_spawn::VM_LIFETIME_FLAG;

/// How often the keeper looks at its launcher and its VM. The endpoint
/// outlives both by at most this long.
const POLL_INTERVAL: Duration = Duration::from_millis(500);

/// The VM state directory a keeper-mode invocation names, or `None` for an
/// ordinary endpoint invocation.
///
/// `args` is the full argument list, program name first. Anything other than
/// no arguments or exactly the flag and one directory is refused, so a
/// malformed launch cannot fall through to an endpoint with the wrong
/// lifetime.
pub fn requested_vm_state_dir(args: impl IntoIterator<Item = OsString>) -> Result<Option<PathBuf>> {
    let mut args = args.into_iter().skip(1);
    let Some(flag) = args.next() else {
        return Ok(None);
    };
    if flag != VM_LIFETIME_FLAG {
        bail!("unexpected argument {flag:?}; the endpoint takes its configuration on stdin");
    }
    let dir = args
        .next()
        .with_context(|| format!("{VM_LIFETIME_FLAG} needs the VM's state directory"))?;
    if let Some(extra) = args.next() {
        bail!("unexpected argument {extra:?} after {VM_LIFETIME_FLAG}");
    }
    Ok(Some(PathBuf::from(dir)))
}

/// Run as the keeper of `endpoint` for the VM recorded in `vm_state_dir`.
///
/// Returns the exit code the keeper should leave with: the endpoint's own when
/// it exits by itself, zero when the keeper stopped it because neither the
/// launcher nor the VM is left to serve.
pub fn keep_endpoint_for_vm(mut endpoint: Command, vm_state_dir: &Path) -> i32 {
    // SAFETY: `getppid` is async-signal-safe and infallible.
    let launcher = unsafe { libc::getppid() };
    let child = match endpoint.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("mvm-network-endpoint keeper: starting the endpoint failed: {error}");
            return 1;
        }
    };
    release_launcher_pipes();
    let state_dir = vm_state_dir.to_path_buf();
    keep(
        child,
        &Probes {
            launcher_alive: &move || launcher_is_alive(launcher),
            vm_alive: &move || {
                mvm_vmm::host::process_liveness::state_dir_has_live_process(&state_dir)
            },
        },
        POLL_INTERVAL,
    )
}

/// The two questions the keeper asks on every poll.
struct Probes<'a> {
    launcher_alive: &'a dyn Fn() -> bool,
    vm_alive: &'a dyn Fn() -> bool,
}

/// Whether the endpoint still has someone to serve.
fn endpoint_needed(launcher_alive: bool, vm_alive: bool) -> bool {
    launcher_alive || vm_alive
}

fn keep(mut child: Child, probes: &Probes<'_>, interval: Duration) -> i32 {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return exit_code(status),
            Ok(None) => {}
            Err(error) => {
                eprintln!("mvm-network-endpoint keeper: waiting on the endpoint failed: {error}");
                stop(&mut child);
                return 1;
            }
        }
        if !endpoint_needed((probes.launcher_alive)(), (probes.vm_alive)()) {
            stop(&mut child);
            return 0;
        }
        std::thread::sleep(interval);
    }
}

/// Whether the process that started the keeper is still its parent. A
/// re-parented keeper reports a different parent (init, or a subreaper), never
/// the launcher's pid again.
fn launcher_is_alive(launcher: libc::pid_t) -> bool {
    // SAFETY: `getppid` is async-signal-safe and infallible.
    let parent = unsafe { libc::getppid() };
    launcher > 1 && parent == launcher
}

/// Terminate the endpoint the way the stop path would and reap it.
fn stop(child: &mut Child) {
    if let Ok(pid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: signalling our own unreaped child; its pid cannot have been
        // recycled while it is still waitable.
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
    }
    let _ = child.wait();
}

fn exit_code(status: ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt as _;
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

/// Point the keeper's stdin and stdout at `/dev/null`.
///
/// The endpoint holds its own copies of the launcher's pipes. Were the keeper
/// to keep its write end of the stdout pipe, a launcher reading the endpoint's
/// handshake would not see end-of-file when the endpoint died before writing
/// it. Best-effort: a keeper that cannot open `/dev/null` only delays that
/// end-of-file until it exits itself.
fn release_launcher_pipes() {
    use std::os::fd::AsRawFd as _;
    let Ok(null) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
    else {
        return;
    };
    for fd in [libc::STDIN_FILENO, libc::STDOUT_FILENO] {
        // SAFETY: `dup2` onto a standard descriptor this process owns; `null`
        // stays open for the duration of the call.
        unsafe {
            libc::dup2(null.as_raw_fd(), fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const FAST: Duration = Duration::from_millis(20);

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    fn sleeper() -> Child {
        Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep")
    }

    fn running(child_pid: u32) -> bool {
        mvm_vmm::host::process_liveness::pid_is_alive(child_pid as i32)
    }

    #[test]
    fn only_the_flag_and_one_directory_select_keeper_mode() {
        assert_eq!(
            requested_vm_state_dir(args(&["mvm-network-endpoint"])).expect("no args"),
            None
        );
        assert_eq!(
            requested_vm_state_dir(args(&[
                "mvm-network-endpoint",
                VM_LIFETIME_FLAG,
                "/vms/web"
            ]))
            .expect("keeper args"),
            Some(PathBuf::from("/vms/web"))
        );
        for malformed in [
            &["mvm-network-endpoint", VM_LIFETIME_FLAG][..],
            &["mvm-network-endpoint", "--other", "/vms/web"],
            &[
                "mvm-network-endpoint",
                VM_LIFETIME_FLAG,
                "/vms/web",
                "extra",
            ],
        ] {
            assert!(
                requested_vm_state_dir(args(malformed)).is_err(),
                "{malformed:?} must be refused"
            );
        }
    }

    #[test]
    fn the_endpoint_is_needed_while_either_owner_is_alive() {
        assert!(endpoint_needed(true, false));
        assert!(endpoint_needed(false, true));
        assert!(endpoint_needed(true, true));
        assert!(!endpoint_needed(false, false));
    }

    #[test]
    fn an_endpoint_that_exits_by_itself_passes_its_code_through() {
        let child = Command::new("sh")
            .args(["-c", "exit 3"])
            .spawn()
            .expect("spawn sh");
        let code = keep(
            child,
            &Probes {
                launcher_alive: &|| true,
                vm_alive: &|| true,
            },
            FAST,
        );
        assert_eq!(code, 3);
    }

    #[test]
    fn with_no_launcher_and_no_vm_the_endpoint_is_stopped() {
        let child = sleeper();
        let pid = child.id();
        let code = keep(
            child,
            &Probes {
                launcher_alive: &|| false,
                vm_alive: &|| false,
            },
            FAST,
        );
        assert_eq!(code, 0);
        assert!(!running(pid), "the endpoint must not outlive its keeper");
    }

    #[test]
    fn the_endpoint_outlives_its_launcher_until_the_vm_stops() {
        let vm_running = Arc::new(AtomicBool::new(true));
        let child = sleeper();
        let pid = child.id();
        let keeper = {
            let vm_running = Arc::clone(&vm_running);
            std::thread::spawn(move || {
                keep(
                    child,
                    &Probes {
                        launcher_alive: &|| false,
                        vm_alive: &|| vm_running.load(Ordering::SeqCst),
                    },
                    FAST,
                )
            })
        };

        std::thread::sleep(FAST * 10);
        assert!(
            running(pid),
            "a running VM keeps its endpoint after the launcher has gone"
        );
        assert!(!keeper.is_finished());

        vm_running.store(false, Ordering::SeqCst);
        assert_eq!(keeper.join().expect("keeper thread"), 0);
        assert!(!running(pid), "a stopped VM's endpoint is stopped with it");
    }

    #[test]
    fn a_reparented_keeper_no_longer_counts_its_launcher() {
        // SAFETY: `getppid` is infallible.
        let parent = unsafe { libc::getppid() };
        assert!(launcher_is_alive(parent));
        assert!(!launcher_is_alive(parent + 1));
        assert!(!launcher_is_alive(1));
    }
}
