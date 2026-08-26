//! `mvmctl seccomp-audit` — run a command and report which syscalls it
//! uses that are missing from an mvm seccomp tier.
//!
//! This is a host-side developer tool: it ptraces the wrapped command on
//! a Linux host, records every unique syscall number, diffs the set
//! against a tier allowlist, and prints a ledger of missing syscalls.
//! It does not boot a microVM and does not install a seccomp filter, so
//! the workload runs normally while being observed.
//!
//! The tracer follows clones, forks and vforks, so a multi-threaded or
//! multi-process workload is audited whole. This matters for deriving a real
//! allowlist: every host role that would consume one builds a multi-threaded
//! tokio runtime, and an allowlist derived from the main thread alone is
//! incomplete by construction — the failure mode being SIGSYS under load,
//! after the filter is already installed.
//!
//! Syscall entry/exit state is tracked per tracee. It cannot be one flag for
//! the session: entry and exit are separate stops, sibling threads interleave
//! them freely, and a shared flag would pair one thread's entry with
//! another's exit and record the wrong half.
//!
//! Linux-only: ptrace is not available on macOS, and the seccomp tiers
//! are defined for Linux guests.

use anyhow::{Result, bail};
use clap::Args as ClapArgs;

use mvm_core::crypto::seccomp::SeccompTier;

use super::Cli;

#[derive(ClapArgs, Debug, Clone)]
#[command(name = "seccomp-audit")]
pub(in crate::commands) struct Args {
    /// Seccomp tier to audit against (essential, minimal, standard, network, unrestricted).
    #[arg(value_parser = parse_tier)]
    tier: String,

    /// Emit the ledger as JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Exit with code 1 if any observed syscall is missing from the tier.
    #[arg(long)]
    fail_on_missing: bool,

    /// Command to run after `--`.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

fn parse_tier(s: &str) -> std::result::Result<String, String> {
    s.parse::<SeccompTier>()
        .map(|_| s.to_string())
        .map_err(|_| format!("unknown seccomp tier {s:?}"))
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg(target_os = "linux")]
struct Report {
    tier: String,
    allowed: usize,
    observed: usize,
    missing: usize,
    missing_syscalls: Vec<SyscallEntry>,
    child_exit_code: Option<i32>,
    recommendation: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[cfg(target_os = "linux")]
struct SyscallEntry {
    nr: i64,
    name: String,
}

pub(in crate::commands) fn run(_cli: &Cli, args: Args) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_linux(args)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        bail!("mvmctl seccomp-audit is only available on Linux hosts");
    }
}

/// Whether a stop is a new tracee halting at birth rather than a signal the
/// workload sent itself.
///
/// Asking to follow clones means every new thread stops with `SIGSTOP` the
/// moment it exists. That stop is an artefact of attachment; forwarding it with
/// `ptrace::syscall(pid, Some(sig))` would deliver a stop the workload never
/// raised and can wedge a thread before it runs its first instruction. A
/// genuine `SIGSTOP` to an already-known tracee still has to be delivered.
/// Takes the raw signal number rather than `nix`'s `Signal` so it stays
/// testable on hosts where `nix` is not linked; `nix` is a Linux-only
/// dependency here but this decision is worth a witness anywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_new_tracee_birth_stop(first_sighting: bool, signal: i32) -> bool {
    first_sighting && signal == libc::SIGSTOP
}

#[cfg(target_os = "linux")]
fn run_linux(args: Args) -> Result<()> {
    use anyhow::Context;
    use nix::sys::ptrace::{self, Options};
    use nix::sys::signal::Signal;
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::Pid;
    use std::collections::{HashMap, HashSet};

    use mvm_core::crypto::seccomp::syscall_table;

    let tier: SeccompTier = args.tier.parse().context("invalid seccomp tier")?;
    let allowed_nrs: HashSet<i64> = tier
        .syscalls()
        .iter()
        .filter_map(|name| syscall_table::syscall_number(name))
        .collect();

    if args.command.is_empty() {
        bail!("missing command to audit");
    }
    let program = &args.command[0];

    let program_c = std::ffi::CString::new(program.as_str())
        .with_context(|| format!("invalid program name: {program}"))?;
    let argv_c: Vec<std::ffi::CString> = args
        .command
        .iter()
        .map(|s| std::ffi::CString::new(s.as_str()).context("command argument contains a NUL byte"))
        .collect::<anyhow::Result<_>>()?;

    // We fork manually instead of using std::process::Command so the child can
    // stop itself with SIGSTOP immediately after PTRACE_TRACEME, before the
    // execve. std::process::Command::spawn blocks on a status pipe from the
    // child until after all pre_exec closures return, so raising SIGSTOP inside
    // a pre_exec hook would deadlock the parent.
    let main_pid = match unsafe { nix::unistd::fork() }
        .with_context(|| format!("failed to fork child for {program}"))?
    {
        nix::unistd::ForkResult::Child => {
            // From here on we are in the child. Errors cannot be reported back
            // to the parent; exit with a distinctive status.
            if let Err(e) = (|| -> anyhow::Result<()> {
                ptrace::traceme().context("PTRACE_TRACEME failed")?;
                // Do not leak unrelated file descriptors into the audited command.
                close_non_stdio_fds();
                nix::sys::signal::raise(Signal::SIGSTOP).context("raise(SIGSTOP) failed")?;
                match nix::unistd::execvp(&program_c, &argv_c) {
                    Ok(never) => match never {},
                    Err(error) => Err(error).context("execvp failed"),
                }
            })() {
                eprintln!("mvmctl seccomp-audit (child): {e:#}");
            }
            std::process::exit(126);
        }
        nix::unistd::ForkResult::Parent { child } => child,
    };

    // Wait for the child's self-inflicted SIGSTOP so we can configure options.
    match waitpid(main_pid, None)? {
        WaitStatus::Stopped(_, Signal::SIGSTOP) => {}
        other => bail!("unexpected initial wait status: {other:?}"),
    }

    // TRACECLONE/FORK/VFORK make every new thread and child a tracee of ours,
    // stopped at birth, so none of them runs a syscall we fail to see.
    let options = Options::PTRACE_O_TRACESYSGOOD
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK;
    ptrace::setoptions(main_pid, options).context("failed to set ptrace options")?;

    // Start the tracee; from here on we use PTRACE_SYSCALL to stop at every entry/exit.
    ptrace::syscall(main_pid, None).context("failed to resume tracee")?;

    let mut observed = HashSet::new();
    // Per-tracee syscall-entry state. A tracee alternates entry/exit stops, but
    // siblings interleave, so this cannot collapse to one flag for the session.
    let mut in_syscall: HashMap<Pid, bool> = HashMap::new();
    // Tracees we have seen. A clone event and the new child's own SIGSTOP race,
    // so whichever arrives first registers it and the other is a no-op.
    let mut live: HashSet<Pid> = HashSet::new();
    live.insert(main_pid);

    let mut main_exit_code = None;

    // __WALL: without it waitpid ignores clone()d threads, which is most of
    // what we are here to observe.
    let wait_flags = Some(WaitPidFlag::__WALL);

    while !live.is_empty() {
        let status = match waitpid(Pid::from_raw(-1), wait_flags) {
            Ok(status) => status,
            // No children left to reap.
            Err(nix::errno::Errno::ECHILD) => break,
            Err(e) => return Err(e).context("waitpid failed"),
        };

        let pid = match status.pid() {
            Some(pid) => pid,
            None => continue,
        };

        match status {
            WaitStatus::Exited(_, code) => {
                live.remove(&pid);
                in_syscall.remove(&pid);
                if pid == main_pid {
                    main_exit_code = Some(code);
                }
                continue;
            }
            WaitStatus::Signaled(_, sig, _) => {
                live.remove(&pid);
                in_syscall.remove(&pid);
                // Only the main process dying by signal invalidates the audit;
                // a worker thread killed by design does not.
                if pid == main_pid {
                    bail!("audited command killed by signal {sig:?}");
                }
                continue;
            }
            WaitStatus::PtraceSyscall(_) => {
                let regs = ptrace::getregs(pid).context("failed to read tracee registers")?;
                let nr = extract_syscall_number(&regs);

                let entering = in_syscall.entry(pid).or_insert(false);
                *entering = !*entering;
                if *entering {
                    observed.insert(nr);
                }

                ptrace::syscall(pid, None).context("failed to resume after syscall")?;
            }
            WaitStatus::PtraceEvent(_, _, _) => {
                // A clone/fork/vfork event carries the new tracee's pid. Register
                // it here; it is already stopped and gets resumed on its own stop.
                if let Ok(new) = ptrace::getevent(pid) {
                    let new_pid = Pid::from_raw(new as i32);
                    if new > 0 {
                        live.insert(new_pid);
                    }
                }
                ptrace::syscall(pid, None).context("failed to resume after ptrace event")?;
            }
            WaitStatus::Stopped(_, sig) => {
                // A tracee we have not seen yet is a new thread stopping at
                // birth; its SIGSTOP is an artefact of attachment, not a signal
                // the workload sent, so it must not be delivered onward.
                if is_new_tracee_birth_stop(live.insert(pid), sig as i32) {
                    ptrace::syscall(pid, None).context("failed to resume new tracee")?;
                } else {
                    ptrace::syscall(pid, Some(sig)).context("failed to deliver signal")?;
                }
            }
            _ => {}
        }
    }

    // The main child has already been reaped by the waitpid loop above.
    let _child_pid = main_pid;

    let mut missing_nrs: Vec<i64> = observed.difference(&allowed_nrs).copied().collect();
    missing_nrs.sort();

    let missing_syscalls: Vec<SyscallEntry> = missing_nrs
        .iter()
        .map(|nr| SyscallEntry {
            nr: *nr,
            name: syscall_table::syscall_name(*nr)
                .unwrap_or("unknown")
                .to_string(),
        })
        .collect();

    let recommendation = recommendation_text(&tier, &missing_syscalls);

    let report = Report {
        tier: tier.to_string(),
        allowed: allowed_nrs.len(),
        observed: observed.len(),
        missing: missing_syscalls.len(),
        missing_syscalls,
        child_exit_code: main_exit_code,
        recommendation,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_human_report(&report);
    }

    if args.fail_on_missing && !report.missing_syscalls.is_empty() {
        std::process::exit(1);
    }

    // Propagate the child's exit code so the audit is transparent to scripts.
    if let Some(code) = main_exit_code
        && code != 0
    {
        std::process::exit(code);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn extract_syscall_number(regs: &libc::user_regs_struct) -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        regs.orig_rax as i64
    }
    #[cfg(target_arch = "aarch64")]
    {
        regs.regs[8] as i64
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        compile_error!("mvmctl seccomp-audit only supports x86_64 and aarch64 on Linux");
    }
}

#[cfg(target_os = "linux")]
fn close_non_stdio_fds() {
    // Best-effort close of any file descriptors the parent left open. We do
    // not treat errors as fatal: the audited command must run even if a close
    // fails because the fd was already closed or invalid.
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } as i32;
    let max_fd = if max_fd < 0 { 1024 } else { max_fd };
    for fd in 3..max_fd {
        let _ = nix::unistd::close(fd);
    }
}

#[cfg(target_os = "linux")]
fn recommendation_text(tier: &SeccompTier, missing: &[SyscallEntry]) -> Option<String> {
    if missing.is_empty() {
        return None;
    }

    // If the current tier already has network syscalls, the only wider tier is
    // unrestricted. Otherwise suggest the next tier up.
    let has_network = matches!(tier, SeccompTier::Network);
    if has_network {
        Some(
            "observed syscalls exceed the network tier; use --tier unrestricted for full access"
                .to_string(),
        )
    } else {
        Some(format!(
            "consider --tier {} or higher for the observed workload",
            next_tier(tier)
        ))
    }
}

#[cfg(target_os = "linux")]
fn next_tier(tier: &SeccompTier) -> &'static str {
    match tier {
        SeccompTier::Essential => "minimal",
        SeccompTier::Minimal => "standard",
        SeccompTier::Standard => "network",
        SeccompTier::Network | SeccompTier::Unrestricted => "unrestricted",
    }
}

#[cfg(target_os = "linux")]
fn print_human_report(report: &Report) {
    println!("Seccomp audit report");
    println!("  tier:              {}", report.tier);
    println!("  allowed syscalls:  {}", report.allowed);
    println!("  observed syscalls: {}", report.observed);
    println!("  missing syscalls:  {}", report.missing);
    if let Some(code) = report.child_exit_code {
        println!("  child exit code:   {code}");
    }

    if !report.missing_syscalls.is_empty() {
        println!("\nSyscalls observed but not in tier:");
        for sc in &report.missing_syscalls {
            println!("  {:>4}  {}", sc.nr, sc.name);
        }
        if let Some(rec) = &report.recommendation {
            println!("\nRecommendation: {rec}");
        }
    } else {
        println!(
            "\nAll observed syscalls are allowed by the {} tier.",
            report.tier
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn next_tier_progression() {
        assert_eq!(next_tier(&SeccompTier::Essential), "minimal");
        assert_eq!(next_tier(&SeccompTier::Minimal), "standard");
        assert_eq!(next_tier(&SeccompTier::Standard), "network");
        assert_eq!(next_tier(&SeccompTier::Network), "unrestricted");
        assert_eq!(next_tier(&SeccompTier::Unrestricted), "unrestricted");
    }
}

#[cfg(test)]
mod traceclone_tests {
    use super::is_new_tracee_birth_stop;

    #[test]
    fn a_new_tracees_birth_sigstop_is_not_forwarded() {
        assert!(is_new_tracee_birth_stop(true, libc::SIGSTOP));
    }

    #[test]
    fn a_known_tracees_sigstop_is_still_delivered() {
        // The workload really did stop itself; swallowing this would change
        // the behaviour of the program under audit.
        assert!(!is_new_tracee_birth_stop(false, libc::SIGSTOP));
    }

    #[test]
    fn a_new_tracees_other_signal_is_still_delivered() {
        // Only SIGSTOP is the attachment artefact. A first-sighting SIGSEGV is
        // real and must reach the tracee.
        assert!(!is_new_tracee_birth_stop(true, libc::SIGSEGV));
        assert!(!is_new_tracee_birth_stop(true, libc::SIGTERM));
    }
}
