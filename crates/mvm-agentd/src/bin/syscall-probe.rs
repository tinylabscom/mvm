//! `syscall-probe` — exits with the errno of an attempted syscall.
//!
//! Test-only binary. Spawned by `tests/seccomp_apply.rs` under
//! `mvm-seccomp-apply <tier> --` to verify that tier allowlists
//! actually deny what they claim. The optional first argument names the
//! probe: `inet` (the default), `vsock`, or `groups`.
//!
//! An optional second argument names a tier the probe installs on itself
//! before probing (`syscall-probe groups essential`). Self-confinement is
//! what a tier without `rt_sigaction` requires: the shim's apply-then-exec
//! goes through std's `Command::exec`, which resets SIGPIPE after the
//! filter is installed, so the handoff dies there under `essential`. This
//! is also the agent's own ordering — its pre-exec hook installs the
//! filter after std's signal setup. Exit-code contract:
//!
//! - 0 → the socket opened or `getgroups(0, NULL)` returned a group count.
//! - 1 → call failed with `EPERM` (the seccomp-shaped denial).
//! - 2 → the named tier failed to compile or install.
//! - other → call failed with a different errno (raw value, capped at 254).
//! - 64 → an argument is not one this probe knows.
//! - 65 → a tier was named and installed, but the kernel reports no filter
//!   afterwards, so a passing probe would say nothing.
//!
//! Not shipped in production: `nix/packages/mvm-guest-agent.nix`
//! explicitly selects `mvm-guest-agent` and `mvm-seccomp-apply` as
//! the bins to build, so this binary stays in `target/` only.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("syscall-probe runs inside Linux microVM guests only");
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn main() {
    let mut args = std::env::args().skip(1);
    let probe_name = args.next().unwrap_or_else(|| "inet".to_string());
    if let Some(tier) = args.next() {
        confine_to(&tier);
    }
    if probe_name == "groups" {
        // A zero-sized query reads only the count; it cannot change groups.
        if unsafe { libc::getgroups(0, std::ptr::null_mut()) } < 0 {
            exit_errno("getgroups(0, NULL)");
        }
        return;
    }
    let family = match probe_name.as_str() {
        "inet" => libc::AF_INET,
        "vsock" => libc::AF_VSOCK,
        other => {
            eprintln!("syscall-probe: unknown probe {other:?} (expected inet, vsock or groups)");
            std::process::exit(64);
        }
    };
    let fd = unsafe { libc::socket(family, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        exit_errno("socket");
    }
    unsafe {
        libc::close(fd);
    }
    std::process::exit(0);
}

/// Install `tier`'s filter on the probe itself, then confirm the kernel
/// reports one before the probed call runs: a silently skipped install would
/// read as a pass. `unrestricted` compiles to nothing, so it installs nothing
/// and skips the confirmation.
#[cfg(target_os = "linux")]
fn confine_to(tier_name: &str) {
    let tier: mvm_core::crypto::seccomp::SeccompTier = match tier_name.parse() {
        Ok(tier) => tier,
        Err(error) => {
            eprintln!("syscall-probe: unknown tier {tier_name:?}: {error}");
            std::process::exit(64);
        }
    };
    let program = match mvm_agentd::workload_seccomp::compile(tier) {
        Ok(program) => program,
        Err(error) => {
            eprintln!("syscall-probe: compile {tier}: {error}");
            std::process::exit(2);
        }
    };
    let Some(program) = program else {
        return;
    };
    if let Err(error) = mvm_agentd::workload_seccomp::install(&program) {
        eprintln!("syscall-probe: install {tier}: {error}");
        std::process::exit(2);
    }
    // SAFETY: prctl(PR_GET_SECCOMP) takes only scalar args, reads the calling
    // thread's state and has no preconditions. The return is the thread's
    // seccomp mode; 2 is SECCOMP_MODE_FILTER.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if mode != 2 {
        eprintln!("syscall-probe: seccomp mode {mode} after install, expected 2");
        std::process::exit(65);
    }
}

#[cfg(target_os = "linux")]
fn exit_errno(call: &str) -> ! {
    let err = std::io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(255);
    eprintln!("syscall-probe: {call} failed: errno={errno} ({err})");
    // Exit codes are u8; cap below 255 so signal termination stays distinct.
    std::process::exit(errno.min(254));
}
