//! `mvm-seccomp-apply` — install a seccomp BPF filter, then run a wrapped command.
//!
//! Usage:
//!     mvm-seccomp-apply <tier> -- <cmd> [args...]
//!
//! `<tier>` is one of `essential` / `minimal` / `standard` / `network`
//! / `unrestricted` (matching `mvm_security::seccomp::SeccompTier`).
//! On `unrestricted`, the shim is a no-op handoff — useful so the
//! launcher line stays uniform regardless of tier.
//!
//! Why a shim instead of `setpriv --seccomp-filter`:
//!
//! - `setpriv --seccomp-filter` consumes a binary BPF dump; producing
//!   the dump at Nix-evaluation time would require pinning a libseccomp
//!   build inside the rootfs's closure. Compiling in-process via
//!   `seccompiler` keeps the dependency on a small Rust crate and
//!   compiles consistently across tier definitions.
//!
//! - The shim is short, zero external runtime dependencies beyond
//!   what `mvm-guest-agent` already drags in. It piggybacks on the
//!   guest agent's store path so it ships in the same closure.
//!
//! Linux-only: seccomp is a Linux kernel feature, and the seccompiler
//! crate doesn't even build on Darwin. The binary's `main` is gated
//! on `target_os = "linux"`; on other targets it errors with a clear
//! message so `cargo check --workspace` still passes for CLI dev on a
//! Mac.
//!
//! Architecture decision: ADR-002 §W2.4. Plan: `specs/plans/26-w2-defense-in-depth.md`.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "mvm-seccomp-apply runs inside Linux microVM guests only — \
         the host shouldn't be invoking it directly."
    );
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use mvm_security::seccomp::SeccompTier;
#[cfg(target_os = "linux")]
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "aarch64", target_arch = "x86_64"))
))]
compile_error!("mvm-seccomp-apply only supports aarch64 and x86_64 on Linux");

#[cfg(target_os = "linux")]
fn main() {
    let mut args = env::args();
    let _argv0 = args.next();

    let tier_str = args.next().unwrap_or_else(|| die("missing <tier>"));
    let separator = args.next().unwrap_or_else(|| die("missing `--` separator"));
    if separator != "--" {
        die("expected `--` between tier and command");
    }
    let cmd = args
        .next()
        .unwrap_or_else(|| die("missing command after `--`"));
    let cmd_args: Vec<String> = args.collect();

    let tier: SeccompTier = tier_str
        .parse()
        .unwrap_or_else(|e| die(&format!("invalid tier {tier_str:?}: {e}")));

    if !tier.is_unrestricted() {
        apply_filter(tier).unwrap_or_else(|e| die(&format!("seccomp install failed: {e}")));
    }

    // Hand off to the wrapped command via a single Unix syscall (no
    // intermediate sh, no PATH lookup beyond what the kernel does).
    // The seccomp filter is inherited by the new process image because
    // PR_SET_SECCOMP is sticky.
    let err = Command::new(&cmd).args(&cmd_args).exec();
    die(&format!("execve {cmd}: {err}"));
}

/// Compile the tier's allowlist to BPF and install it. Any syscall
/// outside the list returns SECCOMP_RET_ERRNO with EPERM, keeping
/// the process alive so the user sees a clean failure rather than a
/// SIGSYS coredump — matching the project's posture that build/dev
/// failures are explicit, not catastrophic.
#[cfg(target_os = "linux")]
fn apply_filter(tier: SeccompTier) -> anyhow::Result<()> {
    set_no_new_privs()?;

    let allowed = tier.syscalls();
    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        std::collections::BTreeMap::new();

    for name in allowed {
        let nr = syscall_nr(name);
        if nr < 0 {
            // Unknown / unavailable on this arch; skip silently.
            // The tier is best-effort coarse-grained.
            continue;
        }
        // `Vec::new()` for rules means "match any args" — we don't
        // currently filter on syscall arguments. That's a deliberate
        // simplification; tier definitions are coarse-grained.
        rules.insert(nr, Vec::new());
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TARGET_ARCH,
    )?;
    let program: BpfProgram = filter.try_into()?;
    seccompiler::apply_filter(&program)?;
    Ok(())
}

/// Set PR_SET_NO_NEW_PRIVS on the current process. Defense-in-depth:
/// the kernel requires NNP for an unprivileged process to install a
/// seccomp filter, and the launch wrapper already passes
/// `setpriv --no-new-privs`. Owning the call here means a future
/// caller that forgets the setpriv flag still gets the filter
/// installed instead of a late EACCES from `seccomp(2)`. The bit is
/// idempotent — setting it when already set is a no-op.
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> anyhow::Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) takes only scalar
    // args and has no preconditions on process state. The kernel
    // returns 0 on success and -1 with errno on failure; we surface
    // the errno via std::io::Error::last_os_error.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ))
    }
}

/// Map a syscall name to its number on this target. The list is
/// curated to match `mvm_security::seccomp::SeccompTier::syscalls()`.
///
/// Maintenance note: anything in the "common" list must be present in
/// libc for both x86_64-linux and aarch64-linux. Anything x86_64-only
/// (legacy `select`, `pipe`, `open`, ...) goes in the cfg-gated
/// section. Anything aarch64-only goes in its own cfg block. The
/// caller silently skips names not in the table.
#[cfg(target_os = "linux")]
fn syscall_nr(name: &str) -> i64 {
    // common-to-x86_64-and-aarch64-linux modern syscalls
    let common: &[(&str, i64)] = &[
        ("read", libc::SYS_read as i64),
        ("write", libc::SYS_write as i64),
        ("close", libc::SYS_close as i64),
        ("fstat", libc::SYS_fstat as i64),
        ("newfstatat", libc::SYS_newfstatat as i64),
        ("statx", libc::SYS_statx as i64),
        ("mmap", libc::SYS_mmap as i64),
        ("mprotect", libc::SYS_mprotect as i64),
        ("munmap", libc::SYS_munmap as i64),
        ("brk", libc::SYS_brk as i64),
        ("rt_sigaction", libc::SYS_rt_sigaction as i64),
        ("rt_sigprocmask", libc::SYS_rt_sigprocmask as i64),
        ("rt_sigreturn", libc::SYS_rt_sigreturn as i64),
        ("rt_sigpending", libc::SYS_rt_sigpending as i64),
        ("rt_sigtimedwait", libc::SYS_rt_sigtimedwait as i64),
        ("rt_sigqueueinfo", libc::SYS_rt_sigqueueinfo as i64),
        ("ioctl", libc::SYS_ioctl as i64),
        ("pread64", libc::SYS_pread64 as i64),
        ("pwrite64", libc::SYS_pwrite64 as i64),
        ("readv", libc::SYS_readv as i64),
        ("writev", libc::SYS_writev as i64),
        ("pipe2", libc::SYS_pipe2 as i64),
        ("sched_yield", libc::SYS_sched_yield as i64),
        ("mremap", libc::SYS_mremap as i64),
        ("madvise", libc::SYS_madvise as i64),
        ("dup", libc::SYS_dup as i64),
        ("dup3", libc::SYS_dup3 as i64),
        ("nanosleep", libc::SYS_nanosleep as i64),
        ("getpid", libc::SYS_getpid as i64),
        // sendfile is x86_64-only as a separate name; aarch64-glibc
        // expresses it as sendfile64 (which uses SYS_sendfile64). Move
        // to the cfg-gated section below so both arches build.
        ("socket", libc::SYS_socket as i64),
        ("connect", libc::SYS_connect as i64),
        ("accept", libc::SYS_accept as i64),
        ("sendto", libc::SYS_sendto as i64),
        ("recvfrom", libc::SYS_recvfrom as i64),
        ("sendmsg", libc::SYS_sendmsg as i64),
        ("recvmsg", libc::SYS_recvmsg as i64),
        ("shutdown", libc::SYS_shutdown as i64),
        ("bind", libc::SYS_bind as i64),
        ("listen", libc::SYS_listen as i64),
        ("getsockname", libc::SYS_getsockname as i64),
        ("getpeername", libc::SYS_getpeername as i64),
        ("socketpair", libc::SYS_socketpair as i64),
        ("setsockopt", libc::SYS_setsockopt as i64),
        ("getsockopt", libc::SYS_getsockopt as i64),
        ("clone", libc::SYS_clone as i64),
        ("clone3", libc::SYS_clone3 as i64),
        ("execve", libc::SYS_execve as i64),
        ("execveat", libc::SYS_execveat as i64),
        ("exit", libc::SYS_exit as i64),
        ("exit_group", libc::SYS_exit_group as i64),
        ("wait4", libc::SYS_wait4 as i64),
        ("waitid", libc::SYS_waitid as i64),
        ("kill", libc::SYS_kill as i64),
        ("uname", libc::SYS_uname as i64),
        ("fcntl", libc::SYS_fcntl as i64),
        ("flock", libc::SYS_flock as i64),
        ("fsync", libc::SYS_fsync as i64),
        ("fdatasync", libc::SYS_fdatasync as i64),
        ("truncate", libc::SYS_truncate as i64),
        ("ftruncate", libc::SYS_ftruncate as i64),
        ("getdents64", libc::SYS_getdents64 as i64),
        ("getcwd", libc::SYS_getcwd as i64),
        ("chdir", libc::SYS_chdir as i64),
        ("fchdir", libc::SYS_fchdir as i64),
        ("fchmod", libc::SYS_fchmod as i64),
        ("fchown", libc::SYS_fchown as i64),
        ("umask", libc::SYS_umask as i64),
        ("gettimeofday", libc::SYS_gettimeofday as i64),
        ("getrlimit", libc::SYS_getrlimit as i64),
        ("getrusage", libc::SYS_getrusage as i64),
        ("sysinfo", libc::SYS_sysinfo as i64),
        ("times", libc::SYS_times as i64),
        ("getuid", libc::SYS_getuid as i64),
        ("geteuid", libc::SYS_geteuid as i64),
        ("getgid", libc::SYS_getgid as i64),
        ("getegid", libc::SYS_getegid as i64),
        ("setpgid", libc::SYS_setpgid as i64),
        ("getppid", libc::SYS_getppid as i64),
        ("setsid", libc::SYS_setsid as i64),
        ("setreuid", libc::SYS_setreuid as i64),
        ("setregid", libc::SYS_setregid as i64),
        ("getgroups", libc::SYS_getgroups as i64),
        ("setgroups", libc::SYS_setgroups as i64),
        ("setresuid", libc::SYS_setresuid as i64),
        ("getresuid", libc::SYS_getresuid as i64),
        ("setresgid", libc::SYS_setresgid as i64),
        ("getresgid", libc::SYS_getresgid as i64),
        ("getpgid", libc::SYS_getpgid as i64),
        ("getsid", libc::SYS_getsid as i64),
        ("capget", libc::SYS_capget as i64),
        ("capset", libc::SYS_capset as i64),
        ("sigaltstack", libc::SYS_sigaltstack as i64),
        ("personality", libc::SYS_personality as i64),
        ("statfs", libc::SYS_statfs as i64),
        ("fstatfs", libc::SYS_fstatfs as i64),
        ("getpriority", libc::SYS_getpriority as i64),
        ("setpriority", libc::SYS_setpriority as i64),
        ("mlock", libc::SYS_mlock as i64),
        ("munlock", libc::SYS_munlock as i64),
        ("mlockall", libc::SYS_mlockall as i64),
        ("munlockall", libc::SYS_munlockall as i64),
        ("prctl", libc::SYS_prctl as i64),
        ("setrlimit", libc::SYS_setrlimit as i64),
        ("sync", libc::SYS_sync as i64),
        ("gettid", libc::SYS_gettid as i64),
        ("tkill", libc::SYS_tkill as i64),
        ("futex", libc::SYS_futex as i64),
        ("sched_setaffinity", libc::SYS_sched_setaffinity as i64),
        ("sched_getaffinity", libc::SYS_sched_getaffinity as i64),
        ("set_tid_address", libc::SYS_set_tid_address as i64),
        ("restart_syscall", libc::SYS_restart_syscall as i64),
        ("timer_create", libc::SYS_timer_create as i64),
        ("timer_settime", libc::SYS_timer_settime as i64),
        ("timer_gettime", libc::SYS_timer_gettime as i64),
        ("timer_getoverrun", libc::SYS_timer_getoverrun as i64),
        ("timer_delete", libc::SYS_timer_delete as i64),
        ("clock_gettime", libc::SYS_clock_gettime as i64),
        ("clock_getres", libc::SYS_clock_getres as i64),
        ("clock_nanosleep", libc::SYS_clock_nanosleep as i64),
        ("tgkill", libc::SYS_tgkill as i64),
        ("openat", libc::SYS_openat as i64),
        ("mkdirat", libc::SYS_mkdirat as i64),
        ("mknodat", libc::SYS_mknodat as i64),
        ("fchownat", libc::SYS_fchownat as i64),
        ("unlinkat", libc::SYS_unlinkat as i64),
        ("renameat", libc::SYS_renameat as i64),
        ("renameat2", libc::SYS_renameat2 as i64),
        ("linkat", libc::SYS_linkat as i64),
        ("symlinkat", libc::SYS_symlinkat as i64),
        ("readlinkat", libc::SYS_readlinkat as i64),
        ("fchmodat", libc::SYS_fchmodat as i64),
        ("faccessat", libc::SYS_faccessat as i64),
        ("faccessat2", libc::SYS_faccessat2 as i64),
        ("ppoll", libc::SYS_ppoll as i64),
        ("pselect6", libc::SYS_pselect6 as i64),
        ("set_robust_list", libc::SYS_set_robust_list as i64),
        ("get_robust_list", libc::SYS_get_robust_list as i64),
        ("splice", libc::SYS_splice as i64),
        ("tee", libc::SYS_tee as i64),
        ("vmsplice", libc::SYS_vmsplice as i64),
        ("utimensat", libc::SYS_utimensat as i64),
        ("epoll_pwait", libc::SYS_epoll_pwait as i64),
        ("timerfd_create", libc::SYS_timerfd_create as i64),
        ("timerfd_settime", libc::SYS_timerfd_settime as i64),
        ("timerfd_gettime", libc::SYS_timerfd_gettime as i64),
        ("fallocate", libc::SYS_fallocate as i64),
        ("accept4", libc::SYS_accept4 as i64),
        ("signalfd4", libc::SYS_signalfd4 as i64),
        ("eventfd2", libc::SYS_eventfd2 as i64),
        ("epoll_create1", libc::SYS_epoll_create1 as i64),
        ("epoll_ctl", libc::SYS_epoll_ctl as i64),
        ("inotify_init1", libc::SYS_inotify_init1 as i64),
        ("inotify_add_watch", libc::SYS_inotify_add_watch as i64),
        ("inotify_rm_watch", libc::SYS_inotify_rm_watch as i64),
        ("preadv", libc::SYS_preadv as i64),
        ("pwritev", libc::SYS_pwritev as i64),
        ("recvmmsg", libc::SYS_recvmmsg as i64),
        ("prlimit64", libc::SYS_prlimit64 as i64),
        ("syncfs", libc::SYS_syncfs as i64),
        ("sendmmsg", libc::SYS_sendmmsg as i64),
        ("getrandom", libc::SYS_getrandom as i64),
        ("memfd_create", libc::SYS_memfd_create as i64),
        ("close_range", libc::SYS_close_range as i64),
        ("rseq", libc::SYS_rseq as i64),
        ("lseek", libc::SYS_lseek as i64),
        ("getitimer", libc::SYS_getitimer as i64),
        ("setitimer", libc::SYS_setitimer as i64),
        ("sched_setparam", libc::SYS_sched_setparam as i64),
        ("sched_getparam", libc::SYS_sched_getparam as i64),
        ("sched_setscheduler", libc::SYS_sched_setscheduler as i64),
        ("sched_getscheduler", libc::SYS_sched_getscheduler as i64),
    ];

    if let Some((_, nr)) = common.iter().find(|(n, _)| *n == name) {
        return *nr;
    }

    // x86_64 has legacy syscall names (select, pipe, open, ...) that
    // aarch64-glibc translates to modern variants. Honour them when
    // we're actually on x86_64.
    #[cfg(target_arch = "x86_64")]
    {
        let x86_only: &[(&str, i64)] = &[
            ("access", libc::SYS_access as i64),
            ("dup2", libc::SYS_dup2 as i64),
            ("fork", libc::SYS_fork as i64),
            ("vfork", libc::SYS_vfork as i64),
            ("mkdir", libc::SYS_mkdir as i64),
            ("rmdir", libc::SYS_rmdir as i64),
            ("open", libc::SYS_open as i64),
            ("pipe", libc::SYS_pipe as i64),
            ("poll", libc::SYS_poll as i64),
            ("readlink", libc::SYS_readlink as i64),
            ("select", libc::SYS_select as i64),
            ("stat", libc::SYS_stat as i64),
            ("lstat", libc::SYS_lstat as i64),
            ("unlink", libc::SYS_unlink as i64),
            ("rename", libc::SYS_rename as i64),
            ("link", libc::SYS_link as i64),
            ("symlink", libc::SYS_symlink as i64),
            ("getdents", libc::SYS_getdents as i64),
            ("chmod", libc::SYS_chmod as i64),
            ("chown", libc::SYS_chown as i64),
            ("lchown", libc::SYS_lchown as i64),
            ("epoll_wait", libc::SYS_epoll_wait as i64),
            ("epoll_create1", libc::SYS_epoll_create1 as i64),
            ("arch_prctl", libc::SYS_arch_prctl as i64),
            ("sendfile", libc::SYS_sendfile as i64),
        ];
        if let Some((_, nr)) = x86_only.iter().find(|(n, _)| *n == name) {
            return *nr;
        }
    }

    eprintln!(
        "mvm-seccomp-apply: warning: unknown or unavailable syscall \
         {name:?} on this arch; skipping"
    );
    -1
}

#[cfg(target_os = "linux")]
fn die(msg: &str) -> ! {
    eprintln!("mvm-seccomp-apply: {msg}");
    std::process::exit(2);
}
