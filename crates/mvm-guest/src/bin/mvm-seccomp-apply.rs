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
        ("read", libc::SYS_read),
        ("write", libc::SYS_write),
        ("close", libc::SYS_close),
        ("fstat", libc::SYS_fstat),
        ("newfstatat", libc::SYS_newfstatat),
        ("statx", libc::SYS_statx),
        ("mmap", libc::SYS_mmap),
        ("mprotect", libc::SYS_mprotect),
        ("munmap", libc::SYS_munmap),
        ("brk", libc::SYS_brk),
        ("rt_sigaction", libc::SYS_rt_sigaction),
        ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
        ("rt_sigreturn", libc::SYS_rt_sigreturn),
        ("rt_sigpending", libc::SYS_rt_sigpending),
        ("rt_sigtimedwait", libc::SYS_rt_sigtimedwait),
        ("rt_sigqueueinfo", libc::SYS_rt_sigqueueinfo),
        ("ioctl", libc::SYS_ioctl),
        ("pread64", libc::SYS_pread64),
        ("pwrite64", libc::SYS_pwrite64),
        ("readv", libc::SYS_readv),
        ("writev", libc::SYS_writev),
        ("pipe2", libc::SYS_pipe2),
        ("sched_yield", libc::SYS_sched_yield),
        ("mremap", libc::SYS_mremap),
        ("madvise", libc::SYS_madvise),
        ("dup", libc::SYS_dup),
        ("dup3", libc::SYS_dup3),
        ("nanosleep", libc::SYS_nanosleep),
        ("getpid", libc::SYS_getpid),
        // sendfile is x86_64-only as a separate name; aarch64-glibc
        // expresses it as sendfile64 (which uses SYS_sendfile64). Move
        // to the cfg-gated section below so both arches build.
        ("socket", libc::SYS_socket),
        ("connect", libc::SYS_connect),
        ("accept", libc::SYS_accept),
        ("sendto", libc::SYS_sendto),
        ("recvfrom", libc::SYS_recvfrom),
        ("sendmsg", libc::SYS_sendmsg),
        ("recvmsg", libc::SYS_recvmsg),
        ("shutdown", libc::SYS_shutdown),
        ("bind", libc::SYS_bind),
        ("listen", libc::SYS_listen),
        ("getsockname", libc::SYS_getsockname),
        ("getpeername", libc::SYS_getpeername),
        ("socketpair", libc::SYS_socketpair),
        ("setsockopt", libc::SYS_setsockopt),
        ("getsockopt", libc::SYS_getsockopt),
        ("clone", libc::SYS_clone),
        ("clone3", libc::SYS_clone3),
        ("execve", libc::SYS_execve),
        ("execveat", libc::SYS_execveat),
        ("exit", libc::SYS_exit),
        ("exit_group", libc::SYS_exit_group),
        ("wait4", libc::SYS_wait4),
        ("waitid", libc::SYS_waitid),
        ("kill", libc::SYS_kill),
        ("uname", libc::SYS_uname),
        ("fcntl", libc::SYS_fcntl),
        ("flock", libc::SYS_flock),
        ("fsync", libc::SYS_fsync),
        ("fdatasync", libc::SYS_fdatasync),
        ("truncate", libc::SYS_truncate),
        ("ftruncate", libc::SYS_ftruncate),
        ("getdents64", libc::SYS_getdents64),
        ("getcwd", libc::SYS_getcwd),
        ("chdir", libc::SYS_chdir),
        ("fchdir", libc::SYS_fchdir),
        ("fchmod", libc::SYS_fchmod),
        ("fchown", libc::SYS_fchown),
        ("umask", libc::SYS_umask),
        ("gettimeofday", libc::SYS_gettimeofday),
        ("getrlimit", libc::SYS_getrlimit),
        ("getrusage", libc::SYS_getrusage),
        ("sysinfo", libc::SYS_sysinfo),
        ("times", libc::SYS_times),
        ("getuid", libc::SYS_getuid),
        ("geteuid", libc::SYS_geteuid),
        ("getgid", libc::SYS_getgid),
        ("getegid", libc::SYS_getegid),
        ("setpgid", libc::SYS_setpgid),
        ("getppid", libc::SYS_getppid),
        ("setsid", libc::SYS_setsid),
        ("setreuid", libc::SYS_setreuid),
        ("setregid", libc::SYS_setregid),
        ("getgroups", libc::SYS_getgroups),
        ("setgroups", libc::SYS_setgroups),
        ("setresuid", libc::SYS_setresuid),
        ("getresuid", libc::SYS_getresuid),
        ("setresgid", libc::SYS_setresgid),
        ("getresgid", libc::SYS_getresgid),
        ("getpgid", libc::SYS_getpgid),
        ("getsid", libc::SYS_getsid),
        ("capget", libc::SYS_capget),
        ("capset", libc::SYS_capset),
        ("sigaltstack", libc::SYS_sigaltstack),
        ("personality", libc::SYS_personality),
        ("statfs", libc::SYS_statfs),
        ("fstatfs", libc::SYS_fstatfs),
        ("getpriority", libc::SYS_getpriority),
        ("setpriority", libc::SYS_setpriority),
        ("mlock", libc::SYS_mlock),
        ("munlock", libc::SYS_munlock),
        ("mlockall", libc::SYS_mlockall),
        ("munlockall", libc::SYS_munlockall),
        ("prctl", libc::SYS_prctl),
        ("setrlimit", libc::SYS_setrlimit),
        ("sync", libc::SYS_sync),
        ("gettid", libc::SYS_gettid),
        ("tkill", libc::SYS_tkill),
        ("futex", libc::SYS_futex),
        ("sched_setaffinity", libc::SYS_sched_setaffinity),
        ("sched_getaffinity", libc::SYS_sched_getaffinity),
        ("set_tid_address", libc::SYS_set_tid_address),
        ("restart_syscall", libc::SYS_restart_syscall),
        ("timer_create", libc::SYS_timer_create),
        ("timer_settime", libc::SYS_timer_settime),
        ("timer_gettime", libc::SYS_timer_gettime),
        ("timer_getoverrun", libc::SYS_timer_getoverrun),
        ("timer_delete", libc::SYS_timer_delete),
        ("clock_gettime", libc::SYS_clock_gettime),
        ("clock_getres", libc::SYS_clock_getres),
        ("clock_nanosleep", libc::SYS_clock_nanosleep),
        ("tgkill", libc::SYS_tgkill),
        ("openat", libc::SYS_openat),
        ("mkdirat", libc::SYS_mkdirat),
        ("mknodat", libc::SYS_mknodat),
        ("fchownat", libc::SYS_fchownat),
        ("unlinkat", libc::SYS_unlinkat),
        ("renameat", libc::SYS_renameat),
        ("renameat2", libc::SYS_renameat2),
        ("linkat", libc::SYS_linkat),
        ("symlinkat", libc::SYS_symlinkat),
        ("readlinkat", libc::SYS_readlinkat),
        ("fchmodat", libc::SYS_fchmodat),
        ("faccessat", libc::SYS_faccessat),
        ("faccessat2", libc::SYS_faccessat2),
        ("ppoll", libc::SYS_ppoll),
        ("pselect6", libc::SYS_pselect6),
        ("set_robust_list", libc::SYS_set_robust_list),
        ("get_robust_list", libc::SYS_get_robust_list),
        ("splice", libc::SYS_splice),
        ("tee", libc::SYS_tee),
        ("vmsplice", libc::SYS_vmsplice),
        ("utimensat", libc::SYS_utimensat),
        ("epoll_pwait", libc::SYS_epoll_pwait),
        ("timerfd_create", libc::SYS_timerfd_create),
        ("timerfd_settime", libc::SYS_timerfd_settime),
        ("timerfd_gettime", libc::SYS_timerfd_gettime),
        ("fallocate", libc::SYS_fallocate),
        ("accept4", libc::SYS_accept4),
        ("signalfd4", libc::SYS_signalfd4),
        ("eventfd2", libc::SYS_eventfd2),
        ("epoll_create1", libc::SYS_epoll_create1),
        ("epoll_ctl", libc::SYS_epoll_ctl),
        ("inotify_init1", libc::SYS_inotify_init1),
        ("inotify_add_watch", libc::SYS_inotify_add_watch),
        ("inotify_rm_watch", libc::SYS_inotify_rm_watch),
        ("preadv", libc::SYS_preadv),
        ("pwritev", libc::SYS_pwritev),
        ("recvmmsg", libc::SYS_recvmmsg),
        ("prlimit64", libc::SYS_prlimit64),
        ("syncfs", libc::SYS_syncfs),
        ("sendmmsg", libc::SYS_sendmmsg),
        ("getrandom", libc::SYS_getrandom),
        ("memfd_create", libc::SYS_memfd_create),
        ("close_range", libc::SYS_close_range),
        ("rseq", libc::SYS_rseq),
        ("lseek", libc::SYS_lseek),
        ("getitimer", libc::SYS_getitimer),
        ("setitimer", libc::SYS_setitimer),
        ("sched_setparam", libc::SYS_sched_setparam),
        ("sched_getparam", libc::SYS_sched_getparam),
        ("sched_setscheduler", libc::SYS_sched_setscheduler),
        ("sched_getscheduler", libc::SYS_sched_getscheduler),
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
            ("access", libc::SYS_access),
            ("dup2", libc::SYS_dup2),
            ("fork", libc::SYS_fork),
            ("vfork", libc::SYS_vfork),
            ("mkdir", libc::SYS_mkdir),
            ("rmdir", libc::SYS_rmdir),
            ("open", libc::SYS_open),
            ("pipe", libc::SYS_pipe),
            ("poll", libc::SYS_poll),
            ("readlink", libc::SYS_readlink),
            ("select", libc::SYS_select),
            ("stat", libc::SYS_stat),
            ("lstat", libc::SYS_lstat),
            ("unlink", libc::SYS_unlink),
            ("rename", libc::SYS_rename),
            ("link", libc::SYS_link),
            ("symlink", libc::SYS_symlink),
            ("getdents", libc::SYS_getdents),
            ("chmod", libc::SYS_chmod),
            ("chown", libc::SYS_chown),
            ("lchown", libc::SYS_lchown),
            ("epoll_wait", libc::SYS_epoll_wait),
            ("epoll_create1", libc::SYS_epoll_create1),
            ("arch_prctl", libc::SYS_arch_prctl),
            ("sendfile", libc::SYS_sendfile),
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
