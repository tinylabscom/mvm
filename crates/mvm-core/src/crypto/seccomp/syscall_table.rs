//! Linux syscall name↔number lookups for seccomp tooling.
//!
//! This module is Linux-only and currently supports x86_64 and aarch64.
//! It exists so that the tier definitions (which are names) can be compiled
//! into BPF filters, and so that audit tooling can report observed syscall
//! numbers back as human-readable names.
//!
//! The table is intentionally conservative: a name that does not exist on the
//! current target returns `None` from [`syscall_number`], and a number that is
//! not in the table returns `None` from [`syscall_name`]. Callers must handle
//! both cases.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Look up the syscall number for a name on this target.
///
/// Returns `None` if the name is unknown or not available on the current
/// architecture (e.g., legacy x86_64-only names on aarch64).
pub fn syscall_number(name: &str) -> Option<i64> {
    let table = number_table();
    table.get(name).copied()
}

/// Look up the syscall name for a number on this target.
///
/// Returns `None` if the number is not in the curated table. Numbers that
/// are valid on the kernel but unknown to this table are reported as
/// `"unknown(<nr>)"` by callers that need a printable label.
pub fn syscall_name(nr: i64) -> Option<&'static str> {
    let table = name_table();
    table.get(&nr).copied()
}

/// All curated syscall names for the current target, in no particular order.
pub fn known_names() -> &'static [&'static str] {
    static NAMES: OnceLock<Vec<&'static str>> = OnceLock::new();
    NAMES.get_or_init(|| number_table().keys().copied().collect())
}

fn number_table() -> &'static HashMap<&'static str, i64> {
    static TABLE: OnceLock<HashMap<&'static str, i64>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m = HashMap::new();
        for (name, nr) in common_syscalls() {
            m.insert(*name, *nr);
        }
        #[cfg(target_arch = "x86_64")]
        for (name, nr) in x86_64_syscalls() {
            m.insert(*name, *nr);
        }
        #[cfg(target_arch = "aarch64")]
        for (name, nr) in aarch64_syscalls() {
            m.insert(*name, *nr);
        }
        m
    })
}

fn name_table() -> &'static HashMap<i64, &'static str> {
    static TABLE: OnceLock<HashMap<i64, &'static str>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut m: HashMap<i64, &'static str> = HashMap::new();
        for (name, nr) in number_table().iter() {
            // If the same number has multiple names (rare), prefer the
            // shortest/common name by overwriting only when the new name is
            // shorter. This keeps the report readable.
            if let Some(existing) = m.get(nr)
                && name.len() >= existing.len()
            {
                continue;
            }
            m.insert(*nr, *name);
        }
        m
    })
}

const fn common_syscalls() -> &'static [(&'static str, i64)] {
    &[
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
        ("mremap", libc::SYS_mremap),
        ("madvise", libc::SYS_madvise),
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
        ("dup", libc::SYS_dup),
        ("dup3", libc::SYS_dup3),
        ("nanosleep", libc::SYS_nanosleep),
        ("getpid", libc::SYS_getpid),
        ("socket", libc::SYS_socket),
        ("connect", libc::SYS_connect),
        ("accept", libc::SYS_accept),
        ("accept4", libc::SYS_accept4),
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
    ]
}

#[cfg(target_arch = "x86_64")]
const fn x86_64_syscalls() -> &'static [(&'static str, i64)] {
    &[
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
        ("arch_prctl", libc::SYS_arch_prctl),
        ("sendfile", libc::SYS_sendfile),
        ("getpgrp", libc::SYS_getpgrp),
        ("futimesat", libc::SYS_futimesat),
    ]
}

#[cfg(target_arch = "aarch64")]
const fn aarch64_syscalls() -> &'static [(&'static str, i64)] {
    // No arch-specific names currently needed: legacy 32-bit-only names
    // (e.g., `sendfile64`) do not exist as separate syscall constants on
    // aarch64, and the 64-bit `sendfile` is used implicitly where needed.
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_roundtrips() {
        let nr = syscall_number("read").expect("read must be known");
        assert_eq!(syscall_name(nr), Some("read"));
    }

    #[test]
    fn unknown_name_is_none() {
        assert!(syscall_number("definitely_not_a_syscall").is_none());
    }

    #[test]
    fn unknown_number_is_none() {
        assert!(syscall_name(i64::MAX).is_none());
    }

    /// Legacy syscalls that exist on x86_64 and genuinely do not exist on
    /// aarch64, which only has the `*at` / `p*` variants. A tier may name
    /// these — `apply_filter` skips a name that does not resolve, by design —
    /// but the set has to be *declared*, so that a name resolving nowhere is a
    /// typo rather than a silent no-op.
    const LEGACY_X86_ONLY: &[&str] = &[
        "access",
        "arch_prctl",
        "chmod",
        "chown",
        "dup2",
        "epoll_wait",
        "fork",
        "futimesat",
        "getdents",
        "getpgrp",
        "lchown",
        "link",
        "lstat",
        "mkdir",
        "open",
        "pipe",
        "poll",
        "readlink",
        "rename",
        "rmdir",
        "select",
        "sendfile",
        "stat",
        "symlink",
        "unlink",
        "vfork",
    ];

    /// Every tier name either resolves here or is a declared legacy name.
    ///
    /// This replaces an assertion that every name resolves on every arch,
    /// which was stronger than the design: `mvm-seccomp-apply::apply_filter`
    /// deliberately skips a name it cannot resolve ("the tier is best-effort
    /// coarse-grained"). The old form passed on x86_64 and could only ever
    /// fail on aarch64, where it flagged correct behaviour.
    #[test]
    fn every_tier_name_resolves_or_is_a_declared_legacy_name() {
        use crate::crypto::seccomp::SeccompTier;
        for tier in SeccompTier::ALL {
            for name in tier.syscalls() {
                assert!(
                    syscall_number(name).is_some() || LEGACY_X86_ONLY.contains(&name),
                    "{name} in tier {tier} resolves on no architecture and is not \
                     declared in LEGACY_X86_ONLY — typo, or a name that needs adding \
                     to the syscall table"
                );
            }
        }
    }

    /// The assertion with teeth, and the one that would have caught the epoll
    /// hole: when a tier grants a capability through a legacy name, it must
    /// also grant the name that carries that capability on aarch64. Otherwise
    /// the capability exists on x86_64 and is silently EPERM on ARM.
    ///
    /// `arch_prctl` and `sendfile` are absent: the first is genuinely x86-only
    /// with no ARM equivalent, and the second's 64-bit form is used implicitly.
    #[test]
    fn a_legacy_name_never_grants_a_capability_that_aarch64_then_lacks() {
        use crate::crypto::seccomp::SeccompTier;
        const REPLACEMENT: &[(&str, &str)] = &[
            ("access", "faccessat"),
            ("chmod", "fchmodat"),
            ("chown", "fchownat"),
            ("dup2", "dup3"),
            ("epoll_wait", "epoll_pwait"),
            ("fork", "clone"),
            ("futimesat", "utimensat"),
            ("getdents", "getdents64"),
            ("getpgrp", "getpgid"),
            ("lchown", "fchownat"),
            ("link", "linkat"),
            ("lstat", "newfstatat"),
            ("mkdir", "mkdirat"),
            ("open", "openat"),
            ("pipe", "pipe2"),
            ("poll", "ppoll"),
            ("readlink", "readlinkat"),
            ("rename", "renameat"),
            ("rmdir", "unlinkat"),
            ("select", "pselect6"),
            ("stat", "newfstatat"),
            ("symlink", "symlinkat"),
            ("unlink", "unlinkat"),
            ("vfork", "clone"),
        ];

        for tier in SeccompTier::ALL {
            let granted = tier.syscalls();
            for (legacy, modern) in REPLACEMENT {
                if !granted.contains(legacy) {
                    continue;
                }
                assert!(
                    granted.contains(modern),
                    "tier {tier} allows the legacy `{legacy}` but not `{modern}`, \
                     which is what carries that capability on aarch64 — the tier \
                     would grant it on x86_64 and EPERM it on ARM"
                );
            }
        }
    }

    /// Each declared replacement has to be resolvable, or the check above is
    /// asserting against a name the table cannot supply.
    #[test]
    fn declared_legacy_names_are_actually_absent_here_or_present_everywhere() {
        for name in LEGACY_X86_ONLY {
            if cfg!(target_arch = "aarch64") {
                assert!(
                    syscall_number(name).is_none(),
                    "{name} is declared x86-only but resolves on aarch64 — drop it \
                     from LEGACY_X86_ONLY"
                );
            } else {
                assert!(
                    syscall_number(name).is_some(),
                    "{name} is declared x86-only but does not resolve on x86_64"
                );
            }
        }
    }
}
