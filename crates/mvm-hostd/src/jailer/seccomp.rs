//! seccomp-BPF filter via `seccompiler`.
//!
//! `seccompiler` 0.5 expects syscall numbers (libc::SYS_*) keyed by
//! `i64` in the rules map; it does not ship a public name-to-nr table
//! (the `sys` module exists but is private to the crate). We carry our
//! own table below — restricted to the syscalls
//! `ConfinementSpec::firecracker_bridge()` actually lists — so adding
//! a new entry to that allowlist also requires touching this lookup,
//! which is the audit point we want.

use crate::jailer::{ConfinementSpec, JailerError};
use seccompiler::{SeccompAction, SeccompFilter, SeccompRule, TargetArch};
use std::collections::BTreeMap;

#[cfg(target_arch = "x86_64")]
const TARGET_ARCH: TargetArch = TargetArch::x86_64;
#[cfg(target_arch = "aarch64")]
const TARGET_ARCH: TargetArch = TargetArch::aarch64;

/// Canonical (name, syscall-number) table for the
/// `mvm-firecracker-bridge` sidecar. This is the single source of
/// truth for the bridge's syscall allowlist:
/// `ConfinementSpec::firecracker_bridge()` derives its
/// `allowed_syscalls` from the names here, and `syscall_name_to_nr`
/// looks up numbers against it. Adding a syscall is a single edit;
/// review process is documented in `SECCOMP.md` §"Adding a syscall".
///
/// **Never relax this list without security review.** Names known to
/// be dangerous (`execve`, `setuid`, `setgid`, `ptrace`, `capset`) are
/// asserted-absent in `lib.rs::tests` as defense-in-depth.
///
/// Architecture divergence: `stat` / `lstat` map to `SYS_stat` /
/// `SYS_lstat` on x86_64 and are folded into `SYS_newfstatat` on aarch64
/// (aarch64 doesn't expose the path-stat syscalls separately).
/// `epoll_wait` maps to `SYS_epoll_wait` on x86_64 and is folded into
/// `SYS_epoll_pwait` on aarch64 for the same reason. The fold happens
/// here so the policy layer (`ConfinementSpec`) stays arch-agnostic.
#[cfg(target_arch = "x86_64")]
pub(crate) const BRIDGE_SYSCALLS: &[(&str, libc::c_long)] = &[
    ("read", libc::SYS_read),
    ("write", libc::SYS_write),
    ("fsync", libc::SYS_fsync),
    ("openat", libc::SYS_openat),
    ("close", libc::SYS_close),
    // arch divergence: x86_64 keeps `stat` / `lstat` as their own
    // syscalls; aarch64 folds both into `fstatat` (see aarch64 block).
    ("stat", libc::SYS_stat),
    ("lstat", libc::SYS_lstat),
    ("fstat", libc::SYS_fstat),
    ("socket", libc::SYS_socket),
    ("bind", libc::SYS_bind),
    ("connect", libc::SYS_connect),
    ("accept", libc::SYS_accept),
    ("accept4", libc::SYS_accept4),
    ("sendmsg", libc::SYS_sendmsg),
    ("recvmsg", libc::SYS_recvmsg),
    ("sendto", libc::SYS_sendto),
    ("recvfrom", libc::SYS_recvfrom),
    ("splice", libc::SYS_splice),
    ("clock_gettime", libc::SYS_clock_gettime),
    ("futex", libc::SYS_futex),
    ("exit", libc::SYS_exit),
    ("exit_group", libc::SYS_exit_group),
    ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
    ("rt_sigaction", libc::SYS_rt_sigaction),
    // The Rust runtime installs an alternate signal stack (stack-overflow
    // guard) during thread setup; without this the bridge takes SIGSYS on its
    // own `sigaltstack` as soon as the packet thread spins up. Found via live
    // FC strace — the allowlist had never been exercised on the real sidecar.
    ("sigaltstack", libc::SYS_sigaltstack),
    ("mmap", libc::SYS_mmap),
    ("munmap", libc::SYS_munmap),
    ("mprotect", libc::SYS_mprotect),
    ("brk", libc::SYS_brk),
    ("getpid", libc::SYS_getpid),
    ("gettid", libc::SYS_gettid),
    ("getuid", libc::SYS_getuid),
    ("getgid", libc::SYS_getgid),
    ("getrandom", libc::SYS_getrandom),
    ("epoll_create1", libc::SYS_epoll_create1),
    ("epoll_ctl", libc::SYS_epoll_ctl),
    // arch divergence: x86_64 keeps `epoll_wait` as its own syscall;
    // aarch64 folds it into `epoll_pwait` (see aarch64 block).
    ("epoll_wait", libc::SYS_epoll_wait),
    ("epoll_pwait", libc::SYS_epoll_pwait),
    ("prctl", libc::SYS_prctl),
    ("set_tid_address", libc::SYS_set_tid_address),
    ("set_robust_list", libc::SYS_set_robust_list),
    // ── substitution-endpoint additions ────────────────────────────
    // The endpoint runs a multi-thread tokio runtime and a rustls TLS
    // forward leg (reqwest, rustls-native-certs) that the bridge does
    // not. These cover thread creation, the glibc allocator + resolver,
    // socket-option negotiation, and cert-store directory reads. Erring
    // toward inclusion: a missing syscall SIGSYS-kills the endpoint
    // mid-egress, which is worse than a slightly wider allowlist on an
    // already-isolated per-VM process.
    ("clone", libc::SYS_clone),     // tokio worker / blocking thread spawn
    ("clone3", libc::SYS_clone3),   // modern glibc pthread_create path
    ("rseq", libc::SYS_rseq),       // glibc registers rseq on each new thread
    ("madvise", libc::SYS_madvise), // allocator MADV_DONTNEED / MADV_FREE
    ("sched_yield", libc::SYS_sched_yield), // futex spin fallback
    ("eventfd2", libc::SYS_eventfd2), // tokio reactor wakeup fd
    ("getsockname", libc::SYS_getsockname),
    ("getpeername", libc::SYS_getpeername),
    ("getsockopt", libc::SYS_getsockopt), // SO_ORIGINAL_DST (terminator), TLS
    ("setsockopt", libc::SYS_setsockopt), // TCP_NODELAY, socket tuning
    ("poll", libc::SYS_poll),             // glibc resolver / connect timeouts
    ("ppoll", libc::SYS_ppoll),
    ("pread64", libc::SYS_pread64),
    ("pwrite64", libc::SYS_pwrite64),
    ("statx", libc::SYS_statx), // newer glibc stat() for cert files
    ("socketpair", libc::SYS_socketpair),
    ("recvmmsg", libc::SYS_recvmmsg),     // glibc DNS resolver
    ("sendmmsg", libc::SYS_sendmmsg),     // glibc DNS resolver
    ("getdents64", libc::SYS_getdents64), // read /etc/ssl/certs dir
    ("readlinkat", libc::SYS_readlinkat), // cert symlink resolution
    ("fcntl", libc::SYS_fcntl),           // O_NONBLOCK on accepted sockets
    ("shutdown", libc::SYS_shutdown),     // graceful socket close
    ("clock_nanosleep", libc::SYS_clock_nanosleep), // tokio timer
    // The audit signer create_dir_all's the audit dir on first open;
    // Rust std emits the legacy `mkdir` on x86_64.
    ("mkdir", libc::SYS_mkdir),
    ("mkdirat", libc::SYS_mkdirat),
    // tokio's runtime queries CPU affinity when it spawns workers after
    // confinement (worker count / NUMA placement).
    ("sched_getaffinity", libc::SYS_sched_getaffinity),
];

#[cfg(target_arch = "aarch64")]
pub(crate) const BRIDGE_SYSCALLS: &[(&str, libc::c_long)] = &[
    ("read", libc::SYS_read),
    ("write", libc::SYS_write),
    ("fsync", libc::SYS_fsync),
    ("openat", libc::SYS_openat),
    ("close", libc::SYS_close),
    // arch divergence: aarch64 does not expose `stat` / `lstat` as
    // their own syscalls — both fold into `newfstatat` (syscall 79; libc
    // exposes no bare `SYS_fstatat` on aarch64). The policy layer still
    // references the names `stat` / `lstat` for readability.
    ("stat", libc::SYS_newfstatat),
    ("lstat", libc::SYS_newfstatat),
    ("fstat", libc::SYS_fstat),
    ("socket", libc::SYS_socket),
    ("bind", libc::SYS_bind),
    ("connect", libc::SYS_connect),
    ("accept", libc::SYS_accept),
    ("accept4", libc::SYS_accept4),
    ("sendmsg", libc::SYS_sendmsg),
    ("recvmsg", libc::SYS_recvmsg),
    ("sendto", libc::SYS_sendto),
    ("recvfrom", libc::SYS_recvfrom),
    ("splice", libc::SYS_splice),
    ("clock_gettime", libc::SYS_clock_gettime),
    ("futex", libc::SYS_futex),
    ("exit", libc::SYS_exit),
    ("exit_group", libc::SYS_exit_group),
    ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
    ("rt_sigaction", libc::SYS_rt_sigaction),
    // The Rust runtime installs an alternate signal stack (stack-overflow
    // guard) during thread setup; without this the bridge takes SIGSYS on its
    // own `sigaltstack` as soon as the packet thread spins up. Found via live
    // FC strace — the allowlist had never been exercised on the real sidecar.
    ("sigaltstack", libc::SYS_sigaltstack),
    ("mmap", libc::SYS_mmap),
    ("munmap", libc::SYS_munmap),
    ("mprotect", libc::SYS_mprotect),
    ("brk", libc::SYS_brk),
    ("getpid", libc::SYS_getpid),
    ("gettid", libc::SYS_gettid),
    ("getuid", libc::SYS_getuid),
    ("getgid", libc::SYS_getgid),
    ("getrandom", libc::SYS_getrandom),
    ("epoll_create1", libc::SYS_epoll_create1),
    ("epoll_ctl", libc::SYS_epoll_ctl),
    // arch divergence: aarch64 does not expose `epoll_wait` — fold
    // into `epoll_pwait` (the policy layer keeps the legacy name).
    ("epoll_wait", libc::SYS_epoll_pwait),
    ("epoll_pwait", libc::SYS_epoll_pwait),
    ("prctl", libc::SYS_prctl),
    ("set_tid_address", libc::SYS_set_tid_address),
    ("set_robust_list", libc::SYS_set_robust_list),
    // ── substitution-endpoint additions (see x86_64 block for rationale) ──
    ("clone", libc::SYS_clone),
    ("clone3", libc::SYS_clone3),
    ("rseq", libc::SYS_rseq),
    ("madvise", libc::SYS_madvise),
    ("sched_yield", libc::SYS_sched_yield),
    ("eventfd2", libc::SYS_eventfd2),
    ("getsockname", libc::SYS_getsockname),
    ("getpeername", libc::SYS_getpeername),
    ("getsockopt", libc::SYS_getsockopt),
    ("setsockopt", libc::SYS_setsockopt),
    // arch divergence: aarch64 has no bare `poll` syscall — both `poll`
    // and `ppoll` fold into `SYS_ppoll` (the policy layer keeps both names).
    ("poll", libc::SYS_ppoll),
    ("ppoll", libc::SYS_ppoll),
    ("pread64", libc::SYS_pread64),
    ("pwrite64", libc::SYS_pwrite64),
    ("statx", libc::SYS_statx),
    ("socketpair", libc::SYS_socketpair),
    ("recvmmsg", libc::SYS_recvmmsg),
    ("sendmmsg", libc::SYS_sendmmsg),
    ("getdents64", libc::SYS_getdents64),
    ("readlinkat", libc::SYS_readlinkat),
    ("fcntl", libc::SYS_fcntl),
    ("shutdown", libc::SYS_shutdown),
    ("clock_nanosleep", libc::SYS_clock_nanosleep),
    // arch divergence: aarch64 has no bare `mkdir` — it folds into
    // `mkdirat` (the policy layer keeps both names).
    ("mkdir", libc::SYS_mkdirat),
    ("mkdirat", libc::SYS_mkdirat),
    // tokio's runtime queries CPU affinity when it spawns workers after
    // confinement (worker count / NUMA placement).
    ("sched_getaffinity", libc::SYS_sched_getaffinity),
];

/// Resolve a syscall by name to its `libc::SYS_*` number on the current
/// architecture. Returns `None` for any name not in `BRIDGE_SYSCALLS`.
///
/// Every entry in `ConfinementSpec::firecracker_bridge()`'s
/// `allowed_syscalls` must have a row in `BRIDGE_SYSCALLS`; because
/// the spec is derived from that table, the discipline is structural
/// (you can't add a name without a number, you can't add a number
/// without a name).
fn syscall_name_to_nr(name: &str) -> Option<libc::c_long> {
    BRIDGE_SYSCALLS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
}

pub fn apply(spec: &ConfinementSpec) -> Result<(), JailerError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for name in &spec.allowed_syscalls {
        let nr = syscall_name_to_nr(name).ok_or_else(|| {
            JailerError::SeccompInstall(format!(
                "unknown syscall name {name:?}; extend BRIDGE_SYSCALLS in mvm-jailer-lite::seccomp"
            ))
        })?;
        rules.insert(nr, vec![]);
    }
    // SeccompAction::Trap (vs Errno(EACCES)) is intentional: the
    // bridge sidecar is expected to be killed by SIGSYS on a forbidden
    // syscall, and the supervisor's BridgeRestartPolicy::HardFail
    // tears the VM down. Errno would let a
    // compromised bridge observe the rejection and retry or pivot,
    // which is exactly what we want to forbid. SECCOMP.md §"Refusal
    // posture" documents this trade-off.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Trap,
        SeccompAction::Allow,
        TARGET_ARCH,
    )
    .map_err(|e| JailerError::SeccompInstall(format!("{e:?}")))?;
    let bpf: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| JailerError::SeccompInstall(format!("{e:?}")))?;
    seccompiler::apply_filter(&bpf).map_err(|e| JailerError::SeccompInstall(format!("{e:?}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_name_to_nr_returns_none_for_unknown_name() {
        assert!(syscall_name_to_nr("execve").is_none());
        assert!(syscall_name_to_nr("setuid").is_none());
        assert!(syscall_name_to_nr("ptrace").is_none());
        assert!(syscall_name_to_nr("definitely_not_a_real_syscall").is_none());
    }

    #[test]
    fn syscall_name_to_nr_resolves_known_names() {
        // Spot-check a representative slice rather than every entry —
        // the negative tests in lib.rs already exercise the audit
        // discipline.
        assert!(syscall_name_to_nr("read").is_some());
        assert!(syscall_name_to_nr("write").is_some());
        assert!(syscall_name_to_nr("splice").is_some());
        assert!(syscall_name_to_nr("fsync").is_some());
    }

    #[test]
    fn bridge_syscalls_has_no_duplicate_names() {
        // Defense against a future arch-block edit accidentally
        // shipping two rows for the same name (which would silently
        // shadow the first under `find()`).
        let mut seen: Vec<&str> = BRIDGE_SYSCALLS.iter().map(|(n, _)| *n).collect();
        seen.sort_unstable();
        let original_len = seen.len();
        seen.dedup();
        assert_eq!(
            original_len,
            seen.len(),
            "BRIDGE_SYSCALLS contains duplicate name"
        );
    }
}
