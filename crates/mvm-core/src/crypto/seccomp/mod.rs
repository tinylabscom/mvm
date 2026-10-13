use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[cfg(target_os = "linux")]
pub mod syscall_table;

/// Cumulative seccomp profile tiers. Each tier is a strict superset of the
/// previous one, adding more syscall permissions for broader workload needs.
///
/// The syscall lists cover x86_64 and aarch64 Linux. A name that does not
/// exist on the target arch is skipped when the filter is built, so a tier
/// may name both a legacy syscall and its `*at` replacement; both are needed
/// for the capability to survive on both arches. Tier membership is defined by
/// [`SeccompTier::syscalls`], which returns the full set of allowed syscall
/// names for that tier.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SeccompTier {
    /// ~40 syscalls: just enough to load and exit a binary (linker, glibc init).
    Essential,
    /// ~110 syscalls: adds signals, pipes, timers, process control, polling.
    Minimal,
    /// ~140 syscalls: adds file manipulation, fs ops. Default for most workloads.
    #[default]
    Standard,
    /// `standard` plus `AF_VSOCK` stream sockets: `socket` is granted only
    /// for that family (see [`SeccompTier::argument_scoped_syscalls`]), with
    /// `connect` and the `sendto`/`recvfrom` pair a stream read and write
    /// lower to. No other address family can be opened, so the only peers a
    /// process can reach are the vsock ports the VMM exposes. For a launch
    /// that needs its GPU endpoint and nothing else.
    Vsock,
    /// ~160 syscalls: adds sockets, connect, bind, sendmsg. For networked agents.
    Network,
    /// All syscalls allowed. Dev/debug mode, no restrictions.
    Unrestricted,
}

impl SeccompTier {
    /// All tiers in order from most restrictive to least.
    pub const ALL: &[Self] = &[
        Self::Essential,
        Self::Minimal,
        Self::Standard,
        Self::Vsock,
        Self::Network,
        Self::Unrestricted,
    ];

    /// Return the full list of syscall names this tier allows whatever their
    /// arguments. Each tier is cumulative — it includes all syscalls from
    /// lower tiers. A syscall a tier allows only for some argument values is
    /// not here; it is in [`Self::argument_scoped_syscalls`].
    pub fn syscalls(&self) -> Vec<&'static str> {
        match self {
            Self::Essential => essential_syscalls().to_vec(),
            Self::Minimal => {
                let mut s = essential_syscalls().to_vec();
                s.extend_from_slice(minimal_extra());
                s
            }
            Self::Standard => {
                let mut s = essential_syscalls().to_vec();
                s.extend_from_slice(minimal_extra());
                s.extend_from_slice(standard_extra());
                s
            }
            Self::Vsock => {
                let mut s = essential_syscalls().to_vec();
                s.extend_from_slice(minimal_extra());
                s.extend_from_slice(standard_extra());
                s.extend_from_slice(vsock_extra());
                s
            }
            Self::Network => {
                let mut s = essential_syscalls().to_vec();
                s.extend_from_slice(minimal_extra());
                s.extend_from_slice(standard_extra());
                s.extend_from_slice(network_extra());
                s
            }
            Self::Unrestricted => vec![], // empty = allow all
        }
    }

    /// Syscalls this tier allows only when one argument takes a listed value,
    /// on top of [`Self::syscalls`]. A name here is never also in
    /// [`Self::syscalls`] for the same tier, since an unconditional grant
    /// would make the scope meaningless.
    pub fn argument_scoped_syscalls(&self) -> &'static [ArgumentScopedSyscall] {
        match self {
            Self::Vsock => &[ArgumentScopedSyscall {
                name: "socket",
                arg_index: 0,
                allowed: &[AF_VSOCK],
            }],
            Self::Essential
            | Self::Minimal
            | Self::Standard
            | Self::Network
            | Self::Unrestricted => &[],
        }
    }

    /// Whether this tier allows all syscalls (no filtering).
    pub fn is_unrestricted(&self) -> bool {
        matches!(self, Self::Unrestricted)
    }

    /// Generate a JSON seccomp manifest suitable for the guest init to load.
    /// Returns `None` for unrestricted (no filter needed).
    pub fn to_manifest(&self) -> Option<SeccompManifest> {
        if self.is_unrestricted() {
            return None;
        }
        Some(SeccompManifest {
            tier: *self,
            action: SeccompAction::KillProcess,
            allowed_syscalls: self.syscalls().iter().map(|s| (*s).to_string()).collect(),
        })
    }
}

/// The filter a signed plan's tier name selects.
impl From<crate::plan::PlanSeccompTier> for SeccompTier {
    fn from(tier: crate::plan::PlanSeccompTier) -> Self {
        use crate::plan::PlanSeccompTier as Plan;
        match tier {
            Plan::Essential => Self::Essential,
            Plan::Minimal => Self::Minimal,
            Plan::Standard => Self::Standard,
            Plan::Vsock => Self::Vsock,
            Plan::Network => Self::Network,
            Plan::Unrestricted => Self::Unrestricted,
        }
    }
}

impl FromStr for SeccompTier {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "essential" => Ok(Self::Essential),
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "vsock" => Ok(Self::Vsock),
            "network" => Ok(Self::Network),
            "unrestricted" => Ok(Self::Unrestricted),
            _ => anyhow::bail!(
                "unknown seccomp tier {:?} (expected: essential, minimal, standard, vsock, network, unrestricted)",
                s
            ),
        }
    }
}

impl fmt::Display for SeccompTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Essential => write!(f, "essential"),
            Self::Minimal => write!(f, "minimal"),
            Self::Standard => write!(f, "standard"),
            Self::Vsock => write!(f, "vsock"),
            Self::Network => write!(f, "network"),
            Self::Unrestricted => write!(f, "unrestricted"),
        }
    }
}

/// Linux's `AF_VSOCK` address family number, the same on every architecture.
pub const AF_VSOCK: u64 = 40;

/// A syscall a tier allows only when the argument at `arg_index` equals one of
/// `allowed`. The comparison is on the argument's low 32 bits, which is the
/// width of every `int` argument this is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgumentScopedSyscall {
    pub name: &'static str,
    pub arg_index: u8,
    pub allowed: &'static [u64],
}

/// Action taken when a syscall is not in the allowed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompAction {
    /// Kill the process (SECCOMP_RET_KILL_PROCESS). Strictest.
    KillProcess,
    /// Send SIGSYS (SECCOMP_RET_TRAP). Useful for debugging.
    Trap,
    /// Return EPERM (SECCOMP_RET_ERRNO). Allows graceful handling.
    Errno,
    /// Log but allow (SECCOMP_RET_LOG). Audit mode.
    Log,
}

/// JSON manifest describing a seccomp filter, written to the config drive
/// for the guest init to apply via `seccomp(2)` or `prctl(PR_SET_SECCOMP)`.
///
/// It carries only the unconditional allowlist: a tier's argument-scoped
/// syscalls are absent, so a filter built from the manifest alone denies them
/// outright rather than allowing them unscoped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompManifest {
    pub tier: SeccompTier,
    pub action: SeccompAction,
    pub allowed_syscalls: Vec<String>,
}

/// Named security profile bundling seccomp tier with resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    /// Tight restrictions: minimal seccomp, 128MB mem, 1 CPU.
    Strict,
    /// Balanced: standard seccomp, 512MB mem, 2 CPUs.
    Moderate,
    /// Relaxed: unrestricted seccomp, 2GB mem, 4 CPUs.
    Permissive,
}

/// Resource limits bundled with a security profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileLimits {
    pub seccomp_tier: SeccompTier,
    pub memory_mib: u32,
    pub cpus: u32,
}

impl SecurityProfile {
    pub fn limits(&self) -> ProfileLimits {
        match self {
            Self::Strict => ProfileLimits {
                seccomp_tier: SeccompTier::Minimal,
                memory_mib: 128,
                cpus: 1,
            },
            Self::Moderate => ProfileLimits {
                seccomp_tier: SeccompTier::Standard,
                memory_mib: 512,
                cpus: 2,
            },
            Self::Permissive => ProfileLimits {
                seccomp_tier: SeccompTier::Unrestricted,
                memory_mib: 2048,
                cpus: 4,
            },
        }
    }
}

impl FromStr for SecurityProfile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "strict" => Ok(Self::Strict),
            "moderate" => Ok(Self::Moderate),
            "permissive" => Ok(Self::Permissive),
            _ => anyhow::bail!(
                "unknown security profile {:?} (expected: strict, moderate, permissive)",
                s
            ),
        }
    }
}

impl fmt::Display for SecurityProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strict => write!(f, "strict"),
            Self::Moderate => write!(f, "moderate"),
            Self::Permissive => write!(f, "permissive"),
        }
    }
}

// ============================================================================
// Syscall lists (x86_64 Linux)
// ============================================================================

/// Tier 1: Process bootstrap — linker, glibc init, exit.
fn essential_syscalls() -> &'static [&'static str] {
    &[
        // Lifecycle
        "exit",
        "exit_group",
        // Exec
        "execve",
        "execveat",
        // Memory (linker)
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        // File (linker)
        "openat",
        "open",
        "read",
        "write",
        "close",
        "close_range",
        // Stat
        "fstat",
        "stat",
        "lstat",
        "newfstatat",
        "statx",
        // Access
        "access",
        "faccessat",
        "faccessat2",
        // Seek
        "lseek",
        // Links
        "readlink",
        "readlinkat",
        // glibc init
        "arch_prctl",
        "set_tid_address",
        "set_robust_list",
        "futex",
        "getrandom",
        "rseq",
        "prlimit64",
        "prctl",
        // CWD
        "getcwd",
        // Identity
        "getpid",
        "gettid",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        // Read-only, like the calls above. A shell's `test -r`, `-w` and `-x`
        // ask for the supplementary groups whenever the caller does not own
        // the file, so without it they fail with EPERM.
        "getgroups",
        // FD
        "fcntl",
    ]
}

/// Tier 2 extras: signals, pipes, timers, process control, polling.
fn minimal_extra() -> &'static [&'static str] {
    &[
        // Signals
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigqueueinfo",
        "rt_sigreturn",
        "rt_sigsuspend",
        "restart_syscall",
        "sigaltstack",
        "kill",
        "tkill",
        "tgkill",
        // Processes
        "clone",
        "clone3",
        "fork",
        "vfork",
        "wait4",
        "waitid",
        // Advanced I/O
        "readv",
        "writev",
        "pread64",
        "pwrite64",
        "ioctl",
        "flock",
        // FDs
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "eventfd2",
        // Time
        "clock_gettime",
        "clock_getres",
        "gettimeofday",
        "nanosleep",
        "clock_nanosleep",
        // Timers
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_getoverrun",
        "timer_delete",
        // Info
        "getppid",
        "getresuid",
        "getresgid",
        "uname",
        "umask",
        "sysinfo",
        "getpgrp",
        "getpgid",
        "setpgid",
        "getsid",
        "setsid",
        // Scheduling
        "sched_getaffinity",
        "sched_yield",
        // Limits
        "getrlimit",
        "setrlimit",
        "getrusage",
        // Polling
        "pselect6",
        "ppoll",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        // aarch64 has no `epoll_wait`; glibc's `epoll_wait()` dispatches
        // `epoll_pwait` there. Without this the entry above resolves to
        // nothing on aarch64 and every epoll call in a confined role takes
        // EPERM — the capability is granted on x86_64 and silently absent on
        // ARM. Listing both names grants one capability on both, which is what
        // the jailer's own table already does.
        "epoll_pwait",
        "poll",
        "select",
        // Dir
        "chdir",
        "fchdir",
        "getdents",
        "getdents64",
        // Memory
        "mremap",
        "mlock",
        "munlock",
        "mlockall",
        "munlockall",
        "memfd_create",
        // Misc
        "get_robust_list",
    ]
}

/// Tier 3 extras: file manipulation, filesystem operations.
fn standard_extra() -> &'static [&'static str] {
    &[
        // Create/delete
        "mkdir",
        "mkdirat",
        "rmdir",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "link",
        "linkat",
        "symlink",
        "symlinkat",
        // Permissions
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "fchownat",
        "lchown",
        // Times
        "utimensat",
        "futimesat",
        // Truncate
        "truncate",
        "ftruncate",
        "fallocate",
        // A connected AF_UNIX pair reaches no address, so it belongs with the
        // file tier rather than the network one.
        "socketpair",
        // Data transfer
        "sendfile",
        "splice",
        "tee",
        "vmsplice",
        // Fs info
        "statfs",
        "fstatfs",
        "fsync",
        "fdatasync",
    ]
}

/// `vsock` tier extras on top of `standard`, beside the `AF_VSOCK`-scoped
/// `socket`. None of these can create a descriptor: they act on one the
/// process already holds, and the only sockets it can open are vsock ones.
/// `sendto` and `recvfrom` are listed because glibc lowers `send` and `recv`
/// to them, and Rust's `UnixStream::read` calls `recv`.
fn vsock_extra() -> &'static [&'static str] {
    &["connect", "sendto", "recvfrom"]
}

/// Tier 4 extras: sockets and networking.
fn network_extra() -> &'static [&'static str] {
    &[
        "socket",
        "bind",
        "listen",
        "accept",
        "accept4",
        "connect",
        "shutdown",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "sendmmsg",
        "recvmmsg",
        "setsockopt",
        "getsockopt",
        "getsockname",
        "getpeername",
    ]
}

#[cfg(test)]
mod tests {
    /// A plan's tier and the filter it selects share a name, which is how the
    /// cmdline carries it; the conversion has to agree with that.
    #[test]
    fn every_plan_tier_selects_the_filter_of_the_same_name() {
        use crate::plan::PlanSeccompTier;
        for plan in [
            PlanSeccompTier::Essential,
            PlanSeccompTier::Minimal,
            PlanSeccompTier::Standard,
            PlanSeccompTier::Vsock,
            PlanSeccompTier::Network,
            PlanSeccompTier::Unrestricted,
        ] {
            assert_eq!(SeccompTier::from(plan).to_string(), plan.to_string());
        }
    }

    use super::*;

    #[test]
    fn tier_parse_roundtrip() {
        for tier in SeccompTier::ALL {
            let s = tier.to_string();
            let parsed: SeccompTier = s.parse().unwrap();
            assert_eq!(&parsed, tier);
        }
    }

    #[test]
    fn tier_parse_invalid() {
        assert!("bogus".parse::<SeccompTier>().is_err());
    }

    #[test]
    fn tier_ordering() {
        assert!(SeccompTier::Essential < SeccompTier::Minimal);
        assert!(SeccompTier::Minimal < SeccompTier::Standard);
        assert!(SeccompTier::Standard < SeccompTier::Vsock);
        assert!(SeccompTier::Vsock < SeccompTier::Network);
        assert!(SeccompTier::Network < SeccompTier::Unrestricted);
    }

    #[test]
    fn tier_cumulative_subset() {
        let essential = SeccompTier::Essential.syscalls();
        let minimal = SeccompTier::Minimal.syscalls();
        let standard = SeccompTier::Standard.syscalls();
        let vsock = SeccompTier::Vsock.syscalls();
        let network = SeccompTier::Network.syscalls();

        // Each tier should be a strict superset of the previous
        for sc in &essential {
            assert!(
                minimal.contains(sc),
                "minimal should include essential syscall {sc}"
            );
        }
        assert!(minimal.len() > essential.len());

        for sc in &minimal {
            assert!(
                standard.contains(sc),
                "standard should include minimal syscall {sc}"
            );
        }
        assert!(standard.len() > minimal.len());

        for sc in &standard {
            assert!(
                vsock.contains(sc),
                "vsock should include standard syscall {sc}"
            );
        }
        assert!(vsock.len() > standard.len());

        for sc in &vsock {
            assert!(
                network.contains(sc),
                "network should include vsock syscall {sc}"
            );
        }
        assert!(network.len() > vsock.len());
    }

    #[test]
    fn tier_syscall_counts() {
        assert!(
            SeccompTier::Essential.syscalls().len() >= 35,
            "essential should have ~40 syscalls"
        );
        assert!(
            SeccompTier::Minimal.syscalls().len() >= 100,
            "minimal should have ~110 syscalls"
        );
        assert!(
            SeccompTier::Standard.syscalls().len() >= 130,
            "standard should have ~140 syscalls"
        );
        assert!(
            SeccompTier::Network.syscalls().len() >= 148,
            "network should have ~160 syscalls"
        );
    }

    #[test]
    fn unrestricted_has_no_syscalls() {
        assert!(SeccompTier::Unrestricted.syscalls().is_empty());
    }

    #[test]
    fn unrestricted_no_manifest() {
        assert!(SeccompTier::Unrestricted.to_manifest().is_none());
    }

    /// Every tier a workload can run under lets it read its own supplementary
    /// groups. Busybox `test -r` calls `getgroups` for a file the caller does
    /// not own, so a tier without it breaks ordinary shell scripts.
    #[test]
    fn every_enforced_tier_lets_a_process_read_its_groups() {
        for tier in [
            SeccompTier::Essential,
            SeccompTier::Minimal,
            SeccompTier::Standard,
            SeccompTier::Vsock,
            SeccompTier::Network,
        ] {
            assert!(
                tier.syscalls().contains(&"getgroups"),
                "{tier} must grant getgroups"
            );
            assert!(
                !tier.syscalls().contains(&"setgroups"),
                "{tier} must not grant setgroups"
            );
        }
    }

    #[test]
    fn standard_manifest_has_syscalls() {
        let manifest = SeccompTier::Standard.to_manifest().unwrap();
        assert_eq!(manifest.tier, SeccompTier::Standard);
        assert!(!manifest.allowed_syscalls.is_empty());
        assert!(manifest.allowed_syscalls.contains(&"read".to_string()));
        assert!(manifest.allowed_syscalls.contains(&"write".to_string()));
        assert!(manifest.allowed_syscalls.contains(&"mkdir".to_string()));
        // Standard should NOT have network syscalls
        assert!(!manifest.allowed_syscalls.contains(&"socket".to_string()));
    }

    /// A tier enforced on general workload processes has to let them wait for
    /// a signal and resume an interrupted sleep. Without `rt_sigsuspend` a
    /// shell's `wait` builtin fails with EPERM instead of blocking; without
    /// `restart_syscall` a `nanosleep` interrupted by SIGSTOP/SIGCONT returns
    /// EPERM instead of resuming.
    #[test]
    fn minimal_lets_a_process_wait_for_a_signal_and_resume_a_sleep() {
        let minimal = SeccompTier::Minimal.syscalls();
        for name in ["rt_sigsuspend", "restart_syscall"] {
            assert!(minimal.contains(&name), "minimal must grant {name}");
        }
    }

    /// `socketpair` creates a connected `AF_UNIX` pair and nothing else: it can
    /// reach no address. Interpreters use it for in-process wakeups (Python's
    /// asyncio self-pipe among them), so `standard` grants it while still
    /// refusing `socket`, which is what reaches a network.
    #[test]
    fn standard_grants_a_socket_pair_but_not_a_socket() {
        let standard = SeccompTier::Standard.syscalls();
        assert!(standard.contains(&"socketpair"));
        for name in ["socket", "connect", "bind", "listen"] {
            assert!(!standard.contains(&name), "standard must not grant {name}");
        }
    }

    /// A GPU-granted launch reaches its host endpoint over vsock and nothing
    /// else, so the `vsock` tier grants `socket` only for `AF_VSOCK`, plus the
    /// calls that use the connected stream. Nothing that creates a descriptor
    /// any other way, or that serves or carries descriptors, comes with it.
    #[test]
    fn vsock_grants_socket_only_for_af_vsock() {
        let vsock = SeccompTier::Vsock;
        assert!(
            !vsock.syscalls().contains(&"socket"),
            "socket must be scoped by family, never granted outright"
        );
        assert_eq!(
            vsock.argument_scoped_syscalls(),
            &[ArgumentScopedSyscall {
                name: "socket",
                arg_index: 0,
                allowed: &[AF_VSOCK],
            }]
        );
        for name in ["connect", "sendto", "recvfrom"] {
            assert!(vsock.syscalls().contains(&name), "vsock must grant {name}");
        }
        for name in [
            "bind", "listen", "accept", "accept4", "sendmsg", "recvmsg", "sendmmsg", "recvmmsg",
        ] {
            assert!(
                !vsock.syscalls().contains(&name),
                "vsock must not grant {name}"
            );
        }
        let manifest = vsock.to_manifest().expect("vsock enforces a filter");
        assert!(!manifest.allowed_syscalls.contains(&"socket".to_string()));
    }

    /// Only `vsock` scopes a syscall by argument. Every other tier either
    /// grants `socket` outright (`network`), refuses it (the tiers below), or
    /// installs no filter (`unrestricted`).
    #[test]
    fn only_the_vsock_tier_scopes_a_syscall_by_argument() {
        for tier in SeccompTier::ALL {
            let scoped = tier.argument_scoped_syscalls();
            assert_eq!(
                !scoped.is_empty(),
                *tier == SeccompTier::Vsock,
                "{tier} has scoped syscalls {scoped:?}"
            );
            for entry in scoped {
                assert!(
                    !tier.syscalls().contains(&entry.name),
                    "{tier} grants {} both outright and scoped",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn network_manifest_has_socket() {
        let manifest = SeccompTier::Network.to_manifest().unwrap();
        assert!(manifest.allowed_syscalls.contains(&"socket".to_string()));
        assert!(manifest.allowed_syscalls.contains(&"connect".to_string()));
    }

    #[test]
    fn no_duplicate_syscalls() {
        for tier in SeccompTier::ALL {
            let syscalls = tier.syscalls();
            let mut seen = std::collections::HashSet::new();
            for sc in &syscalls {
                assert!(seen.insert(sc), "duplicate syscall {sc} in tier {tier}");
            }
        }
    }

    #[test]
    fn tier_serde_roundtrip() {
        for tier in SeccompTier::ALL {
            let json = serde_json::to_string(tier).unwrap();
            let parsed: SeccompTier = serde_json::from_str(&json).unwrap();
            assert_eq!(&parsed, tier);
        }
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = SeccompTier::Minimal.to_manifest().unwrap();
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: SeccompManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tier, SeccompTier::Minimal);
        assert_eq!(
            parsed.allowed_syscalls.len(),
            manifest.allowed_syscalls.len()
        );
    }

    #[test]
    fn default_tier_is_standard() {
        assert_eq!(SeccompTier::default(), SeccompTier::Standard);
    }

    #[test]
    fn security_profile_strict_limits() {
        let limits = SecurityProfile::Strict.limits();
        assert_eq!(limits.seccomp_tier, SeccompTier::Minimal);
        assert_eq!(limits.memory_mib, 128);
        assert_eq!(limits.cpus, 1);
    }

    #[test]
    fn security_profile_moderate_limits() {
        let limits = SecurityProfile::Moderate.limits();
        assert_eq!(limits.seccomp_tier, SeccompTier::Standard);
        assert_eq!(limits.memory_mib, 512);
        assert_eq!(limits.cpus, 2);
    }

    #[test]
    fn security_profile_permissive_limits() {
        let limits = SecurityProfile::Permissive.limits();
        assert_eq!(limits.seccomp_tier, SeccompTier::Unrestricted);
        assert_eq!(limits.memory_mib, 2048);
        assert_eq!(limits.cpus, 4);
    }

    #[test]
    fn security_profile_parse_roundtrip() {
        for (s, expected) in [
            ("strict", SecurityProfile::Strict),
            ("moderate", SecurityProfile::Moderate),
            ("permissive", SecurityProfile::Permissive),
        ] {
            let parsed: SecurityProfile = s.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.to_string(), s);
        }
    }

    #[test]
    fn security_profile_parse_invalid() {
        assert!("bogus".parse::<SecurityProfile>().is_err());
    }

    #[test]
    fn seccomp_action_serde() {
        for action in [
            SeccompAction::KillProcess,
            SeccompAction::Trap,
            SeccompAction::Errno,
            SeccompAction::Log,
        ] {
            let json = serde_json::to_string(&action).unwrap();
            let parsed: SeccompAction = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, action);
        }
    }
}
