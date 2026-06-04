use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Cumulative seccomp profile tiers. Each tier is a strict superset of the
/// previous one, adding more syscall permissions for broader workload needs.
///
/// The syscall lists target x86_64 Linux. Tier membership is defined by
/// [`SeccompTier::syscalls`], which returns the full set of allowed syscall
/// names for that tier.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum SeccompTier {
    /// ~40 syscalls: just enough to load and exit a binary (linker, glibc init).
    Essential,
    /// ~110 syscalls: adds signals, pipes, timers, process control, polling.
    Minimal,
    /// ~140 syscalls: adds file manipulation, fs ops. Default for most workloads.
    #[default]
    Standard,
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
        Self::Network,
        Self::Unrestricted,
    ];

    /// Return the full list of allowed syscall names for this tier.
    /// Each tier is cumulative — it includes all syscalls from lower tiers.
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

impl FromStr for SeccompTier {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "essential" => Ok(Self::Essential),
            "minimal" => Ok(Self::Minimal),
            "standard" => Ok(Self::Standard),
            "network" => Ok(Self::Network),
            "unrestricted" => Ok(Self::Unrestricted),
            _ => anyhow::bail!(
                "unknown seccomp tier {:?} (expected: essential, minimal, standard, network, unrestricted)",
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
            Self::Network => write!(f, "network"),
            Self::Unrestricted => write!(f, "unrestricted"),
        }
    }
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

/// Tier 4 extras: sockets and networking.
fn network_extra() -> &'static [&'static str] {
    &[
        "socket",
        "socketpair",
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
        assert!(SeccompTier::Standard < SeccompTier::Network);
        assert!(SeccompTier::Network < SeccompTier::Unrestricted);
    }

    #[test]
    fn tier_cumulative_subset() {
        let essential = SeccompTier::Essential.syscalls();
        let minimal = SeccompTier::Minimal.syscalls();
        let standard = SeccompTier::Standard.syscalls();
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
                network.contains(sc),
                "network should include standard syscall {sc}"
            );
        }
        assert!(network.len() > standard.len());
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
