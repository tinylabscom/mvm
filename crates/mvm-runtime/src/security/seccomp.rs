use anyhow::{Context, Result};

use crate::shell;

const SECCOMP_DIR: &str = "/var/lib/mvm/seccomp";

/// Get the seccomp filter file path for Firecracker based on policy.
///
/// - "baseline": None (Firecracker's built-in default seccomp)
/// - "strict": path to custom restricted profile
pub fn seccomp_filter_path(policy: &str) -> Option<String> {
    match policy {
        "strict" => Some(format!("{}/strict.json", SECCOMP_DIR)),
        _ => None, // "baseline" — use Firecracker's built-in
    }
}

/// Ensure the strict seccomp profile exists on disk.
///
/// Generates a restrictive BPF filter that only allows syscalls
/// required by Firecracker (based on the official recommended set).
pub fn ensure_strict_profile() -> Result<()> {
    let profile = strict_profile_json();

    shell::run_in_vm(&format!(
        r#"
        mkdir -p {dir}
        cat > {dir}/strict.json << 'MVMEOF'
{json}
MVMEOF
        "#,
        dir = SECCOMP_DIR,
        json = profile,
    ))
    .with_context(|| "Failed to write strict seccomp profile")?;

    Ok(())
}

/// Generate the strict seccomp filter JSON for Firecracker.
///
/// This is a restrictive allowlist of syscalls that Firecracker needs.
/// Based on the official Firecracker seccomp recommendations.
fn strict_profile_json() -> &'static str {
    r#"{
  "Vmm": {
    "default_action": "trap",
    "filter_action": "allow",
    "filter": [
      { "syscall": "accept4" },
      { "syscall": "brk" },
      { "syscall": "clock_gettime" },
      { "syscall": "close" },
      { "syscall": "dup" },
      { "syscall": "epoll_create1" },
      { "syscall": "epoll_ctl" },
      { "syscall": "epoll_pwait" },
      { "syscall": "exit" },
      { "syscall": "exit_group" },
      { "syscall": "fallocate" },
      { "syscall": "fcntl" },
      { "syscall": "fstat" },
      { "syscall": "futex" },
      { "syscall": "getrandom" },
      { "syscall": "ioctl" },
      { "syscall": "lseek" },
      { "syscall": "madvise" },
      { "syscall": "mmap" },
      { "syscall": "mprotect" },
      { "syscall": "munmap" },
      { "syscall": "newfstatat" },
      { "syscall": "open" },
      { "syscall": "openat" },
      { "syscall": "pipe2" },
      { "syscall": "read" },
      { "syscall": "readv" },
      { "syscall": "recvfrom" },
      { "syscall": "recvmsg" },
      { "syscall": "rt_sigaction" },
      { "syscall": "rt_sigprocmask" },
      { "syscall": "rt_sigreturn" },
      { "syscall": "sendmsg" },
      { "syscall": "sendto" },
      { "syscall": "set_robust_list" },
      { "syscall": "sigaltstack" },
      { "syscall": "socket" },
      { "syscall": "timerfd_create" },
      { "syscall": "timerfd_settime" },
      { "syscall": "tkill" },
      { "syscall": "write" },
      { "syscall": "writev" }
    ]
  },
  "Api": {
    "default_action": "trap",
    "filter_action": "allow",
    "filter": [
      { "syscall": "accept4" },
      { "syscall": "bind" },
      { "syscall": "close" },
      { "syscall": "epoll_create1" },
      { "syscall": "epoll_ctl" },
      { "syscall": "epoll_pwait" },
      { "syscall": "exit" },
      { "syscall": "exit_group" },
      { "syscall": "futex" },
      { "syscall": "listen" },
      { "syscall": "read" },
      { "syscall": "recvfrom" },
      { "syscall": "rt_sigaction" },
      { "syscall": "rt_sigprocmask" },
      { "syscall": "rt_sigreturn" },
      { "syscall": "sendto" },
      { "syscall": "sigaltstack" },
      { "syscall": "socket" },
      { "syscall": "write" }
    ]
  },
  "Vcpu": {
    "default_action": "trap",
    "filter_action": "allow",
    "filter": [
      { "syscall": "close" },
      { "syscall": "exit" },
      { "syscall": "exit_group" },
      { "syscall": "futex" },
      { "syscall": "ioctl" },
      { "syscall": "read" },
      { "syscall": "rt_sigaction" },
      { "syscall": "rt_sigprocmask" },
      { "syscall": "rt_sigreturn" },
      { "syscall": "sigaltstack" },
      { "syscall": "write" }
    ]
  }
}"#
}

/// Generate the seccomp syscall allowlist for the hostd daemon.
///
/// Hostd only needs: socket operations, file I/O, process management
/// (fork/exec for shell commands), and netlink for bridge/TAP setup.
pub fn hostd_syscall_allowlist() -> &'static [&'static str] {
    &[
        // Process
        "clone",
        "clone3",
        "execve",
        "exit",
        "exit_group",
        "wait4",
        "kill",
        "getpid",
        "getppid",
        "gettid",
        "set_tid_address",
        "set_robust_list",
        // File I/O
        "openat",
        "close",
        "read",
        "write",
        "fstat",
        "newfstatat",
        "lseek",
        "fcntl",
        "dup",
        "dup2",
        "dup3",
        "pipe2",
        "mkdir",
        "mkdirat",
        "unlink",
        "unlinkat",
        "rename",
        "renameat",
        "renameat2",
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "fchownat",
        "readlink",
        "readlinkat",
        "getcwd",
        "access",
        "faccessat",
        "faccessat2",
        "statx",
        // Memory
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        "mremap",
        // Socket (Unix domain socket for IPC)
        "socket",
        "bind",
        "listen",
        "accept4",
        "connect",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "shutdown",
        "getsockname",
        "getpeername",
        "setsockopt",
        "getsockopt",
        // Network (netlink for bridge/TAP, ioctl for network devices)
        "ioctl",
        // Signals
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sigaltstack",
        // Time
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        // Misc
        "futex",
        "getrandom",
        "arch_prctl",
        "prctl",
        "rseq",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        // cgroups
        "mount",
        "umount2",
        "pivot_root",
        "chroot",
        "chdir",
        "fchdir",
        // Device nodes (mknod for /dev/kvm, /dev/net/tun)
        "mknod",
        "mknodat",
        // UID/GID switching (jailer)
        "setuid",
        "setgid",
        "setgroups",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_filter_path_baseline() {
        assert!(seccomp_filter_path("baseline").is_none());
    }

    #[test]
    fn test_seccomp_filter_path_strict() {
        let path = seccomp_filter_path("strict").unwrap();
        assert!(path.contains("strict.json"));
        assert!(path.starts_with("/var/lib/mvm/seccomp"));
    }

    #[test]
    fn test_seccomp_filter_path_unknown() {
        assert!(seccomp_filter_path("unknown").is_none());
    }

    #[test]
    fn test_strict_profile_valid_json() {
        let json = strict_profile_json();
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(parsed.get("Vmm").is_some());
        assert!(parsed.get("Api").is_some());
        assert!(parsed.get("Vcpu").is_some());
    }

    #[test]
    fn test_hostd_syscall_allowlist_not_empty() {
        let list = hostd_syscall_allowlist();
        assert!(!list.is_empty());
        // Must include critical syscalls for hostd operation
        assert!(list.contains(&"socket"));
        assert!(list.contains(&"bind"));
        assert!(list.contains(&"accept4"));
        assert!(list.contains(&"execve"));
        assert!(list.contains(&"ioctl"));
        assert!(list.contains(&"clone"));
        assert!(list.contains(&"mknod"));
        assert!(list.contains(&"chroot"));
        assert!(list.contains(&"setuid"));
    }

    #[test]
    fn test_hostd_syscall_allowlist_no_duplicates() {
        let list = hostd_syscall_allowlist();
        let mut seen = std::collections::HashSet::new();
        for syscall in list {
            assert!(seen.insert(syscall), "Duplicate syscall: {}", syscall);
        }
    }
}
