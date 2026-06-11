//! Confinement helper for per-VM sibling processes that run alongside
//! Firecracker on Linux.
//!
//! Wraps `seccompiler` (Firecracker-maintained) + `landlock` (official
//! Rust LSM binding) behind a single `confine_self(&ConfinementSpec)`
//! entry point. Non-Linux targets compile as inert stubs (the bridge
//! that calls `confine_self` is Linux-only at runtime; the stub keeps
//! workspace `cargo check` green on macOS / Windows contributor hosts).
//!
//! The `dead_code` allow below is gated to non-Linux targets because
//! `ConfinementSpec`'s syscall-name + path fields are only consumed by
//! the Linux-only `seccomp` + `landlock` modules. On macOS / Windows
//! the type is built (so callers compile) but its fields aren't read
//! by anything, which would otherwise trip the compiler's dead-code
//! lint. Per-symbol `#[cfg(target_os = "linux")]` would force every
//! field + impl method to carry the gate; a file-level cfg-attr is
//! cleaner and still leaves Linux compilation unaffected.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum JailerError {
    #[error("seccomp filter install failed: {0}")]
    SeccompInstall(String),
    #[error("landlock ruleset apply failed: {0}")]
    LandlockApply(String),
    #[error("kernel does not support landlock ABI v2 (need Linux 5.19+)")]
    LandlockUnavailable,
    #[error("kernel does not support seccomp-bpf (need Linux 4.14+)")]
    SeccompUnavailable,
    /// A path in the `ConfinementSpec` could not be opened to install a
    /// Landlock rule. Carries the failing path so the operator sees
    /// which directory needs to exist (the bridge's audit-dir is the
    /// most common cause: `~/.mvm/audit/` must be pre-created with
    /// mode 0700 by the supervisor's bootstrap before the bridge spawns).
    #[error("landlock path missing: {path}: {source}")]
    PathNotFound {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct ConfinementSpec {
    pub readable_paths: Vec<PathBuf>,
    pub read_write_paths: Vec<PathBuf>,
    pub allowed_syscalls: Vec<&'static str>,
}

impl ConfinementSpec {
    /// Canonical spec for `mvm-firecracker-bridge`. `SECCOMP.md` and
    /// `LANDLOCK.md` in the crate root document the rationale + review
    /// process for syscall additions.
    ///
    /// The syscall allowlist is sourced from the canonical
    /// `seccomp::BRIDGE_SYSCALLS` table on Linux, so a contributor can
    /// only extend it in one place — adding a name here without the
    /// matching `libc::SYS_*` row would fail to compile. On non-Linux
    /// targets the list is empty (the stub `confine_self` is a no-op /
    /// error path; callers must hard-exit before reaching it in
    /// production), keeping the type API parity across hosts.
    pub fn firecracker_bridge(audit_dir: PathBuf, keys_dir: PathBuf, passt_path: PathBuf) -> Self {
        #[cfg(target_os = "linux")]
        let allowed_syscalls: Vec<&'static str> = crate::jailer::seccomp::BRIDGE_SYSCALLS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        #[cfg(not(target_os = "linux"))]
        let allowed_syscalls: Vec<&'static str> = Vec::new();
        Self {
            readable_paths: vec![passt_path, keys_dir],
            read_write_paths: vec![audit_dir],
            allowed_syscalls,
        }
    }
}

/// Apply Landlock filesystem confinement then seccomp-BPF syscall
/// filtering to the calling thread.
///
/// **Partial-confinement contract:** on `Err`, the process may be in
/// any of three states: nothing applied (the Landlock step failed
/// before `restrict_self`), Landlock applied only (Landlock returned
/// `Ok` but the seccomp install failed), or both applied (the seccomp
/// install itself failed in a way that left the BPF program
/// half-loaded — vanishingly rare but possible because seccomp filter
/// installation is not transactional). The caller MUST hard-exit the
/// process on any error — there is no `disengage` API in either
/// kernel LSM, and a half-confined process running attacker-influenced
/// code is strictly worse than a confined one. The
/// `mvm-firecracker-bridge` sidecar honours this contract by returning
/// the error up to `main`, which logs and exits nonzero; the
/// supervisor's `BridgeRestartPolicy::HardFail` is the cleanup
/// mechanism that turns the exit into a VM teardown.
#[cfg(target_os = "linux")]
pub fn confine_self(spec: &ConfinementSpec) -> Result<(), JailerError> {
    crate::jailer::landlock::apply(spec)?;
    crate::jailer::seccomp::apply(spec)?;
    Ok(())
}

/// Non-Linux stub. Returns `JailerError::SeccompUnavailable` so a
/// caller that accidentally hits this path on macOS / Windows
/// fail-closes instead of running unconfined. The partial-confinement
/// contract on the Linux variant still applies to any production
/// caller — see that doc for the hard-exit requirement.
#[cfg(not(target_os = "linux"))]
pub fn confine_self(_spec: &ConfinementSpec) -> Result<(), JailerError> {
    Err(JailerError::SeccompUnavailable)
}

#[cfg(target_os = "linux")]
pub mod landlock;
#[cfg(target_os = "linux")]
pub mod seccomp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_bridge_spec_has_audit_write_paths() {
        let spec = ConfinementSpec::firecracker_bridge(
            "/tmp/audit".into(),
            "/tmp/keys".into(),
            "/usr/bin/passt".into(),
        );
        assert!(
            spec.read_write_paths
                .iter()
                .any(|p| p == std::path::Path::new("/tmp/audit"))
        );
        assert!(
            spec.readable_paths
                .iter()
                .any(|p| p == std::path::Path::new("/tmp/keys"))
        );
        assert!(
            spec.readable_paths
                .iter()
                .any(|p| p == std::path::Path::new("/usr/bin/passt"))
        );
    }

    /// On Linux the syscall allowlist is populated from the canonical
    /// `seccomp::BRIDGE_SYSCALLS` table. We assert the contents here
    /// (positive + negative) rather than in seccomp.rs because the
    /// allowlist is the security-policy surface — a future contributor
    /// editing the table touches this test, which is the audit point.
    #[cfg(target_os = "linux")]
    #[test]
    fn firecracker_bridge_allowlist_includes_required_syscalls() {
        let spec = ConfinementSpec::firecracker_bridge(
            "/tmp/audit".into(),
            "/tmp/keys".into(),
            "/usr/bin/passt".into(),
        );
        assert!(spec.allowed_syscalls.contains(&"splice"));
        assert!(spec.allowed_syscalls.contains(&"fsync"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firecracker_bridge_allowlist_rejects_dangerous_syscalls() {
        let spec = ConfinementSpec::firecracker_bridge(
            "/tmp/audit".into(),
            "/tmp/keys".into(),
            "/usr/bin/passt".into(),
        );
        assert!(!spec.allowed_syscalls.contains(&"execve"));
        assert!(!spec.allowed_syscalls.contains(&"setuid"));
        assert!(!spec.allowed_syscalls.contains(&"ptrace"));
        assert!(!spec.allowed_syscalls.contains(&"setgid"));
        assert!(!spec.allowed_syscalls.contains(&"capset"));
    }
}
