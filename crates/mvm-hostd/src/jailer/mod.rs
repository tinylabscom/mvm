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

    /// Canonical spec for `mvm-substitution-endpoint` — the per-VM process
    /// that holds the workload's decrypted secrets AND parses untrusted guest
    /// bytes over vsock/UDS. Confining it bounds the blast radius of a parser
    /// compromise: a hijacked endpoint can read only its own tenant's stores
    /// and the TLS/DNS files its forward leg needs, and can invoke only the
    /// network-service syscall set.
    ///
    /// `readable_paths` covers the secret + binding stores (resolved by the
    /// caller exactly as `assemble` does — config override or `~/.mvm`
    /// default) plus the TLS root + DNS resolver files the reqwest
    /// (`rustls-native-certs`) forward leg reads PER REQUEST during `serve`,
    /// so they must stay readable AFTER confinement. The endpoint as assembled
    /// attaches no audit recorder, so `read_write_paths` is empty.
    ///
    /// The syscall allowlist comes from the same canonical
    /// `seccomp::BRIDGE_SYSCALLS` table the bridge uses — extended with the
    /// extra syscalls the tokio multi-thread runtime + rustls TLS forward leg
    /// touch (see the table's comments). On non-Linux targets the list is
    /// empty (the stub `confine_self` errors; the bin hard-exits before
    /// reaching it). `existing_paths` filters to paths that exist on this host
    /// — `/etc/pki`, `/etc/resolv.conf`, etc. are distro-dependent, and a
    /// missing readable path makes the Landlock `open` step fail closed.
    pub fn substitution_endpoint(secret_store_dir: PathBuf, binding_store_dir: PathBuf) -> Self {
        #[cfg(target_os = "linux")]
        let allowed_syscalls: Vec<&'static str> = crate::jailer::seccomp::BRIDGE_SYSCALLS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        #[cfg(not(target_os = "linux"))]
        let allowed_syscalls: Vec<&'static str> = Vec::new();

        // The forward leg uses reqwest's rustls-tls backend, which loads the
        // host's native root store (rustls-native-certs reads /etc/ssl/certs +
        // /etc/pki/tls). DNS goes through getaddrinfo (resolv.conf / hosts /
        // nsswitch). These are read per request during serve, so they must be
        // inside the Landlock ruleset.
        let tls_dns_paths: Vec<PathBuf> = [
            "/etc/ssl",
            "/etc/pki",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();

        let mut readable_paths = vec![secret_store_dir, binding_store_dir];
        readable_paths.extend(tls_dns_paths);

        Self {
            // Filter to extant paths: /etc/pki / /etc/resolv.conf are distro-
            // dependent, and Landlock's `open` on a missing path fails closed
            // (PathNotFound), which would abort an otherwise-healthy endpoint.
            readable_paths: existing_paths(readable_paths),
            read_write_paths: Vec::new(),
            allowed_syscalls,
        }
    }
}

/// Drop paths that don't exist on this host. Landlock installs a rule by
/// `open`ing each path; a missing one returns `PathNotFound` and (per the
/// hard-exit contract) would abort the process. The store dirs are created by
/// the supervisor before spawn and the TLS/DNS files are present on any host
/// that can actually make an egress call, but `/etc/pki` / `/etc/resolv.conf`
/// vary by distro — filtering keeps the spec portable without weakening it
/// (a path that isn't there grants no access anyway).
fn existing_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.into_iter().filter(|p| p.exists()).collect()
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

    #[test]
    fn substitution_endpoint_spec_grants_read_on_stores() {
        // Use real existing dirs so they survive the `existing_paths` filter;
        // the binary's own crate manifest dir is guaranteed present.
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let bindings = store.clone();
        let spec = ConfinementSpec::substitution_endpoint(store.clone(), bindings.clone());
        assert!(
            spec.readable_paths.iter().any(|p| p == &store),
            "secret store dir must be readable"
        );
        assert!(
            spec.readable_paths.iter().any(|p| p == &bindings),
            "binding store dir must be readable"
        );
    }

    #[test]
    fn substitution_endpoint_spec_has_no_write_paths() {
        // The endpoint as assembled attaches no audit recorder, so it needs no
        // writable directory. If a recorder is ever wired into `assemble`, the
        // audit dir must be added to `read_write_paths` (and this test updated).
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::substitution_endpoint(store.clone(), store);
        assert!(spec.read_write_paths.is_empty());
    }

    #[test]
    fn substitution_endpoint_spec_drops_nonexistent_paths() {
        // A bogus store dir is filtered out — Landlock's `open` on a missing
        // path fails closed, which would abort an otherwise-healthy endpoint.
        let missing = PathBuf::from("/definitely/not/a/real/store/dir/xyzzy");
        let spec = ConfinementSpec::substitution_endpoint(missing.clone(), missing.clone());
        assert!(
            !spec.readable_paths.iter().any(|p| p == &missing),
            "nonexistent store dir must be filtered out"
        );
    }

    /// On Linux the endpoint allowlist is the bridge table plus the tokio +
    /// TLS-forward additions. Assert the additions are present (the egress
    /// path needs them) and the dangerous names still absent.
    #[cfg(target_os = "linux")]
    #[test]
    fn substitution_endpoint_allowlist_covers_tls_and_runtime() {
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::substitution_endpoint(store.clone(), store);
        // Thread creation for tokio workers / blocking pool.
        assert!(spec.allowed_syscalls.contains(&"clone"));
        // Socket-option negotiation (incl. SO_ORIGINAL_DST on the terminator).
        assert!(spec.allowed_syscalls.contains(&"getsockopt"));
        assert!(spec.allowed_syscalls.contains(&"setsockopt"));
        // Cert-store dir read for rustls-native-certs.
        assert!(spec.allowed_syscalls.contains(&"getdents64"));
        // Still no privilege-escalation syscalls.
        assert!(!spec.allowed_syscalls.contains(&"execve"));
        assert!(!spec.allowed_syscalls.contains(&"ptrace"));
        assert!(!spec.allowed_syscalls.contains(&"setuid"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn substitution_endpoint_allowlist_empty_off_linux() {
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::substitution_endpoint(store.clone(), store);
        assert!(spec.allowed_syscalls.is_empty());
    }
}
