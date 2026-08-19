//! Confinement helper for per-VM sibling processes that run alongside
//! Firecracker on Linux.
//!
//! Wraps `seccompiler` (Firecracker-maintained) + `landlock` (official
//! Rust LSM binding) behind a single `confine_self(&ConfinementSpec)`
//! entry point. Non-Linux targets compile as inert stubs (the roles that
//! call `confine_self` are Linux-only at runtime; the stub keeps
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

use std::path::{Path, PathBuf};

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
    /// which directory needs to exist (the audit dir is the
    /// most common cause: `~/.mvm/audit/` must be pre-created with
    /// mode 0700 by the supervisor's bootstrap before the role spawns).
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
    /// Canonical spec for `mvm-network-endpoint` — the per-VM process
    /// that holds the workload's decrypted secrets AND parses untrusted guest
    /// bytes over vsock/UDS. Confining it bounds the blast radius of a parser
    /// compromise: a hijacked endpoint can read only its own tenant's stores
    /// and the TLS/DNS files its forward leg needs, and can invoke only the
    /// network-service syscall set.
    ///
    /// `readable_paths` covers the secret + binding stores (resolved by the
    /// caller exactly as `assemble` does — config override or `~/.mvm`
    /// default) plus the TLS root + DNS resolver files the HTTP
    /// (`rustls-native-certs`) forward leg reads PER REQUEST during `serve`,
    /// so they must stay readable AFTER confinement. The audit recorder reads
    /// the signer key (`keys_dir`) and appends the chain-signed substitution log
    /// (`audit_dir`), so the key is readable and the audit dir is read-write.
    ///
    /// The syscall allowlist comes from the same canonical
    /// `seccomp::CONFINED_ROLE_SYSCALLS` table — extended with the
    /// extra syscalls the tokio multi-thread runtime + rustls TLS forward leg
    /// touch (see the table's comments). On non-Linux targets the list is
    /// empty (the stub `confine_self` errors; the bin hard-exits before
    /// reaching it). `existing_paths` filters to paths that exist on this host
    /// — `/etc/pki`, `/etc/resolv.conf`, etc. are distro-dependent, and a
    /// missing readable path makes the Landlock `open` step fail closed.
    ///
    /// `resolver_uds` threads in the M2 `ResolverBackend::Remote { uds_path,
    /// .. }` socket path: `Some(path)` when the endpoint config selects the
    /// remote fleet-secrets daemon, additionally permitting connect +
    /// read/write on that ONE socket so `RemoteResolver` can reach it after
    /// confinement. `None` (the `Local` backend, and the default) leaves the
    /// confinement identical to before this parameter existed — no socket
    /// egress at all.
    ///
    /// Deliberately **not** run through `existing_paths` like the TLS/DNS
    /// grants above: `Remote` mode is useless without the resolver reachable,
    /// so a socket path that doesn't (yet) exist should make Landlock's own
    /// `PathNotFound` refuse to serve — not silently vanish into an empty
    /// grant that "succeeds" while leaving `Remote` unable to resolve
    /// anything. That would be confinement quietly defeating the feature it
    /// was supposed to permit.
    ///
    /// No seccomp change accompanies this: `socket` / `connect` / `read` /
    /// `write` / `setsockopt` are already unconditionally in this spec's
    /// `allowed_syscalls` (the same `BRIDGE_SYSCALLS` rows the TLS forward
    /// leg's TCP egress already relies on) — seccomp here filters by syscall
    /// number only, with no per-call argument/address-family predicate, so
    /// there is nothing narrower to add for AF_UNIX specifically. The
    /// confinement narrowing for `Remote` is entirely a Landlock (path)
    /// concern.
    pub fn network_endpoint(
        secret_store_dir: PathBuf,
        binding_store_dir: PathBuf,
        audit_dir: PathBuf,
        keys_dir: PathBuf,
        resolver_uds: Option<&Path>,
    ) -> Self {
        #[cfg(target_os = "linux")]
        let allowed_syscalls: Vec<&'static str> = crate::jailer::seccomp::CONFINED_ROLE_SYSCALLS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        #[cfg(not(target_os = "linux"))]
        let allowed_syscalls: Vec<&'static str> = Vec::new();

        // The forward leg uses mvm-http's rustls backend, which loads the
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

        // The chain-signed audit recorder reads the host signer key (keys_dir)
        // and appends to the per-tenant log (audit_dir). Without these grants a
        // confined endpoint with a recorder attached couldn't sign — so the
        // key is readable and the audit dir is read-write.
        let mut readable_paths = vec![secret_store_dir, binding_store_dir, keys_dir];
        readable_paths.extend(tls_dns_paths);

        let mut read_write_paths = existing_paths(vec![audit_dir]);
        if let Some(uds) = resolver_uds {
            // NOT filtered by `existing_paths` — see the doc comment above:
            // this grant must fail closed (via Landlock's `PathNotFound`) if
            // the socket isn't there, rather than silently drop out.
            read_write_paths.push(uds.to_path_buf());
        }

        Self {
            // Filter to extant paths: /etc/pki / /etc/resolv.conf are distro-
            // dependent, and Landlock's `open` on a missing path fails closed
            // (PathNotFound), which would abort an otherwise-healthy endpoint.
            readable_paths: existing_paths(readable_paths),
            read_write_paths,
            allowed_syscalls,
        }
    }

    /// Permit the endpoint to create its authenticated-session marker inside
    /// one already-existing per-VM directory. Keeping this as an explicit
    /// opt-in preserves the narrower default for endpoints that do not expose
    /// launch-readiness evidence.
    #[must_use]
    pub fn with_session_marker_parent(mut self, parent: Option<&Path>) -> Self {
        if let Some(parent) = parent {
            self.read_write_paths.push(parent.to_path_buf());
        }
        self
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
/// `mvm-network-endpoint` honours this contract by returning the error
/// up to `main`, which logs and exits nonzero; the supervisor turns that exit
/// into a VM teardown.
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

    /// Distinct dirs per role, so a read-only grant is distinguishable from a
    /// writable one.
    ///
    /// The sibling tests pass one directory for all four arguments, which
    /// cannot tell those apart: the signer key landing in `read_write_paths`
    /// would let a compromised endpoint replace the key it signs with, and
    /// every existing assertion would still pass.
    #[test]
    fn network_endpoint_spec_keeps_the_signer_key_read_only() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let secrets = tmp.path().join("secrets");
        let bindings = tmp.path().join("bindings");
        let audit = tmp.path().join("audit");
        let keys = tmp.path().join("keys");
        for d in [&secrets, &bindings, &audit, &keys] {
            std::fs::create_dir_all(d).expect("create spec dir");
        }

        // `None` resolver backend: this test is about the key grant, and a
        // resolver socket would add an unrelated write path.
        let spec = ConfinementSpec::network_endpoint(
            secrets.clone(),
            bindings.clone(),
            audit.clone(),
            keys.clone(),
            None,
        );

        assert!(
            spec.readable_paths.iter().any(|p| p == &keys),
            "keys dir must be readable: {:?}",
            spec.readable_paths
        );
        assert!(
            !spec.read_write_paths.iter().any(|p| p == &keys),
            "keys dir must NOT be writable: {:?}",
            spec.read_write_paths
        );
        assert!(
            spec.read_write_paths.iter().any(|p| p == &audit),
            "audit dir is the only write grant: {:?}",
            spec.read_write_paths
        );
    }

    /// On Linux the syscall allowlist is populated from the canonical
    /// `seccomp::CONFINED_ROLE_SYSCALLS` table. We assert the contents here
    /// (positive + negative) rather than in seccomp.rs because the
    /// allowlist is the security-policy surface — a future contributor
    /// editing the table touches this test, which is the audit point.
    #[cfg(target_os = "linux")]
    #[test]
    fn confined_role_allowlist_includes_required_syscalls() {
        let spec = ConfinementSpec::network_endpoint(
            "/tmp/secrets".into(),
            "/tmp/bindings".into(),
            "/tmp/audit".into(),
            "/tmp/keys".into(),
            None,
        );
        assert!(spec.allowed_syscalls.contains(&"splice"));
        assert!(spec.allowed_syscalls.contains(&"fsync"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn confined_role_allowlist_rejects_dangerous_syscalls() {
        let spec = ConfinementSpec::network_endpoint(
            "/tmp/secrets".into(),
            "/tmp/bindings".into(),
            "/tmp/audit".into(),
            "/tmp/keys".into(),
            None,
        );
        assert!(!spec.allowed_syscalls.contains(&"execve"));
        assert!(!spec.allowed_syscalls.contains(&"setuid"));
        assert!(!spec.allowed_syscalls.contains(&"ptrace"));
        assert!(!spec.allowed_syscalls.contains(&"setgid"));
        assert!(!spec.allowed_syscalls.contains(&"capset"));
    }

    #[test]
    fn network_endpoint_spec_grants_read_on_stores() {
        // Use real existing dirs so they survive the `existing_paths` filter;
        // the binary's own crate manifest dir is guaranteed present.
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let bindings = store.clone();
        let spec = ConfinementSpec::network_endpoint(
            store.clone(),
            bindings.clone(),
            store.clone(),
            store.clone(),
            None,
        );
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
    fn network_endpoint_spec_grants_audit_dir_write_and_keys_read() {
        // The audit recorder appends to the audit dir and reads the signer key,
        // so the audit dir is read-write and the keys dir readable.
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::network_endpoint(
            dir.clone(),
            dir.clone(),
            dir.clone(),
            dir.clone(),
            None,
        );
        assert!(
            spec.read_write_paths.iter().any(|p| p == &dir),
            "audit dir must be read-write"
        );
    }

    #[test]
    fn network_endpoint_spec_drops_nonexistent_paths() {
        // A bogus store dir is filtered out — Landlock's `open` on a missing
        // path fails closed, which would abort an otherwise-healthy endpoint.
        let missing = PathBuf::from("/definitely/not/a/real/store/dir/xyzzy");
        let spec = ConfinementSpec::network_endpoint(
            missing.clone(),
            missing.clone(),
            missing.clone(),
            missing.clone(),
            None,
        );
        assert!(
            !spec.readable_paths.iter().any(|p| p == &missing),
            "nonexistent store dir must be filtered out"
        );
    }

    /// M3: `Local` (`None`) must leave the confinement byte-for-byte
    /// identical to before the resolver-UDS grant existed — no socket path
    /// anywhere in either grant set.
    #[test]
    fn network_endpoint_spec_local_backend_grants_no_socket() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::network_endpoint(
            dir.clone(),
            dir.clone(),
            dir.clone(),
            dir.clone(),
            None,
        );
        assert_eq!(
            spec.read_write_paths,
            vec![dir],
            "Local must add nothing beyond the audit dir"
        );
    }

    #[test]
    fn network_endpoint_spec_grants_only_the_configured_session_marker_parent() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let marker_parent = dir.join("tests");
        let spec =
            ConfinementSpec::network_endpoint(dir.clone(), dir.clone(), dir.clone(), dir, None)
                .with_session_marker_parent(Some(&marker_parent));

        assert!(spec.read_write_paths.contains(&marker_parent));
        assert_eq!(spec.read_write_paths.len(), 2);
    }

    /// M3: `Remote { uds_path, .. }` (`Some(uds)`) additionally permits
    /// connect + read/write on that ONE socket — the exact extra grant this
    /// task adds, and nothing more.
    #[test]
    fn network_endpoint_spec_remote_backend_grants_resolver_uds() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let uds = dir.join("Cargo.toml");
        let spec = ConfinementSpec::network_endpoint(
            dir.clone(),
            dir.clone(),
            dir.clone(),
            dir.clone(),
            Some(uds.as_path()),
        );
        assert!(
            spec.read_write_paths.contains(&uds),
            "resolver UDS path must be read-write granted under Remote"
        );
        assert_eq!(
            spec.read_write_paths.len(),
            2,
            "exactly audit dir + resolver uds, nothing broader"
        );
    }

    /// M3: unlike the best-effort TLS/DNS grants, the resolver UDS grant must
    /// NOT be silently dropped when the path doesn't exist (yet) — `Remote`
    /// mode is useless without it, so a missing socket should surface as
    /// Landlock's own `PathNotFound` (fail-closed) rather than a quietly
    /// empty grant that lets confinement "succeed" while leaving `Remote`
    /// unable to resolve anything.
    #[test]
    fn network_endpoint_spec_keeps_resolver_uds_even_if_missing() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let missing = PathBuf::from("/definitely/not/a/real/resolver/socket/xyzzy.sock");
        let spec = ConfinementSpec::network_endpoint(
            dir.clone(),
            dir.clone(),
            dir.clone(),
            dir.clone(),
            Some(missing.as_path()),
        );
        assert!(
            spec.read_write_paths.contains(&missing),
            "resolver uds path must survive even when absent from disk"
        );
    }

    /// On Linux the endpoint allowlist is the shared table plus the tokio +
    /// TLS-forward additions. Assert the additions are present (the egress
    /// path needs them) and the dangerous names still absent.
    #[cfg(target_os = "linux")]
    #[test]
    fn network_endpoint_allowlist_covers_tls_and_runtime() {
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::network_endpoint(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            None,
        );
        // Thread creation for tokio workers / blocking pool.
        assert!(spec.allowed_syscalls.contains(&"clone"));
        // Socket-option negotiation (incl. SO_ORIGINAL_DST on the terminator).
        assert!(spec.allowed_syscalls.contains(&"getsockopt"));
        assert!(spec.allowed_syscalls.contains(&"setsockopt"));
        // Cert-store dir read for rustls-native-certs.
        assert!(spec.allowed_syscalls.contains(&"getdents64"));
        // Appending to the per-tenant audit log takes a file lock. Without
        // this the endpoint is killed by SIGSYS on the first flow it allows —
        // after the upstream connect succeeded, so the failure surfaces as a
        // guest whose proxy handshake never completes.
        assert!(spec.allowed_syscalls.contains(&"flock"));
        // Still no privilege-escalation syscalls.
        assert!(!spec.allowed_syscalls.contains(&"execve"));
        assert!(!spec.allowed_syscalls.contains(&"ptrace"));
        assert!(!spec.allowed_syscalls.contains(&"setuid"));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn network_endpoint_allowlist_empty_off_linux() {
        let store = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let spec = ConfinementSpec::network_endpoint(
            store.clone(),
            store.clone(),
            store.clone(),
            store.clone(),
            None,
        );
        assert!(spec.allowed_syscalls.is_empty());
    }
}
