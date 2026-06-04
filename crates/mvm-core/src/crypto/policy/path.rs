//! Path policy — Control 1 of the filesystem-volumes plan.
//!
//! Single chokepoint for *every* host-supplied path that reaches the
//! guest filesystem. New FS verbs (`FsRead`, `FsWrite`, …) and the
//! eventual virtio-fs share-mount verb route through `PathPolicy`
//! before touching the disk.
//!
//! # What the policy enforces
//!
//! 1. **Reject relative / empty / non-UTF-8 paths** — a host cannot
//!    smuggle ambiguity past the agent.
//! 2. **Canonicalize** (`realpath`) — symlinks resolved before
//!    deny-list checks so a guest-side symlink can't redirect a host
//!    request into a denied prefix.
//! 3. **Default deny-list** — `/etc/mvm/*` (agent integration
//!    configs), `/run/mvm-secrets/*` (per-service secrets), and a
//!    small handful of host-introspection paths (`/proc/1`,
//!    `/proc/self`, `/sys/kernel/security`). These contain
//!    high-sensitivity bytes a compromised host should not be able
//!    to read out via the FS RPC even though uid 901 + W2's
//!    bind-mounts already restrict write access.
//! 4. **Optional allow-roots** — when set, a canonical path *must*
//!    live under one of them. Empty means "anything not denied is
//!    fine"; the eventual mvm-supervisor in production layers in a
//!    template-declared allow-root list.
//!
//! # Why injectable canonicalization
//!
//! `std::fs::canonicalize` walks the *real* filesystem. That makes
//! pure-logic tests (deny-list edge cases, traversal handling,
//! charset rejection) flaky and platform-dependent. The
//! `PathCanonicalizer` trait lets tests substitute a stub that
//! returns whatever path they want; the production agent uses
//! `OsCanonicalizer` which delegates to `std::fs::canonicalize`.
//! Both share one validation pipeline so the in-VM behaviour matches
//! the unit-test behaviour by construction.
//!
//! # What this module deliberately does NOT do
//!
//! - It does not attempt to bound recursive walks, payload sizes,
//!   etc. Those are per-verb caps owned by the agent handler — the
//!   policy returns a canonical path and a yes/no, nothing more.
//! - It does not enforce per-uid or per-tenant scoping. The guest
//!   agent already runs as uid 901 with W2 bounding sets; the
//!   supervisor handles tenant isolation at a higher layer.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// What the caller intends to do with the path. The policy can
/// branch on this in future revisions (e.g. read-only allow-roots
/// vs read-write); v1 treats every op the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOp {
    Read,
    Write,
    List,
    Stat,
    Mkdir,
    Remove,
    /// Source side of a `FsMove`.
    MoveSrc,
    /// Destination side of a `FsMove`.
    MoveDst,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("path is empty")]
    Empty,
    #[error("path {raw:?} is not absolute (starts with `/`)")]
    NotAbsolute { raw: String },
    #[error("path {raw:?} contains a NUL byte")]
    EmbeddedNul { raw: String },
    #[error("path {raw:?} canonicalization failed: {reason}")]
    CanonicalizationFailed { raw: String, reason: String },
    #[error("path {canonical:?} is denied: matches deny-prefix {matched:?}")]
    Denied { canonical: String, matched: String },
    #[error("path {canonical:?} is outside the configured allow-roots")]
    OutsideAllowRoot { canonical: String },
}

/// Source of canonical paths. Production uses `OsCanonicalizer`;
/// tests use a stub that returns canned answers.
pub trait PathCanonicalizer {
    fn canonicalize(&self, raw: &Path) -> Result<PathBuf, std::io::Error>;
}

/// Production canonicalizer — delegates to `std::fs::canonicalize`.
pub struct OsCanonicalizer;

impl PathCanonicalizer for OsCanonicalizer {
    fn canonicalize(&self, raw: &Path) -> Result<PathBuf, std::io::Error> {
        std::fs::canonicalize(raw)
    }
}

/// Validated canonical path returned by `PathPolicy::validate`.
/// Wraps a `PathBuf` so callers can't accidentally reach into an
/// un-validated `&str` and treat it as if it had passed the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath(PathBuf);

impl CanonicalPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

/// Path policy with deny-prefixes and optional allow-roots.
///
/// `default()` ships the conservative deny-list called for in the
/// filesystem-volumes plan §"Phase A1 — FS RPC". Callers can layer
/// additional deny-prefixes via `with_extra_deny`.
pub struct PathPolicy {
    deny_prefixes: Vec<PathBuf>,
    allow_roots: Vec<PathBuf>,
}

impl Default for PathPolicy {
    fn default() -> Self {
        Self {
            deny_prefixes: default_deny_prefixes(),
            allow_roots: Vec::new(),
        }
    }
}

impl PathPolicy {
    /// Build a policy with the default deny-prefixes plus extras.
    pub fn with_extra_deny<I, P>(extras: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let mut deny = default_deny_prefixes();
        deny.extend(extras.into_iter().map(Into::into));
        Self {
            deny_prefixes: deny,
            allow_roots: Vec::new(),
        }
    }

    /// Constrain to a non-empty allow-root list. A canonical path
    /// must live under one of these roots. Empty means "no
    /// restriction" — only the deny-list applies.
    pub fn with_allow_roots<I, P>(mut self, roots: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        self.allow_roots = roots.into_iter().map(Into::into).collect();
        self
    }

    /// Run the full validation pipeline against an externally-
    /// supplied path string.
    pub fn validate<C: PathCanonicalizer>(
        &self,
        canonicalizer: &C,
        raw: &str,
        _op: PathOp,
    ) -> Result<CanonicalPath, PolicyError> {
        if raw.is_empty() {
            return Err(PolicyError::Empty);
        }
        if raw.as_bytes().contains(&0) {
            return Err(PolicyError::EmbeddedNul {
                raw: raw.to_string(),
            });
        }
        let raw_path = Path::new(raw);
        if !raw_path.is_absolute() {
            return Err(PolicyError::NotAbsolute {
                raw: raw.to_string(),
            });
        }

        let canonical = canonicalizer.canonicalize(raw_path).map_err(|e| {
            PolicyError::CanonicalizationFailed {
                raw: raw.to_string(),
                reason: e.to_string(),
            }
        })?;

        if let Some(matched) = self.deny_match(&canonical) {
            return Err(PolicyError::Denied {
                canonical: canonical.display().to_string(),
                matched: matched.display().to_string(),
            });
        }

        if !self.allow_roots.is_empty() && !self.matches_any_allow_root(&canonical) {
            return Err(PolicyError::OutsideAllowRoot {
                canonical: canonical.display().to_string(),
            });
        }

        Ok(CanonicalPath(canonical))
    }

    fn deny_match(&self, canonical: &Path) -> Option<&Path> {
        self.deny_prefixes
            .iter()
            .find(|prefix| starts_with_segment_aware(canonical, prefix))
            .map(PathBuf::as_path)
    }

    fn matches_any_allow_root(&self, canonical: &Path) -> bool {
        self.allow_roots
            .iter()
            .any(|root| starts_with_segment_aware(canonical, root))
    }
}

/// Default deny-prefixes shipped with `PathPolicy::default`. Listed
/// here so the values are visible to anyone reviewing the policy
/// surface and so reviewers see all five entries in one place.
fn default_deny_prefixes() -> Vec<PathBuf> {
    vec![
        // Agent integration configs + per-service secrets.
        // W2.1 bind-mounts make these read-only; this defense-in-
        // depth blocks the FS RPC from leaking their *contents*.
        PathBuf::from("/etc/mvm"),
        PathBuf::from("/run/mvm-secrets"),
        // Host introspection: PID 1 (init namespace metadata),
        // /proc/self (caller's mount/cred view), /sys/kernel/security
        // (LSM hooks, IMA logs). The rest of /proc and /sys is
        // permitted; callers genuinely use those for diagnostics.
        PathBuf::from("/proc/1"),
        PathBuf::from("/proc/self"),
        PathBuf::from("/sys/kernel/security"),
    ]
}

/// Path-prefix check that respects component boundaries — `/foo/bar`
/// is "under" `/foo` but `/foobar` is *not*. `Path::starts_with`
/// already provides this semantics; documented here so reviewers
/// don't second-guess us swapping in a string-prefix check by
/// accident.
fn starts_with_segment_aware(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test canonicalizer that returns a fixed mapping. Lets us
    /// exercise the policy without going through the real
    /// filesystem.
    struct StubCanonicalizer {
        map: std::collections::HashMap<PathBuf, PathBuf>,
        fail: Option<std::io::ErrorKind>,
    }

    impl StubCanonicalizer {
        fn new() -> Self {
            Self {
                map: std::collections::HashMap::new(),
                fail: None,
            }
        }
        fn map(mut self, raw: impl Into<PathBuf>, canonical: impl Into<PathBuf>) -> Self {
            self.map.insert(raw.into(), canonical.into());
            self
        }
        fn fail_with(mut self, kind: std::io::ErrorKind) -> Self {
            self.fail = Some(kind);
            self
        }
    }

    impl PathCanonicalizer for StubCanonicalizer {
        fn canonicalize(&self, raw: &Path) -> Result<PathBuf, std::io::Error> {
            if let Some(kind) = self.fail {
                return Err(std::io::Error::new(kind, "stub canonicalize failure"));
            }
            self.map.get(raw).cloned().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, raw.display().to_string())
            })
        }
    }

    #[test]
    fn rejects_empty_path() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new();
        assert!(matches!(
            policy.validate(&canon, "", PathOp::Read),
            Err(PolicyError::Empty)
        ));
    }

    #[test]
    fn rejects_relative_path() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new();
        assert!(matches!(
            policy.validate(&canon, "tmp/x", PathOp::Read),
            Err(PolicyError::NotAbsolute { .. })
        ));
        assert!(matches!(
            policy.validate(&canon, "../etc/mvm/keys", PathOp::Read),
            Err(PolicyError::NotAbsolute { .. })
        ));
    }

    #[test]
    fn rejects_embedded_nul() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new();
        let raw = "/tmp/x\0y";
        assert!(matches!(
            policy.validate(&canon, raw, PathOp::Read),
            Err(PolicyError::EmbeddedNul { .. })
        ));
    }

    #[test]
    fn propagates_canonicalize_failure() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new().fail_with(std::io::ErrorKind::NotFound);
        let result = policy.validate(&canon, "/nonexistent", PathOp::Read);
        assert!(matches!(
            result,
            Err(PolicyError::CanonicalizationFailed { .. })
        ));
    }

    #[test]
    fn denies_paths_under_etc_mvm_after_canonicalization() {
        let policy = PathPolicy::default();
        // Host asks for `/data/innocent` but the path canonicalizes
        // (via a guest-side symlink) to `/etc/mvm/integrations.toml`.
        // The deny-list must match the *canonical* form, not the
        // raw input.
        let canon = StubCanonicalizer::new().map("/data/innocent", "/etc/mvm/integrations.toml");
        let err = policy
            .validate(&canon, "/data/innocent", PathOp::Read)
            .unwrap_err();
        match err {
            PolicyError::Denied { canonical, matched } => {
                assert_eq!(canonical, "/etc/mvm/integrations.toml");
                assert_eq!(matched, "/etc/mvm");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    #[test]
    fn denies_run_mvm_secrets() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new().map("/run/mvm-secrets/foo", "/run/mvm-secrets/foo");
        assert!(matches!(
            policy.validate(&canon, "/run/mvm-secrets/foo", PathOp::Read),
            Err(PolicyError::Denied { .. })
        ));
    }

    #[test]
    fn denies_proc_self_and_proc_1() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new()
            .map("/proc/self/maps", "/proc/self/maps")
            .map("/proc/1/cmdline", "/proc/1/cmdline");
        assert!(matches!(
            policy.validate(&canon, "/proc/self/maps", PathOp::Read),
            Err(PolicyError::Denied { .. })
        ));
        assert!(matches!(
            policy.validate(&canon, "/proc/1/cmdline", PathOp::Read),
            Err(PolicyError::Denied { .. })
        ));
    }

    #[test]
    fn permits_other_proc_paths() {
        // Default deny-list only blocks /proc/1 and /proc/self —
        // /proc/<pid> for other PIDs and /proc/cpuinfo etc. are
        // useful diagnostic surfaces and should pass.
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new()
            .map("/proc/cpuinfo", "/proc/cpuinfo")
            .map("/proc/123/status", "/proc/123/status");
        assert!(
            policy
                .validate(&canon, "/proc/cpuinfo", PathOp::Read)
                .is_ok()
        );
        assert!(
            policy
                .validate(&canon, "/proc/123/status", PathOp::Read)
                .is_ok()
        );
    }

    #[test]
    fn deny_match_is_segment_aware() {
        // `/etc/mvmrc` is a sibling of `/etc/mvm/`, not a child of
        // the deny-prefix. Must NOT be falsely denied.
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new().map("/etc/mvmrc", "/etc/mvmrc");
        assert!(policy.validate(&canon, "/etc/mvmrc", PathOp::Read).is_ok());
    }

    #[test]
    fn extra_deny_prefixes_layer_on_top() {
        let policy = PathPolicy::with_extra_deny(["/var/lib/secret"]);
        let canon = StubCanonicalizer::new()
            .map("/var/lib/secret/key", "/var/lib/secret/key")
            // Defaults still apply alongside.
            .map("/etc/mvm/x", "/etc/mvm/x");
        assert!(matches!(
            policy.validate(&canon, "/var/lib/secret/key", PathOp::Read),
            Err(PolicyError::Denied { .. })
        ));
        assert!(matches!(
            policy.validate(&canon, "/etc/mvm/x", PathOp::Read),
            Err(PolicyError::Denied { .. })
        ));
    }

    #[test]
    fn allow_roots_when_set_restrict_to_subtree() {
        let policy = PathPolicy::default().with_allow_roots(["/data", "/work"]);
        let canon = StubCanonicalizer::new()
            .map("/data/file", "/data/file")
            .map("/work/x", "/work/x")
            .map("/tmp/x", "/tmp/x");
        assert!(policy.validate(&canon, "/data/file", PathOp::Read).is_ok());
        assert!(policy.validate(&canon, "/work/x", PathOp::Read).is_ok());
        assert!(matches!(
            policy.validate(&canon, "/tmp/x", PathOp::Read),
            Err(PolicyError::OutsideAllowRoot { .. })
        ));
    }

    #[test]
    fn allow_roots_dont_override_deny_list() {
        // /etc/mvm is denied even when /etc is an allow-root: the
        // deny check runs first.
        let policy = PathPolicy::default().with_allow_roots(["/etc"]);
        let canon = StubCanonicalizer::new().map("/etc/mvm/x", "/etc/mvm/x");
        assert!(matches!(
            policy.validate(&canon, "/etc/mvm/x", PathOp::Read),
            Err(PolicyError::Denied { .. })
        ));
    }

    #[test]
    fn permits_data_paths_under_default_policy() {
        let policy = PathPolicy::default();
        let canon = StubCanonicalizer::new().map("/data/x.csv", "/data/x.csv");
        let validated = policy
            .validate(&canon, "/data/x.csv", PathOp::Read)
            .unwrap();
        assert_eq!(validated.as_path(), Path::new("/data/x.csv"));
    }

    #[test]
    fn os_canonicalizer_resolves_real_path() {
        // Lightweight integration check that OsCanonicalizer is
        // wired correctly — uses a path that's guaranteed to exist
        // on every CI host.
        let canon = OsCanonicalizer;
        let result = canon.canonicalize(Path::new("/")).unwrap();
        assert_eq!(result, PathBuf::from("/"));
    }
}
