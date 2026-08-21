//! Mount-path policy.
//!
//! Restricts where a host-supplied virtio-fs share can land inside
//! the guest. Shares cross the verity boundary (they're not part
//! of the rootfs); without this policy a share could be mounted
//! over a path the mvm runtime owns and shadow it post-boot.
//!
//! # Policy shape
//!
//! - **Allow-roots** — a share may *only* land at or under `/data`,
//!   `/work`, or `/mnt`. An allow-list, not a deny-list: the rootfs
//!   and every runtime-managed mount is off-limits *by construction*
//!   rather than by enumeration, so a path the policy has never heard
//!   of is refused rather than admitted.
//! - **Protected paths** — the paths the mvm runtime owns. Most sit
//!   outside the allow-roots and are already unreachable; the ones
//!   that matter are those *inside* an allow-root, notably the config
//!   and secret drives under `/mnt`, which the allow-roots alone
//!   would admit.
//!
//! # Containment is bidirectional
//!
//! A candidate mountpoint is rejected when it is a **descendant** of
//! a protected path (mounting *inside* the runtime's tree) *or* an
//! **ancestor** of one (mounting *over* a parent, which shadows
//! everything beneath it).
//!
//! The ancestor direction is not decoration. `/mnt` is an allow-root
//! and `/mnt/config` is protected, so a descendant-only check admits
//! a share at `/mnt` that hides the config and secret drives — or,
//! if the share mounts first, lands the secret drive *inside* a
//! host-shared directory. Any reserved path beneath an allow-root has
//! this shape; checking both directions closes the class rather than
//! the instance.
//!
//! Pure logic — no fs I/O. Callers feed the policy a string from
//! the wire and get a typed verdict. The agent runs the actual
//! `mount(2)` after the policy has approved the path.

use std::path::Path;

use thiserror::Error;

/// Subtrees a share may mount under.
pub const MOUNT_ALLOW_ROOTS: &[&str] = &["/data", "/work", "/mnt"];

/// Paths the mvm runtime owns, which a share may neither sit inside
/// nor shadow.
///
/// The entries beneath an allow-root are the load-bearing ones —
/// `/mnt/config` and `/mnt/secrets` are reachable under the
/// allow-roots and must be carved back out. The rest are outside the
/// allow-roots already; they are listed so a refusal names the runtime
/// path it is protecting instead of reporting a bare allow-root miss,
/// and so widening an allow-root later cannot silently expose them.
pub const PROTECTED_RUNTIME_PATHS: &[&str] = &[
    // Reachable under an allow-root: the config and secret drives.
    "/mnt/config",
    "/mnt/secrets",
    // Outside the allow-roots, named for error quality and defence in
    // depth.
    "/proc",
    "/sys",
    "/dev",
    "/init",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/boot",
    "/mvm",
    "/run/mvm",
    "/run/mvm-secrets",
    "/run/mvm-etc",
    "/nix",
    "/run/booted-system",
    "/run/current-system",
];

/// Reasons the mount-path policy rejects a candidate path.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MountPathError {
    #[error("mount path is empty")]
    Empty,
    #[error("mount path {raw:?} must be absolute")]
    NotAbsolute { raw: String },
    #[error("mount path {raw:?} contains a NUL byte")]
    EmbeddedNul { raw: String },
    #[error("mount path {raw:?} contains `..` (path traversal not allowed)")]
    PathTraversal { raw: String },
    #[error("mount path {raw:?} is inside the mvm runtime path {matched:?}")]
    Denied { raw: String, matched: String },
    #[error(
        "mount path {raw:?} would shadow the mvm runtime path {protected:?}; \
         mount on a subdirectory instead"
    )]
    Shadows { raw: String, protected: String },
    #[error("mount path {raw:?} is outside the allow-roots {allow:?}")]
    OutsideAllowRoots { raw: String, allow: Vec<String> },
}

/// Mount-path policy. `default()` is the shipped posture; the
/// constructors exist for tests that need a different shape.
#[derive(Debug, Clone)]
pub struct MountPathPolicy {
    allow_roots: Vec<String>,
    protected: Vec<String>,
}

impl Default for MountPathPolicy {
    fn default() -> Self {
        Self {
            allow_roots: owned(MOUNT_ALLOW_ROOTS),
            protected: owned(PROTECTED_RUNTIME_PATHS),
        }
    }
}

fn owned(paths: &[&str]) -> Vec<String> {
    paths.iter().map(|s| (*s).to_string()).collect()
}

impl MountPathPolicy {
    /// Build a policy with caller-supplied allow-roots, keeping the
    /// default protected-path set.
    pub fn with_allow_roots<I, S>(roots: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow_roots: roots.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }

    /// Add an extra protected path on top of the defaults.
    pub fn with_extra_deny<I, S>(mut self, extras: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.protected.extend(extras.into_iter().map(Into::into));
        self
    }

    /// Validate `raw` against the policy. Returns the canonical
    /// path string on success — same shape as the input but with
    /// trailing slashes normalised away.
    pub fn validate(&self, raw: &str) -> Result<String, MountPathError> {
        if raw.is_empty() {
            return Err(MountPathError::Empty);
        }
        if raw.as_bytes().contains(&0) {
            return Err(MountPathError::EmbeddedNul {
                raw: raw.to_string(),
            });
        }
        let path = Path::new(raw);
        if !path.is_absolute() {
            return Err(MountPathError::NotAbsolute {
                raw: raw.to_string(),
            });
        }
        // `..` traversal is rejected up front. We don't `realpath`
        // — the leaf may not exist yet (the agent creates it before
        // mounting) — but we do require that every component is a
        // plain name without `..`.
        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(MountPathError::PathTraversal {
                    raw: raw.to_string(),
                });
            }
        }

        let normalized = normalize_trailing_slashes(raw);
        let normalized_path = Path::new(&normalized);

        // Exact-root reject, ahead of the containment checks so that
        // mounting over `/` reports itself rather than naming whichever
        // protected path happens to sort first.
        if normalized_path == Path::new("/") {
            return Err(MountPathError::Denied {
                raw: raw.to_string(),
                matched: "/".to_string(),
            });
        }

        // Containment first, in both directions. A path can sit under
        // an allow-root and still collide with a protected path — `/mnt`
        // shadows the config and secret drives — so the protected set
        // wins over the allow-roots.
        if let Some(matched) = self.containing_protected(normalized_path) {
            return Err(MountPathError::Denied {
                raw: raw.to_string(),
                matched: matched.to_string(),
            });
        }
        if let Some(protected) = self.shadowed_protected(normalized_path) {
            return Err(MountPathError::Shadows {
                raw: raw.to_string(),
                protected: protected.to_string(),
            });
        }

        if !self
            .allow_roots
            .iter()
            .any(|root| starts_with_segment_aware(normalized_path, Path::new(root.as_str())))
        {
            return Err(MountPathError::OutsideAllowRoots {
                raw: raw.to_string(),
                allow: self.allow_roots.clone(),
            });
        }
        Ok(normalized)
    }

    /// The protected path that `path` sits at or under, if any —
    /// i.e. mounting *inside* the mvm runtime's tree.
    fn containing_protected(&self, path: &Path) -> Option<&str> {
        self.protected
            .iter()
            .find(|prefix| starts_with_segment_aware(path, Path::new(prefix.as_str())))
            .map(String::as_str)
    }

    /// The protected path that sits at or under `path`, if any —
    /// i.e. mounting *over* a parent and shadowing what's beneath.
    fn shadowed_protected(&self, path: &Path) -> Option<&str> {
        self.protected
            .iter()
            .find(|protected| starts_with_segment_aware(Path::new(protected.as_str()), path))
            .map(String::as_str)
    }
}

/// Free-function shortcut for callers that don't need the
/// configurable policy. Applies the [`MountTier::Strict`] posture.
pub fn validate_mount_path(raw: &str) -> Result<String, MountPathError> {
    MountPathPolicy::default().validate(raw)
}

fn normalize_trailing_slashes(raw: &str) -> String {
    let mut s = raw.trim_end_matches('/').to_string();
    if s.is_empty() {
        s.push('/');
    }
    s
}

/// `Path::starts_with` is component-aware: `/foo/bar` starts with
/// `/foo` but `/foobar` does not. That segment awareness is what keeps
/// `/nixos` out of the `/nix` protected subtree and `/etcetera` out of
/// `/etc`.
fn starts_with_segment_aware(path: &Path, prefix: &Path) -> bool {
    path.starts_with(prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_mount_path(""), Err(MountPathError::Empty));
    }

    #[test]
    fn rejects_relative() {
        assert!(matches!(
            validate_mount_path("data/x"),
            Err(MountPathError::NotAbsolute { .. })
        ));
        assert!(matches!(
            validate_mount_path("./mnt"),
            Err(MountPathError::NotAbsolute { .. })
        ));
    }

    #[test]
    fn rejects_embedded_nul() {
        assert!(matches!(
            validate_mount_path("/data/x\0y"),
            Err(MountPathError::EmbeddedNul { .. })
        ));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(matches!(
            validate_mount_path("/data/../etc"),
            Err(MountPathError::PathTraversal { .. })
        ));
    }

    #[test]
    fn accepts_allow_roots() {
        for path in ["/data", "/data/x/y", "/work", "/work/sandbox", "/mnt/share"] {
            validate_mount_path(path)
                .unwrap_or_else(|e| panic!("expected accept for {path:?}, got {e}"));
        }
    }

    #[test]
    fn rejects_outside_allow_roots() {
        for path in ["/home/user", "/tmp", "/var/lib/app", "/opt", "/srv"] {
            assert!(
                matches!(
                    validate_mount_path(path),
                    Err(MountPathError::OutsideAllowRoots { .. })
                ),
                "should reject {path:?}",
            );
        }
    }

    #[test]
    fn denies_the_runtime_paths() {
        for path in [
            "/etc/mvm/keys",
            "/usr/bin/sh",
            "/usr/local/bin/mvm-guest-agent",
            "/lib/x86_64-linux-gnu/libc.so",
            "/lib64/ld-linux.so",
            "/bin/sh",
            "/sbin/init",
            "/boot/vmlinuz",
            "/init",
            "/proc/self",
            "/sys/kernel",
            "/dev/null",
            "/run/mvm-secrets/foo",
            "/run/mvm-etc/passwd",
            "/mvm/runtime",
            "/nix",
            "/nix/store/abc123-pkg",
            "/run/booted-system/sw/bin/sh",
            "/run/current-system/etc/profile",
        ] {
            let err = validate_mount_path(path).unwrap_err();
            assert!(
                matches!(err, MountPathError::Denied { .. }),
                "expected Denied for {path:?}, got {err:?}",
            );
        }
    }

    /// The ancestor half of the containment rule, which is the whole
    /// reason the check runs in both directions.
    ///
    /// `/mnt` is an allow-root, so an allow-roots-plus-descendants check
    /// admits it — and a share there hides `/mnt/config` and
    /// `/mnt/secrets`, or lands the secret drive inside a host-shared
    /// directory depending on mount order. Deleting `shadowed_protected`
    /// must fail this test.
    #[test]
    fn bare_mnt_is_refused_because_it_shadows_the_config_drive() {
        let err = validate_mount_path("/mnt").unwrap_err();
        match err {
            MountPathError::Shadows { protected, .. } => {
                assert!(
                    protected == "/mnt/config" || protected == "/mnt/secrets",
                    "expected a reserved drive, got {protected:?}"
                );
            }
            other => panic!("expected Shadows for /mnt, got {other:?}"),
        }
        // The reserved drives themselves, and paths beneath them.
        for reserved in ["/mnt/config", "/mnt/secrets"] {
            assert!(
                matches!(
                    validate_mount_path(reserved),
                    Err(MountPathError::Denied { .. })
                ),
                "{reserved} is reserved by the runtime"
            );
            assert!(
                validate_mount_path(&format!("{reserved}/nested")).is_err(),
                "{reserved}/nested is under a reserved drive"
            );
        }
        // Siblings under the same allow-root stay fine, including one
        // that merely shares a string prefix with a reserved drive.
        for ok in ["/mnt/share", "/mnt/configx", "/mnt/secretsy"] {
            validate_mount_path(ok).unwrap_or_else(|e| panic!("{ok} should be allowed: {e}"));
        }
    }

    /// The ancestor rule must honour segment boundaries in the same way
    /// the descendant rule does, or it would refuse unrelated siblings.
    #[test]
    fn the_ancestor_rule_is_segment_aware() {
        let policy = MountPathPolicy::with_allow_roots(["/"]).with_extra_deny(["/a/bc/keep"]);
        // `/a/bc` is a genuine ancestor of the protected path.
        assert!(matches!(
            policy.validate("/a/bc"),
            Err(MountPathError::Shadows { .. })
        ));
        // `/a/b` merely shares a string prefix with `/a/bc` and is not.
        policy
            .validate("/a/b")
            .expect("/a/b is not an ancestor of /a/bc/keep");
    }

    #[test]
    fn nix_paths_denied_segment_aware() {
        // `/nixos` is not a child of `/nix` — containment must honour
        // path-segment boundaries.
        let err = validate_mount_path("/nixos").unwrap_err();
        assert!(
            matches!(err, MountPathError::OutsideAllowRoots { .. }),
            "expected OutsideAllowRoots for /nixos (not a /nix child), got {err:?}",
        );
    }

    #[test]
    fn deny_match_is_segment_aware_for_etc() {
        // `/etcetera` shares a string prefix with `/etc` but is not a
        // child of it, so it fails on the allow-roots, not containment.
        let err = validate_mount_path("/etcetera").unwrap_err();
        assert!(
            matches!(err, MountPathError::OutsideAllowRoots { .. }),
            "expected OutsideAllowRoots for /etcetera, got {err:?}",
        );
    }

    #[test]
    fn root_path_alone_is_denied() {
        let err = validate_mount_path("/").unwrap_err();
        assert!(matches!(err, MountPathError::Denied { .. }));
    }

    #[test]
    fn trailing_slash_is_normalised() {
        let normalized = validate_mount_path("/data/").unwrap();
        assert_eq!(normalized, "/data");
        // And normalising must not change a verdict.
        assert!(validate_mount_path("/mnt/").is_err());
    }

    #[test]
    fn extra_deny_layer_takes_priority_over_allow_root() {
        let policy = MountPathPolicy::default().with_extra_deny(["/data/secrets"]);
        // `/data/secrets/key` is under the `/data` allow-root, but
        // matches the extra protected path — must reject.
        assert!(matches!(
            policy.validate("/data/secrets/key"),
            Err(MountPathError::Denied { .. })
        ));
        // Sibling under `/data` but outside the protected path is fine.
        policy.validate("/data/public/x").unwrap();
    }

    #[test]
    fn custom_allow_roots_replace_defaults() {
        let policy = MountPathPolicy::with_allow_roots(["/sandbox"]);
        policy.validate("/sandbox/x").unwrap();
        // `/data` is not in this policy's allow-roots.
        assert!(matches!(
            policy.validate("/data/x"),
            Err(MountPathError::OutsideAllowRoots { .. })
        ));
        // The protected set still applies.
        assert!(matches!(
            policy.validate("/etc/mvm/x"),
            Err(MountPathError::Denied { .. })
        ));
    }
}
