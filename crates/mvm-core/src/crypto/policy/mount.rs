//! Mount-path policy — D of the filesystem-volumes plan.
//!
//! Restricts where a host-supplied virtio-fs share can land inside
//! the guest. Shares cross the verity boundary (they're not part
//! of the rootfs); without this policy a host could mount a share
//! over `/usr` or `/etc/mvm/` and shadow verity-protected files
//! post-boot. The whitelist + deny-list pair pins shares to a
//! small set of subtrees that the rootfs explicitly leaves
//! writable.
//!
//! # Policy shape
//!
//! - **Allow-roots** — shares may only mount under one of these
//!   prefixes. The default ships `/mnt`, `/data`, and `/work`,
//!   matching the conventions in the project's example flakes.
//! - **Deny-prefixes** — even when an allow-root is widened by
//!   image-specific config, these prefixes can never be a mount
//!   target. The default covers the verity-protected tree
//!   (`/etc`, `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/boot`,
//!   `/init`) plus `/proc`, `/sys`, `/dev`, and `/run/mvm-secrets`.
//!
//! Pure logic — no fs I/O. Callers feed the policy a string from
//! the wire and get a typed verdict. The agent runs the actual
//! `mount(2)` after the policy has approved the path.

use std::path::Path;

use thiserror::Error;

/// Default subtrees a share can be mounted under.
pub const DEFAULT_MOUNT_ALLOW_ROOTS: &[&str] = &["/mnt", "/data", "/work"];

/// Default prefixes that always reject a share mount, regardless
/// of allow-root override. The bare-root path `/` is rejected by
/// a separate check in `validate` — `Path::starts_with("/")` is
/// trivially true for every absolute path, so listing `/` here
/// would block everything.
///
/// **Nix-immutable paths** (`/nix`, `/run/booted-system`,
/// `/run/current-system`) are denied per plan 45 §"Nix semantics
/// alignment" — the Nix store is content-addressed and
/// reproducibility-critical; volumes must never overlay it.
pub const DEFAULT_MOUNT_DENY_PREFIXES: &[&str] = &[
    "/etc",
    "/usr",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/boot",
    "/init",
    "/proc",
    "/sys",
    "/dev",
    "/run/mvm-secrets",
    "/run/mvm-etc",
    // Nix-immutable paths (plan 45 §"Nix semantics alignment").
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
    #[error("mount path {raw:?} matches deny-prefix {matched:?}")]
    Denied { raw: String, matched: String },
    #[error("mount path {raw:?} is outside the allow-roots {allow:?}")]
    OutsideAllowRoots { raw: String, allow: Vec<String> },
}

/// Mount-path policy. Production wires
/// `MountPathPolicy::default()` at construction time; tests can
/// build a custom policy via `with_allow_roots` /
/// `with_deny_prefixes`.
#[derive(Debug, Clone)]
pub struct MountPathPolicy {
    allow_roots: Vec<String>,
    deny_prefixes: Vec<String>,
}

impl Default for MountPathPolicy {
    fn default() -> Self {
        Self {
            allow_roots: DEFAULT_MOUNT_ALLOW_ROOTS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            deny_prefixes: DEFAULT_MOUNT_DENY_PREFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl MountPathPolicy {
    /// Build a policy with caller-supplied allow-roots, default
    /// deny-prefixes still active.
    pub fn with_allow_roots<I, S>(roots: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow_roots: roots.into_iter().map(Into::into).collect(),
            deny_prefixes: DEFAULT_MOUNT_DENY_PREFIXES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }

    /// Add an extra deny-prefix on top of the defaults.
    pub fn with_extra_deny<I, S>(mut self, extras: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deny_prefixes
            .extend(extras.into_iter().map(Into::into));
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

        // Exact-root reject. Mounting a share over `/` is always
        // wrong; the deny-prefix list can't enforce this on its
        // own because `starts_with("/")` is universally true.
        if normalized_path == Path::new("/") {
            return Err(MountPathError::Denied {
                raw: raw.to_string(),
                matched: "/".to_string(),
            });
        }

        // Deny check first. A path can match an allow-root and
        // still hit a deny-prefix (e.g. allow `/data` plus a deny
        // on `/data/secrets/`); deny wins.
        if let Some(matched) = self.deny_match(normalized_path) {
            return Err(MountPathError::Denied {
                raw: raw.to_string(),
                matched: matched.to_string(),
            });
        }

        if !self.matches_any_allow_root(normalized_path) {
            return Err(MountPathError::OutsideAllowRoots {
                raw: raw.to_string(),
                allow: self.allow_roots.clone(),
            });
        }
        Ok(normalized)
    }

    fn deny_match(&self, path: &Path) -> Option<&str> {
        self.deny_prefixes
            .iter()
            .find(|prefix| starts_with_segment_aware(path, Path::new(prefix.as_str())))
            .map(String::as_str)
    }

    fn matches_any_allow_root(&self, path: &Path) -> bool {
        self.allow_roots
            .iter()
            .any(|root| starts_with_segment_aware(path, Path::new(root.as_str())))
    }
}

/// Free-function shortcut for callers that don't need the
/// configurable policy.
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

fn starts_with_segment_aware(path: &Path, prefix: &Path) -> bool {
    // Path::starts_with is component-aware (`/foo` starts_with `/`
    // and `/foo/bar`/`/foo` but not `/foobar`). Special-case the
    // bare-root prefix because Path::starts_with("/") is true for
    // every absolute path, which we *want* for the deny `/` rule —
    // the bare-root deny is what blocks `mount over /`. Above the
    // bare-root case, normal segment semantics apply.
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
    fn accepts_default_allow_roots() {
        for path in ["/mnt", "/mnt/foo", "/data", "/data/x/y", "/work/sandbox"] {
            validate_mount_path(path)
                .unwrap_or_else(|e| panic!("expected accept for {path:?}, got {e}"));
        }
    }

    #[test]
    fn rejects_outside_allow_roots() {
        for path in ["/home/user", "/tmp", "/var/lib/app"] {
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
    fn rejects_default_deny_prefixes() {
        // Each of these shouldn't even get evaluated against the
        // allow-roots — the deny-list fires first.
        for path in [
            "/etc/mvm/keys",
            "/usr/bin/sh",
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
            // Nix-immutable paths (plan 45 §"Nix semantics alignment").
            "/nix",
            "/nix/store/abc123-pkg",
            "/nix/var/log",
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

    #[test]
    fn nix_paths_denied_segment_aware() {
        // `/nixos` is not a child of `/nix` — the deny match must
        // honour path-segment boundaries.
        let err = validate_mount_path("/nixos").unwrap_err();
        assert!(
            matches!(err, MountPathError::OutsideAllowRoots { .. }),
            "expected OutsideAllowRoots for /nixos (not a /nix child), got {err:?}",
        );
    }

    #[test]
    fn deny_match_is_segment_aware_for_etc() {
        // `/etcetera` shares a string prefix with `/etc` but is
        // not a child of it. Should be allowed (assuming it lives
        // under an allow-root — it doesn't, so it's rejected for
        // OutsideAllowRoots, *not* Denied).
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
    }

    #[test]
    fn extra_deny_layer_takes_priority_over_allow_root() {
        let policy = MountPathPolicy::default().with_extra_deny(["/data/secrets"]);
        // `/data/secrets/key` is under the `/data` allow-root, but
        // matches the extra deny — must reject.
        assert!(matches!(
            policy.validate("/data/secrets/key"),
            Err(MountPathError::Denied { .. })
        ));
        // Sibling under `/data` but outside the deny is fine.
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
        // Defaults deny-list still applies.
        assert!(matches!(
            policy.validate("/etc/mvm/x"),
            Err(MountPathError::Denied { .. })
        ));
    }
}
