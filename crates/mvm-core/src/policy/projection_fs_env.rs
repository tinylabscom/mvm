//! WASI capability projection seam (filesystem preopens + env vars).
//!
//! The fs/env analogue of [`crate::policy::projection`]. One resolved
//! [`EffectivePolicy`] bound projects to the deny-by-default grant sets
//! a wasm-component runner enforces: a set of filesystem preopens (a
//! guest path + an access mode) and a set of permitted env-var names.
//! A *requested* grant (the workload IR, wired in the runner plan) is
//! clamped against the resolved bound — intersection only, a request
//! attenuates and never widens. Decision logic only: no I/O, no
//! wasmtime, no enforcement.
//!
//! Unlike egress there is no `Unrestricted` mode here — fs/env are
//! always explicit. An empty resolved set grants nothing.
//!
//! [`EffectivePolicy`]: crate::policy::resolver::EffectivePolicy

use thiserror::Error;

use crate::policy::policies::FsGrantSpec;

/// Access mode of a filesystem preopen. `ReadOnly < ReadWrite` so a
/// resolved RW bound covers an RO request but not vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsAccess {
    ReadOnly,
    ReadWrite,
}

/// One canonical filesystem preopen: an absolute guest path and the
/// access the component is granted under it. `guest_path` is a clean
/// absolute path (validated at canonicalization — no `..`, non-empty,
/// leading `/`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FsGrant {
    pub guest_path: String,
    pub access: FsAccess,
}

/// The canonical filesystem projection of a resolved policy bound.
/// Deny-by-default: an empty rule set admits nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalFs {
    pub grants: Vec<FsGrant>,
}

impl CanonicalFs {
    /// Pure membership decision: is `path` admitted at `access`?
    /// True when some grant's `guest_path` is `path` or an ancestor of
    /// it AND the grant's access is at least `access`.
    pub fn permits(&self, path: &str, access: FsAccess) -> bool {
        self.grants
            .iter()
            .any(|g| g.access >= access && path_under(&g.guest_path, path))
    }
}

/// True when `prefix` is `path` or an ancestor directory of it,
/// compared by whole path segments (so `/a/bc` is NOT under `/a/b`).
fn path_under(prefix: &str, path: &str) -> bool {
    if prefix == path {
        return true;
    }
    let prefix_trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
    path.strip_prefix(prefix_trimmed)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Projection-time refusals for the fs/env domains. Every variant is
/// a fail-closed admission error.
#[derive(Debug, Error)]
pub enum FsEnvError {
    #[error("fs grant path {path:?} is not absolute (must start with '/')")]
    NonAbsolutePath { path: String },
    #[error("fs grant path {path:?} contains a '..' traversal segment")]
    PathTraversal { path: String },
    #[error("unknown fs access {access:?} for {path:?} (expected \"ro\" or \"rw\")")]
    UnknownAccess { path: String, access: String },
    #[error("env var name {name:?} is empty or contains '=' or NUL")]
    BadEnvName { name: String },
}

impl FsAccess {
    /// Parse the `"ro"` / `"rw"` wire form. Loud refusal otherwise.
    fn parse(path: &str, s: &str) -> Result<Self, FsEnvError> {
        match s {
            "ro" => Ok(Self::ReadOnly),
            "rw" => Ok(Self::ReadWrite),
            other => Err(FsEnvError::UnknownAccess {
                path: path.to_string(),
                access: other.to_string(),
            }),
        }
    }
}

/// Reject anything that is not a clean absolute path. Traversal is a
/// loud refusal, never silently sanitized.
fn validate_abs_path(path: &str) -> Result<(), FsEnvError> {
    if !path.starts_with('/') {
        return Err(FsEnvError::NonAbsolutePath {
            path: path.to_string(),
        });
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err(FsEnvError::PathTraversal {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Lower a resolved policy's fs grant specs into the canonical set.
/// Refuses malformed paths/access; collapses duplicate paths so the
/// widest access (rw) wins. Deny-by-default: empty specs → empty set.
pub fn canonicalize_fs(specs: &[FsGrantSpec]) -> Result<CanonicalFs, FsEnvError> {
    let mut grants: Vec<FsGrant> = Vec::new();
    for spec in specs {
        validate_abs_path(&spec.guest_path)?;
        let access = FsAccess::parse(&spec.guest_path, &spec.access)?;
        let path = spec
            .guest_path
            .strip_suffix('/')
            .unwrap_or(&spec.guest_path);
        match grants.iter_mut().find(|g| g.guest_path == path) {
            Some(existing) => existing.access = existing.access.max(access),
            None => grants.push(FsGrant {
                guest_path: path.to_string(),
                access,
            }),
        }
    }
    grants.sort();
    Ok(CanonicalFs { grants })
}

/// The canonical env-name projection: the set of env-var names a
/// component may see. Values are filled by the env/secret-substitution
/// path elsewhere — this is name-level only. Deny-by-default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEnv {
    pub allowed: Vec<String>,
}

impl CanonicalEnv {
    /// Pure membership decision: is `name` a permitted env var?
    pub fn permits(&self, name: &str) -> bool {
        self.allowed.iter().any(|n| n == name)
    }
}

/// Lower a resolved policy's permitted env names into the canonical
/// set. Refuses empty names or names containing `=` / NUL (which can
/// never be a valid env key). Sorted + deduped.
pub fn canonicalize_env(names: &[String]) -> Result<CanonicalEnv, FsEnvError> {
    let mut allowed: Vec<String> = Vec::new();
    for name in names {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            return Err(FsEnvError::BadEnvName { name: name.clone() });
        }
        if !allowed.iter().any(|n| n == name) {
            allowed.push(name.clone());
        }
    }
    allowed.sort();
    Ok(CanonicalEnv { allowed })
}

/// True when resolved grant `r` covers requested grant `q`: `r`'s path
/// is `q`'s path or an ancestor, AND `r` grants at least `q`'s access.
fn fs_covers(r: &FsGrant, q: &FsGrant) -> bool {
    r.access >= q.access && path_under(&r.guest_path, &q.guest_path)
}

/// Intersection-only merge of a *requested* fs grant set against the
/// *resolved* (authoritative) bound. A requested grant survives only
/// when some resolved grant fully covers it (path + access); partial
/// coverage drops it whole, fail-closed. The request attenuates, never
/// widens — the same `clamp` invariant the network projection enforces,
/// applied to the fs domain.
pub fn clamp_fs(requested: &CanonicalFs, resolved: &CanonicalFs) -> CanonicalFs {
    let grants = requested
        .grants
        .iter()
        .filter(|q| resolved.grants.iter().any(|r| fs_covers(r, q)))
        .cloned()
        .collect();
    CanonicalFs { grants }
}

/// Intersection-only merge of requested env names against the resolved
/// allowed-name bound. A requested name survives only if the bound
/// permits it.
pub fn clamp_env(requested: &CanonicalEnv, resolved: &CanonicalEnv) -> CanonicalEnv {
    let allowed = requested
        .allowed
        .iter()
        .filter(|n| resolved.permits(n))
        .cloned()
        .collect();
    CanonicalEnv { allowed }
}

/// One filesystem preopen in the WASI-facing shape — the data the
/// guest runner maps onto a `wasmtime`/`WasiCtxBuilder` preopen.
/// Backend-agnostic by design: no wasmtime types reach `mvm-core`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasiPreopen {
    pub guest_path: String,
    pub writable: bool,
}

/// Project the granted fs set into the runner-facing preopen list.
/// One entry per grant; `writable` is true exactly for `ReadWrite`.
pub fn to_wasi_preopens(granted: &CanonicalFs) -> Vec<WasiPreopen> {
    granted
        .grants
        .iter()
        .map(|g| WasiPreopen {
            guest_path: g.guest_path.clone(),
            writable: g.access == FsAccess::ReadWrite,
        })
        .collect()
}

/// Project the granted env set into the runner-facing name list.
pub fn to_wasi_env_names(granted: &CanonicalEnv) -> Vec<String> {
    granted.allowed.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::policies::FsGrantSpec;

    fn fs_spec(path: &str, access: &str) -> FsGrantSpec {
        FsGrantSpec {
            guest_path: path.to_string(),
            access: access.to_string(),
        }
    }

    fn fs(grants: &[(&str, FsAccess)]) -> CanonicalFs {
        CanonicalFs {
            grants: grants
                .iter()
                .map(|(p, a)| FsGrant {
                    guest_path: p.to_string(),
                    access: *a,
                })
                .collect(),
        }
    }

    #[test]
    fn fs_permits_path_under_granted_preopen() {
        let fs = CanonicalFs {
            grants: vec![FsGrant {
                guest_path: "/data".to_string(),
                access: FsAccess::ReadOnly,
            }],
        };
        assert!(fs.permits("/data", FsAccess::ReadOnly));
        assert!(fs.permits("/data/in.txt", FsAccess::ReadOnly));
        assert!(fs.permits("/data/sub/deep.txt", FsAccess::ReadOnly));
    }

    #[test]
    fn fs_denies_outside_sibling_and_insufficient_access() {
        let fs = CanonicalFs {
            grants: vec![FsGrant {
                guest_path: "/data".to_string(),
                access: FsAccess::ReadOnly,
            }],
        };
        assert!(!fs.permits("/etc/passwd", FsAccess::ReadOnly), "outside");
        assert!(
            !fs.permits("/database", FsAccess::ReadOnly),
            "sibling prefix-collision"
        );
        assert!(
            !fs.permits("/data/in.txt", FsAccess::ReadWrite),
            "RW under RO bound"
        );
    }

    #[test]
    fn fs_empty_is_deny_all() {
        let fs = CanonicalFs { grants: vec![] };
        assert!(!fs.permits("/data", FsAccess::ReadOnly));
    }

    #[test]
    fn fs_rw_grant_covers_ro_and_rw_reads() {
        let fs = CanonicalFs {
            grants: vec![FsGrant {
                guest_path: "/work".to_string(),
                access: FsAccess::ReadWrite,
            }],
        };
        assert!(fs.permits("/work/out.txt", FsAccess::ReadOnly));
        assert!(fs.permits("/work/out.txt", FsAccess::ReadWrite));
    }

    #[test]
    fn canonicalize_fs_lowers_and_dedups() {
        let specs = vec![fs_spec("/data", "ro"), fs_spec("/work", "rw")];
        let fs = canonicalize_fs(&specs).unwrap();
        assert!(fs.permits("/data/x", FsAccess::ReadOnly));
        assert!(fs.permits("/work/y", FsAccess::ReadWrite));
    }

    #[test]
    fn canonicalize_fs_rw_supersedes_ro_for_same_path() {
        // Same path granted ro and rw collapses to the wider rw.
        let specs = vec![fs_spec("/work", "ro"), fs_spec("/work", "rw")];
        let fs = canonicalize_fs(&specs).unwrap();
        assert_eq!(fs.grants.len(), 1, "merged: {:?}", fs.grants);
        assert!(fs.permits("/work/y", FsAccess::ReadWrite));
    }

    #[test]
    fn canonicalize_fs_refuses_relative_traversal_and_bad_access() {
        assert!(matches!(
            canonicalize_fs(&[fs_spec("data", "ro")]).unwrap_err(),
            FsEnvError::NonAbsolutePath { .. }
        ));
        assert!(matches!(
            canonicalize_fs(&[fs_spec("/data/../etc", "ro")]).unwrap_err(),
            FsEnvError::PathTraversal { .. }
        ));
        assert!(matches!(
            canonicalize_fs(&[fs_spec("", "ro")]).unwrap_err(),
            FsEnvError::NonAbsolutePath { .. }
        ));
        assert!(matches!(
            canonicalize_fs(&[fs_spec("/data", "exec")]).unwrap_err(),
            FsEnvError::UnknownAccess { .. }
        ));
    }

    #[test]
    fn canonicalize_env_dedups_and_sorts() {
        let env = canonicalize_env(&["PATH".to_string(), "HOME".to_string(), "PATH".to_string()])
            .unwrap();
        assert_eq!(env.allowed, vec!["HOME".to_string(), "PATH".to_string()]);
        assert!(env.permits("PATH"));
        assert!(!env.permits("SECRET_KEY"));
    }

    #[test]
    fn canonicalize_env_empty_is_deny_all() {
        let env = canonicalize_env(&[]).unwrap();
        assert!(!env.permits("PATH"));
    }

    #[test]
    fn canonicalize_env_refuses_malformed_names() {
        assert!(matches!(
            canonicalize_env(&["".to_string()]).unwrap_err(),
            FsEnvError::BadEnvName { .. }
        ));
        assert!(matches!(
            canonicalize_env(&["A=B".to_string()]).unwrap_err(),
            FsEnvError::BadEnvName { .. }
        ));
    }

    #[test]
    fn clamp_fs_keeps_only_covered_requests() {
        let requested = fs(&[
            ("/data/sub", FsAccess::ReadOnly), // under resolved /data → kept
            ("/etc", FsAccess::ReadOnly),      // not granted → dropped
        ]);
        let resolved = fs(&[("/data", FsAccess::ReadOnly)]);
        let granted = clamp_fs(&requested, &resolved);
        assert!(granted.permits("/data/sub/x", FsAccess::ReadOnly));
        assert!(!granted.permits("/etc/passwd", FsAccess::ReadOnly));
    }

    #[test]
    fn clamp_fs_rw_request_under_ro_bound_drops() {
        let requested = fs(&[("/data", FsAccess::ReadWrite)]);
        let resolved = fs(&[("/data", FsAccess::ReadOnly)]);
        let granted = clamp_fs(&requested, &resolved);
        assert_eq!(granted.grants, vec![], "RW not covered by RO bound");
    }

    #[test]
    fn clamp_fs_ro_request_under_rw_bound_survives_as_ro() {
        let requested = fs(&[("/work/out", FsAccess::ReadOnly)]);
        let resolved = fs(&[("/work", FsAccess::ReadWrite)]);
        let granted = clamp_fs(&requested, &resolved);
        assert!(granted.permits("/work/out/x", FsAccess::ReadOnly));
        assert!(
            !granted.permits("/work/out/x", FsAccess::ReadWrite),
            "request asked ro"
        );
    }

    #[test]
    fn clamp_env_keeps_only_resolved_names() {
        let requested = CanonicalEnv {
            allowed: vec!["PATH".into(), "SECRET".into()],
        };
        let resolved = CanonicalEnv {
            allowed: vec!["PATH".into(), "HOME".into()],
        };
        let granted = clamp_env(&requested, &resolved);
        assert!(granted.permits("PATH"));
        assert!(!granted.permits("SECRET"), "not in resolved bound");
        assert!(!granted.permits("HOME"), "not requested");
    }

    #[test]
    fn to_wasi_preopens_emits_one_entry_per_grant_with_writable_flag() {
        let granted = fs(&[
            ("/data", FsAccess::ReadOnly),
            ("/work", FsAccess::ReadWrite),
        ]);
        let pre = to_wasi_preopens(&granted);
        assert_eq!(
            pre,
            vec![
                WasiPreopen {
                    guest_path: "/data".into(),
                    writable: false
                },
                WasiPreopen {
                    guest_path: "/work".into(),
                    writable: true
                },
            ]
        );
    }

    #[test]
    fn denied_dir_is_not_preopened() {
        // The security-critical negative: a path the bound does not grant
        // never appears in the preopen list the runner will hand wasmtime.
        let requested = fs(&[("/etc", FsAccess::ReadOnly)]);
        let resolved = fs(&[("/data", FsAccess::ReadOnly)]);
        let granted = clamp_fs(&requested, &resolved);
        let pre = to_wasi_preopens(&granted);
        assert!(
            !pre.iter().any(|p| p.guest_path == "/etc"),
            "denied /etc must not be preopened: {pre:?}"
        );
        assert!(pre.is_empty());
    }

    #[test]
    fn to_wasi_env_names_passes_through_allowed_names() {
        let granted = CanonicalEnv {
            allowed: vec!["HOME".into(), "PATH".into()],
        };
        assert_eq!(
            to_wasi_env_names(&granted),
            vec!["HOME".to_string(), "PATH".to_string()]
        );
    }
}

#[cfg(test)]
mod property {
    use super::*;

    /// Deterministic xorshift64 — no rand dep at this layer.
    struct Xs(u64);
    impl Xs {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn gen_fs(rng: &mut Xs) -> CanonicalFs {
        let dirs = [
            "/a",
            "/a/b",
            "/a/b/c",
            "/data",
            "/data/sub",
            "/work",
            "/etc",
        ];
        let mut grants = Vec::new();
        for _ in 0..rng.below(5) {
            let path = dirs[rng.below(dirs.len() as u64) as usize];
            let access = if rng.below(2) == 0 {
                FsAccess::ReadOnly
            } else {
                FsAccess::ReadWrite
            };
            grants.push(FsGrant {
                guest_path: path.to_string(),
                access,
            });
        }
        CanonicalFs { grants }
    }

    /// Probe paths biased to grant edges plus a few siblings.
    fn fs_probes() -> Vec<(&'static str, FsAccess)> {
        vec![
            ("/a/b/c/file", FsAccess::ReadOnly),
            ("/a/b/c/file", FsAccess::ReadWrite),
            ("/data/sub/x", FsAccess::ReadOnly),
            ("/data/sub/x", FsAccess::ReadWrite),
            ("/work/o", FsAccess::ReadWrite),
            ("/etc/passwd", FsAccess::ReadOnly),
            ("/database", FsAccess::ReadOnly),
            ("/", FsAccess::ReadOnly),
        ]
    }

    /// clamp_fs soundness: the granted set never admits a probe the
    /// resolved bound denies. The fs-domain analogue of
    /// projection.rs::clamp_never_widens_property.
    #[test]
    fn clamp_fs_never_widens_property() {
        let mut rng = Xs(0x1_92f5_e0a1);
        for _ in 0..512 {
            let requested = gen_fs(&mut rng);
            let resolved = gen_fs(&mut rng);
            let granted = clamp_fs(&requested, &resolved);
            for (path, access) in fs_probes() {
                if granted.permits(path, access) {
                    assert!(
                        resolved.permits(path, access),
                        "clamp_fs widened: {path} {access:?}\n req={requested:?}\n res={resolved:?}"
                    );
                }
            }
        }
    }

    /// clamp_env soundness: same invariant for env names.
    #[test]
    fn clamp_env_never_widens_property() {
        let mut rng = Xs(0x1_92e0_b2c3);
        let names = ["PATH", "HOME", "SECRET", "TOKEN", "LANG", "TZ"];
        for _ in 0..512 {
            let pick = |rng: &mut Xs| CanonicalEnv {
                allowed: names
                    .iter()
                    .filter(|_| rng.below(2) == 0)
                    .map(|s| s.to_string())
                    .collect(),
            };
            let requested = pick(&mut rng);
            let resolved = pick(&mut rng);
            let granted = clamp_env(&requested, &resolved);
            for n in names {
                if granted.permits(n) {
                    assert!(resolved.permits(n), "clamp_env widened: {n}");
                }
            }
        }
    }
}
