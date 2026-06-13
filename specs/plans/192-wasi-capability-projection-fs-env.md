# Plan 192 — WASI capability projection (fs/env) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the capability-projection seam from network (Plan 188) to the WASI filesystem-preopen and env-var domains, so a wasm-component workload's fs/env grants are deny-by-default, clamp-authored (a request attenuates, never widens the tenant bound), and projected into a backend-agnostic WASI-config shape the in-guest runner will consume.

**Architecture:** A new pure-logic module `crates/mvm-core/src/policy/projection_fs_env.rs`, sibling to `projection.rs`, mirroring its resolve→canonicalize→clamp→wasi-shape walk for two new capability domains. `CanonicalFs`/`CanonicalEnv` are the authoritative resolved grant sets; `clamp_fs`/`clamp_env` are intersection-only merges; `to_wasi_preopens`/`to_wasi_env_names` emit the data the A3 guest runner turns into wasmtime preopens/env. A new `WasiCapPolicy` sub-policy on `EffectivePolicy` carries the tenant bound. Decision logic only — no I/O, no wasmtime, no enforcement. This is **A1** of ADR-081; A2 (`.wasm` admission) and A3 (guest runner + Nix bake + AOT) are follow-on plans that consume this.

**Tech Stack:** Rust, `mvm-core` (no async/runtime deps — the `xtask check-core-runtime-free` gate must stay green), `serde` (already a dep), no new crates.

**Source of truth:** `specs/adrs/081-wasm-component-runner.md` §Decision 3 + §Decomposition (A1). The network analogue this mirrors line-for-line is `crates/mvm-core/src/policy/projection.rs` (Plan 188).

---

## Design decisions locked by ADR-081 (read before starting)

- **Deny-by-default, both domains.** An empty resolved set grants nothing. There is **no `Unrestricted`/`open` mode for fs/env** (unlike egress) — a component sees only the preopens/env-names explicitly granted. This is simpler than `CanonicalEgress` and deliberate.
- **Clamp = intersection-only.** A *requested* grant (from the workload IR, wired in A3) survives only if a *resolved* grant (the tenant bound) covers it. Partial coverage drops the whole grant, fail-closed. This is the Plan 188 `clamp` invariant, re-expressed for fs paths and env names.
- **fs covering rule:** resolved grant `R` covers requested grant `Q` iff `R.guest_path` is `Q.guest_path` or an ancestor directory of it, **and** `R.access >= Q.access` (an RW request under an RO bound drops; an RO request under an RW bound survives as RO).
- **env grant is name-level.** A1 decides *which env var names* a component may see. The *values* are filled later by the existing env/secret-substitution path (claim 13) — out of scope here. `clamp_env` survival = the requested name is in the resolved allowed-name set.
- **No path normalization cleverness.** Refuse anything that isn't a clean absolute path: must start with `/`, must not contain a `..` segment, must not be empty. A traversal-shaped path is a loud refusal at projection (mirrors `refuse_inverted_ports`), never a silently-sanitized grant.

---

## File Structure

- **Create:** `crates/mvm-core/src/policy/projection_fs_env.rs` — the entire fs/env projection seam (types, canonicalize, clamp, wasi-shape, decision fns, tests, property witnesses). One responsibility: the fs/env analogue of `projection.rs`.
- **Modify:** `crates/mvm-core/src/policy/policies.rs` — add the `WasiCapPolicy` sub-policy + its specs (`FsGrantSpec`).
- **Modify:** `crates/mvm-core/src/policy/resolver.rs` — add the `wasi` field to `EffectivePolicy` and resolve it via `pick`.
- **Modify:** `crates/mvm-core/src/policy/mod.rs` — `pub mod projection_fs_env;` + re-export the public surface alongside `projection`.
- **Modify:** `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md` — bookkeeping (Task 6).

---

### Task 1: Fs grant types + decision function

**Files:**
- Create: `crates/mvm-core/src/policy/projection_fs_env.rs`
- Modify: `crates/mvm-core/src/policy/mod.rs`

- [ ] **Step 1: Register the module**

In `crates/mvm-core/src/policy/mod.rs`, find the line `pub mod projection;` and add directly below it:

```rust
pub mod projection_fs_env;
```

- [ ] **Step 2: Write the failing test**

Create `crates/mvm-core/src/policy/projection_fs_env.rs` with the types and a test. Start the file with this content:

```rust
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!fs.permits("/database", FsAccess::ReadOnly), "sibling prefix-collision");
        assert!(!fs.permits("/data/in.txt", FsAccess::ReadWrite), "RW under RO bound");
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
}
```

- [ ] **Step 3: Run test to verify it fails, then passes**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::fs_ -- --nocapture`
Expected: the module compiles and all four `fs_*` tests PASS (the implementation is included in Step 2 — this task ships type + decision logic together because the decision fn is trivial and the tests are the spec for `path_under`'s segment-boundary rule).

- [ ] **Step 4: Verify the segment-boundary guard specifically**

Confirm `fs_denies_outside_sibling_and_insufficient_access` passes — it is the witness that `/database` is not treated as under `/data`. If it fails, `path_under` is doing a raw `starts_with` and must compare on the `/`-boundary as written.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection_fs_env.rs crates/mvm-core/src/policy/mod.rs
git commit -m "feat(core): CanonicalFs preopen grants + segment-boundary permits"
```

---

### Task 2: canonicalize_fs — lower the resolved bound, refuse malformed paths

**Files:**
- Modify: `crates/mvm-core/src/policy/projection_fs_env.rs`
- Modify: `crates/mvm-core/src/policy/policies.rs`

- [ ] **Step 1: Add the bound spec type**

In `crates/mvm-core/src/policy/policies.rs`, after the `EgressPolicy` definition, add the fs grant spec (mirror the derive set on `L4RuleSpec`):

```rust
/// One filesystem-preopen grant in a policy bound. `access` is the
/// wire string `"ro"` / `"rw"`; anything else refuses at projection.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsGrantSpec {
    pub guest_path: String,
    pub access: String,
}
```

- [ ] **Step 2: Write the failing test**

In `projection_fs_env.rs`, add to the `tests` module:

```rust
use crate::policy::policies::FsGrantSpec;

fn fs_spec(path: &str, access: &str) -> FsGrantSpec {
    FsGrantSpec {
        guest_path: path.to_string(),
        access: access.to_string(),
    }
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
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::canonicalize_fs`
Expected: FAIL to compile — `canonicalize_fs`, `FsEnvError` not defined.

- [ ] **Step 4: Write the implementation**

In `projection_fs_env.rs`, above the `tests` module, add the error enum, the access parser, and `canonicalize_fs`:

```rust
use thiserror::Error;

use crate::policy::policies::FsGrantSpec;

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
        let path = spec.guest_path.strip_suffix('/').unwrap_or(&spec.guest_path);
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::canonicalize_fs`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add crates/mvm-core/src/policy/projection_fs_env.rs crates/mvm-core/src/policy/policies.rs
git commit -m "feat(core): canonicalize_fs lowering with traversal refusal + rw-supersedes merge"
```

---

### Task 3: Env grant types + canonicalize_env

**Files:**
- Modify: `crates/mvm-core/src/policy/projection_fs_env.rs`

- [ ] **Step 1: Write the failing test**

In `projection_fs_env.rs` `tests` module:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::canonicalize_env`
Expected: FAIL to compile — `CanonicalEnv`, `canonicalize_env` not defined.

- [ ] **Step 3: Write the implementation**

In `projection_fs_env.rs`, after `canonicalize_fs`:

```rust
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::canonicalize_env`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection_fs_env.rs
git commit -m "feat(core): CanonicalEnv name-level projection + canonicalize_env"
```

---

### Task 4: clamp_fs + clamp_env — intersection-only merge

**Files:**
- Modify: `crates/mvm-core/src/policy/projection_fs_env.rs`

- [ ] **Step 1: Write the failing test**

In the `tests` module:

```rust
fn fs(grants: &[(&str, FsAccess)]) -> CanonicalFs {
    CanonicalFs {
        grants: grants
            .iter()
            .map(|(p, a)| FsGrant { guest_path: p.to_string(), access: *a })
            .collect(),
    }
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
    assert!(!granted.permits("/work/out/x", FsAccess::ReadWrite), "request asked ro");
}

#[test]
fn clamp_env_keeps_only_resolved_names() {
    let requested = CanonicalEnv { allowed: vec!["PATH".into(), "SECRET".into()] };
    let resolved = CanonicalEnv { allowed: vec!["PATH".into(), "HOME".into()] };
    let granted = clamp_env(&requested, &resolved);
    assert!(granted.permits("PATH"));
    assert!(!granted.permits("SECRET"), "not in resolved bound");
    assert!(!granted.permits("HOME"), "not requested");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::clamp_`
Expected: FAIL to compile — `clamp_fs`, `clamp_env` not defined.

- [ ] **Step 3: Write the implementation**

In `projection_fs_env.rs`, after `canonicalize_env`:

```rust
/// True when resolved grant `r` covers requested grant `q`: `r`'s path
/// is `q`'s path or an ancestor, AND `r` grants at least `q`'s access.
fn fs_covers(r: &FsGrant, q: &FsGrant) -> bool {
    r.access >= q.access && path_under(&r.guest_path, &q.guest_path)
}

/// Intersection-only merge of a *requested* fs grant set against the
/// *resolved* (authoritative) bound. A requested grant survives only
/// when some resolved grant fully covers it (path + access); partial
/// coverage drops it whole, fail-closed. The request attenuates, never
/// widens — the Plan 188 `clamp` invariant for the fs domain.
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::clamp_`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection_fs_env.rs
git commit -m "feat(core): clamp_fs/clamp_env intersection-only merges (request attenuates)"
```

---

### Task 5: WASI-shape generator + the "denied is not preopened" negative witness

**Files:**
- Modify: `crates/mvm-core/src/policy/projection_fs_env.rs`

This is the data the A3 guest runner turns into wasmtime preopens/env. Keeping it backend-agnostic (plain `String`/`bool`) keeps wasmtime out of `mvm-core`.

- [ ] **Step 1: Write the failing test**

In the `tests` module:

```rust
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
            WasiPreopen { guest_path: "/data".into(), writable: false },
            WasiPreopen { guest_path: "/work".into(), writable: true },
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
    let granted = CanonicalEnv { allowed: vec!["HOME".into(), "PATH".into()] };
    assert_eq!(to_wasi_env_names(&granted), vec!["HOME".to_string(), "PATH".to_string()]);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::to_wasi`
Expected: FAIL to compile — `WasiPreopen`, `to_wasi_preopens`, `to_wasi_env_names` not defined.

- [ ] **Step 3: Write the implementation**

In `projection_fs_env.rs`, after `clamp_env`:

```rust
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p mvm-core policy::projection_fs_env::tests::to_wasi && cargo test -p mvm-core policy::projection_fs_env::tests::denied_dir`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-core/src/policy/projection_fs_env.rs
git commit -m "feat(core): WASI preopen/env-name generator + denied-not-preopened witness"
```

---

### Task 6: Property witness, EffectivePolicy wiring, exports, bookkeeping

**Files:**
- Modify: `crates/mvm-core/src/policy/projection_fs_env.rs`
- Modify: `crates/mvm-core/src/policy/policies.rs`
- Modify: `crates/mvm-core/src/policy/resolver.rs`
- Modify: `crates/mvm-core/src/policy/mod.rs`
- Modify: `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`

- [ ] **Step 1: Write the clamp-never-widens property witness (failing)**

In `projection_fs_env.rs`, add a `property` module at the end of the file (sibling to `tests`), mirroring `projection.rs`'s xorshift generator:

```rust
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
        let dirs = ["/a", "/a/b", "/a/b/c", "/data", "/data/sub", "/work", "/etc"];
        let mut grants = Vec::new();
        for _ in 0..rng.below(5) {
            let path = dirs[rng.below(dirs.len() as u64) as usize];
            let access = if rng.below(2) == 0 { FsAccess::ReadOnly } else { FsAccess::ReadWrite };
            grants.push(FsGrant { guest_path: path.to_string(), access });
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
        let mut rng = Xs(0x192_f5_e0a1);
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
        let mut rng = Xs(0x192_e0_b2c3);
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
```

- [ ] **Step 2: Run the property witnesses**

Run: `cargo test -p mvm-core policy::projection_fs_env::property`
Expected: PASS (2 tests). If `clamp_fs_never_widens_property` fails, `fs_covers`/`path_under` have a widening bug — fix there, not in the test.

- [ ] **Step 3: Add the WasiCapPolicy sub-policy**

In `crates/mvm-core/src/policy/policies.rs`, after `FsGrantSpec`, add:

```rust
/// The tenant bound on a wasm-component's WASI capabilities: which
/// filesystem preopens and env-var names it may receive. Deny-by-
/// default — an empty policy grants nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasiCapPolicy {
    #[serde(default)]
    pub fs: Vec<FsGrantSpec>,
    #[serde(default)]
    pub env: Vec<String>,
}
```

- [ ] **Step 4: Wire it into EffectivePolicy**

In `crates/mvm-core/src/policy/resolver.rs`:

1. Add the field to the `EffectivePolicy` struct (after `audit`):

```rust
    #[serde(default)]
    pub wasi: WasiCapPolicy,
```

2. Import it — add `WasiCapPolicy` to the `use crate::policy::policies::{...}` list (or add a `use` if absent).

3. Resolve it in `resolve()` alongside the others (after the `audit:` line):

```rust
        wasi: pick(overlay.and_then(|o| o.wasi.clone()), &bundle.wasi),
```

> **Note for the implementer:** step 3 requires `PolicyBundle` and `TenantOverlay` (in `crates/mvm-core/src/policy/bundle.rs`) to carry a `wasi` field too. Add `#[serde(default)] pub wasi: WasiCapPolicy` to `PolicyBundle` and `#[serde(default)] pub wasi: Option<WasiCapPolicy>` to `TenantOverlay`, mirroring how `network`/`egress` appear in each. Build will tell you exactly which structs need the field; the `#[serde(default)]` keeps existing bundle JSON deserializing.

- [ ] **Step 5: Verify the resolver still builds and resolves**

Run: `cargo test -p mvm-core policy::resolver`
Expected: PASS — existing resolver tests still green; `EffectivePolicy::default().wasi` is the empty (deny-all) `WasiCapPolicy`.

- [ ] **Step 6: Re-export the public surface**

In `crates/mvm-core/src/policy/mod.rs`, find where `projection`'s public items are re-exported (e.g. `pub use projection::{...}`). Add a sibling re-export:

```rust
pub use projection_fs_env::{
    canonicalize_env, canonicalize_fs, clamp_env, clamp_fs, to_wasi_env_names,
    to_wasi_preopens, CanonicalEnv, CanonicalFs, FsAccess, FsEnvError, FsGrant, WasiPreopen,
};
```

> If `mod.rs` does not re-export `projection`'s items (callers use the `projection::` path), skip the `pub use` and leave the module path-qualified to match the existing convention.

- [ ] **Step 7: Full gate run**

Run, in order:

```bash
cargo fmt --all -- --check
cargo nextest run -p mvm-core
cargo clippy -p mvm-core -- -D warnings
cargo run -p xtask -- check-core-runtime-free
```

Expected: fmt clean; all `mvm-core` tests pass (including the new `projection_fs_env` module + property witnesses); zero clippy warnings; `check-core-runtime-free` green (no `tokio` pulled — this plan adds none).

- [ ] **Step 8: Spec bookkeeping**

- In `specs/REFACTOR-STATUS.md`: add a glance line and a detail entry recording "Plan 192 (ADR-081 A1) — WASI fs/env capability projection LANDED", and bump the "Last updated" date.
- In `specs/SPRINT.md`: record Plan 192 under the active sprint with the A1 deliverable + the two clamp-never-widens witnesses; note A2 (`.wasm` admission) and A3 (guest runner/Nix/AOT) as the remaining ADR-081 legs (their own plans).

- [ ] **Step 9: Commit**

```bash
git add crates/mvm-core/src/policy/projection_fs_env.rs crates/mvm-core/src/policy/policies.rs crates/mvm-core/src/policy/resolver.rs crates/mvm-core/src/policy/bundle.rs crates/mvm-core/src/policy/mod.rs specs/REFACTOR-STATUS.md specs/SPRINT.md
git commit -m "feat(core): WasiCapPolicy bound + clamp-never-widens property witnesses (ADR-081 A1)"
```

---

## Self-Review

**Spec coverage (against ADR-081 §Decision 3 + A1):**
- "fs/env capabilities, not just network" → Tasks 1–3 (`CanonicalFs`, `CanonicalEnv`, canonicalizers). ✓
- "clamp from Plan 188 applies" → Task 4 (`clamp_fs`/`clamp_env`, intersection-only) + Task 6 property witnesses. ✓
- "deny-by-default" → no `Unrestricted` for fs/env; empty-is-deny-all tests in Tasks 1 & 3. ✓
- "clamp invariant (request never widens tenant policy)" → `clamp_fs_never_widens_property` + `clamp_env_never_widens_property`. ✓
- "WASI-config generator … turns resolved policy into the actual preopen/env grant set" → Task 5 (`to_wasi_preopens`/`to_wasi_env_names`). ✓
- "negative tests (a denied dir is not preopened)" → Task 5 `denied_dir_is_not_preopened`. ✓
- "extends `mvm-core::policy::projection`" → sibling module + `WasiCapPolicy` on `EffectivePolicy`. ✓
- Out of scope here (correctly deferred to A2/A3): `.wasm` admission, the IR request-side source of requested grants, the guest runner, Nix bake, AOT, seccomp. The clamp consumers in A1 take `CanonicalFs`/`CanonicalEnv` directly; A3 supplies the requested side from the IR.

**Placeholder scan:** none — every code step carries complete code; every run step carries the exact command + expected result.

**Type consistency:** `FsAccess`/`FsGrant`/`CanonicalFs`/`CanonicalEnv`/`FsEnvError`/`WasiPreopen` and the fns `canonicalize_fs`/`canonicalize_env`/`clamp_fs`/`clamp_env`/`to_wasi_preopens`/`to_wasi_env_names`/`path_under`/`fs_covers` are named identically across all tasks. `FsAccess: Ord` (derived in Task 1) is what makes `>=` in `fs_covers`/`permits` and `.max()` in `canonicalize_fs` compile. `FsGrantSpec`/`WasiCapPolicy` live in `policies.rs`; `EffectivePolicy.wasi` is wired in `resolver.rs`.

## Follow-on (separate plans — do NOT implement here)

- **Plan 193 = ADR-081 A2:** `.wasm` artifact admission — `mvmctl run ./x.wasm` → SHA-256 → signed `ExecutionPlan` (claim 8/9) → provenance (digest + wasmtime version) in the audit chain.
- **Plan 194 = ADR-081 A3:** guest runner + Nix bake + AOT — bake wasmtime for `Wasm` workloads; AOT-compile `.wasm`→`.cwasm` in the builder; map this plan's `WasiPreopen`/env-name output onto the `wasmtime run` invocation + WASI config; tighten guest seccomp to forbid `PROT_EXEC`.
