# Cargo target-dir guard

Backing: shipped-source
Validation: check-sprint-append

**Status: IMPLEMENTED — merge delivery remains.** Companion to the
stale-helper contract fix (PR #3132): that one stops a *runtime* helper from
an older revision being silently reused; this one stops cargo itself from
type-checking this tree against *artifacts* built from another source tree.

## Problem

`cargo build` in this repo failed with `E0063: missing field
virtiofs_shares`, naming a field that existed in no on-disk source — the
merge deleting `virtiofs_shares` (#3109) had already landed. The
explanation was in a shared target directory,
`/Users/auser/work/tinylabs/mvmco/.target-mvmd-issuer`, holding `mvm-vmm`
rlibs from 2026-08-17 that still carried `virtiofs_shares` metadata. A
shell that had exported `CARGO_TARGET_DIR` to that shared dir — leftover
from unrelated issuer work — silently poisoned every later cargo invocation
in this tree: cargo fingerprints embed absolute source paths, but a shared
target dir keyed on the same toolchain + features served the stale rmeta.

Nothing about `E0063` says the cache lied, and the diagnosis cost real
time. This is the compile-time sibling of the stale-supervisor bug.

## The guard

`scripts/cargo-target-dir-guard.sh` is sourced by both cargo wrapper
scripts immediately after they resolve the workspace root. It reclaims
`CARGO_TARGET_DIR` when — and only when — it is set and points outside the
current source tree, and it says so loudly on stderr. The policy mirrors
`scripts/dev-env.sh`:

- unset -> no-op (nothing to reclaim);
- a value inside this worktree, including the dev-env state dir
  (`.mvm-test/target`), is a real override and is honored silently;
- anything else — another worktree, a sibling shared dir, a relative path
  that resolves per-cwd — is reclaimed to `<repo>/target`, loudly;
- `MVM_DEV_ENV_KEEP_INHERITED=1` keeps the inherited value anyway, still
  loudly.

Only `CARGO_TARGET_DIR` is claimed. A shared `CARGO_HOME` costs lock
contention, not wrong artifacts; a shared `MVM_HOME` is a runtime-state
concern the runtime already guards. CI never sets `CARGO_TARGET_DIR`, so
the guard is a no-op there.

## Work

- [x] Write `scripts/cargo-target-dir-guard.sh` and source it from
  `scripts/cargo-fast.sh` and `scripts/cargo-stable.sh` right after the
  workspace root is computed.
- [x] Add `scripts/cargo-target-dir-guard.test.sh` covering all four
  policy cases (unset, inside-honored, outside-reclaimed, keep-inherited),
  asserting both the final value and whether the guard spoke up.
- [x] Shellcheck the guard, both wrappers, and the gate test; extend the
  CI shellcheck list and add a gate-test step beside the other
  `*.test.sh` gate steps.
- [x] Smoke the end-to-end path through both wrappers, including the
  reclaim message naming the actual contaminated dir from the incident.

## Validation

- `bash scripts/cargo-target-dir-guard.test.sh` — 7 cases, all green.
- `shellcheck` clean on all four touched scripts at CI severity.
- `CARGO_TARGET_DIR=<contaminated shared dir> bash scripts/cargo-fast.sh
  --version` reclaims loudly and exits 0; an inside-tree value stays silent;
  `MVM_DEV_ENV_KEEP_INHERITED=1` keeps the value loudly.
- Merge delivery: PR, full CI matrix.
