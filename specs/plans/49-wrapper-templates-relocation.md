# Plan 49 — Wrapper templates relocation

Status: **Proposed.** Pairs with Plan 48 (function-service factories).

## Background

The per-language wrapper templates that implement the function-call
wire contract today live in mvmforge:

- `mvmforge/nix/wrappers/python-runner.py`
- `mvmforge/nix/wrappers/node-runner.mjs`
- `mvmforge/nix/wrappers/wasm-runner.sh`
- `mvmforge/nix/wrappers/README.md`

The wire contract they implement (read `[args, kwargs]` from stdin,
dispatch the named function, write encoded return on stdout, structured
envelope on failure) is mvm's `mvmctl invoke` protocol — substrate
concern. Per mvmforge ADR-0010 §3 + ADR-0009 (function-call entrypoints),
the wrappers move to mvm.

Wrapper invariants enforced (per ADR-0009):

- Two-mode (prod | dev) gated by `/etc/mvm/wrapper.json`.
- prod: `PR_SET_DUMPABLE=0`; sanitized error envelope; no traceback,
  no file paths, no payload bytes in logs.
- Decoder hardening: max nesting depth 64, reject duplicate keys,
  reject non-finite floats.
- Closed serialization-format enum (`json`, `msgpack`); code-executing
  formats forbidden.
- Defense-in-depth stdin cap: 16 MiB.
- Single-shot invariant: one invocation per process.

## Goal

Pure file relocation. No logic change. The wrappers become canonical
on the mvm side; mvmforge's bundled copies become dead code after
`flake.lock` bump.

## Implementation

### Step 1: Copy files

```
mvmforge/nix/wrappers/python-runner.py   →  mvm/nix/wrappers/python-runner.py
mvmforge/nix/wrappers/node-runner.mjs    →  mvm/nix/wrappers/node-runner.mjs
mvmforge/nix/wrappers/wasm-runner.sh     →  mvm/nix/wrappers/wasm-runner.sh
mvmforge/nix/wrappers/README.md          →  mvm/nix/wrappers/README.md
```

Preserve file modes and shebangs. Update `README.md` to reflect the
new home (drop mvmforge-relative references; add cross-references to
ADR-007 in mvm and ADR-0009 in mvmforge).

### Step 2: Update factory paths

Plan 48's factories reference wrappers at relative paths. After
relocation those paths point at `mvm/nix/wrappers/`. Update factory
imports — coordinate with Plan 48 in the same PR to avoid a broken
intermediate state.

### Step 3: Port the wrapper test suite

The mvmforge wrapper-test harness at
`mvmforge/tests/wrappers/test_python_runner.py` (and the forbidden-
check sibling) treats the wrapper as a black box: spawn it with a
temporary `wrapper.json` config + tiny user module, send stdin
payload, capture stdout/stderr/exit_code. Helpers: `_make_wrapper`,
`_make_app`, `_run`.

Port to `mvm/tests/wrappers/`:

```
mvm/tests/wrappers/
├── conftest.py           # shared fixtures
├── test_python_runner.py # ports mvmforge's
└── test_forbidden_check.py
```

Add a CI lane invoking `pytest mvm/tests/wrappers/` (extend an
existing GitHub Actions workflow rather than a new file).

### Backward compat during transition

mvmforge's feature-detect at
`mvmforge/crates/mvmforge/src/flake.rs:68-82` already falls back to
bundled wrappers if upstream symbols aren't present yet. This plan
ships the upstream symbols (factories from Plan 48 referencing
relocated wrappers); on the next mvmforge `flake.lock` bump, mvmforge
flips to upstream and the bundled copies become dead code. mvmforge's
cleanup PR (cross-repo plan §F) deletes them.

## Critical files

- New: `mvm/nix/wrappers/python-runner.py` (copied)
- New: `mvm/nix/wrappers/node-runner.mjs` (copied)
- New: `mvm/nix/wrappers/wasm-runner.sh` (copied)
- New: `mvm/nix/wrappers/README.md` (copied + updated)
- Modified: factory files from Plan 48 (path updates only)
- New: `mvm/tests/wrappers/` directory (test suite ported)
- Modified: CI workflow file in `.github/workflows/` to add the
  pytest lane (likely `nix.yml` or a new `wrappers.yml`).

## Acceptance

- `pytest mvm/tests/wrappers/` passes for all three runners.
- The factory smoke test from Plan 48 still passes after the path
  updates.
- mvmforge `just real-mvm-check` against the relocated copies runs
  green.

## Effort

~1 day. Pure mechanical file move + test port.

## Out of scope

- Wrapper logic changes. Deferred to Plan 52 (fd-3 control channel)
  which moves the envelope from stderr-marker to fd-3 framing.
- Adding a Rust runner. Deferred per mvmforge ADR-0015 (Rust SDK)
  Phase 2.
