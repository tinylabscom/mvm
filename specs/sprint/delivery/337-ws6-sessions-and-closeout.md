# Plan 337 — WS-6.3/6.5 (sessions) and WS-8.1: the plan is complete

**Delivered:** 2026-08-17
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Follows:** `337-ws6-tier-c-increment-1.md`

## First: the two open issues were already fixed

#2559 (Rust `host_port` accepts port 0) and #2558 (TypeScript machine wrapper
unbounded) were both closed by other sessions on 2026-08-16, while this work
was in flight. Verified against main rather than trusting the closed state:
`validate.rs:79` rejects port 0 for every language at one seam — the approach
the issue recommended — and `_machine.ts` now bounds `spawnSync` with
`timeout` + `maxBuffer` and classifies `ETIMEDOUT` / `ENOBUFS` separately, with
tests. Nothing to redo.

## Sessions — the choice, made explicit and tested

`sdks/typescript/src/_session.ts` completes Tier C. The WS-6.1 sizing found
that Python's `contextvars` + `Token` has no equivalent in `AsyncLocalStorage`,
which scopes to a *callback* rather than handing back a token, and that the two
available shapes are not interchangeable:

- `session(id, body)` — **chosen**. Visible for exactly the dynamic extent of
  `body`, including across `await`; concurrent sessions in different async
  tasks cannot see each other's.
- `using s = session(id)` over a module-level variable — closer to Python's
  call shape, but concurrent sessions clobber one another.

The first was taken because the second's failure mode is one session's context
leaking into another — a correctness bug, not an ergonomic one. That is not
asserted in prose only: a test runs two overlapping async bodies and checks each
observes only its own id, which is precisely the case the rejected shape fails.

The abandonment net is weaker than Python's by necessity — `FinalizationRegistry`
may never run and is not run at exit — so the callback shape carries a
`try/finally` instead. That is the stronger guard available, and another reason
the shape was chosen rather than a consolation for it. Teardown swallows its own
failure so it cannot mask a body exception, matching Python's `_teardown`, and
is covered by a test that throws from the body and asserts both the re-raise and
the stop.

`_remote.ts` now consults the active session and attaches `--session`, matching
Python's `_prepare_invoke`. Cross-workload dispatch through `workload_ref` opts
out: a session belongs to one workload and must not leak into a call against
another.

## The last divergence name

`current_recording_dict` was renamed to `current_recording`. The `_dict` suffix
encoded a Python-specific return type; the TypeScript counterpart
(`currentRecording`) returns a typed object and was internal only because
nothing had needed it from outside. Both surfaces now expose the same capability
under names that agree. A hard rename rather than an alias, per the project's
convention of not carrying shims.

## WS-8.1, and the plan closed

Both directional backlogs are empty. What remains in `surface_divergence.json`
describes differences rather than debt:

- `python_only_permanent_by_design` — `derive_schema` needs runtime type
  information TypeScript erases before the program runs; `SecretInArgWarning`
  is a warning type JavaScript does not have.
- `python_only_type_erased_in_typescript` — names that exist in TypeScript as
  `export type`, which `tsc` erases, so a runtime surface check cannot see them.

**Across Plan 337: `python_only_absent_from_typescript` went 30 → 0, and
`typescript_only_absent_from_python` went 2 → 0 and stayed there.**

## Verification

- `cargo +nightly fmt --all -- --check` — clean
- `check-stubs` — no drift
- Python **223 passed, 7 skipped**
- TypeScript **143 passed** (five new session tests), typecheck + build clean
- BDD **206 scenarios, 205 passed, 1 skipped**

Two BDD failures seen along the way were a stale target directory of my own
making — `mvmctl` and `xtask` had been built from the wrong working directory,
so the harness could not find them. Rebuilt in place; unrelated to the change.

## What Plan 337 ended up being

The plan opened by asking whether 29 names should be ported to TypeScript. The
answer turned out to be no on both counts: the number was wrong, and porting was
the wrong verb. What shipped is four Rust registries — env names, error
taxonomy, constructors, and the surfaces each is allowed to appear on — from
which both language SDKs are generated, plus a golden-IR document and a two-way
divergence gate that make the remaining differences describable rather than
accidental.
