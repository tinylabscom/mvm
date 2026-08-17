# Plan 337 — WS-7 (Tier F decision) and WS-8 (close-out)

**Delivered:** 2026-08-16
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Follows:** WS-3 + WS-4 (`337-ws3-tier-a-constructors.md`,
`337-ws4-tier-b-constructors.md`)

## WS-7 — option 2 confirmed, and it was not free

`derive_schema` builds a JSON Schema from a Python function's type hints.
TypeScript erases types before the program runs, so at the moment a decorator
could inspect a function, `(name: string) => string` and `(name: any) => any`
are the same value. The plan offered three options and recommended (2):
callers pass the schema explicitly.

That recommendation stands. Compile-time generation (1) would force a build
step into every consumer's project, and a validator library (3) adds a
dependency and a second way to spell a type — both speculative until a real
TypeScript `@mvm.func` user exists, which is Tier C's problem, not this one.

**One correction to the plan's own text.** Option 2 was described as "No new
machinery". That was wrong. TypeScript's `entrypoint_function` accepted no
schema arguments at all, so the recommended option was not worse ergonomics —
it was impossible. The IR has carried `args_schema` and `return_schema` all
along; only the constructor omitted them. Both are now accepted, which is what
makes the decision exercisable rather than notional.

The difference is documented where someone meets it: the TypeScript SDK's own
README, under "Call schemas", next to the constructor they are already reading
about. It gives the reason rather than the absence.

`surface_divergence.json` gains a third bucket,
`python_only_permanent_by_design`. The two existing buckets both mean "not done
yet" in some form; this one never will be, and folding it into the backlog
would misreport the backlog's size. It is distinct from
`python_only_type_erased_in_typescript`, which covers names that *do* exist in
TypeScript but only as `export type`.

## WS-8 — close-out, with 8.1 honestly open

**8.2 holds.** Every generated artifact is regenerated and byte-compared by
`check-stubs`: the four schema-backed stub sets plus `sdk-env-v0`,
`sdk-errors-v0` and `sdk-ctors-v0`. It runs twice — in `lint-policy` and inside
the BDD suite — and each new artifact was *shown* to fail the gate on a
hand-edit rather than assumed to.

**8.1 does not, and claiming otherwise would be false.** The target is a
divergence file holding only Tier F plus the type-erased set. It also holds 16
names: Tier C's remote-function machinery and the eight error types only Tier C
raises. Those close when WS-6 lands — the error taxonomy deliberately waits for
it, because generating the types first would export classes nothing in
TypeScript can throw. Everything 8.1 can close without Tier C is closed.

## Where the plan stands

| | |
| --- | --- |
| WS-1 mechanism spike | done — extraction rejected, declarative manifest chosen |
| WS-2 Tier E env names | done |
| WS-3 Tier A constructors | done — 8 generated, Python hand-copies deleted |
| WS-4 Tier B | done — `warm_process` generated, `addon_use` hand-written and pinned |
| WS-5 Tier D errors | host-services half done; the 8 Tier C errors land with WS-6 |
| WS-6.1 Tier C sizing | done — declared-subset recommendation recorded |
| WS-6.2–6.6 Tier C | **open**, and wants a scoping decision first |
| WS-7 Tier F | done |
| WS-8 close-out | done except 8.1, which Tier C gates |

Divergence across the whole plan: `python_only_absent_from_typescript` 30 → 16;
`typescript_only_absent_from_python` 2 → 0, and it has stayed there.

## Verification

- `cargo +nightly fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets` — zero warnings
- `cargo nextest run --workspace` — 11,971 passed
- `cargo test --workspace --doc` — clean
- All 45 xtask gates from the CI Invariant job
- `check-stubs` — no drift across all seven artifacts
- Python 223 passed; TypeScript typecheck + build clean
- BDD 200 scenarios passed

## Open, and needing a decision rather than more code

WS-6.2–6.6. The WS-6.1 sizing found `MVM_NO_VM=1` unportable (it derives argv
from Python function introspection, which JavaScript cannot do at all), session
scoping a choice between correct async isolation and Python-like ergonomics,
and the `weakref.finalize` abandonment net degrading to a best-effort
`FinalizationRegistry`. The recommendation on record is to ship TypeScript Tier
C as a declared subset. That is a scoping call, not an implementation detail:
it determines whether WS-6 means "port Tier C" or "port the portable half and
declare the rest".
