# Plan 337 — WS-3 (Tier A constructors generated)

**Delivered:** 2026-08-16
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Follows:** WS-1 + WS-2 (`337-sdk-surface-generated-from-rust.md`) and
WS-5 + WS-6.1 (`337-ws5-error-taxonomy.md`)

This is the workstream the WS-1 spike existed to enable, and the first real
test of its decision: Tier E's constants and Tier D's classes are flat, but a
constructor has parameters, defaults, runtime constraints and a target variant.

## What landed

`crates/mvm-sdk/src/ctor_registry.rs` declares all eight Tier A constructors
declaratively. `emit_sdk_ctors` serialises the registry;
`xtask/src/gen_sdk_surface.rs` renders `mvm/_ctors/generated.py` and
`src/_ctors/generated.ts`. The eight Python hand-copies are **deleted**;
`_dsl` re-exports the generated ones so every existing importer keeps working.
TypeScript gains all eight, which it never had.

The constraint vocabulary needed to cover Tier A is three cases — `NonEmpty`,
`IntExclusiveRange`, `EnumMember` (with aliases). Small enough to be worth the
machinery; large enough that no parser could have inferred it from Rust, which
is the WS-1 finding restated in working code.

## Three things worth knowing

**Generation removed a fragility, not just duplication.** The hand-written
Python named the numbered variant class directly — `_ir.NetworkDns3`,
`_ir.Dependencies1` — and `datamodel-codegen` renumbers those classes *and*
their `KindN` enums whenever the schema changes. The generated code resolves
the variant by discriminant, so neither number is written down anywhere. That
is a breakage class the hand-written surface carried and the generated one
cannot.

**Constraint messages are stored verbatim rather than derived.** The two enum
messages disagree in shape — `'uv' or 'pip-tools'` versus
`'pnpm' / 'npm' / 'yarn'` — and inventing a rule that produces both would be
fiction. Storing them keeps the generated Python byte-identical and makes the
inconsistency visible in the registry instead of hidden in two files.

**`kw_only` is Python-only**, recorded the way `ErrorBase::Warning` is:
TypeScript has no keyword-only parameters, so its emitter renders them
positionally. Declared rather than silently dropped.

## Evidence

Byte-compatibility was established **differentially**, not by inference. A
harness called each hand-written constructor and its generated twin across 26
cases — every valid path, both alias spellings (`pip-tools` and `pip_tools`),
the port boundaries (1, 65535, 0, 65536, −1), and every refusal — comparing the
constructed value structurally and the exception type and message verbatim.
**Zero differences.** Only then were the hand-copies removed, after which the
Python suite passed unchanged: **212 passed, 7 skipped, no test edits**.

WS-3.4 is the golden-IR behavioural gate the WS-1 decision called for, now
real: one `features/suites/s27_sdk/fixtures/ctor_golden.json`, both languages,
pinning built values *and* refusal messages. It earned its keep on first run —
it caught that Python's `{tool!r}` renders `'poetry'` where the first
TypeScript emitter used `JSON.stringify` and rendered `"poetry"`. Python is the
reference, so the emitter now renders a repr-alike and the two agree
byte-for-byte. A name-level comparison could not have seen that.

`python_only_absent_from_typescript` drops from 27 names to 19. What remains is
Tier C's machinery and the names that cannot be generated.

## Verification

- `cargo +nightly fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets` — zero warnings
- `cargo nextest run --workspace` — **11,955 passed**, no failures
- All 45 xtask gates from the CI Invariant job — run locally
- `check-stubs` — no drift on the new artifact
- Python **212 passed, zero test-file edits**, hand-copies removed
- TypeScript typecheck + build clean; all eight constructors present in the
  built ESM
- BDD **200 scenarios passed**, including the new Tier A golden scenario

## Not done

WS-4 (Tier B), WS-6.2–6.6 (Tier C), WS-7, WS-8.
