# Plan 337 — WS-4 (Tier B constructors)

**Delivered:** 2026-08-16
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Follows:** WS-3 (`337-ws3-tier-a-constructors.md`)

Tier B is two constructors Rust did not have. The plan's ordering — add them to
`mvm_sdk::ctor` first, so Rust is the complete surface, then generate — is what
made the interesting result visible.

## `warm_process`: generated

Added to `crates/mvm-sdk/src/ctor/concurrency.rs` with a `ConcurrencyExt`
chained-setter trait, matching the `NetworkExt` / `EntrypointExt` idiom rather
than growing a five-argument function. Then declared in the constructor
registry, which needed exactly one extension: a nullable default, for
`max_queue_depth`.

Verified differentially against the hand-written Python twin over six cases
before the hand-copy was deleted.

## `addon_use`: hand-written, deliberately

Expressing it declaratively would need four capabilities no other constructor
uses:

1. a cross-parameter XOR constraint (`version` or `path`, exactly one);
2. a **branching target** — a different `AddonRef` variant depending on which
   argument was passed;
3. a derived string field, `addons.mvm.io/{name}`;
4. default-if-absent, for `sha256` and `params`.

Building a mini-language for one function is the over-abstraction the project
guidelines warn against, so it stays hand-written in Python and TypeScript. The
WS-1 standard still applies and is met: a copy is dangerous when *nothing
checks it*, and this pair is pinned against each other by the s27 golden IR
document, refusal message included.

**Rust does not have the XOR at all.** `addon_use_registry` and
`addon_use_local` are two functions, so "both or neither" cannot be written.
That is the WS-1 thesis a third time — the dynamic surfaces need a runtime
check precisely where Rust makes the state unrepresentable.

## Two defects the new coverage found

**A regression WS-3 introduced, which 212 tests missed.** Deleting the
hand-written `node_deps` also removed the module-level `_UNRESOLVED_SHA256`
declared immediately after it, leaving `addon_use` raising `NameError` on every
call. The Python suite still passed in full, because **nothing in it called
`addon_use`**. The cross-language golden fixture caught it on first run.

The fix is the constant restored; the *lesson* is the coverage gap, so
`tests/test_ctors.py` now covers both Tier B constructors and spot-checks Tier
A. It was confirmed to fail without the fix (2 failed) and pass with it — a
Python break should fail the Python suite, not only the BDD layer.

**An accidental public-API widening.** The first `_addon.ts` exported
`UNRESOLVED_SHA256`, where Python's is `_`-prefixed and private. The
surface-divergence gate flagged a new TypeScript-only name immediately; it is
now module-private, matching its twin. That gate is two-way for exactly this
reason.

## Verification

- `cargo +nightly fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets` — zero warnings
- `check-stubs` — no drift
- Python **223 passed, 7 skipped** (up from 212: the new constructor tests)
- TypeScript typecheck + build clean
- BDD **200 scenarios passed**, golden document covers Tier A and Tier B in
  both languages
- `python_only_absent_from_typescript`: 19 → 17; everything remaining is Tier C
  machinery, its error taxonomy, or Tier F's `derive_schema`

## Not done

WS-6.2–6.6 (Tier C), WS-7, WS-8.
