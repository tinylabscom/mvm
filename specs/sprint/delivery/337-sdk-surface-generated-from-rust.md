# Plan 337 — WS-1 (spike) and WS-2 (Tier E)

**Delivered:** 2026-08-15
**Plan:** `specs/plans/337-sdk-surface-generated-from-rust.md`
**Stacked on:** `feat/sdk-bdd-coverage` (Plan 336 / PR 2501), which carries the
plan document and the s27 fixtures this builds on.

## WS-1 — the spike, and why it re-scoped the plan rather than stopping it

The plan asked whether a constructor manifest can be *extracted* from the Rust
`ctor` functions, by one of two mechanisms. Both were built against the real
`crates/mvm-sdk/src/ctor/` sources and scored against a criterion written down
**before** either existed: reproduce the *Python* signature of `python_deps` and
`dns_resolver`, including `tool="uv"`, `port=53`, keyword-only calling and the
`"pip-tools"` alias.

Both mechanisms work. Neither meets the criterion. Two results:

**1. The plan's "more precise" claim about the attribute mechanism is false.**
An attribute macro is invoked once per item and sees only that item's tokens, so
it cannot resolve `python_deps` → `python_deps_with(lockfile, PythonTool::Uv)`.
The whole-file `syn` parse holds every function at once and recovers that
default in a second pass. On the single axis where recovery from Rust was
possible at all, the "more precise" mechanism lost.

**2. The four remaining gaps are not parser failures.** `port=53`,
keyword-only, `1..=65535` and `"pip-tools"` are absent from the Rust source at
any level of effort, because Rust does not need them: `port: u16` *is* Python's
range check and `tool: PythonTool` *is* its enum check. Rust is the surface that
discharges those constraints **statically**; Python and TypeScript need runtime
checks precisely because they lack the types.

So the plan's two requirements — byte-compatible generated Python, and a
manifest extracted from the ctors — are mutually unsatisfiable. That is a
specification failure, not a tooling failure, which is why the WS-1.5 gate did
not fire: the gate exists to catch "the tooling won't work", and the tooling
works.

**Decision.** The manifest is authored declaratively in Rust and records
*constraints* rather than validation code, leaving each emitter to decide
whether a constraint is discharged by the target language's type system or needs
a runtime check. The Rust ctors stay hand-written — generating them would force
`-> Result` and wreck the prelude's composition for a ~50-line payoff inside a
shipping crate. `syn` is retained but re-scoped to a fail-closed **coverage
gate**, paired with a **golden-IR behavioural gate**, since coverage proves a
name is listed and only the golden document proves it still behaves as listed.

Dependency cost independently rules out the attribute mechanism: it needs a new
workspace member plus `inventory` inside `mvm-sdk`, which is
`crate-type = ["lib", "cdylib"]` and `dlopen`ed by both SDKs — link-section
registration across that boundary is an unbudgeted risk, and `inventory` is
currently dev-only via `cucumber`. `syn` in `xtask` costs zero shipped-closure
delta.

**Defect surfaced, not fixed here:** Rust's `host_port` accepts port `0`;
Python's rejects it. `u16` is not `1..=65535`. No signature-level gate would
ever catch this, which is the argument for the golden-IR gate above. Filed as
#2559.

Tier A is **not** descoped to a hand-port.

## WS-2 — Tier E, the proving ground

`crates/mvm-sdk/src/env.rs` declares each name once through a `macro_rules!`
that emits both a `pub const` and a `REGISTRY` row. `emit_sdk_env` writes
`schema/sdk-env-v0.json` (a JSON **instance**, not a schema);
`xtask/src/gen_sdk_surface.rs` renders `mvm/_env/vars.py` and
`src/_env/vars.ts`. Both are drift-gated by `check-stubs`, which already runs
twice — in `lint-policy` and inside the BDD suite.

`typescript_only_absent_from_python` is now `[]`.

**Scoped at five names, not four.** The fifth, `MVM_CLI_BIN_ENV`, is the best
justification for the tier: it was written out four times —
`mvm-sdk/src/machine.rs`, `mvm-sdk/src/facade.rs` (twice in one crate, the
second commented "shared with `machine.rs`" when it was a copy), `_cli.py`,
`_cli.ts` — and because all four agreed, **no gate could see it**. Counting
divergence entries would never have found it.

### Two things worth knowing

**The existing pipeline cannot emit a constant.** `json-schema-to-typescript`
produces `export type` only, and `tsc` erases types — so a "generated" constant
would be missing from the built ESM namespace and invisible to the s27 check,
which reads `Object.keys(mvm)` at runtime. The drift gate would have certified a
binding that does not exist. Hence a small hand-written emitter in xtask; its
determinism depends only on that function, so the pinned-generator rationale is
unaffected.

**Emitting every name into every language would have been dishonest.** Clearing
the last two entries from the divergence file was one line away, but TypeScript's
`_machine.ts` reads no environment at all, so `MVM_MACHINE_TIMEOUT_ENV` and
`MVM_MACHINE_MAX_OUTPUT_ENV` would have been dead exports certifying a parity
that does not exist. Each registry row instead declares the surfaces that
*read* it; a new s27 step checks that claim **in both directions** (declared ⇒
present, undeclared ⇒ absent), and a unit test pins the pair as
not-TypeScript. They remain in `python_only_absent_from_typescript` as a
**behaviour** gap, which is what they are.

### Pre-existing flake fixed in passing

`features/suites/s27_sdk/fixtures/typescript_live.mjs` called
`process_.wait()` without awaiting it. `wait()` returns a Promise and spawns
asynchronously while every other verb is `spawnSync`, so the recorded argv
non-deterministically showed `fs write` landing before `proc wait`. Measured on
the **unmodified base branch**: 9/20 correct. With the `await`: 30/30. This was
not introduced here — my change only perturbed the timing — but the s27 suite
now gates PRs, so it had to be fixed to get a reliable signal.

## Follow-up filed

TypeScript `_machine.ts` calls `spawnSync` with no `timeout` and no
`maxBuffer`: it can wait forever, and Node's 1 MiB `ENOBUFS` overflow is
reported as a spawn failure, where Python raises typed `TransportTimeout` /
`TransportOutputOverflow`. Filed as #2558. Deliberately not bundled — it is a behaviour
change to a shipped SDK, not env-name codegen.

## Verification

- `cargo +nightly fmt --all -- --check` — clean
- `cargo clippy --workspace --all-targets` — zero warnings
- `cargo nextest run --workspace` — green
- `cargo run -p xtask -- check-stubs` — no drift; **and** proven to fail
  (exit 1, naming the file) on a hand-edited generated constant
- `check-honesty`, `check-no-overclaim` — clean
- Python: **212 passed, 7 skipped, zero test-file edits** — the
  byte-compatibility bar
- TypeScript: 135 passed; `typecheck` and `build` clean
- BDD: 193 scenarios passed, including the new
  "every Rust-owned env-var name reaches the surfaces it claims"

## Not done

WS-3 – WS-5, WS-7, WS-8, and explicitly **WS-6** (Tier C, the ~1,165-line
remote-function surface).
