# Machine-verb conformance audit (CLI + Python + TypeScript + Rust)

**Question:** does every SDK language drive the `mvmctl machine` surface
consistently, and is that parity *enforced* rather than hand-maintained?

**Source of truth:** the CLI `MachineAction` enum
(`crates/mvm-cli/src/commands/machine/mod.rs`). Every SDK is a thin argv
builder over `mvmctl machine <verb>`; the CLI parser is what actually admits
the argv, so it anchors the contract.

## What already exists (reuse-first finding)

A shared golden-argv contract is already in place — `sdks/machine-fixtures/*.argv`,
one argument per line, generated from / round-tripped by the CLI parser. Before
this audit, three surfaces asserted against it:

| Surface | Asserts fixtures? | Mechanism |
|---|---|---|
| CLI (source of truth) | yes | `sdk_machine_fixture` re-parses each fixture through `parse_owned` |
| Python | yes | `_fixture()` vs `_machine_*_argv` |
| TypeScript | yes | `readArgvFixture()` vs `machine*Argv` |
| **Rust SDK** | **NO — the gap** | builders existed (`machine_args()`), never checked |

The Rust `machine.rs` builders emit a pure argv (`MachineRunBuilder::machine_args`
et al.) but nothing asserted it matched the shared fixtures — so the Rust SDK
could silently drift from the CLI/Python/TS. **Closed** by
`crates/mvm-sdk/tests/machine_verb_conformance.rs`, which makes Rust a
first-class participant in the same contract, plus a CLI-anchor test that proves
every fixture is argv the CLI parser actually accepts.

## Verb coverage matrix (after closing the gaps)

Legend: ● driver+pure-argv-builder · ◐ driver only · ○ absent · 🔒 fixture-conformed

| CLI verb | Python | TypeScript | Rust `machine.rs` | Rust facade (`MvmClient`) | Shared fixture |
|---|---|---|---|---|---|
| run           | ● | ● | ● | ◐ (gated on admitted-boot) | 🔒 ×3 |
| create        | ● | ● | ● | ○ | 🔒 |
| check-artifact| ● | ● | ● | ○ | 🔒 |
| start         | ● | ● | ● | ○ | 🔒 |
| exec          | ● | ● | ● | ● | 🔒 |
| shell         | ● | ● | ● | ○ (excluded: interactive PTY) | 🔒 |
| stop          | ● | ● | ● | ● | 🔒 |
| ls / list     | ● | ● | ● | ● | 🔒 |
| logs          | ● | ● | ● | ● | 🔒 |
| inspect       | ● | ● | ● | ○ | 🔒 |
| rm            | ● | ● | ● | ○ | 🔒 ×2 |
| build         | ○ | ○ | ○ | ○ | — (image pipeline, no SDK surface by design) |
| console       | ○ | ○ | ○ | ○ | — (dev-only interactive PTY, out of scope) |

Every verb a user drives is now conformance-checked across all four surfaces.
Only `build` and `console` remain CLI-only, both by design.

## Gaps found — and what was done

1. **Rust SDK was not conformance-checked** against the shared fixtures.
   *Fixed* — Rust joined the contract (`machine_verb_conformance.rs`).

2. **Fixture coverage stopped at run/create/check-artifact.** *Fixed* —
   CLI-anchored fixtures added for `start`/`exec`/`shell`/`stop`/`ls`/`logs`/
   `inspect`/`rm`(+`rm --all`), each asserted in all four surfaces.

3. **`ls`/`logs` were absent from every bespoke SDK `Machine` class.** *Fixed* —
   added `Machine.ls()` + `Machine.logs()` (and pure argv builders) in Python,
   TypeScript, and Rust `machine.rs`.

4. **`inspect`/`rm` had no SDK surface anywhere.** *Fixed* — added
   `Machine.inspect()` and `Machine.rm()` (+ an all-targets `rm --all` builder)
   in all three SDKs. `build`/`console` left CLI-only by design.

5. **Real correctness bug surfaced by anchoring on the CLI:** all three SDKs
   emitted `stop --name <name>`, but the CLI `stop` takes a **positional** name
   and rejects `--name` — so `Machine(...).stop()` was broken in Python, TS, and
   Rust `machine.rs` (the facade already used the positional form). *Fixed* in
   all three; the CLI-anchor test (`every_shared_machine_fixture_parses_to_its_verb`)
   now proves every fixture is argv the CLI actually accepts, so this class of
   drift fails CI going forward.

6. **Two divergent Rust surfaces remain** — `machine.rs` (bespoke builder
   driver, now the full verb set) and the facade `SubprocessBackend`
   (`MvmClient`: list/run/stop/logs/exec). Convergence onto the `MvmClient`
   trait is **Plan 218's** scope, not this change; local `run` there is
   genuinely gated on the admitted-boot library seam (issue #1388). This audit
   quantifies the delta the plan closes.

## The harness (approach 1, across all languages)

`sdks/machine-fixtures/*.argv` (14 fixtures) is the single golden contract. Two
independent guards keep it honest:

- **CLI anchor** — `every_shared_machine_fixture_parses_to_its_verb` re-parses
  every fixture through the real CLI parser and asserts it maps to the verb its
  first line names. A fixture the CLI rejects (e.g. `stop --name`) fails here.
- **Per-language conformance** — each SDK asserts its pure argv builder emits
  the golden bytes, in its native runner:
  - **Rust** — `cargo test -p mvm-sdk --test machine_verb_conformance` (15 tests)
  - **Python** — `pytest sdks/python/tests/test_machine.py` (21 tests)
  - **TypeScript** — `vitest tests/machine.test.ts` (14 tests)

The Rust `fixture_coverage_is_accounted_for` tripwire audits the fixture set
against the Rust assertion set, so adding a fixture without wiring it into every
language fails closed.

Adding a fixture without adding the matching per-language assertion trips the
Rust coverage tripwire — the fixture set and the Rust assertion set are audited
against each other, so the harness fails closed on drift.
