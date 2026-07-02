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
could silently drift from the CLI/Python/TS. **Closed here** by
`crates/mvm-sdk/tests/machine_verb_conformance.rs`, which makes Rust a
first-class participant in the same contract (6 tests, all green).

## Verb coverage matrix

Legend: ● driver+pure-argv-builder · ◐ driver only · ○ absent · 🔒 fixture-conformed

| CLI verb | Python | TypeScript | Rust `machine.rs` | Rust facade (`MvmClient`) | Shared fixture |
|---|---|---|---|---|---|
| run           | ● | ● | ● | ◐ (gated on admitted-boot) | 🔒 ×3 |
| create        | ● | ● | ● | ○ | 🔒 |
| check-artifact| ● | ● | ● | ○ | 🔒 |
| start         | ◐ | ◐ | ● | ○ | — |
| exec          | ◐ | ◐ | ● | ● | — |
| shell         | ◐ | ◐ | ● | ○ (excluded: interactive PTY) | — |
| stop          | ◐ | ◐ | ● | ● | — |
| ls / list     | ○ | ○ | ○ | ● | — |
| logs          | ○ | ○ | ○ | ● | — |
| inspect       | ○ | ○ | ○ | ○ | — |
| rm            | ○ | ○ | ○ | ○ | — |
| build         | ○ | ○ | ○ | ○ | — |
| console       | ○ | ○ | ○ | ○ (dev-only, out of facade) | — |

## Gaps found

1. **Rust SDK was not conformance-checked** against the shared fixtures.
   *Fixed* — Rust now asserts run/create/check-artifact against the golden argv.

2. **Fixture coverage stops at run/create/check-artifact.** `start`, `exec`,
   `shell`, `stop` have builders in all three SDKs but *no shared fixture*, so
   their argv is not cross-language conformance-checked. This is the next
   fixture batch to add (CLI-anchored, then a matching assertion in each SDK).
   The Rust `fixture_coverage_is_accounted_for` test names these four as the
   known-uncovered builders so the gap is executable, not just prose.

3. **`ls`/`list` and `logs` are absent from every bespoke SDK `Machine` class**
   (Python, TS, and Rust `machine.rs`). They exist *only* on the Rust facade
   `SubprocessBackend`. So an SDK user driving `Machine` cannot enumerate or
   tail machines — a real capability gap, not just a conformance one.

4. **`inspect`, `rm`, `build`, `console` have no SDK surface anywhere.** Likely
   intentional for `console` (dev-only interactive) and `build`, but `inspect`
   and `rm` are plausible lifecycle gaps worth a decision.

5. **Two divergent Rust surfaces.** `machine.rs` (bespoke builder driver:
   run/create/check-artifact/start/exec/shell/stop) and the facade
   `SubprocessBackend` (`MvmClient`: list/run/stop/logs/exec) cover *disjoint*
   verb sets. Convergence onto the `MvmClient` trait is Plan 218's scope; this
   audit quantifies the delta the plan has to close.

## The harness (approach 1, across all languages)

`sdks/machine-fixtures/*.argv` is the single golden contract. Each language
asserts its argv builder emits the golden bytes for the covered verbs, in its
native test runner:

- **Rust** — `cargo test -p mvm-sdk --test machine_verb_conformance` (6 tests)
- **Python** — `pytest` (`sdks/python/tests`, 15 machine tests)
- **TypeScript** — `vitest` (`sdks/typescript/tests/machine.test.ts`)
- **CLI** — `parse_owned` round-trip in `machine/mod.rs` tests (anchor)

Adding a fixture without adding the matching per-language assertion trips the
Rust coverage tripwire — the fixture set and the Rust assertion set are audited
against each other, so the harness fails closed on drift.
