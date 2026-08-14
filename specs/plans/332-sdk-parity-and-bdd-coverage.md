# Plan 332 — Runtime SDK parity repair + BDD coverage

**Status: IN PROGRESS**
**Opened:** 2026-08-14

## Why

An audit of `crates/mvm-sdk` (Rust core + Python + TypeScript language SDKs)
found the runtime SDK's cross-language argv contract is not actually gated on
the Python and TypeScript legs, and that the BDD suite covers only three of the
SDK's surfaces.

Measured on `origin/main` @ `b26496f2b`:

| suite | result |
| --- | --- |
| `cargo nextest run -p mvm-sdk` | 345 passed, 0 failed |
| `python3 -m pytest` (sdks/python) | 209 passed, **1 failed**, 7 skipped |
| `npx vitest run` (sdks/typescript) | 132 passed, **1 failed** |

Both language failures are the same defect.

### Defect 1 — the golden argv corpus is shadowed

`tests/machine-fixtures/*.argv` is the shared golden contract: the CLI anchors
it against the real clap parser
(`mvm_cli::commands::machine::tests::every_shared_machine_fixture_parses_to_its_verb`)
and the Rust SDK asserts its builders reproduce it
(`crates/mvm-sdk/tests/machine_verb_conformance.rs`). That makes the corpus mean
"argv the real CLI accepts".

A second, divergent copy exists at `crates/tests/machine-fixtures/`. Nothing
anchors it. Both language SDKs resolve to it:

- Python `tests/test_machine.py::_fixture` — `Path(__file__).parents[4]` from
  `crates/mvm-sdk/sdks/python/tests/` lands on `crates/`, not the repo root.
- TypeScript `tests/machine.test.ts::readArgvFixture` — `path.join("..","..","..")`
  from `crates/mvm-sdk/sdks/typescript/` lands on `crates/`, not the repo root.

The shadow has already drifted: `run-admission.argv` says `/workspace` where the
canonical says `/work` (today's failure), and it is missing `start-image.argv`
entirely.

### Defect 2 — `machine start --image` never reached the language SDKs

`start-image.argv` was added to the canonical corpus by #2469. The Rust builder
grew `.image()/.cpus()/.memory()`; `_machine_start_argv` (Python) and
`machineStartArgv` (TypeScript) did not. The shadow corpus hid this — the
language suites never saw the new fixture.

### Defect 3 — no coverage tripwire outside Rust

`machine_verb_conformance.rs::fixture_coverage_is_accounted_for` fails when a
fixture gains no Rust assertion. Python and TypeScript have no equivalent, so a
new fixture is silently unenforced in two of three languages.

### Defect 4 — `fake-mvm` has drifted from the CLI surface

`crates/mvm-sdk/sdks/python/tests/fixtures/fake-mvm` still routes top-level
`fs`, `proc`, `ls`, `down`, `pause`, `resume`, `set-ttl`, `snapshot`, `metrics`.
The live runtime SDK calls `machine fs …`, `machine proc …`, `machine ls --json`
and `machine stop`; the stub's `machine` case accepts only
`run|create|start|exec|shell|stop|check-artifact|ls|inspect|rm` and would reject
`fs`/`proc`/`cp`/`forward`. Live-mode tests each hand-roll their own stub
instead, so there are three CLI doubles and none is checked against the real
parser.

### Defect 5 — BDD covers three surfaces out of ten

`features/suites/s27_sdk/sdk_contract.feature` covers decorator emit, runtime
record-mode ops, and codegen drift. Uncovered: live-mode transport, the
`Machine` verb surface, filesystem ops, process ops, port forward, the sealed
(prod) refusal path, `MVM_SDK_MODE` resolution, recording caps, and Python↔TS
public-surface parity.

## Non-goals

- Booting a real microVM from a BDD scenario. The s27 suite stays hermetic;
  live-tier boot is covered by s5/s26.
- Changing the runtime SDK's public API shape.

## Workstreams

### WS-A — collapse the shadow fixture corpus

- [x] A1. Repoint Python `_fixture` at the repo-root `tests/machine-fixtures`
- [x] A2. Repoint TypeScript `readArgvFixture` at the repo-root corpus, resolved
      from the test file rather than the process cwd
- [x] A3. Delete `crates/tests/machine-fixtures/`
- [x] A4. `xtask check-two-surfaces`-style gate: fail if a second
      `machine-fixtures` directory reappears anywhere in the tree
- [x] A5. Both language suites green against the canonical corpus

### WS-B — restore cross-language `machine start --image`

- [x] B1. Python `_machine_start_argv` accepts `image` / `cpus` / `memory`
- [x] B2. TypeScript `machineStartArgv` accepts `image` / `cpus` / `memory`
- [x] B3. Both assert against `start-image.argv`

### WS-C — coverage tripwires in every language

- [x] C1. Python test enumerating `tests/machine-fixtures/*.argv` and failing on
      any fixture with no assertion
- [x] C2. TypeScript equivalent
- [x] C3. Confirm each tripwire goes red when a fixture is added without an
      assertion

### WS-D — one CLI double, anchored on the real parser

- [ ] D1. Teach `fake-mvm` the `machine {fs,proc,cp,forward}` routes the live
      SDK actually calls; drop the retired top-level routes
- [ ] D2. Record every argv the SDK emits under live mode
- [ ] D3. Assert each recorded argv parses under the real `mvmctl` clap parser,
      the same anchor the machine fixtures already have

### WS-E — BDD coverage for the uncovered SDK surface

- [ ] E1. `runtime_live_transport.feature` — live mode emits the expected
      `mvmctl machine …` argv sequence, Python and TypeScript
- [ ] E2. `machine_verbs.feature` — the `Machine` surface, all three languages,
      against the canonical corpus
- [ ] E3. `sandbox_fs_proc.feature` — filesystem and process ops round-trip
- [ ] E4. `sdk_refusals.feature` — sealed-tier `commands.start` refusal,
      `MVM_SDK_MODE=plan` rejection, recording caps
- [ ] E5. `sdk_surface_parity.feature` — Python and TypeScript export the same
      public surface
- [ ] E6. Register the new suites in `model/claims.toml` / the conformance
      runner as required by `xtask check-conformance`

### WS-F — gates and docs

- [ ] F1. `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`
- [ ] F2. `cargo nextest run --workspace` + `cargo test --workspace --doc`
- [ ] F3. Python + TypeScript suites green
- [ ] F4. `specs/REFACTOR-STATUS.md` rollup updated
- [ ] F5. Delivery note under `specs/sprint/delivery/`
