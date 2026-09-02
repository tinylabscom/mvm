# Plan 336 — Runtime SDK parity repair + BDD coverage

Backing: shipped-source
Validation: check-two-surfaces

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

### Defect 6 — the published TypeScript SDK throws on every host-side call

`@runmvm/mvm` is `"type": "module"` and `tsc` emits ESM, but `_sandbox.ts` and
`_machine.ts` reached for node builtins with `require()` — 16 call sites. In ESM
`require` is not defined, so **every** host-side entry point (`Machine.run` and
every sibling verb, `Sandbox.create` in live mode, and each fs/proc operation)
threw `ReferenceError: require is not defined` for anyone consuming the built
package.

The 132-test vitest suite never saw it: vitest runs the TypeScript *sources*
through a module runner that supplies CJS interop. The defect only exists in the
emitted artifact. `_hostsvc.ts` had already hit this and solved it correctly with
`createRequire` — that fix just never propagated.

Fixed by importing the builtins statically. `koffi` stays lazy behind
`createRequire`: it is a native addon and deferring its load is deliberate. The
new live-transport scenarios run the built ESM under plain `node`, which is what
keeps this fixed.

### Defect 7 — the Python and TypeScript public surfaces have diverged

Comparing `mvm.__all__` against the TypeScript namespace's runtime keys
(normalising case convention) gives 33 shared names, 38 Python-only and 18
TypeScript-only. Two distinct problems are mixed together:

- TypeScript exports internals that were never meant to be public:
  `LiveTransport`, `parseUpEnvelope`, `deriveAttachedBuildMode`,
  `flushRecordingToOutPath`, `currentRecording`, `SandboxCommands`,
  `SandboxFiles`.
- TypeScript is missing real Python surface: `func`, `session`, `egress`,
  `dns_none` / `dns_resolver` / `dns_system`, `addon_use`, `host_port`,
  `no_deps` / `node_deps` / `python_deps`, `derive_schema`, `warm_process`,
  `workload_ref`, `current_session_id`, `RemoteFunction`.

Some of the Python-only names are erased-at-runtime type exports and are not
real divergence; separating those from the genuine gaps needs a decision about
which surface is canonical, so it is split out rather than guessed at here.

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

### WS-D — fix the ESM packaging defect

- [x] D1. Import node builtins statically in `_sandbox.ts` / `_machine.ts`;
      keep `koffi` lazy behind `createRequire`
- [x] D2. `npm run typecheck` and `npm run build` clean
- [x] D3. Built artifact exercised under plain `node`, not only under vitest

### WS-E — BDD coverage for the live runtime surface

- [x] E1. `recording-mvmctl` — one CLI double shared by both languages,
      capturing each invocation's argv as JSON
- [x] E2. `python_live.py` / `typescript_live.mjs` — the same Sandbox session in
      both languages, driving the built artifacts
- [x] E3. `runtime_live_transport.feature` — the argv trace matches a golden
      session, both languages produce identical traces, and every invocation
      names a `machine` verb the CLI defines
- [x] E4. Sealed-machine refusals: `commands.start` and `files.write` refused,
      `MVM_SDK_MODE=plan` and an unknown mode rejected, and nothing reached the
      CLI in any of those cases
- [x] E5. No registration needed — `check-conformance` gates CONFORMANCE.md
      against the claim model, not the feature-file set; the new suite is picked
      up by the runner's directory walk. Gate confirmed clean.

### WS-H — make the BDD suite gate a PR (Defect 8)

`bdd.yml` was only ever called from `release.yml`, `publish-crates.yml`,
`publish-sdk.yml` and `kernel-build.yml`, all release/tag-triggered. On a pull
request `ci.yml` compiled the step definitions (`clippy --features bdd`) and ran
`--test meta`, but never executed a single Gherkin scenario. Every scenario in
`features/suites/` — the six added here and the pre-existing s27 SDK ones —
could go red and still merge green. That is how both Defect 1 and Defect 6
survived.

- [x] H1. `scope` job publishes a second `bdd` output, fail-closed alongside
      `code`
- [x] H2. `bdd-conformance` lane calls the same reusable `bdd.yml` the release
      path calls, so the PR gate and the release gate cannot drift
- [x] H3. Filter scoped to what the scenarios actually exercise:
      `crates/mvm-sdk/`, `crates/mvm-cli/`, `crates/mvm-conformance/`,
      `features/`, `tests/machine-fixtures/`, the two workflow files, the
      Justfile
- [x] H4. Folded into the already-required `Test` aggregate, matched against its
      own scope — no branch-protection change needed
- [x] H5. Classifier exercised against real and synthetic change sets: fires on
      SDK / CLI / corpus / feature edits, skips on docs-only and on an
      unrelated crate

Deliberately narrower than the suite's full reach: scenarios over egress,
snapshots and verified boot are driven by crates outside this filter and stay
covered only by the release-tag lane. Widening it is a call about PR latency,
not an oversight.

### WS-G — surface divergence (Defect 7)

Measured precisely rather than in aggregate. Of the original 38 Python-only
names, 12 are `export type` in TypeScript — erased by tsc, so absent at runtime
while genuinely present in the API. Of the 18 TypeScript-only names, 9 exist in
Python too but only inside the private `_hostsvc` module.

That leaves two decidable problems and one that is a feature port:

- [x] G1. Stop exporting the 7 internals — `LiveTransport`, `SandboxCommands`,
      `SandboxFiles`, `currentRecording`, `deriveAttachedBuildMode`,
      `flushRecordingToOutPath`, `parseUpEnvelope`. The tests that reached them
      through the package index now import the owning module, which is what
      testing an internal is supposed to look like.
- [x] G2. Export the 9 host-service errors from Python's root. TypeScript had
      this right: `mvm.audit.emit(...)` and `mvm.host.time()` raise them, so a
      caller has to be able to name what it catches, and `except
      mvm.HostServiceError` was impossible.
- [x] G3. Gate it. `surface_divergence.json` records the reviewed difference and
      a BDD scenario fails when reality stops matching it — confirmed to go red
      when a single internal is re-exported.
- [x] G4. Scoped out into Plan 337, "Generate the SDK surface from Rust
      instead of porting it".
      Investigating it changed the shape of the answer: `egress`, `host_port`,
      the `dns_*` trio and the `*_deps` trio already exist in
      `mvm_sdk::ctor` and are hand-copied into Python, so porting them to
      TypeScript would make three copies rather than two. Plan 337 generates
      that layer from Rust instead, which also deletes the Python copies.
- [x] G5. Fix the parity gate's normalization. Folding case collapsed the class
      `Session` onto the function `session` — both SDKs export both — hiding one
      of each pair and able to report parity when only half had been added. Keys
      are now category-scoped; the absent count corrected from 27 to 29.

Result: TypeScript-only divergence went from 18 names to 2
(`MVM_SDK_MODE_ENV`, `MVM_SDK_OUT_PATH_ENV`); shared surface went from 33 to 42.

### WS-I — two `mvm-agentd` flakes surfaced by the workspace run

Not SDK work, but surfaced by verifying this branch and fixed rather than
deferred: `test_execute_stdout_cap_prunes_and_marks_a_gap_without_killing_the_wrapper`
and `test_execute_wrapper_cannot_forge_an_agent_gap_record_on_fd3` both assert
on output a still-running wrapper produced, under a 300 ms deadline that has to
cover fork/exec plus a first write plus one poll.

- [x] I1. Root cause established by construction — a 1 ms deadline reproduces
      the reported `gaps=0 stdout_len=0` on every run, with the retention path
      uninvolved
- [x] I2. Both given a deadline sized to the property; crate suite time
      unchanged
- [x] I3. Ten runs of each under 16-way CPU saturation pass
- [x] I4. The neighbouring timeout test left alone — it asserts only that the
      timeout fired, never on captured output

### WS-F — gates and docs

- [x] F1. `cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`
- [x] F2. `cargo nextest run --workspace` + `cargo test --workspace --doc`
- [x] F3. Python + TypeScript suites green
- [x] F4. `specs/REFACTOR-STATUS.md` rollup updated
- [x] F5. Delivery note under `specs/sprint/delivery/`

### WS-J — post-landing guest RPC refusal repair

- [x] J1. Route filesystem and process unary calls through the shared response
      contract so universal policy refusals remain typed errors.
- [x] J2. Preserve the standard-profile default while propagating an explicit
      `mvmctl run --mode live --profile dev` choice into the nested SDK launch.
- [x] J3. Keep Python and TypeScript profile validation, live argv, and refusal
      behavior in parity, including the generated environment-name registry.
- [x] J4. Record the issue closeout in
      `specs/sprint/delivery/2887-guest-rpc-refusals.md`.
