# 332 — Runtime SDK parity repair + live-transport BDD

## What shipped

An audit of the runtime SDK across its three languages, the three defects it
turned up, and BDD coverage for the surface that had none.

### The runtime SDK works — with one packaging defect that made it not

The imperative `Sandbox` surface has two modes. Record mode replays the script
into a `Workload` IR. Live mode shells every operation to `mvmctl machine …`.
Both are wired end-to-end in Rust, Python and TypeScript, and the live path
drives exactly the verb sequence the CLI defines:

```
machine run -d --up-json --name <vm> --manifest <template> --ttl 1800s
machine proc start <vm> -- <argv>
machine proc wait <vm> <pid-token>
machine fs write <vm> <path> --mode 420
machine fs read <vm> <path> --offset 0 --length 16777216
machine fs ls <vm> <path> --json
machine stop <vm> --yes
```

Python and TypeScript emit that trace byte-identically.

The defect: `@runmvm/mvm` is `"type": "module"` and `tsc` emits ESM, but
`_sandbox.ts` and `_machine.ts` reached for node builtins through `require()`
at 16 call sites. `require` does not exist in ESM, so every host-side entry
point — `Machine.run` and every sibling verb, `Sandbox.create` in live mode,
every fs/proc operation — threw `ReferenceError: require is not defined` for
anyone consuming the published package.

The 132-test vitest suite never saw it, because vitest runs the *sources*
through a module runner that supplies CJS interop. `_hostsvc.ts` had already
hit this and solved it with `createRequire`; the fix never propagated. Builtins
are now imported statically; `koffi` stays lazy behind `createRequire` because
it is a native addon.

### The golden argv corpus was shadowed

`tests/machine-fixtures/*.argv` binds the CLI and all three SDKs: the CLI
parses every fixture with the real clap parser, the Rust SDK asserts its
builders reproduce it. A second copy at `crates/tests/machine-fixtures/` was
what Python (`parents[4]`) and TypeScript (a cwd-relative join) actually
resolved to — both land on `crates/`, not the repo root.

Nothing anchored the shadow and it had drifted, so both language suites were
red on main. Repointed both at the canonical corpus, resolved from the test
file rather than the process cwd, and deleted the shadow.

The drift hid a real gap: `machine start --image/--cpus/--memory` reached the
Rust builder but never the language SDKs. Added to both.

### Coverage tripwires

Rust had `fixture_coverage_is_accounted_for`; the language SDKs had nothing, so
a new fixture went unenforced in two of three languages. Each language now has
the equivalent, and `xtask check-single-fixture-corpus` keeps the corpus
singular.

### BDD

`features/suites/s27_sdk/runtime_live_transport.feature` — six scenarios over
one recording `mvmctl` double shared by both languages:

- the live argv trace matches a golden session, per language
- Python and TypeScript produce identical traces
- every recorded invocation names a `machine` verb the CLI defines
- a sealed machine refuses `commands.start` and `files.write`, and
  `MVM_SDK_MODE=plan` / an unknown mode are rejected — with nothing reaching
  the CLI in any of those cases

The fixtures import the *built* artifacts, not the sources. That is what makes
these scenarios able to see the ESM defect at all.

## Verification

| gate | before | after |
| --- | --- | --- |
| `cargo nextest run -p mvm-sdk` | 345 passed | 345 passed |
| `pytest` (sdks/python) | 209 passed, **1 failed** | 212 passed, 7 skipped |
| `vitest run` (sdks/typescript) | 132 passed, **1 failed** | 135 passed |
| conformance (`--features bdd`) | 49 features | 55 features, 188 scenarios, 187 passed, 1 skipped |
| `cargo clippy` (conformance + xtask, all targets) | — | clean |
| `xtask check-conformance` / `check-claim-catalog` / `check-no-spec-refs-in-comments` / `check-single-fixture-corpus` | — | clean |

Both new tripwires and the new xtask gate were confirmed to go red when the
condition they guard is reintroduced.

`cargo nextest run --workspace`: 11603 tests, 11601 passed, 2 failed, 26
skipped. Both failures are in `mvm-agentd::entrypoint_execute` and are
pre-existing on the base commit, not caused by this work — the only Rust this
branch touches is `crates/mvm-conformance/tests/` and `xtask/src/`, and
`mvm-agentd` depends on neither:

- `test_execute_wrapper_cannot_forge_an_agent_gap_record_on_fd3` — passes when
  re-run isolated; parallel-execution flake.
- `test_execute_stdout_cap_prunes_and_marks_a_gap_without_killing_the_wrapper`
  — fails isolated too (`expected one stdout gap, got []`). A real red test on
  main, unrelated to the SDK. No open issue found.

## Deferred

The Python and TypeScript public surfaces have diverged: 33 shared names, 38
Python-only, 18 TypeScript-only. Two problems are mixed together — TypeScript
exporting internals (`LiveTransport`, `parseUpEnvelope`,
`deriveAttachedBuildMode`, `flushRecordingToOutPath`, `currentRecording`,
`SandboxCommands`, `SandboxFiles`) and TypeScript missing real Python surface
(`func`, `session`, `egress`, the `dns_*` trio, `addon_use`, `host_port`, the
`*_deps` trio, `derive_schema`, `warm_process`, `workload_ref`,
`current_session_id`, `RemoteFunction`).

Separating erased-at-runtime type exports from genuine gaps needs a decision
about which surface is canonical, so it is tracked as WS-G in
`specs/plans/332-sdk-parity-and-bdd-coverage.md` rather than guessed at.
