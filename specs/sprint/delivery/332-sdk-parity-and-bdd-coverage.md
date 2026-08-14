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

### The BDD suite did not gate a PR

`bdd.yml` was only ever called from release/tag-triggered workflows. On a pull
request `ci.yml` compiled the step definitions and ran `--test meta`, but never
executed a scenario — so every scenario under `features/suites/`, including the
pre-existing SDK ones, could go red and merge green. That is how both the
shadowed corpus and the ESM defect survived.

`ci.yml` now carries a `bdd-conformance` lane calling the same reusable
workflow the release path calls, gated on a second fail-closed `scope` output
and folded into the already-required `Test` aggregate. The filter covers
`crates/mvm-sdk/`, `crates/mvm-cli/`, `crates/mvm-conformance/`, `features/`,
`tests/machine-fixtures/`, the two workflow files and the Justfile — verified
to fire on each and to skip docs-only and unrelated-crate changes.

It is narrower than the suite's reach on purpose: egress, snapshot and
verified-boot scenarios are driven by crates outside the filter and remain
release-tag only.

## Verification

| gate | before | after |
| --- | --- | --- |
| `cargo nextest run -p mvm-sdk` | 345 passed | 345 passed |
| `pytest` (sdks/python) | 209 passed, **1 failed** | 212 passed, 7 skipped |
| `vitest run` (sdks/typescript) | 132 passed, **1 failed** | 135 passed |
| conformance (`--features bdd`) | 49 features | 55 features, 188 scenarios, 187 passed, 1 skipped |
| `cargo clippy` (conformance + xtask, all targets) | — | clean |
| `xtask check-conformance` / `check-claim-catalog` / `check-no-spec-refs-in-comments` / `check-single-fixture-corpus` | — | clean |
| `cargo test --workspace --doc` | — | 17 crates, 6 passed, 0 failed, 8 ignored |
| `cargo nextest run -p xtask -p mvm-agentd` | — | 1334 passed |

Both new tripwires and the new xtask gate were confirmed to go red when the
condition they guard is reintroduced.

### Two `mvm-agentd` flakes, root-caused and fixed

The first workspace run surfaced two failures in `mvm-agentd::entrypoint_execute`,
both pre-existing on the base commit — the SDK work touches no Rust that
`mvm-agentd` depends on. They are fixed here rather than left for later, because
they share one cause and it is a cause worth naming.

An early reading of this called one of them "a real red test on main" that
"fails isolated too". That was one sample. Repeated runs put it near 20% under
load and green on an idle machine; neither test is deterministically red.

Both assert on output a *still-running* wrapper produced, under a 300 ms
deadline. That deadline has to cover fork/exec of the wrapper binary, its first
4 KiB write, and one 10 ms poll. Under load it does not, and the failure
presents as `gaps=0 stdout_len=0` — which reads as though retention broke, when
in fact the child never ran.

Established by construction, not inference: dropping the deadline to 1 ms
reproduces `gaps=0 stdout_len=0` on every run. The retention path is not
involved. The wrapper writes 4 KiB blocks against a 1 KiB bound, so the first
successful write always breaches the cap; an empty capture can only mean no
write happened.

Both now use a deadline sized to the property they test. The crate suite time
is unchanged — these wrappers never exit, so the deadline is the test's
runtime, and the crate's slowest test already sat above it. Ten runs of each
under 16-way CPU saturation pass; the same loop reproduced the failure before.

This is the same defect class an earlier commit named when it stopped the
result-oriented tests in this file using a spawn deadline as an assertion.
These two were left out of that pass because they genuinely need the `Timeout`
outcome — but needing the timeout does not mean racing it.

### Surface divergence, measured and mostly closed

The aggregate number was misleading. Of 38 Python-only names, 12 are
`export type` in TypeScript — erased by tsc, present in the API. Of 18
TypeScript-only names, 9 exist in Python but only inside private `_hostsvc`.

Two decidable problems, both fixed:

- TypeScript exported 7 internals (`LiveTransport`, `SandboxCommands`,
  `SandboxFiles`, `currentRecording`, `deriveAttachedBuildMode`,
  `flushRecordingToOutPath`, `parseUpEnvelope`). Unexported; the tests that
  reached them through the package index now import the owning module.
- Python could not name its own host-service failures: `mvm.audit.emit(...)`
  raises `NotBoundError`, but `except mvm.HostServiceError` did not resolve.
  All 9 are now exported from the root, matching TypeScript.

TypeScript-only divergence: 18 names → 2. Shared surface: 33 → 42.

`surface_divergence.json` now records the reviewed remainder and a BDD scenario
fails when reality stops matching it — confirmed red when one internal is
re-exported.

## Deferred

27 names remain genuinely absent from TypeScript, and porting them is a feature
port rather than a parity cleanup: the whole `@mvm.func` remote-invocation
surface (`func`, `session`, `Session`, `RemoteFunction`, `current_session_id`,
`workload_ref`, `WorkloadRef`, `derive_schema`, `warm_process` and their error
taxonomy) plus the declarative network/deps helpers (`egress`, the `dns_*`
trio, the `*_deps` trio, `addon_use`, `host_port`).

That needs product intent, so it is tracked as WS-G4 in
`specs/plans/332-sdk-parity-and-bdd-coverage.md`. The gate pins the current
divergence in the meantime, so it cannot widen unnoticed.
