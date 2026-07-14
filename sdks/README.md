# SDKs

Language SDKs for the mvm workload toolchain. Each SDK has two layers
per ADR-0003 (mvmforge-origin):

- **Lower layer** — IR types (`Workload`, `App`, `Source`, …)
  generated from a single Rust-owned JSON Schema. Never hand-edit.
- **Upper layer** — hand-authored declarative DSL (`@mvm.func` /
  `@mvm.app` in Python; `mv.func(...)` higher-order functions in
  TypeScript) and transport (subprocess to `mvmctl invoke`, or socket
  to `mvmd` once that wiring lands). Hand-edited.

## Machine lifecycle wrappers

Python, TypeScript, and Rust expose machine-oriented lifecycle wrappers that
mirror the beginner `mvmctl machine ...` command group. These wrappers are thin
host automation surfaces: they route through `mvmctl machine ...` instead of
reimplementing OCI pull, admission, artifact verification, networking, receipts,
audit, or persistent machine state.

- Python: `mvm.Machine.run/create/check_artifact/start/exec/shell/stop`
- TypeScript: `Machine.run/create/checkArtifact/start/exec/shell/stop`
- Rust: `mvm_sdk::{MachineRun, MachineCreate, MachineCheckArtifact, Machine}` builders

The Rust API is builder-oriented for embedders:

```rust
use mvm_sdk::{Machine, MachineCheckArtifact, MachineRun};

let result = MachineRun::builder()
    .image("alpine")
    .net(true)
    .command(["uname", "-a"])
    .run()?;

let vm = Machine::named("devbox")?;
vm.exec(["echo", "hello"]).run()?;

let artifact = MachineCheckArtifact::builder("app.mvm")
    .json(true)
    .run()?;
# Ok::<(), mvm_sdk::MachineError>(())
```

`check_artifact` / `checkArtifact` / `MachineCheckArtifact` is read-only and
still shells through `mvmctl machine check-artifact`; SDKs do not verify `.mvm`
artifacts privately or bypass CLI admission preview logic.

## Single source of truth

Rust crate `crates/mvm-ir` (`Workload` struct, `schemars` derive)
emits `schema/workload-ir-v0.json`. Both language SDKs regenerate
their lower-layer types from that schema. No pyo3, no napi-rs — the
contract is JSON over the wire.

```
crates/mvm-ir (Rust + schemars)
        │
        ▼
schema/workload-ir-v0.json          ← single source of truth
        │
        ├─→ datamodel-code-generator ─→ sdks/python/mvm/_ir/workload.py
        └─→ json-schema-to-typescript ─→ sdks/typescript/src/ir/workload.ts
```

## Regenerating

After any change to Rust IR types in `crates/mvm-ir/src/workload.rs`
(or `addon.rs`), refresh both SDKs in one command:

```bash
cargo xtask gen-stubs
```

This regenerates:

- `schema/workload-ir-v0.json` — canonical JSON Schema emitted by
  `cargo run -q -p mvm-ir --bin emit_workload_schema`.
- `sdks/python/mvm/_ir/workload.py` — Python dataclasses via
  `datamodel-code-generator` (pinned at `0.25.9`).
- `sdks/typescript/src/ir/workload.ts` — TS interfaces via
  `json-schema-to-typescript` (pinned at `15.0.3`).

Commit all three files together with the Rust change. The generator
versions are pinned inside `xtask/src/gen_stubs.rs`; CI runs
`cargo xtask check-stubs` (via your CI workflow's call) and fails the
build if any of the three artifacts has drifted from a fresh
regeneration.

## Generator tooling

The xtask shells out to `uvx` and `npx`, so devs don't need to
install Python virtualenvs or `npm install` first — just `uv`
(<https://docs.astral.sh/uv/>) and `node` on `PATH`.

```
mvm-ir → emit_workload_schema (Rust)         ← installed via cargo
     ↓
schema → datamodel-codegen (Python)           ← uvx, zero-install
     ↓
schema → json-schema-to-typescript (Node)     ← npx, zero-install
```

## Local builds

To build the SDKs without building the full Rust workspace:

```bash
just sdk-build
```

That delegates to:

- `just sdk-build-python` — build the Python wheel + sdist into
  `sdks/python/dist/`
- `just sdk-build-typescript` — build the TypeScript SDK into
  `sdks/typescript/dist/`

On a fresh clone, install the TypeScript SDK dependencies first:

```bash
just sdk-install-typescript
```

## Local development

When developing the SDKs in this repo, the usual loop is:

1. Build the host CLI you want the SDKs to shell to:

```bash
cargo build -p mvm-cli
export MVM_CLI_BIN="$PWD/target/debug/mvmctl"
```

2. Build the SDK you are changing:

```bash
just sdk-build-python
just sdk-build-typescript
```

3. Exercise the SDK directly from the checkout:

```bash
# Python: use the checkout package directly.
PYTHONPATH="$PWD/sdks/python" python3 your_app.py

# TypeScript: build once, then point a consumer at the local package dir.
npm install "$PWD/sdks/typescript"
```

For Python package work, an editable install is also fine:

```bash
uv venv
. .venv/bin/activate
uv pip install -e sdks/python
```

For TypeScript package work, a local-pack rehearsal matches publish behavior
more closely than importing source files directly:

```bash
just sdk-build-typescript
npm --prefix sdks/typescript pack
```

Then install the generated tarball into a scratch app or test fixture.

Focused local test commands:

```bash
uv run --directory sdks/python pytest
npm --prefix sdks/typescript run test
```

Release-path rehearsal without publishing:

```bash
just sdk-build
# then run the GitHub Actions workflow `.github/workflows/publish-sdk.yml`
# with `dry_run: true`
```

## Release contract

Published SDK releases are driven by `sdks/release.toml`, not by the runtime
toolchain tag stream. Runtime releases continue on `vX.Y.Z`; SDK publication
only runs through `.github/workflows/publish-sdk.yml` for `sdk-vX.Y.Z`
releases or an explicit workflow-dispatch dry-run. The same orchestrator is
called from CI as the `SDK release dry-run` lane.

The published SDK CLI resolution order is:

- `MVM_CLI_BIN`
- `mvmctl`

Published SDKs use the ordinary `mvmctl` binary. A source checkout can still
point `MVM_CLI_BIN` at a locally built `mvmctl`.

## Layout

```
sdks/
├── README.md                       ← this file
├── python/
│   ├── pyproject.toml              ← Python package metadata
│   └── mvm/
│       ├── __init__.py
│       └── _ir/
│           ├── __init__.py
│           └── workload.py         ← GENERATED — do not edit
└── typescript/
    ├── package.json                ← TypeScript package metadata
    └── src/
        └── ir/
            └── workload.ts         ← GENERATED — do not edit
```

The DSL / transport halves (`_dsl.py`, `_remote.py`, `index.ts`,
`_remote.ts`) land in plan-60 Phase 5 Slices D and E.
