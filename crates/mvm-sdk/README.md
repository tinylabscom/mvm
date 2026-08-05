# mvm-sdk

Build-time Rust SDK (`crates/mvm-sdk`, this crate) plus the two
user-facing language SDKs it generates types for, co-located here:
`python/` and `typescript/`. Each SDK has two layers per ADR-0003
(mvmforge-origin):

- **Contract layer** — workload IR and runtime process/filesystem DTOs
  generated from Rust-owned JSON Schemas. Never hand-edit.
- **Ergonomic layer** — hand-authored declarative DSL (`@mvm.func` /
  `@mvm.app` in Python; `mvm.app(...)` higher-order functions in TypeScript)
  and native runtime adapters. These wrappers preserve language-appropriate
  decorators, callbacks, async behavior, and subprocess policy while lowering
  into the generated contracts.

See `python/README.md` and `typescript/README.md` for the per-language
package docs.

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

Golden argv fixtures shared across all three surfaces live in
`tests/machine-fixtures/` — keeping the Python/TypeScript/Rust wrappers
building the same `mvmctl machine ...` argv is what keeps the wrappers thin.

## Single source of truth

This crate's `ir` module (`Workload` struct, `schemars` derive) emits
`schema/workload-ir-v0.json`, and `runtime` emits
`schema/runtime-v0.json`. Both language SDKs regenerate their decorator/IR
and runtime contract types from those schemas. No pyo3, no napi-rs — the
contract is JSON over the wire.

```
mvm-sdk::ir (Rust + schemars)
        │
        ▼
schema/workload-ir-v0.json          ← single source of truth
        │
        ├─→ datamodel-code-generator ─→ python/mvm/_ir/workload.py
        └─→ json-schema-to-typescript ─→ typescript/src/ir/workload.ts

mvm-sdk::runtime (Rust + schemars)
        │
        ▼
schema/runtime-v0.json
        │
        ├─→ datamodel-code-generator ─→ python/mvm/_runtime/runtime.py
        └─→ json-schema-to-typescript ─→ typescript/src/runtime/runtime.ts
```

## Regenerating

After any change to the Rust IR or runtime contract types, refresh both SDKs
in one command:

```bash
cargo xtask gen-stubs
```

This regenerates:

- `schema/workload-ir-v0.json` — canonical JSON Schema emitted by
  `cargo run -q -p mvm-sdk --bin emit_workload_schema`.
- `schema/runtime-v0.json` — canonical runtime contract schema emitted by
  `cargo run -q -p mvm-sdk --bin emit_runtime_schema`.
- `python/mvm/_ir/workload.py` — Python dataclasses via
  `datamodel-code-generator` (pinned at `0.25.9`).
- `python/mvm/_runtime/runtime.py` — generated runtime DTOs.
- `typescript/src/ir/workload.ts` — TS interfaces via
  `json-schema-to-typescript` (pinned at `15.0.3`).
- `typescript/src/runtime/runtime.ts` — generated runtime DTOs.

Commit the schemas and generated language artifacts together with the Rust
change. The generator versions are pinned inside `xtask/src/gen_stubs.rs`; CI runs
`cargo xtask check-stubs` and fails the build if any of the three
artifacts has drifted from a fresh regeneration.

## Generator tooling

The xtask shells out to `uvx` and `npx`, so devs don't need to
install Python virtualenvs or `npm install` first — just `uv`
(<https://docs.astral.sh/uv/>) and `node` on `PATH`.

```
mvm-sdk::ir → emit_workload_schema (Rust)     ← installed via cargo
     ↓
schema → datamodel-codegen (Python)           ← uvx, zero-install
     ↓
schema → json-schema-to-typescript (Node)     ← npx, zero-install
```

## Layout

```
crates/mvm-sdk/
├── README.md                       ← this file
├── src/                            ← the Rust build-time SDK + IR
├── python/
│   ├── pyproject.toml
│   └── mvm/
│       ├── __init__.py
│       ├── _ir/
│           └── workload.py         ← GENERATED — do not edit
│       └── _runtime/
│           └── runtime.py          ← GENERATED — do not edit
└── typescript/
    ├── package.json
    └── src/
        ├── ir/
            └── workload.ts         ← GENERATED — do not edit
        └── runtime/
            └── runtime.ts          ← GENERATED — do not edit
```
