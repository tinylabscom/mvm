# mvm-sdk

Build-time Rust SDK (`crates/mvm-sdk`, this crate) plus the two
user-facing language SDKs it generates types for, co-located here:
`python/` and `typescript/`. Each SDK has two layers per ADR-0003
(mvmforge-origin):

- **Lower layer** — IR types (`Workload`, `App`, `Source`, …)
  generated from a single Rust-owned JSON Schema. Never hand-edit.
- **Upper layer** — hand-authored declarative DSL (`@mvm.func` /
  `@mvm.app` in Python; `mv.func(...)` higher-order functions in
  TypeScript) and transport (subprocess to `mvmctl invoke`, or socket
  to `mvmd` once that wiring lands). Hand-edited.

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
`schema/workload-ir-v0.json`. Both language SDKs regenerate their
lower-layer types from that schema. No pyo3, no napi-rs — the
contract is JSON over the wire.

```
mvm-sdk::ir (Rust + schemars)
        │
        ▼
schema/workload-ir-v0.json          ← single source of truth
        │
        ├─→ datamodel-code-generator ─→ python/mvm/_ir/workload.py
        └─→ json-schema-to-typescript ─→ typescript/src/ir/workload.ts
```

## Regenerating

After any change to the Rust IR types in `src/ir/workload.rs` (or
`addon.rs`), refresh both SDKs in one command:

```bash
cargo xtask gen-stubs
```

This regenerates:

- `schema/workload-ir-v0.json` — canonical JSON Schema emitted by
  `cargo run -q -p mvm-sdk --bin emit_workload_schema`.
- `python/mvm/_ir/workload.py` — Python dataclasses via
  `datamodel-code-generator` (pinned at `0.25.9`).
- `typescript/src/ir/workload.ts` — TS interfaces via
  `json-schema-to-typescript` (pinned at `15.0.3`).

Commit all three files together with the Rust change. The generator
versions are pinned inside `xtask/src/gen_stubs.rs`; CI runs
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
│       └── _ir/
│           └── workload.py         ← GENERATED — do not edit
└── typescript/
    ├── package.json
    └── src/
        └── ir/
            └── workload.ts         ← GENERATED — do not edit
```
