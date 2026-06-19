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

- Python: `mvm.Machine.run/create/start/exec/shell/stop`
- TypeScript: `Machine.run/create/start/exec/shell/stop`
- Rust: `mvm_sdk::{MachineRun, MachineCreate, Machine}` builders

The Rust API is builder-oriented for embedders:

```rust
use mvm_sdk::{Machine, MachineRun};

let result = MachineRun::builder()
    .image("alpine")
    .net(true)
    .command(["uname", "-a"])
    .run()?;

let vm = Machine::named("devbox")?;
vm.exec(["echo", "hello"]).run()?;
# Ok::<(), mvm_sdk::MachineError>(())
```

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

## Layout

```
sdks/
├── README.md                       ← this file
├── python/
│   ├── pyproject.toml              ← TBD — Slice D scaffolds this
│   └── mvm/
│       ├── __init__.py
│       └── _ir/
│           ├── __init__.py
│           └── workload.py         ← GENERATED — do not edit
└── typescript/
    ├── package.json                ← TBD — Slice E scaffolds this
    └── src/
        └── ir/
            └── workload.ts         ← GENERATED — do not edit
```

The DSL / transport halves (`_dsl.py`, `_remote.py`, `index.ts`,
`_remote.ts`) land in plan-60 Phase 5 Slices D and E.
