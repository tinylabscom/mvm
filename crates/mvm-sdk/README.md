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
  decorators, callbacks and async behavior while lowering
  into the generated contracts.

See `python/README.md` and `typescript/README.md` for the per-language
package docs.

## Role in the workspace

`mvm-sdk` is used by `mvm-build` to compile workload declarations and sidecar
metadata, by `mvm-cli` for generated/project workflows, and by `mvm-hostd` when
it validates SDK-originated execution data. `mvm-capture` and
`mvm-conformance` use it in tests. The crate re-exports the canonical IR from
`mvm-contract`; it does not maintain a second workload schema.

## How it works: the Rust layer

The builder API constructs a validated `mvm_contract::ir::Workload`. `emit`
canonicalizes that IR and writes it to `MVM_IR_OUT` or stdout for the build
tooling to consume. Decorator parsing and runtime-recording modules translate
language authoring constructs into the same IR. This crate does not drive
machines: booting, driving and stopping one is `mvm-client`'s job, and that
crate re-exports this one as `mvm_client::authoring`, so a Rust program needs
only the one dependency.

Optional features keep secondary surfaces out of the base closure:
`schema` enables schema emission and `deploy-remote` enables the HTTP
deployment path.

## Machine lifecycle

The Python and TypeScript SDKs drive machines in-process through
`libmvm_hostlib` (`crates/mvm-hostlib`), the C ABI over `mvm-client`. Neither
SDK runs `mvmctl`: no process is spawned per call, and there is no subprocess
fallback. `xtask check-no-cli-shellout` fails the build if SDK source reaches
for a process API or resolves the CLI to run it.

- Python: `mvm.Sandbox`, `mvm.Machine`
- TypeScript: `Sandbox`, `Machine`
- Rust: `mvm_client::LocalBackend` and the `MvmClient` trait, directly

Admission, audit, OCI resolution and persistent machine state stay in
`mvm-client`; the library is a thin JSON-in/JSON-out veneer over it. How the
SDKs find the library is documented in `crates/mvm-hostlib/README.md`.

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

## The host-ABI stubs

The host library's machine-readable contract lives once in
`mvm-hostlib`'s method registry (`crates/mvm-hostlib/src/registry.rs`):
one row per dotted method with its request and reply types, admission
classification, and a one-line summary. Two emitters derive the SDK
artifacts from it, so no binding hand-maintains a method list:

- `cargo run -q -p mvm-hostlib --features schema --bin
  emit_host_abi_schema` renders every method's request/reply types into
  `schema/host-abi-v0.json`, which the pinned generators turn into
  `python/mvm/_hostabi/host_abi.py` and
  `typescript/src/hostabi/host_abi.ts`.
- `cargo run -q -p mvm-hostlib --features schema --bin
  emit_host_abi_methods` renders the method table (dotted name, schema
  key, classification, ABI version) into
  `schema/host-abi-methods-v0.json`, which the xtask surface renderers
  turn into `python/mvm/_hostabi/methods.py` and
  `typescript/src/hostabi/methods.ts`.

Both run as part of `cargo xtask gen-stubs` and are drift-checked by
`cargo xtask check-stubs` like every other stub set. The hand-written
parts of each binding are thin on purpose: library resolution, the FFI
declarations, and request/reply marshalling (`python/mvm/_hostlib.py`,
`typescript/src/_hostlib.ts`). Everything the bindings export about the
method surface — names, classifications, ABI version, DTO shapes — is
generated from the registry.

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
