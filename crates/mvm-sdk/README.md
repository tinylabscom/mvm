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

`mvm-sdk` provides workload authoring, decorator parsing, and runtime-recording
lowering. Host compilation and dependency-volume auditing live in
`mvm-compiler`; first-party host tools depend on it directly. `mvm-capture`
and `mvm-conformance` use the SDK authoring surface in tests. The crate
re-exports the canonical IR from `mvm-contract`; it does not maintain a second
workload schema.

## How it works: the Rust layer

The builder API constructs a validated `mvm_contract::ir::Workload`. `emit`
canonicalizes that IR and writes it to `MVM_IR_OUT` or stdout for the build
tooling to consume. Decorator parsing and runtime-recording modules translate
language authoring constructs into the same IR. This crate does not drive
machines: booting, driving and stopping one is `mvm-client`'s job, and that
crate re-exports this one as `mvm_client::authoring`, so a Rust program needs
only the one dependency.

Optional features keep secondary surfaces out of the base closure:

- `schema` enables schema emission.
- `compiler` enables the `mvm_sdk::compile` compatibility facade over
  `mvm-compiler`. Existing Rust callers using that module must enable this
  feature; new host tools should depend on `mvm-compiler` directly.
- `deploy` enables local deployment assembly, records, and verification.
  It also enables `compiler`, but does not enable HTTP transport.
- `deploy-remote` enables `deploy` and its HTTP shipping transport.

All are off by default. The base SDK retains Tree-sitter for Python/TypeScript
decorator parsing, but does not link `mvm-compiler`, `globset`, or `mvm-http`.

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

### Durable sessions, checkpoints and replay

ABI 1.8 adds the following local, stateless operations. These do not replace
the short-lived `session` authoring API or `audit.sessions` inspection.

| Python namespace | TypeScript namespace | Methods | Client owner |
| --- | --- | --- | --- |
| `mvm.agent_sessions` | `agentSessions` | `open`, `list`, `show`, `park`, `renew`, `resume` | `AgentSessions::local()` |
| `mvm.checkpoints` | `checkpoints` | `list`, `info`, `diff`, `verify`, `timeline`, `remove`, `capture`, `restore`, `fork` | `Checkpoints::open()` (`info` calls `read`) |
| `mvm.replay` | `replay` | `run_session` / `runSession` | `ReplayService::run_session` |

Every session or checkpoint mutation requires `intent="execute"` in Python,
or `{ intent: "execute", ...options }` in TypeScript. The ABI uses
`{"intent":"execute","request":{...}}`; omission or an unknown intent is
refused before invoking the service. These operations have no genuine preview.
In particular, session `resume(boot=False)` still re-admits and changes durable
state, and a `vm_full` checkpoint fork boots even when `boot` is false.
Session generation/deadline fences and transition retry reports are preserved.

Replay defaults to `dry_run=True` / `dryRun: true`, the client's verified
preview. Set it explicitly false to fork, boot and deliver prompts.
Tenant and timeout are explicit inputs. The reply contains verified selection
metadata and an optional execution report, not plaintext prompts or a prepared
replay handle. Fork and replay observers are captured internally, not streamed
or serialized; guest output is not returned. Failure midway through replay can
leave its fork running, as with the client operation.

```python
from mvm import agent_sessions, checkpoints, replay

agent_sessions.open("research", intent="execute", members=[])
sessions = agent_sessions.list()
catalog = checkpoints.list()
preview = replay.run_session("research", tenant="local", timeout_secs=30)
```

An empty session has no replay timeline; the final example requires that the
session has subsequently recorded a checkpoint and prompts.

Private keys, custom store roots, caller nonces, raw backends, admission
overrides, secret rebinding/drop controls and caller-supplied audit anchors are
not exposed. The services retain configured host signer custody, tenant checks,
signed lineage verification and grant attenuation. Fork requests are ordinary
forks with no declared secret replacements and no permission to drop secrets;
parents requiring explicit rebinding may therefore be refused.

**Parity remaining:** `revert`, `rewind` and `advance` are deliberately absent.
Their shared client workflow can return an image-revert launch handoff rather
than finish the operation. The SDK must not run part of that workflow and then
report success or an after-the-fact unavailable error. Image-revert launch
handoff completion is unavailable until it is a complete client-owned operation.
Low-level preparation, direct store access, custom-root construction, raw
capture/restore drivers and privileged admission controls remain excluded.

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
