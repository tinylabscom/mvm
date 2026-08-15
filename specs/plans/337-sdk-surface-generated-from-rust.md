# Plan 337 — Generate the SDK surface from Rust instead of porting it

**Status: NOT STARTED**
**Opened:** 2026-08-14
**Follows:** Plan 336 WS-G4

## The finding that reframes this

The obvious reading of the gap is "TypeScript is missing 29 names, port them."
That reading is wrong, and acting on it would make the problem permanent.

Take `egress`. It exists three times:

| where | what it is |
| --- | --- |
| `mvm_sdk::ctor::egress` (Rust) | the real one |
| `mvm._dsl.egress` (Python) | a hand-written re-implementation |
| TypeScript | absent |

The same holds for `host_port`, `dns_none`, `dns_system`, `dns_resolver`,
`no_deps`, `python_deps`, `node_deps` — every one already exists in
`crates/mvm-sdk/src/ctor/`, is hand-copied into Python, and is missing from
TypeScript. Porting them by hand gives three copies instead of two and a third
place to drift.

So the goal is not parity. **The goal is one definition per constructor, in
Rust, with both language surfaces generated from it** — after which parity is
structural rather than something a reviewer has to notice.

## What is already generated, and what this reuses

`xtask gen-stubs` / `check-stubs` is a working pipeline and this plan extends it
rather than inventing a second one. Rust-owned JSON Schemas are the source of
truth; each is emitted by a `schemars`-backed bin and fed through pinned
per-language generators (`datamodel-code-generator` for Python,
`json-schema-to-typescript` for TypeScript). Four artifacts exist today:

- workload IR → `schema/workload-ir-v0.json` → `_ir` / `ir`
- host↔guest protocol → `schema/protocol-v0.json` → `_protocol` / `protocol`
- host-services broker → `schema/broker-services-v0.json`
- live runtime contract → `schema/runtime-v0.json` → `_runtime` / `runtime`

The gap is that these generate **types only**. Every constructor, helper and
error over those types is hand-written per language. That is exactly the layer
the 29 names live in.

## Scope

The 29 names absent from TypeScript, the 2 absent from Python, and the
triplication behind them. Sorted by what each actually needs, because they are
not one kind of thing.

### Tier A — already in Rust, generate both bindings (8)

`host_port`, `egress`, `dns_none`, `dns_system`, `dns_resolver`, `no_deps`,
`python_deps`, `node_deps`

Each is a thin constructor over a generated IR type, with light validation.
Present in `mvm_sdk::ctor` today. Generating these **also deletes the Python
hand-copies**, which is the larger win: it removes an entire class of
drift-by-omission rather than adding a third copy.

### Tier B — constructor-shaped, not yet in Rust (2)

`addon_use`, `warm_process`

Same shape as Tier A, but Rust does not have them. Add to `ctor` first so Rust
is the complete surface, then generate. Doing it in this order matters: adding
them to TypeScript directly would leave Rust the incomplete one.

### Tier C — runtime machinery, hand-authored (7)

`func`, `RemoteFunction`, `session`, `Session`, `current_session_id`,
`workload_ref`, `WorkloadRef`

~1,165 lines of Python behaviour (`_remote.py` 816, `_session.py` 349): the
decorator, subprocess/vsock invocation, session lifecycle. Not derivable from a
schema. Their **wire** types already come from `protocol-v0.json`, so what has
to be written is dispatch and lifecycle, against generated frames.

This is the real cost of the plan and should be sized honestly before starting.

### Tier D — error taxonomy, generate from a Rust registry (8)

`RemoteError`, `MvmTransportError`, `MsgpackUnavailable`, `PayloadTooLarge`,
`NoVmIntrospectionError`, `SecretInArgError`, `SecretInArgWarning`,
`EmittingContextError`

Precedent exists: `_hostsvc.py`'s `_STATUS_EXCEPTIONS` already maps broker
status codes to a typed hierarchy that both SDKs mirror by hand. Lift the code
→ type mapping into Rust and generate the hierarchy in both languages.

### Tier E — env-var names, generate from a Rust registry (4)

`MVM_MACHINE_MAX_OUTPUT_ENV`, `MVM_MACHINE_TIMEOUT_ENV` (absent from
TypeScript) and `MVM_SDK_MODE_ENV`, `MVM_SDK_OUT_PATH_ENV` (absent from
Python).

The only bucket that closes divergence in **both** directions — it takes the
TypeScript-only count to zero. Cheapest tier and worth doing first as the
pipeline's proving ground.

### Tier F — blocked on a design decision (1)

`derive_schema`

Derives a JSON Schema from a Python function's type hints, via
`inspect.signature` and pydantic. **TypeScript types are erased at runtime**, so
there is no equivalent and this cannot be ported as-written. Three options, all
with real costs:

1. **Compile-time generation** — a `ts-json-schema-generator` step over the
   user's source. Most faithful to the Python ergonomics; adds a build step to
   every consumer's project, which the SDK does not currently require.
2. **Explicit schema only** — TypeScript callers pass `argsSchema` / `returnSchema`
   by hand. No new machinery, honest about the language difference, worse
   ergonomics than Python.
3. **Runtime validator library** — take a `zod`-style schema and convert it.
   Good ergonomics, but adds a dependency and a second way to spell a type.

Recommendation: **(2) for the first release**, with (1) revisited once Tier C
lands and there is a real TypeScript `@mvm.func` user to design against.
Shipping (1) or (3) speculatively risks building the wrong thing.

## Non-goals

- Changing the Python surface's behaviour. Python is the reference; generated
  Python must be byte-compatible with what it replaces.
- Generating Tier C. Schemas describe data, not dispatch.
- A new codegen pipeline. This extends `gen-stubs` or it does not ship.

## Design sketch — the constructor artifact

Tiers A/B/D/E all need the same missing capability: emitting **functions and
constants**, where today the pipeline emits only types. JSON Schema cannot
express a constructor, so this needs a fifth artifact with its own shape.

Proposed: `schema/sdk-surface-v0.json`, emitted by a new `emit_sdk_surface`
bin, describing each constructor as data — name, parameters with types and
defaults, the IR type it returns, the variant discriminant it sets, and its
validation rules. A new per-language emitter renders that manifest into Python
and TypeScript source.

The manifest must be **generated from the Rust `ctor` functions, not
hand-maintained beside them** — a hand-kept manifest is just a fourth copy with
extra steps. Two candidate mechanisms, to be settled in W1:

- a proc-macro / attribute on each `ctor` fn that registers it into an
  inventory the emitter walks;
- a `build.rs`-time parse of `src/ctor/*.rs` via `syn`.

The first is more precise and more invasive; the second is zero-friction and
more fragile. **W1 is a spike to choose, not a formality** — if neither is
tractable, Tier A collapses to a hand-port and the plan's value drops sharply.
Decide before committing to W2.

## Workstreams

### WS-1 — spike: can the manifest be generated from Rust?

- [ ] 1.1 Prototype the attribute/inventory mechanism over two `ctor` fns
- [ ] 1.2 Prototype the `syn`-parse mechanism over the same two
- [ ] 1.3 Compare on: fidelity of defaults, validation rules, and doc comments
- [ ] 1.4 Decide, and write the decision into this plan with its reasoning
- [ ] 1.5 **Gate:** if neither is tractable, stop and re-scope before WS-2

### WS-2 — Tier E as the proving ground (cheapest, closes both directions)

- [ ] 2.1 Rust-owned env-name registry
- [ ] 2.2 `emit_sdk_surface` bin emitting the constants
- [ ] 2.3 Python + TypeScript emitters wired into `gen-stubs`
- [ ] 2.4 `check-stubs` fails on drift
- [ ] 2.5 TypeScript-only divergence reaches zero; divergence file updated

### WS-3 — Tier A: generate the constructors, delete the Python copies

- [ ] 3.1 Generate all 8 into TypeScript
- [ ] 3.2 Replace the Python hand-copies with generated code
- [ ] 3.3 Prove byte-compatibility: the existing Python suite passes unchanged
- [ ] 3.4 Extend the s27 BDD fixtures to exercise each constructor in both
      languages against one golden IR document

### WS-4 — Tier B: complete the Rust surface first

- [ ] 4.1 `addon_use` and `warm_process` added to `mvm_sdk::ctor`
- [ ] 4.2 Generated into both languages
- [ ] 4.3 Python hand-copies deleted

### WS-5 — Tier D: error taxonomy from a Rust registry

- [ ] 5.1 Lift the code → type mapping into Rust, `_hostsvc`'s pattern as the
      model
- [ ] 5.2 Generate the hierarchy in both languages
- [ ] 5.3 Assert the taxonomy is catchable in both — the bug Plan 336 fixed by
      hand for the host-service errors

### WS-6 — Tier C: the remote-function surface (the expensive one)

- [ ] 6.1 Size it properly against `_remote.py` and `_session.py` before
      writing code
- [ ] 6.2 `RemoteFunction` + `func` over generated protocol frames
- [ ] 6.3 `Session` + `session` + `current_session_id`
- [ ] 6.4 `WorkloadRef` + `workload_ref`
- [ ] 6.5 BDD coverage against the recording CLI double, both languages, in the
      s27 pattern Plan 336 established
- [ ] 6.6 Error taxonomy from WS-5 wired through

### WS-7 — Tier F decision

- [ ] 7.1 Confirm option 2 for the first release, or overrule with reasoning
- [ ] 7.2 Document the language difference where a user meets it, not only here
- [ ] 7.3 Record it in the divergence file as permanent-by-design, not a gap

### WS-8 — close out

- [ ] 8.1 `surface_divergence.json` reduced to Tier F plus the type-erased set
- [ ] 8.2 `xtask check-stubs` covers every generated artifact
- [ ] 8.3 Full gates: fmt, clippy, workspace nextest, doctests, Python, TypeScript
- [ ] 8.4 `specs/REFACTOR-STATUS.md` and a delivery note

## Sequencing

WS-1 gates everything. WS-2 before WS-3 — it is the cheapest end-to-end
exercise of the new emitter and will surface pipeline problems while they are
still cheap to fix. WS-6 is independent of WS-2..5 and can run in parallel by a
second pair of hands; it is also the workstream most likely to be descoped, so
nothing else should depend on it.

## Honest cost

Tiers A, B, D, E are perhaps a third of the names and most of the durable value:
they delete triplication and make the remaining parity mechanical. Tier C is the
larger half of the effort for seven names, and is a straight port with no
generation available. If the budget only covers one, **do A/B/D/E and leave
Tier C explicitly unported** — the gate from Plan 336 keeps that honest rather
than letting it read as an oversight.
