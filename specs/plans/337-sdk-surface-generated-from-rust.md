# Plan 337 — Generate the SDK surface from Rust instead of porting it

Backing: preview
Validation: none

**Status: IN PROGRESS** — WS-1 complete (decision recorded below), WS-2 underway
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

> **Superseded by the WS-1 result below.** Both mechanisms were built. The
> "more precise" claim about the attribute mechanism is empirically false — an
> attribute macro sees one item at a time and recovered *less* than the `syn`
> parse. More importantly, the requirement that the manifest be *extracted from*
> the `ctor` fns is incompatible with this plan's own byte-compatibility
> non-goal, because the information Python needs is not present in the Rust
> source. The manifest is authored declaratively instead; see WS-1 § Decision.

## Workstreams

### WS-1 — spike: can the manifest be generated from Rust?

- [x] 1.1 Prototype the attribute/inventory mechanism over two `ctor` fns
- [x] 1.2 Prototype the `syn`-parse mechanism over the same two
- [x] 1.3 Compare on: fidelity of defaults, validation rules, and doc comments
- [x] 1.4 Decide, and write the decision into this plan with its reasoning
- [x] 1.5 **Gate:** if neither is tractable, stop and re-scope before WS-2

#### Pre-registered success criterion and prediction

Written down *before* either prototype was built, so the spike is falsifiable
rather than a formality.

> **Criterion.** From the Rust source alone, reproduce the full Python
> signature of `python_deps` and `dns_resolver` — including `tool="uv"`,
> `port=53`, keyword-only calling, and the `"pip-tools"` alias.
>
> **Prediction.** Both mechanisms fail *identically*, because the information
> is absent from the source rather than hard to parse. If so, the spike's
> output is not "neither is tractable, stop" but "extraction is the wrong
> question".

The criterion is deliberately the *Python* signature, not the Rust one. A
mechanism that faithfully reproduces Rust has proved nothing: this plan's own
non-goal is that generated Python be byte-compatible with the hand-written
Python it replaces, so Python's surface is the bar.

#### Result

Both prototypes were built and run against the real `crates/mvm-sdk/src/ctor/`
sources. Both work. Neither meets the criterion.

| axis | A: attribute + `inventory` | B: `syn` parse from xtask |
| --- | --- | --- |
| names, params, arity | recovered | recovered |
| `impl Into<String>` → `string` | recovered | recovered |
| `I: IntoIterator<Item = HostPort>` → `list<HostPort>` | recovered | recovered |
| doc comments, verbatim | recovered | recovered |
| constructed variant | recovered | recovered |
| **`tool = PythonTool::Uv`** (delegated default) | **NOT recovered** | **recovered** |
| `port = 53` | not recovered | not recovered |
| keyword-only calling | not recovered | not recovered |
| `1..=65535` constraint | not recovered | not recovered |
| `"pip-tools"` alias | not recovered | not recovered |

The prediction held on the last four rows and **failed on the fifth**, in a way
worth recording because it reverses this plan's own assumption. The sketch above
calls the attribute mechanism "more precise and more invasive". It is not more
precise — it is strictly *less* precise, and structurally so:

> An attribute macro is invoked **once per annotated item** and is handed only
> that item's tokens. It therefore cannot see that `python_deps` delegates to
> `python_deps_with(lockfile, PythonTool::Uv)` in a way it could resolve — the
> sibling is simply not in scope. The whole-file `syn` parse *does* resolve it,
> because it holds every fn in the file at once and can do a second pass.

So on the single axis where recovery from Rust was possible at all, A lost to B.
A's compile-time coupling buys precision about *one item*; the information we
actually needed was *between* items.

#### The four remaining failures are not parser failures

This is the finding that decides the workstream. `port=53`, keyword-only,
`1..=65535` and `"pip-tools"` are not hard to parse — they **are not in the Rust
source at any level of effort**, because Rust does not need them:

- `port: u16` *is* Python's range check.
- `tool: PythonTool` *is* Python's enum-membership check.
- The `"pip-tools"` alias never arises, because Rust never takes a string there.
- Keyword-only has no Rust expression at all.

Rust is not the impoverished surface here; it is the one that **discharges these
constraints statically**. Python and TypeScript need runtime checks precisely
*because* they lack the types. Extraction can only ever recover what was
written down, and a range that was expressed as `u16` was never written down.

That means the plan's two requirements — "generated Python must be
byte-compatible with what it replaces" (Non-goals) and "the manifest must be
generated from the Rust `ctor` functions" (Design sketch) — are **mutually
unsatisfiable**. No mechanism can satisfy both. This is a specification
failure, not a tooling failure, which is why 1.5 does not fire: the gate exists
to catch "the tooling won't work", and the tooling works fine.

#### Decision

**Neither mechanism, as an extractor. Invert the direction.**

1. **The manifest is the source of truth**, authored declaratively in Rust — for
   each constructor: name, parameters with neutral types and defaults, the IR
   type and variant discriminant it produces, its **constraints**, and its doc.
   Crucially it records *constraints*, not validation code, and each emitter
   then decides whether a given constraint is discharged by the target
   language's type system or needs a runtime check. That is the piece neither
   prototype could ever supply.
2. **The Rust ctors stay hand-written.** Generating them would force
   `-> Result<_, _>` to carry the constraints, which wrecks the composition the
   prelude exists for — `network(mode).with_egress(egress([host_port("a",
   443)]))` becomes a `?`-soup — and degrades rustdoc and go-to-definition, all
   for a ~50-line payoff inside a crate that ships (`mvm-sdk` is in `mvmctl`'s
   closure via `mvm-cli`).
3. **`syn` is retained, re-scoped from extractor to fail-closed coverage gate**:
   every constructor exported from `lib.rs` must have a manifest entry, and vice
   versa. Note this gate must read **`lib.rs`'s `pub use ctor::…` lists, not
   `pub fn` in `src/ctor/*.rs`** — `mod ctor` is private (`lib.rs:53`), so
   `python_deps_with`, `node_deps_with` and the whole of `NetworkExt` are
   `pub fn` without being public API. A gate over `pub fn` over-reports by
   roughly 40% and fails on day one.
4. **A coverage gate alone is not sufficient**, so pair it with a **golden-IR
   behavioural gate**: each manifest entry carries example arguments; a Rust
   test calls the hand-written ctor with them and asserts the serialised IR
   equals a golden document, and the *same* golden document drives the generated
   Python and TypeScript in the s27 BDD suite. Coverage proves a name is listed;
   only this proves it still *behaves* as listed. WS-3.4 already asks for half
   of this — it should be the primary binding mechanism, not a closing step.

#### On "a hand-kept manifest is just a fourth copy with extra steps"

That objection, from the design sketch above, is what pointed this plan at
extraction in the first place, and it does not survive contact with the
codebase's own conventions. A copy is dangerous when **nothing checks it**.
This repo's entire method is *make drift detectable*, not *make repetition
impossible*: `deny.toml`, `check-stubs`, `check_closure_budget`,
`check_claim_catalog`. `surface_divergence.json` — introduced by Plan 336, one
plan ago — is itself a hand-maintained list of names that nobody calls a fourth
copy, because an s27 scenario fails the moment it lies. A manifest bound by
(3) and (4) meets exactly that standard.

#### Dependency cost, which independently rules out A

- **A** needs a new workspace member (a proc-macro crate cannot live inside
  `mvm-sdk`) plus `inventory` as a dependency of `mvm-sdk` itself. `inventory`
  is currently in `Cargo.lock` only via `cucumber`, i.e. dev-only, so this moves
  it into the shipped `mvmctl` closure and onto `check_closure_budget`. Worse,
  `mvm-sdk` is `crate-type = ["lib", "cdylib"]` (`Cargo.toml:15`) and that
  cdylib is `dlopen`ed by every language SDK; `inventory` registers via link
  sections, and collection across a `dlopen`ed boundary is an unbudgeted risk in
  the crate whose FFI shape is load-bearing.
- **B** needs `syn` in `xtask` only. `xtask` is outside the shipped closure and
  `syn` is already in `Cargo.lock` as a transitive proc-macro dependency, so the
  shipped-closure delta is zero.

Even had the fidelity comparison been a tie, this would have decided it.

#### Defect surfaced by the spike

Rust's `host_port` accepts port `0`; Python's rejects it (`_dsl.py:759`,
`0 < port`). `u16` is not the same constraint as `1..=65535`. Nothing in the
tree notices today, and no signature-level gate ever would — it is exactly the
class of drift the golden-IR gate in (4) exists to catch. Filed as #2559; not
fixed here, because changing `host_port`'s behaviour is not a WS-1 change.

#### Consequence for the tiers

Tier A is **not** descoped to a hand-port. It proceeds as generation, from a
declarative manifest rather than an extracted one. Tiers B, D and E are
unaffected in substance — E in particular is now the natural proving ground,
since WS-2 demonstrates the whole manifest→two-languages pipeline using nothing
but `macro_rules!`, no proc-macro and no `syn`, which is independent evidence
for decision (2).

### WS-2 — Tier E as the proving ground (cheapest, closes both directions)

- [x] 2.1 Rust-owned env-name registry
- [x] 2.2 `emit_sdk_surface` bin emitting the constants
- [x] 2.3 Python + TypeScript emitters wired into `gen-stubs`
- [x] 2.4 `check-stubs` fails on drift
- [x] 2.5 TypeScript-only divergence reaches zero; divergence file updated

#### Result

`crates/mvm-sdk/src/env.rs` declares each name once via `macro_rules!`,
producing both a `pub const` and a row in `REGISTRY`. `emit_sdk_env` writes
`schema/sdk-env-v0.json`; `xtask/src/gen_sdk_surface.rs` renders
`mvm/_env/vars.py` and `src/_env/vars.ts`. `typescript_only_absent_from_python`
is now `[]`.

Five names, not the four this plan scoped. The fifth is `MVM_CLI_BIN_ENV`, and
it is the one that best justifies the tier: it was written out **four** times —
`mvm-sdk/src/machine.rs`, `mvm-sdk/src/facade.rs` (twice in one crate, the
second commented "shared with `machine.rs`" when it was in fact a copy),
`_cli.py`, `_cli.ts` — and because all four agreed, **no gate in the repo could
see it**. Counting divergence entries would never have found it. Five
`MVM_SDK_*` string literals in `mvm-cli` now reference the consts too.

Two findings worth carrying forward:

- **The pipeline cannot render a constant.** `json-schema-to-typescript` emits
  `export type` only, and `tsc` erases a type — so a "generated" constant would
  be absent from the built ESM namespace and invisible to the s27 check, which
  reads `Object.keys(mvm)` at runtime. The drift gate would then certify a
  binding that does not exist. Constants are therefore rendered by a small
  hand-written emitter in xtask. This is not a shortcut around the pinned
  generators; determinism is unaffected, because the output depends only on that
  function.
- **Emitting every name into every language would have been dishonest.** The two
  `MVM_MACHINE_*` names are Python-only, and clearing them from the divergence
  file was tempting because it costs one line. But TypeScript's `_machine.ts`
  reads no environment at all, so those exports would be dead and the file would
  claim a parity that does not exist. Each registry row therefore declares the
  surfaces that *read* it, an s27 step checks that claim **in both directions**,
  and a unit test pins the `MVM_MACHINE_*` pair as not-TypeScript. They stay in
  `python_only_absent_from_typescript`, correctly, as a **behaviour** gap.

That behaviour gap is real and tracked separately: `_machine.ts` calls
`spawnSync` with no `timeout` and no `maxBuffer`, so it can wait forever and
reports Node's 1 MiB `ENOBUFS` overflow as a spawn failure, where Python raises
typed `TransportTimeout` / `TransportOutputOverflow`. Filed as #2558; fixing
it is a behaviour change to a shipped SDK, not env-name codegen, so it is not
bundled here.

Note for WS-3: this tier demonstrates the whole manifest→two-languages pipeline
using `macro_rules!` alone — no proc-macro, no `syn`, no new dependency —
which is independent evidence for the WS-1 decision to author the manifest
declaratively rather than extract it.

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
