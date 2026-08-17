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
   Python and TypeScript in the s27 BDD suite. Coverage checks that a name is
   listed; only this would catch a change in how it *behaves*. WS-3.4 asks for half
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

**Fixed 2026-08-16 (#2559), and it brought (4) forward.** The constraint moved
to `mvm_contract::ir::validate`, the one seam every language's document passes
through, rather than into either constructor's signature — which is what
decision (2) requires. `dns_resolver` turned out to have the wider version of
the same hole (no host *or* port check on the Rust side at all) and is covered
by the same helper. The durable half is
`features/suites/s27_sdk/fixtures/network_constraints.json`: one file of golden
verdicts, read by a Rust test and by an s27 scenario driving the Python DSL, so
neither surface can move without the other failing. That is the first slice of
the golden-document gate WS-3.4 asks for, built ahead of WS-3 because the defect
needed it; when WS-3 generates these constructors into TypeScript, the third
surface checks against the same file.

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

**Closed 2026-08-16 (#2558).** `_machine.ts` now passes both bounds and
classifies `result.error` by code — `ETIMEDOUT` as a timeout, `ENOBUFS` as an
overflow, everything else as the spawn failure it actually is. With the
behaviour in place the codegen followed mechanically, exactly as this tier
predicted: both rows gained `TypeScript`, `gen-stubs` emitted the constants, the
divergence file lost its last two behaviour entries, and
`machine_vars_are_not_claimed_for_typescript` inverted into
`machine_vars_are_claimed_for_typescript` — so the honesty property survives and
now fails if the behaviour is removed and the claim left behind.

That work also surfaced something this plan had not accounted for: **neither
SDK's unit suite ran in CI at all.** 212 pytest tests and 138 vitest tests are
not cargo targets, so `cargo nextest run --workspace` never reached them and no
workflow invoked either runner. Any regression witness written in those suites —
including every one WS-3 will need for the generated constructors — was
ungated. `just sdk-test` plus a step on the BDD lane fixes that; WS-3.4's
two-language fixtures now have somewhere to run.

Note for WS-3: this tier demonstrates the whole manifest→two-languages pipeline
using `macro_rules!` alone — no proc-macro, no `syn`, no new dependency —
which is independent evidence for the WS-1 decision to author the manifest
declaratively rather than extract it.

### WS-3 — Tier A: generate the constructors, delete the Python copies

- [x] 3.1 Generate all 8 into TypeScript
- [x] 3.2 Replace the Python hand-copies with generated code
- [x] 3.3 Prove byte-compatibility: the existing Python suite passes unchanged
- [x] 3.4 Extend the s27 BDD fixtures to exercise each constructor in both
      languages against one golden IR document

#### Result — the WS-1 decision holds

`crates/mvm-sdk/src/ctor_registry.rs` declares all eight constructors
declaratively: parameters with types and defaults, **constraints**, and what
each builds. `emit_sdk_ctors` serialises it; `xtask/src/gen_sdk_surface.rs`
renders `mvm/_ctors/generated.py` and `src/_ctors/generated.ts`. The eight
Python hand-copies are deleted and `_dsl` re-exports the generated ones.

The constraint vocabulary needed to cover Tier A turned out to be **three**
cases — `NonEmpty`, `IntExclusiveRange`, `EnumMember` (with aliases) — which is
small enough to be worth the machinery and large enough that no parser could
have inferred it.

**Generation removed a fragility rather than just relocating code.** The
hand-written Python named the numbered variant class directly (`_ir.NetworkDns3`,
`_ir.Dependencies1`), and `datamodel-codegen` renumbers those classes — *and*
their `KindN` enums — whenever the schema changes. The generated code resolves
the variant by discriminant instead, so neither number is written down anywhere.
That is a class of breakage the hand-written surface carried and the generated
one cannot.

**Constraint messages are stored verbatim, not derived.** The two enum messages
disagree in shape — `'uv' or 'pip-tools'` versus `'pnpm' / 'npm' / 'yarn'` — and
inventing a rule that produces both would be fiction. Storing them keeps the
generated Python byte-identical and makes the inconsistency visible.

**`kw_only` is Python-only**, recorded the way `ErrorBase::Warning` is:
TypeScript has no keyword-only parameters, so its emitter renders those
positionally rather than dropping the fact silently.

#### Evidence

Byte-compatibility was checked *differentially*, not by inference: a harness
called each hand-written constructor and its generated twin over 26 cases —
every valid path, both alias spellings, and every refusal — comparing the
constructed value structurally and the exception type and message verbatim.
**Zero differences.** The Python suite then passed unchanged (212 passed, no
test edits) with the hand-copies actually removed.

3.4 is the golden-IR behavioural gate the WS-1 decision asked for, now real: one
`ctor_golden.json`, both languages, built values *and* refusal messages. It
earned its keep immediately — it caught that Python's `{tool!r}` renders
`'poetry'` where the first TypeScript emitter used `JSON.stringify` and rendered
`"poetry"`. Python is the reference, so the emitter now renders a repr-alike and
the two languages agree byte-for-byte.

Divergence: `python_only_absent_from_typescript` drops from 27 names to 19.
What remains is Tier C's machinery and the names that cannot be generated.

### WS-4 — Tier B: complete the Rust surface first

- [x] 4.1 `addon_use` and `warm_process` added to `mvm_sdk::ctor`
- [x] 4.2 Generated into both languages — `warm_process` generated;
      `addon_use` hand-written in both, see below
- [x] 4.3 Python hand-copies deleted — `warm_process` only, for the same reason

#### Result — one of the two generates, and the split is the finding

**`warm_process` is generated.** It needed one registry extension, a nullable
default (`max_queue_depth`), and otherwise fits the existing vocabulary.
Verified differentially against the hand-written twin over six cases before the
hand-copy was deleted.

**`addon_use` is not, deliberately.** Expressing it declaratively needs four
capabilities no other constructor uses: a cross-parameter XOR constraint, a
*branching* target (a different `AddonRef` variant depending on which argument
was passed), a derived string field (`addons.mvm.io/{name}`), and
default-if-absent. Building a mini-language for one function is the
over-abstraction the project guidelines warn against, so it stays hand-written
in each language — but pinned by the s27 golden IR document, which is the
standard WS-1 set: a copy is dangerous when nothing checks it, and this one is
checked.

**Rust does not have the XOR at all.** `addon_use_registry` and
`addon_use_local` are two functions, so "both or neither" cannot be written.
That is the WS-1 thesis appearing a third time: the dynamic surfaces need a
runtime check precisely where Rust makes the state unrepresentable.

#### Two defects the new coverage found

**A regression WS-3 introduced and 212 tests missed.** Deleting the
hand-written `node_deps` also removed the module-level `_UNRESOLVED_SHA256`
that followed it, leaving `addon_use` raising `NameError`. The whole Python
suite still passed, because **nothing in it called `addon_use`**. The
cross-language golden fixture caught it. `tests/test_ctors.py` now covers both
Tier B constructors and spot-checks Tier A, and was confirmed to fail without
the fix — a Python break should fail the Python suite, not only the BDD layer.

**An accidental public-API widening.** The first `_addon.ts` exported
`UNRESOLVED_SHA256`, where Python's is `_`-prefixed and private. The
surface-divergence gate reported a new TypeScript-only name; it is now
module-private, matching its twin.

Divergence: `python_only_absent_from_typescript` drops 19 → 17. Everything
remaining is Tier C machinery, its error taxonomy, or Tier F's `derive_schema`.

### WS-5 — Tier D: error taxonomy from a Rust registry

- [x] 5.1 Lift the code → type mapping into Rust, `_hostsvc`'s pattern as the
      model
- [x] 5.2 Generate the hierarchy in both languages
- [x] 5.3 Assert the taxonomy is catchable in both — the bug Plan 336 fixed by
      hand for the host-service errors
- [ ] 5.4 The eight Tier D types themselves — **deferred into WS-6**, see below

#### Result, and a scope correction

`crates/mvm-sdk/src/error_taxonomy.rs` declares each error type once —
name, base, doc, and the `MVM_HSVC_*` status it is raised for —
producing the registry that `emit_sdk_errors` serialises and
`xtask/src/gen_sdk_surface.rs` renders into `mvm/_errors/types.py` and
`src/_errors/types.ts`. Both hand-written mirrors are deleted.

The status codes are the part worth having done. They lived in
`crate::host_services_ffi` and were re-declared as literals in *both* SDKs
under a comment reading "Must match the `MVM_HSVC_*` status codes in the Rust
cdylib" — a mirror maintained by asking a human. The prose had already drifted
(Rust's `MVM_HSVC_BAD_REQUEST` doc says "audit cap", the TypeScript copy said
"e.g. the 4 KiB audit cap"); harmless in a comment, and the same failure in a
number would have mis-routed a broker error. `STATUS_OK` is generated too, so
nothing of the mirror survives.

**The scope correction.** Tier D's eight named types — `RemoteError`,
`MvmTransportError`, `MsgpackUnavailable`, `PayloadTooLarge`,
`NoVmIntrospectionError`, `SecretInArgError`, `SecretInArgWarning`,
`EmittingContextError` — are **not** generated here, and the sequencing in this
plan's own workstream list is wrong about them.

All eight are raised exclusively by Tier C's machinery in `_remote.py`.
TypeScript has no Tier C, so generating them now would export eight classes
that nothing in TypeScript can throw. That is precisely the dead-export
dishonesty WS-2 refused for the `MVM_MACHINE_*` constants, and it would clear
eight entries from `surface_divergence.json` while closing nothing. They
therefore land **with WS-6**, when TypeScript acquires the code that raises
them — which also makes 6.6 ("error taxonomy from WS-5 wired through") a real
step rather than a retrofit.

The registry is built to absorb them: `ErrorBase` already distinguishes
`Root` / `Runtime` / `Warning` / `Named`, so the hierarchy
(`PayloadTooLarge` extending `MvmTransportError`) and the Python-only
`SecretInArgWarning` are expressible today. `SecretInArgWarning` is the
interesting one — JavaScript has no warning type at all, so it is
permanently Python-only, and `SdkErrorType::exports_to` refuses to emit a
`Warning` into TypeScript rather than trusting the declaration.

### WS-6 — Tier C: the remote-function surface (the expensive one)

- [x] 6.1 Size it properly against `_remote.py` and `_session.py` before
      writing code
- [ ] 6.2 `RemoteFunction` + `func` over generated protocol frames
- [ ] 6.3 `Session` + `session` + `current_session_id`
- [ ] 6.4 `WorkloadRef` + `workload_ref`
- [ ] 6.5 BDD coverage against the recording CLI double, both languages, in the
      s27 pattern Plan 336 established
- [ ] 6.6 Error taxonomy from WS-5 wired through

#### 6.1 result — Tier C is two surfaces, and one of them cannot be ported

The plan sizes Tier C as "~1,165 lines of dispatch and lifecycle". The line
count is exact (`_remote.py` 816, `_session.py` 349). The characterisation is
not: what those lines contain is **two dispatch paths**, and the second one has
no faithful TypeScript form at all.

**1. The `MVM_NO_VM=1` path is unportable.** `_prepare_invoke` branches on it
and calls `mvmctl __sdk-no-vm` instead of `mvmctl invoke`, deriving the argv
from the *local Python function object* via `_no_vm_flags_for`: `fn.__module__`,
`fn.__name__`, and `inspect.getfile(fn)` for the source directory. JavaScript
has no equivalent. `fn.name` exists but is destroyed by minification;
there is no way to ask a function object which module defined it
(`import.meta.url` is per-module, not per-function); and a source path is
recoverable only by parsing `new Error().stack`, which fails for any function
received rather than defined locally. The Rust side already takes
`--language`, so the *substrate* is multi-language — the blocker is the
introspection, and it is not a matter of effort.

**2. Session scoping forces an API-shape choice, not a translation.**
`_session.py` holds the active session in a `contextvars.ContextVar` and stores
the `Token` on the object, resetting it in `__exit__` — with a comment noting
the Token must be reset in the task that set it. TypeScript's nearest
equivalent, `AsyncLocalStorage`, does not work that way: it scopes a value to a
*callback* (`als.run(store, cb)`), with no token to hand back later. So either

  * `session(id, async () => { … })` — faithful async-context isolation, but a
    different call shape from Python's `with mvm.session(id):`; or
  * `using s = session(id)` with `Symbol.dispose` over a module-level variable
    — faithful ergonomics, but concurrent sessions in different async tasks
    clobber each other.

There is no option that is both. This should be decided deliberately, and the
first is the safer default: a wrong answer here is a cross-session data leak,
not an awkward call site.

**3. The abandonment safety net gets strictly weaker.** `Session` registers a
`weakref.finalize` that best-effort stops a session the caller never closed.
JavaScript's `FinalizationRegistry` is the structural analogue, but the
specification permits it to never run at all — and notably it is not run at
exit, where Python's finalizers are. A
TypeScript session that is dropped without disposal will leak the VM until its
TTL reaps it. That is tolerable only because the TTL exists; it must be stated,
not implied.

**4 and 5** are the ones already anticipated: `WorkloadRef.__getattr__` needs a
`Proxy`, and the dual sync/async surface (`__call__` returning an awaitable
alongside a blocking `.sync()`) has no clean JS form, since a promise cannot be
awaited synchronously.

#### The Tier E tail nobody counted

`_remote.py` and `_session.py` read **ten** further environment variables, none
of them in the Rust registry WS-2 built: `MVM_EMITTING`, `MVM_ENVELOPE`,
`MVM_INVOKE_KILL_GRACE_SEC`, `MVM_INVOKE_TIMEOUT_SEC`, `MVM_MAX_OUTPUT_BYTES`,
`MVM_MAX_PAYLOAD_BYTES`, `MVM_NO_VM`, `MVM_SESSION_START_TIMEOUT_SEC`,
`MVM_SESSION_STOP_TIMEOUT_SEC`, `MVM_STRICT_SECRETS`. They belong in the
registry, and they can only be declared for TypeScript once TypeScript reads
them — the same rule WS-2 established. Budget them with WS-6, not as a
separate tier.

#### Recommendation

Ship TypeScript Tier C as a **declared subset**, and record the subset in
`surface_divergence.json` as permanent-by-design rather than as a gap — the
treatment WS-7 gives `derive_schema`, for the same reason:

* remote invocation against a real VM: portable, port it;
* `MVM_NO_VM=1` local dispatch: **not portable**, do not pretend;
* sessions: callback-scoped, accepting the different call shape;
* abandonment finalizer: best-effort only, and documented as best-effort.

On that basis Tier C is worth doing and remains the largest single piece of the
plan. What it is *not* is a mechanical port, and a plan that budgets it as one
will produce a TypeScript surface that looks complete and quietly is not.

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
