# Entrypoints in mvm: shell + function-as-program

## Context

You asked whether mvm supports "entrypoints" — booting a microVM,
running something, getting output back. Shell case exists today
(`mvmctl exec`). The new ask is **language-function entrypoints** in
the Modal style: decorate a function, call it on the host, body runs
in a microVM, return value flows back. Many small VMs (each a FaaS
unit or library shard) compose into a single program.

mvmforge already lands the deploy-time half (decorator → IR → flake →
boot). The decorated function body is currently ignored by the SDK.
What's missing is the call-time half.

**Your framing:** a function call is an *implicit program*. The image
bakes a tiny wrapper that reads args from stdin, dispatches to the
user function, writes the return on stdout. The host SDK runs that
wrapper via mvm with stdin/stdout plumbing. No new vsock verb that
reasons about Python/TS, no language-aware mvm.

**Your hard rule:** *EVERYTHING is written at build time, ALWAYS.*
This rules out: closure shipping at call time, runtime function
registration, dynamic dispatch by name from outside. The wrapper, the
function, the format, the allowlist, the resource shape — all baked
into the rootfs at `mvmforge compile` / `nix build` time. Only the
call payload (stdin bytes) is runtime data.

## Layering

```
Host SDK (mvmforge)                              mvm (this repo)
─────────────────────                            ────────────────────
f.remote(5)                                      mvmctl invoke
  → encode args (per IR-declared format)          ├─ boot/resume VM
  → mvmctl invoke <vm> --stdin args.bin           ├─ pipe stdin
  → decode bytes from stdout                       ├─ run baked entry
                                                   ├─ capture stdout
                                                   └─ return result
                                ▲
                                │ stdin/stdout/exit  (vsock-framed)
                                ▼
Guest (mvmforge-baked at build time)             mvm guest agent
─────────────────────                            ────────────────────
WRAPPER = language-specific runner                RunEntrypoint handler
  baked into rootfs by Nix factory                runs /etc/mvm/entrypoint
  reads stdin (declared format)                   pipes stdin/stdout
  calls fixed user fn(*args)                      enforces caps
  writes return to stdout
```

The only place mvm sits in this picture is a constrained
`RunEntrypoint` verb + the existing warm-VM primitives. Nothing
else needs to learn Python or TypeScript.

## What mvm ships (this repo)

### 1. New vsock verb: `RunEntrypoint`

Today `do_exec` is dev-only behind `dev-shell`
(`crates/mvm-guest/Cargo.toml:38`); production builds reject all exec
requests at `crates/mvm-guest/src/bin/mvm-guest-agent.rs:920`. The CI
lane `prod-agent-no-exec` enforces this (ADR-002 §W4.3).

`RunEntrypoint` is the production-safe alternative. It:

- Reads the path from `/etc/mvm/entrypoint` (single absolute path,
  written by mvmforge's Nix factory at build time).
- Spawns it with the given stdin piped, captures stdout/stderr/exit.
- **No argv override, no shell, no env injection** beyond what the
  IR-declared wrapper expects.
- Ships in **production** builds. CI gates: `prod-agent-no-exec`
  (no `do_exec`) **plus** `prod-agent-has-runentry` (new — asserts
  symbol present in prod).

`do_exec` stays dev-only and dev-mode `mvmctl exec` keeps working.
Production function-call dispatch goes through `RunEntrypoint` only.

**Wire shape** (recommendation, see Decisions below):

```rust
// stdin-only; no argv. Argv adds parallel encoding paths with no
// clear benefit when the format is structured and declared at IR.
GuestRequest::RunEntrypoint {
    stdin: Vec<u8>,
    timeout_secs: u64,
}

// Streaming-shaped from v1, buffered implementation. v1 emits a
// single Stdout chunk + a single Stderr chunk + Exit. v2 chunks
// progressively without breaking the wire.
GuestResponse::EntrypointEvent(EntrypointEvent),
enum EntrypointEvent {
    Stdout { chunk: Vec<u8> },
    Stderr { chunk: Vec<u8> },
    Exit { code: i32 },
    Error { kind: RunEntrypointError, message: String },
}
```

`#[serde(deny_unknown_fields)]` on every type (ADR-002 §W4.1). Fuzz
targets in `crates/mvm-guest/fuzz/` extend to cover both.

### 2. New CLI verb: `mvmctl invoke`

Distinct from `mvmctl exec`. Different semantics, different CI
posture, different mental model:

- `mvmctl exec` — arbitrary shell, dev-only, free-form.
- `mvmctl invoke` — runs the baked entrypoint, prod-safe, no shell.

```
mvmctl invoke <vm-or-template> [--stdin <file>|-] [--timeout 30]
```

Output: writes stdout to its own stdout, stderr to its own stderr,
exits with the guest's exit code. Trivial to compose with other
tooling and what mvmforge's SDK shells out to under the hood.

Reuses existing session-VM primitives in
`crates/mvm-cli/src/exec.rs` (`boot_session_vm`,
`dispatch_in_session`, `tear_down_session_vm`) for warm reuse —
identical to the path `mvmctl mcp` uses today.

### 3. Streaming: protocol-shaped from v1, buffered impl

Recommendation: **yes**, design for streaming from day one. Don't
implement chunking yet — v1 wraps full stdout/stderr in single
`Stdout`/`Stderr` events — but the wire format must support the
chunked future without a breaking change.

Why now: function-call workloads include long-tail cases (LLM
inference, batch jobs) where 1 MiB caps will bite. Reshaping the
protocol later means a vsock break + agent compatibility shim. Cheap
to design correctly the first time.

v1 enforces the same 1 MiB cap as `do_exec`; v2 lifts it by emitting
real chunks.

### 4. Session pools: separate follow-up

Recommendation: **yes, but as a follow-up plan, not v1**.

The session-VM primitives already exist (used by `mvmctl mcp`).
Function calls reuse them as-is — boot once, dispatch many. This
is enough for hot-path FaaS perf if the SDK keeps a session per
workload.

What's *not* in v1:
- Pool sizing / eviction policy
- Per-tenant pool isolation
- Idle reaper
- Snapshot-warm vs cold-warm policy

These are real but they're optimization on top of a working
primitive. Track in `specs/plans/4Y-session-pools.md` (separate).

### 5. (Out of scope) Closure shipping

Modal's ephemeral apps pickle closures at call time. **Excluded** —
your build-time-only rule rules it out, and it's a real security
surface (deserializing untrusted code) we don't want.

## Critical files (mvm side)

- `crates/mvm-guest/src/vsock.rs` — `RunEntrypoint`,
  `EntrypointEvent`, `RunEntrypointError`. ~80 lines + roundtrip +
  tampered-frame tests.
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — handler. Reads
  `/etc/mvm/entrypoint`, spawns, pipes stdin, emits events.
- `crates/mvm-guest/fuzz/` — fuzz targets for new types.
- `crates/mvm-cli/src/commands/mod.rs` + new
  `crates/mvm-cli/src/commands/vm/invoke.rs` — `mvmctl invoke`.
- `crates/mvm-cli/src/exec.rs` — possibly rename to `session.rs` if
  enough is shared between exec and invoke.
- `.github/workflows/ci.yml` — `prod-agent-has-runentry` lane.
- `crates/mvm-cli/src/doctor/` — verify `/etc/mvm/entrypoint` exists
  on prod-built rootfs (one more security claim).
- `specs/adrs/0XX-function-entrypoints.md` — new ADR.
- `specs/plans/4X-function-entrypoints.md` — implementation plan.

## Verification

```
# Existing dev shell still works
cargo run -- exec --image template:hello -- /bin/echo hi

# New: invoke against a prod-built image with baked entrypoint
cargo run -- template build echo-fn   # mvmforge-emitted
cargo run -- invoke template:echo-fn --stdin <(echo '{"msg":"hi"}')
# expect stdout: {"msg":"hi"}

# Doctor verifies the rootfs has the entrypoint file
cargo run -- doctor --image template:echo-fn
# expect: ✓ /etc/mvm/entrypoint present (mode 0755)
```

CI:
- `prod-agent-no-exec` — still passes.
- `prod-agent-has-runentry` (new) — symbol present in prod.
- Vsock fuzz extended for new types.

Tests:
- `crates/mvm-guest/src/vsock.rs` — roundtrip + tampered.
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — handler unit
  test with a fake `/etc/mvm/entrypoint`.
- `crates/mvm-cli/tests/` — integration: build a fake "echo
  function" template, invoke with stdin, assert stdout.

## Recommendations (asked for)

| Question | Recommendation | Why |
| --- | --- | --- |
| Streaming? | **Yes — protocol-shaped from v1, buffered implementation.** | Cheap to design now; a wire break later is expensive. |
| Session pools? | **Yes — but follow-up plan, not v1.** Reuse existing session-VM primitives in v1. | The primitives already exist (`mvmctl mcp` uses them). Pool *management* is the optimization layer — separable. |
| argv vs stdin? | **stdin-only.** | One-function-per-image (build-time directive) means no function-name dispatch needed; argv adds a parallel encoding path with no benefit. Format is IR-declared and baked. |
| `mvmctl invoke`? | **Yes — first-class verb, distinct from `exec`.** | Different semantics, different CI gate, different security posture. Mental hygiene matters; collapsing them invites confusion about what's prod-safe. |
| Closure shipping? | **No — excluded by build-time rule + security.** | — |

## Decorationer (mvmforge) spec

You asked me to drop a spec into
`/Users/auser/work/rust/mine/decorationer/specs/`. Plan mode locks
me to this plan file — so the full ADR + Plan are embedded below.
On plan approval I'll extract to:

- `/Users/auser/work/rust/mine/decorationer/specs/adrs/0009-function-entrypoints.md`
- `/Users/auser/work/rust/mine/decorationer/specs/plans/0003-function-entrypoint-runtime.md`

Numbering follows the existing sequence (ADRs 0001–0008, Plans
0001–0002 already present).

---

### ADR-0009 (DRAFT) — Function-call entrypoints

```markdown
# ADR-0009: Function-call entrypoints

## Status

proposed

## Context

`mvmforge` v0 treats a decorated function body as ignored metadata:
the SDK extracts the workload spec from kwargs (`name`, `image`,
`entrypoint`, `resources`) and emits IR + flake + launch.json. The
function body is dropped per the README.

Users want Modal-style call-time semantics: decorate a function,
call it on the host, body runs inside the microVM, return value
flows back. mvm's substrate (ADR-0005) is gaining a constrained
`RunEntrypoint` verb that runs a baked program with stdin piped in
and stdout/stderr captured. ADR-0009 decides how mvmforge wires
the language side onto that substrate.

The hard constraint inherited from mvm: **everything ships at
build time**. No closure pickling, no runtime registration, no
dynamic dispatch by name. The function, its format choice, and
its wrapper are baked into the rootfs at `mvmforge compile`.

## Decision

1. Extend the IR with a new `entrypoint.kind = "function"` variant
   that captures: `module`, `function`, `serialization_format`
   (`json` | `msgpack` — both are language-agnostic; closed set
   for v1).
2. The decorator preserves the function body as part of the
   bundled source tree (currently discarded). Bundling rules
   from ADR-0008 apply.
3. Per-language Nix factories produce a fixed wrapper at
   `/etc/mvm/entrypoint` that reads stdin, deserializes per the
   declared format, dispatches to the IR-declared function, and
   writes the return on stdout. Errors → exit code != 0 with a
   structured error envelope on stderr.
4. The host SDK call site (`f.remote(*args)`) shells out to
   `mvmctl invoke <workload> --stdin <encoded args>` and decodes
   stdout. The SDK does not know about vsock — that's mvm's job.
5. **One function = one app/workload.** Multi-function workloads
   are expressed as multiple `apps[]` entries. No
   function-name-in-payload dispatch.

## Invariants

- The IR declares the function and format at build time; nothing
  about the dispatch is decided at call time except the args
  bytes themselves.
- `mvmforge canonicalize` is byte-identical across SDKs for
  function-entrypoint workloads (extends ADR-0003).
- The wrapper at `/etc/mvm/entrypoint` is mode 0755, owned root,
  and is the *only* program the prod guest agent will run.
- Closure shipping at call time is forbidden. The function body
  must reside in the rootfs at boot.

## Consequences

Benefits:
- Modal-class ergonomics with mvm-class isolation (Firecracker
  per call/session).
- Reuses ADR-0005 and ADR-0008 unchanged.
- No new SDK ↔ host contract — just an IR field and a wrapper
  convention.
- Production-safe (prod gate stays meaningful — see mvm side).

Costs:
- Bundler must now ship function bodies, not just metadata.
  Tightens ADR-0008's bundling story (test coverage required).
- Per-language wrapper is a new Nix factory surface; today's
  `mkGuest` becomes one path, `mkPythonFunctionService` and
  `mkNodeFunctionService` (deferred-future in v0 README) become
  required for v1.
- Cross-language calls go through JSON/msgpack lossiness — Python
  callers can't return arbitrary Python objects to a TS caller.

Risks:
- IR drift between languages on edge-case types (datetimes,
  bytes, unions). Mitigation: corpus entries that exercise each
  type per language.
- Cold-boot tax. Mitigation: warm-VM session reuse (mvm side).

## Implementation Impact

- `crates/mvmforge-ir/`: extend `Entrypoint` enum;
  canonicalization rules for the new variant; JSON Schema regen.
- `sdks/python/`: decorator preserves body; emitter writes new
  IR variant; bundler ships function source.
- `sdks/typescript/`: same shape, mirrored.
- New Nix factory files under `nix/` (in mvm or mvmforge —
  ADR-0007 contract): `mkPythonFunctionService`,
  `mkNodeFunctionService`. Each produces a wrapper at
  `/etc/mvm/entrypoint`.
- `tests/corpus/`: new entries that exercise function entrypoints
  (Python, TS, cross-format).

## Validation

- `mvmforge canonicalize` passes on function-entrypoint corpus
  entries; byte-identical across SDKs.
- `nix flake check` on a generated artifact succeeds.
- Integration test: build a Python `def add(a, b): return a + b`
  workload, run `mvmctl invoke <vm> --stdin '[2,3]'`, assert
  stdout `5`.
- mvm CI: `prod-agent-has-runentry` passes against the generated
  rootfs.

## Supersedes

None.

## Superseded By

None.
```

---

### Plan-0003 (DRAFT) — Function entrypoint runtime

```markdown
# Plan-0003: Function entrypoint runtime

## Purpose

Land function-call entrypoints (Modal-style `f.remote(...)`) on top
of the mvm `RunEntrypoint` substrate. End-to-end: decorate a Python
or TypeScript function, run `mvmforge up`, then call it from the
host and get a return value back.

## Governing ADRs

- `specs/adrs/0009-function-entrypoints.md`
- `specs/adrs/0005-mvm-as-v1-substrate.md`
- `specs/adrs/0007-mvm-guest-lib-flake-contract.md`
- `specs/adrs/0008-source-tree-bundling.md`

## Scope

- IR: `Entrypoint::Function { module, function, format }` variant.
- Python SDK: preserve fn body, emit new IR variant, bundle source.
- TS SDK: same.
- Nix factories: `mkPythonFunctionService`, `mkNodeFunctionService`
  emitting `/etc/mvm/entrypoint`.
- Host SDK call site: `f.remote(*args)` shells out to
  `mvmctl invoke` with encoded args.
- Corpus entries.

## Non-Scope

- Streaming returns (when mvm ships chunked events, layer on top).
- Pool management (mvm responsibility).
- Cross-process / cross-VM RPC chaining (composition is the user's
  job for now — they call `f.remote(...)` then `g.remote(...)`).
- Type validation beyond schema. We do not infer Python type hints.

## Phases

### Phase 1 — IR

- [ ] Add `Entrypoint::Function { module, function, format }`.
- [ ] Format: enum `Json | Msgpack` (closed set, declared at IR).
- [ ] Canonicalization rules; JSON Schema regen; error codes.
- [ ] Corpus entry: minimal Python function workload, expected
      canonical IR, byte-identical Python ↔ TS.

### Phase 2 — Python SDK

- [ ] Decorator preserves function body in bundled source (today
      ignored — see README).
- [ ] Emitter writes the new IR variant.
- [ ] Bundler ships function source per ADR-0008.
- [ ] Host call site: `f.remote(*args)` encodes per declared
      format, runs `mvmctl invoke`, decodes stdout.
- [ ] Tests: encode → invoke (with fake mvm shim) → decode → equal.

### Phase 3 — TypeScript SDK

- [ ] Mirror Phase 2 surface in TS.
- [ ] Cross-SDK corpus entries: Python and TS function workloads
      produce byte-identical IR.

### Phase 4 — Nix factories

- [ ] `mkPythonFunctionService`: emits wrapper that imports
      module, dispatches function, reads stdin in declared
      format, writes stdout.
- [ ] `mkNodeFunctionService`: same shape.
- [ ] Both write to `/etc/mvm/entrypoint` (single absolute path).
- [ ] Generated flake passes `nix flake check`.

### Phase 5 — Integration

- [ ] End-to-end: `mvmforge up app.py` for a function workload,
      `mvmctl invoke` from host, assert return value.
- [ ] Cross-language: TS host calling Python function over JSON.
- [ ] Error path: function raises → non-zero exit → SDK surfaces
      structured error.

## Acceptance Criteria

- [ ] All four SDK surfaces (Python decorator + emitter + host
      call, TS decorator + emitter + host call) ship.
- [ ] Corpus has function-entrypoint entries for both languages.
- [ ] Generated flakes produce a rootfs that mvm CI's
      `prod-agent-has-runentry` lane validates.
- [ ] Round-trip latency (cold boot) baseline measured; warm
      session reuse (via mvm session VMs) measured separately.

## Risks

- IR drift on edge-case argument types. Mitigation: per-format
  type matrix in corpus.
- Bundling complexity for functions that import the rest of a
  package. Mitigation: lean on ADR-0008's bundle scope; document
  surprises.
- ADR-0007 contract may need a new `mkXFunctionService` symbol
  that mvm's flake re-exports. Coordinate with mvm side.

## Open Questions

- How does the host SDK find the booted VM? Per-call `mvmforge up`
  is heavy; we likely need a "warm" session API in the SDK that
  defers to mvm's session-VM primitives. Defer to Phase 3.
- Format default: JSON or msgpack? Recommend JSON for v1
  (debuggability) with msgpack opt-in via `format=` kwarg.
```

## Security review (concerns this design adds)

ADR-002 covers the existing posture. The function-entrypoint shape
opens new surface; here's what I think is unaddressed and what I'd
fold into the plan and the ADR.

### New surface introduced

1. **Untrusted bytes through the wrapper's deserializer.** stdin
   carries caller-provided bytes that the language wrapper feeds
   into a JSON or msgpack decoder. Caps and hardening are required:
   - stdin size cap (recommend 1 MiB v1, parametric in IR up to a
     hard ceiling).
   - max nesting depth on JSON (recommend 64).
   - reject duplicate keys (already implied by serde
     `deny_unknown_fields`, but the *application-layer* JSON the
     wrapper parses needs explicit limits — that's a Python/Node
     wrapper concern, not mvm's).
   - stdout size cap symmetric (1 MiB v1) — protects host from a
     malicious or runaway guest.
   - Timeout enforced both guest-side (poll-based, like `do_exec`)
     and host-side (drop and tear down).

2. **Code-executing deserializers are forbidden.** The IR's
   `serialization_format` is a closed enum (`Json | Msgpack` only).
   Formats whose decoder can run arbitrary code (Python's `pickle`,
   Ruby `Marshal`, Java `ObjectInputStream`, etc.) are explicitly
   excluded. ADR-0009 invariant.

3. **`/etc/mvm/entrypoint` must live on the verity-protected
   partition.** dm-verity (W3) prevents post-boot modification of
   the rootfs, but only if the file is *on* that rootfs and not a
   symlink into a writable mount. Agent must `realpath` the
   entrypoint at boot and refuse if it resolves outside the verity
   partition. New invariant; doctor verifies.

4. **CI assertion is a *combined* check, not two independent ones.**
   `prod-agent-no-exec` verifies `do_exec` absent. The new
   `prod-agent-has-runentry` verifies `RunEntrypoint` present.
   They must run in the same job (or one must depend on the other)
   so we can't regress half the contract silently.

5. **Session VM state leaks across calls.** Reusing a session VM
   for repeated function calls means call N+1 sees:
   - `/tmp` from call N (and any other writable mount the wrapper
     touched)
   - process memory if the wrapper holds globals across invocations
     (likely, for perf — module-level state is the whole point of
     warm reuse)
   - file descriptors, env mutations, etc.
   This is **by design** for FaaS warm semantics but it's a
   contract that needs naming. Two pieces:
   - **Per-call hygiene**: the wrapper SHOULD clean transient
     state (clear `/tmp/<call-id>`, reset the wrapper's local
     namespace) — codify in the Nix factory.
   - **Cross-tenant isolation is the pool's problem**: a session
     VM is *single-tenant for its lifetime*. The pool must not
     hand a session warmed by tenant A to tenant B. This goes in
     the (deferred) session-pool plan as a hard invariant — name
     it now so the deferred plan has the constraint baked in.

6. **Error envelopes leak internals.** A naive wrapper prints
   stack traces with source paths, env values, possibly secrets.
   Decision:
   - prod wrappers emit a structured error envelope on stderr
     (`{ kind, message, code }`) — no traceback, no paths.
   - dev wrappers may emit tracebacks (gated by build-time flag
     in the Nix factory).
   - mvm doesn't see envelope contents — just bytes — but the
     ADR documents the contract so all language wrappers comply.

7. **Build-time bundling expands the attack surface.** mvmforge
   now bundles function source into the rootfs (today only
   metadata). Risks:
   - Import-time side effects in user code execute during `nix
     build` (nominally inside the Nix sandbox, but worth naming).
   - Larger source trees mean more transitive deps, which means
     `cargo deny` / `audit` (W5.2) coverage must extend to the
     bundled-language ecosystem (pip-audit / npm audit). New CI
     lane, mvmforge side.
   - Source bundling rules in ADR-0008 need to be re-read against
     this — does the existing scope cover function bodies + their
     module-level imports? Plan-0003 lists this as a risk; flagging
     here so it doesn't get lost.

### Already covered by ADR-002 (no new work)

- Per-service uid + setpriv + seccomp around the wrapper (W2.1,
  W2.3, W2.4) — wrapper escape is the same threat as any other
  service.
- Read-only `/etc/{passwd,group,nsswitch.conf}` (W2.2).
- Vsock socket mode 0700 (W1.2) — only the local user can
  `mvmctl invoke`.
- Vsock framing fuzzed (W4.2) — extends to new event types.
- Reproducible build double-check (W5.3) — catches non-determinism
  in the wrapper.

### Out of scope (explicitly named)

- Multi-tenant guests within one VM. ADR-002 already excludes;
  function entrypoints don't change this.
- Authenticated invoke calls (signing the stdin payload). The
  vsock socket perms gate access to the local user; cross-network
  authn is an mvmd concern.
- (network access defaults — moved to M8 as a real surface, not
  out-of-scope; see below)

### Mitigations (one per surface)

#### M1. Untrusted bytes through the wrapper's deserializer

Two layers of defense, both built at build time:

- **Hard caps** (mvm side, in agent):
  - stdin size cap: 1 MiB v1, parametric in IR up to a hard ceiling
    declared in mvm (e.g. 16 MiB).
  - stdout size cap symmetric.
  - timeout: enforced in agent (poll-based like `do_exec`) AND in
    host (drop after `timeout_secs * 1.2` to catch agent stalls).
  - On any cap breach: kill the wrapper process, return
    `EntrypointEvent::Error { kind: PayloadCap, ... }`, mark
    session VM poisoned (see M5).
- **Schema-bound payloads** (mvmforge side, in IR):
  - The IR carries a JSON-Schema-shaped declaration of the
    function's argument and return shape, derived at build time
    from type hints (Python: `pydantic` / `mashumaro`; TS: `zod`
    or `typebox`).
  - Wrapper validates inbound bytes against the schema before
    the user function ever sees the value. Rejects → structured
    error.
  - Host SDK validates outbound encoding against the same schema
    before sending. Defense in depth.
  - v1 may ship without schema if it's too much lift; size + depth
    + format caps are still mandatory. Schema goes in v2.
- **Decoder hardening** (Nix factory):
  - JSON: max nesting depth 64, reject duplicate keys, reject
    non-finite floats (`Infinity`, `NaN`).
  - msgpack: max ext-type id (reject custom code-loading types).
  - Both decoders called from the wrapper are pinned to stdlib
    or audited libraries — no hand-rolled parsing.

#### M2. Code-executing deserializers forbidden

ADR-0009 invariant. Enforced two ways:

- **IR rejects them**: `serialization_format` is a closed enum
  (`Json | Msgpack`). Validation rejects anything else with a
  stable error code.
- **Nix factory contract** (ADR-0007 / ADR-0009): the per-language
  factory's source must not import known-dangerous decoders. CI
  lane greps the generated wrapper artifact for the canonical
  forbidden imports per language (Python `pickle`/`marshal`,
  Ruby `Marshal`, Java `ObjectInputStream`, Node `vm.Script`,
  etc.) and fails if any appear. False-positive risk for
  `marshal` (mvmforge probably never uses it); maintain an
  allowlist.

User code (the function body) may import whatever it wants —
that's not the surface. The surface is what the *wrapper* passes
into a decoder before user code runs. Wrapper is mvmforge-owned,
so we control it.

#### M3. /etc/mvm/entrypoint hardening

- **Path resolution at boot**: agent reads
  `/etc/mvm/entrypoint`, calls `realpath`, asserts the resolved
  path:
  1. Starts with a known prefix on the verity partition (e.g.
     `/usr/lib/mvm/wrappers/`).
  2. Is owned root:root, mode 0755, regular file (not symlink
     after resolution, not setuid).
  3. Is on the same filesystem as `/usr` (i.e. the verity rootfs,
     not a writable overlay or bind mount).
- **Refuse to handle `RunEntrypoint`** if any of those checks
  fail. `mvmctl doctor` reports the same.
- **Nix factory contract**: factories MUST write the entrypoint
  file to that fixed prefix, MUST own it root:root, MUST mode
  0644 the entrypoint pointer file. Enforced in flake-check.
- **Cache the resolved path at boot.** Re-resolving per call
  invites TOCTOU. Resolve once, hold the fd, pass it to
  `fexecve`-style spawn.

#### M4. Combined CI assertion

ONE CI step, ONE prod binary, BOTH assertions:

```yaml
- name: prod-agent-runentry-contract
  run: |
    cargo build --release -p mvm-guest --bin mvm-guest-agent
    BIN=target/release/mvm-guest-agent
    ! nm "$BIN" | grep -E ' T (mvm_guest_agent::)?do_exec$'   # absent
    nm "$BIN"   | grep -E ' T (mvm_guest_agent::)?run_entrypoint$'  # present
```

The exact same `$BIN` is what ships (or is the input to the
release-image step). No separate dev/test build that could mask
a regression in the released artifact. Add a third assertion
that `$BIN`'s mode/sha matches what gets shipped (link the CI
artifact through to the release pipeline so nothing else can be
substituted between check and ship).

Yes — done this way it protects us against the regressions we
actually care about: feature-flag drift, accidental
re-inclusion, or someone splitting the symbol into a sub-crate
that escapes the gate.

#### M5. Session VM state leakage — yes, present; addressed in layers

State leakage between calls in a session VM is real and partly
intentional (warm caches are the perf win). The defense:

- **Pool invariant: single-tenant for lifetime.** A session VM
  is bound to one caller principal at first use and never
  handed to another. The (deferred) session-pool plan inherits
  this as a hard rule. "Tenant" = whatever the SDK declares —
  typically per-deployment / per-build-artifact in the simple
  case; per-end-user in a multi-tenant SaaS. The SDK author
  picks the granularity; pool enforces.
- **Modes for callers who want fresh state**:
  - `mvmctl invoke --fresh` boots a new VM, runs once, tears
    down. Same as today's `mvmctl exec` semantics.
  - `mvmctl invoke --reset` runs the call, then restores the VM
    from its post-boot snapshot before next use (we already have
    snapshot infra). Cheaper than `--fresh`, slightly leakier
    (kernel state, page cache) but practical.
  - default: session reuse, documented contract.
- **Per-call wrapper hygiene** (Nix factory):
  - Per-call `TMPDIR=/tmp/call-<uuid>`, removed on call exit
    (success or failure).
  - Env restored to a build-baked baseline before each call.
  - Working directory reset.
  - User code that wants to keep state across calls puts it in
    module globals (explicit, documented). Anything else gets
    reaped.
- **No file descriptors leak across calls.** Wrapper closes
  any FD opened during the call before returning to listen
  state. Implemented via a build-time wrapper template, not user
  responsibility.
- **Session "poison" semantics.** If a call:
  - exceeds caps,
  - times out,
  - crashes the wrapper (segfault, OOM, etc.),
  - returns a non-zero exit with `kind == InternalError`,

  the host-side session-pool marks the session POISONED, drains
  in-flight calls, tears down the VM. Caller's next call boots a
  fresh one. Single-tenancy means this only affects one caller.

This doesn't reduce leakage to zero — kernel page cache, CPU
state, microarch side channels are still there. ADR-002 names
them out of scope; ADR-0009 inherits.

#### M6. Error envelope hardening

Two-mode wrapper, gated by build-time flag in the Nix factory:

- **prod wrapper** (default for `mode=prod` images):
  - Top-level exception handler around user code.
  - Catches everything; emits structured envelope on stderr:
    ```json
    { "kind": "function-error", "error_id": "<uuid>",
      "message": "<sanitized>" }
    ```
  - **No** traceback, **no** file paths, **no** local var values
    in the envelope.
  - Full traceback ships via a separate operator-log channel
    (vsock secondary stream → host stderr for operators) — the
    SDK caller never sees it; the operator running mvmctl does.
    Distinct channels = distinct trust audiences.
  - User-defined exception classes that the user wants surfaced
    are declared in IR (function's `error_schema` or `raises`
    list — same shape as M1's schema). Anything matching the
    declared shape is passed through unmodified; anything else
    is sanitized to `function-error`.
- **dev wrapper** (`mode=dev` images):
  - Full traceback in stderr OK; SDK caller may see paths.
  - Convenience for debugging; never ships in prod artifacts.
- **CI assertion**: prod-built wrappers contain the
  sanitization branch and lack a "print full traceback" code
  path. Static check on the generated wrapper source pre-bake.

This puts the responsibility on the Nix factory (build-time)
rather than user code. Even if user code does
`raise SomeError("password=" + secret)`, the wrapper catches
it and emits a sanitized envelope.

#### M7. Build-time bundling — sandbox + lockfile + scope

Five disciplines, all leveraging Nix where possible:

- **Nix sandbox does most of the work.** `nix build` runs in a
  network-isolated sandbox (non-fixed-output derivations); only
  declared inputs reach the build. Anything user code tries to
  do at import time (read host fs, exfil over network) is
  blocked by the sandbox itself. This is inherited, not new.
- **Hash-pin all deps.**
  - Python: `requirements.txt --hashes` (pip-tools) or
    `poetry.lock` / `uv.lock` with verification.
  - Node: `package-lock.json` with integrity hashes, or
    `pnpm-lock.yaml` with strict resolution.
  - Reject the IR at validation time if the bundled tree
    declares unhashed dependencies. New error code in
    mvmforge: `E_UNPINNED_DEPS`.
- **No import-time execution of user modules at build time.**
  The Python SDK currently extracts decorator state by
  *running* the user's module — `import app` triggers
  `mv.workload(...)` and `@mv.app(...)`. That import runs
  user-controlled code in the SDK's process, before bundling.
  Mitigations:
  - Run the SDK emitter inside the Nix build sandbox, so even
    that import-time execution is sandboxed.
  - OR: switch to AST-based extraction (no import). Heavier;
    likely a follow-up, not v1.
  - Document: the SDK trusts the source tree as much as the
    operator running `mvmforge up` does.
- **Disable post-install / build hooks for runtime deps.**
  - Node: `npm install --ignore-scripts` for runtime deps. Build
    hooks for TS compile run separately, in a controlled scope.
  - Python: PEP-517 builds for pure-Python wheels are fine;
    sdists with `setup.py` execute arbitrary code at build
    time — disallow for runtime deps (force wheel-only via
    `pip install --only-binary=:all:`).
  - Enforced in the Nix factory; reject the build with a clear
    error if a non-wheel dep is required.
- **Vendor advisory checking.**
  - mvmforge CI: pip-audit / npm audit / cargo audit on the
    bundled tree.
  - Block build with known-vulnerable packages above a chosen
    severity threshold (start: HIGH/CRITICAL).
  - Mirror of mvm's `cargo deny` (W5.2) but for the language
    ecosystem.
- **Tighten bundling scope.** ADR-0008 governs scope; tighten
  to: bundle only the function's reachable transitive imports,
  not the whole project tree. Static analysis (Python: `ast` +
  `modulefinder`; TS: `tsc --listFiles` + tree-shake) gives the
  closure. Reduces blast radius of any vulnerable bundled dep.
- **Optional belt-and-suspenders: build attestation.** mvmforge
  emits a manifest of every file in the rootfs + its hash; mvm
  agent verifies a sample at boot. Largely redundant with
  dm-verity (W3) but cheap, and useful if dm-verity is ever
  disabled in test/dev images.

#### M8. Network: explicit-only, deny by default

**Vsock vs. network.** Two distinct channels, different threat
profiles, different defaults:

| Channel | What it is | Default | How it's bounded |
| --- | --- | --- | --- |
| **vsock** | host↔guest control (Firecracker virtio-vsock) — carries `RunEntrypoint`, stdin/stdout, agent ping | always present (mvm needs it) | implicitly contained: doesn't reach off-host; host socket is mode 0700 (W1.2); other VMs cannot reach a VM's vsock |
| **network** | TAP iface + `br-mvm` bridge + iptables NAT to internet (per CLAUDE.md dev-network layout) | **deny** for function workloads | only present if IR declares it; firewalled to the declared shape |

**Defaults change.** Function-entrypoint workloads default to
`network.mode = "none"`:
- No TAP interface allocated.
- No IP address, no DNS resolver, no default route in the guest.
- Bridge does not learn the VM's MAC.
- Wrapper boots and runs with loopback only (`lo`).

If the user wants network they declare it explicitly in the IR
(today's `network.mode = "bridge"` plus a future, narrower set of
grants). Removing the implicit grant means a function that doesn't
declare network *cannot* reach the internet, the host, or peer VMs
even if the function or its bundled deps try.

**Egress and peer reachability are separate explicit grants.** Today
mvmforge's `network.mode = "bridge"` is one bit — on or off. That's
too coarse for explicit-only. The IR should grow:

- `network.egress` — `none | allowlist`. If `allowlist`, IR carries
  the host:port set the wrapper may dial. iptables/nft rules in
  the bridge namespace enforce.
- `network.peers` — explicit list of *other workload ids* this VM
  can reach. Bridge sets up per-source-MAC firewall rules
  accordingly. Default empty.
- `network.ingress` — `none | ports[]`. Inbound from peers (or
  from the host, if any). Default `none`.
- `network.dns` — `none | resolver | system`. Default `none`. DNS
  is its own grant because resolvers can be exfiltration channels.

This is a meaningful IR extension and a real piece of work in
mvmforge — track in the decorationer Plan-0003 as a separate phase
or a dependent ADR. mvm side just needs to honor what the IR says
when configuring the TAP/bridge for the workload — it already
plumbs `network.mode` through; expanding to the new fields is
mechanical.

**vsock authority does not bypass network policy.** The wrapper
runs under setpriv with seccomp; it cannot raise sockets it isn't
allowed to. Network deny means kernel-side denial, not wrapper-side
opt-in. So a compromised wrapper still can't reach off-VM if the
IR didn't grant network.

**Doctor / build verification.** mvmforge `validate` rejects IR
that:
- Declares `network.peers` referencing workloads not in the same
  build graph.
- Declares `network.egress.allowlist` containing wildcards (`*.*`,
  `0.0.0.0/0`) — explicit means specific. (Or: allow wildcard
  with a noisy warning — pick one. I lean on rejecting; users who
  truly want any-egress are usually doing something they should
  reconsider.)
- Declares `network.dns = system` for prod-mode images without an
  explicit resolver — system DNS leaks the host's resolver config.

`mvmctl doctor` reports the live network posture for a running VM:
TAP present yes/no, firewall rule count, peer reachability matrix.

**vsock surface stays the same.** No new vsock-side grants — the
verbs the agent exposes are already a closed set, and `RunEntrypoint`
is the only one that runs guest code. The W1.3 proxy port allowlist
already drops anything outside the agent + forward ranges.

**Open question for v1 vs v2.** The new IR fields
(`egress`/`peers`/`ingress`/`dns`) are real work in mvmforge. v1 of
function entrypoints could ship with just `mode = none` (default)
and the existing `mode = bridge` (opt-in, full network as today).
v2 lands the granular fields. I'd vote v1 ships the deny-by-default
flip even if the granular grants land later — flipping the default
later is a breaking change for any workload that relied on the
implicit grant.

#### M9. Snapshot file integrity

The warm-pool and `--reset` modes (M5) restore a VM from a saved
Firecracker snapshot. The snapshot lives as a regular file on the
host (`~/.cache/mvm/snapshots/...`). If an attacker swaps that
file, the resumed VM is whatever the attacker wrote — arbitrary
code execution at boot, bypassing dm-verity entirely (verity
verifies on disk reads from the rootfs; a snapshot's *memory image*
is a separate trust path).

Mitigations:

- **Per-snapshot HMAC, keyed by a host-local secret** (in
  `~/.mvm/snapshot.key`, mode 0600, generated on first run). mvmctl
  signs at create, verifies at restore. Any modification to the
  snapshot or its sibling memory-image file fails verification and
  refuses to resume.
- **Snapshot directory is mode 0700** (already inherited from W1.5;
  add a doctor check that confirms it on every run).
- **Atomic create**: write to `<file>.tmp`, fsync, rename. Never a
  partially-valid snapshot on disk.
- **Refuse to resume snapshots from a different mvmctl version
  unless explicitly opted in.** Snapshot format compatibility is
  brittle; a stale snapshot is a stale codebase.

Keep this as a tracked invariant for the deferred session-pool
plan: every cached VM identity is a (rootfs verity hash + snapshot
HMAC) pair.

#### M10. Logging policy: never log payload contents

stdin/stdout/stderr can contain anything — secrets, PII, tokens.
Default agent + mvmctl logging must:

- Log invocation **metadata** only: timestamp, workload id, exit
  code, duration, payload sizes, error kind. No bytes from stdin,
  stdout, or stderr.
- A debug log mode (`MVM_LOG_PAYLOADS=1`) exists for development;
  it's a noisy banner-on-startup flag, refuses in
  prod-mode-detected hosts (e.g. when `/etc/mvm/variant` reads
  `prod`), and is mutually exclusive with shipping the agent at
  all in production builds.
- The operator log channel from M6 (full tracebacks for ops) does
  **not** include payload contents either — only function-side
  errors that the wrapper produced, scrubbed of the values that
  triggered them when possible.

Put this in ADR-0009 explicitly: payloads are by default
unobservable to the operator, observable only to the caller (who
already has them) and the wrapper (running under guest-side
seccomp).

#### M11. Coredumps disabled in prod wrappers

A wrapper crash with coredumps enabled writes process memory to
disk. That memory contains the in-flight stdin payload, partial
return values, and any secrets the wrapper had loaded.

Mitigations:

- Wrapper sets `prctl(PR_SET_DUMPABLE, 0)` at startup (or before
  reading the first stdin byte).
- Init enforces `RLIMIT_CORE = 0` for the wrapper service.
- Both built into the Nix factory's wrapper template — not optional.
- Dev wrappers may relax this (developer needs the dump to debug).

Also: disable `ptrace` attach on the wrapper (`PR_SET_DUMPABLE` 0
already does this in conjunction with yama). One small change,
closes a whole class of disclosure paths.

#### M12. Concurrency on session VMs: serialize per VM

Open question I should have surfaced earlier: does the agent allow
multiple in-flight `RunEntrypoint` calls on the same VM?

Recommendation: **no, one in-flight call per session VM.**
Concurrency comes from pool growth, not from intra-VM parallelism.
Reasons:

- Wrapper state (TMPDIR, env, FDs from M5) is per-call. Concurrent
  calls would interleave in confusing ways.
- Memory budget is per-VM. Two calls' working sets can OOM a VM
  sized for one.
- Error semantics are simpler: a poisoned call poisons one VM,
  not many tenants on one VM.

Implementation: agent holds a mutex around `RunEntrypoint`; second
caller gets `EntrypointEvent::Error { kind: Busy }` immediately,
host-side pool then routes to a different warm VM (or boots one).

#### M13. Secrets path: per-service injection, never stdin

A caller's first instinct is to put a secret (API key, DB
password) in the function's args — i.e. in the stdin payload.
That's wrong for several reasons stacked together:

- stdin payloads are visible to the host SDK invoking mvmctl
  (necessarily — they have to encode them).
- Some logging path could capture them (M10 closes the default,
  but a misconfigured operator-debug toggle could open it).
- They become part of every replay test, every captured bug
  report, every screenshot.

Right path:

- Secrets flow via the existing per-service mechanism in
  `/run/mvm-secrets/<svc>/` (CLAUDE.md, post-W2.1; mode 0500 dir,
  files mode 0400, owned by the service uid).
- mvmforge's `SecretRef` IR field (named in mvmforge README as
  not-yet-implemented) is the deploy-time declaration that wires
  the secret in at boot.
- ADR-0009 explicitly forbids secret content in stdin schemas.
  Validation rule: schema fields named `*token*`, `*password*`,
  `*key*`, `*secret*` produce a build warning; declared-secret
  types (a future IR primitive) hard-error.

This is mostly mvmforge's job. mvm side: agent doesn't accept
secret data over the call channel — there's nothing to do at the
agent except *not adding* a "set runtime secret" verb.

#### M14. Wrapper crash + signal safety

The wrapper's per-call hygiene (M5: TMPDIR cleanup, env reset,
FD close) must run even when:

- The wrapper crashes mid-call (segfault, OOM, panic in user code
  bubbling past the wrapper's catch).
- The agent kills the wrapper on timeout / cap-breach (M1).
- mvmctl is killed mid-invoke and the agent decides to clean up.

Implementation:

- TMPDIR cleanup runs from the *agent*, not the wrapper.
  `/tmp/call-<uuid>` is a directory the agent created with the
  call's id; it's `rm -rf`'d after the wrapper exits regardless
  of how it exited. Pulling the responsibility out of the wrapper
  means it's robust to wrapper crashes.
- Env / FD reset: the wrapper is *re-spawned* per call rather
  than running a long-lived listen loop. The "warm" piece is the
  VM (page cache, loaded interpreter); each call gets a fresh
  wrapper process with fresh FDs and env. Modest perf cost
  vs. cleanup correctness — worth it.
- Session VM tear-down on `mvmctl invoke` interruption: agent
  notices vsock disconnect mid-call, sends SIGTERM to wrapper,
  cleans TMPDIR, returns to listen state for next call.

#### M15. Per-language seccomp profiles

ADR-002 ships a `standard` seccomp tier (W2.4). Different language
wrappers have different syscall needs:

- Python: needs `clone3` (threading), `mmap` flags for the GC,
  `getrandom` for `os.urandom`.
- Node: libuv uses `epoll`, `eventfd2`, `signalfd4`, etc.
- Go (future): runtime touches more syscalls.

Risk: a too-tight profile breaks the wrapper at runtime; a
too-loose profile leaves attack surface.

Mitigation:

- Ship per-language seccomp tiers: `standard-python`,
  `standard-node`, derived from `standard` plus the language's
  documented runtime syscall set.
- Each tier's allowlist is built and reviewed in the same place
  the language wrapper lives (Nix factory).
- CI lane: boot a representative wrapper, run a smoke function,
  assert no unexpected EPERM denials.
- A new wrapper language requires a new tier — gate on review.

This is mostly Nix-factory work in mvmforge; mvm just exposes the
tier-loading mechanism (already there per W2.4).

#### M16. Wrapper distribution / supply chain

The wrapper itself is mvmforge code, generated by Nix factories
into the rootfs. Two questions:

1. **How is the user sure the wrapper is what mvmforge says it
   is?** mvmforge's source needs to live somewhere with strong
   provenance (signed releases, reproducible builds). The W5.3
   reproducibility guarantee in mvm extends naturally to mvmforge
   if its build is reproducible too — track in the mvmforge plan.
2. **How is mvmforge sure the user's image hasn't tampered with
   the wrapper post-bake?** dm-verity (W3) covers this — the
   wrapper is on the verity rootfs, can't be modified post-build
   without breaking the roothash.

So the chain is:
- mvmforge source → reproducible build → known wrapper bytes
- wrapper baked into rootfs → dm-verity covers the rootfs
- agent reads `/etc/mvm/entrypoint` and verifies path on verity
  partition (M3)

Each link is covered. Naming the chain explicitly in ADR-0009
makes it auditable.

A future follow-up: SLSA-style attestation (signed manifest of
build inputs + builder identity) so a downstream consumer of a
mvmforge artifact can verify the chain without rebuilding. v1
relies on reproducibility + dm-verity; SLSA is v2+.

### Plan deltas

Folding the above + mitigations M1–M16 into the plan would add:

- **mvm-side ADR**: invariants 3, 4, plus stdin/stdout caps and
  timeout enforcement explicit.
- **mvmforge ADR-0009**: invariants 2, 5 (per-call hygiene + pool
  single-tenancy as a deferred-plan input), 6, 7.
- **Session-pool follow-up plan**: pre-baked invariant —
  *single-tenant for lifetime*.
- **doctor**: verify `/etc/mvm/entrypoint` is on the verity
  partition and resolves directly (no symlinks crossing FS
  boundaries).
- **CI**: combined `prod-agent-runentry-contract` lane (asserts
  both halves of the symbol contract atomically).

## Decisions (locked)

- **Format default**: **JSON** in v1, msgpack opt-in via the IR
  `format` field. JSON debugs cleanly with
  `mvmctl invoke ... --stdin <(echo '...')` + `cat`; msgpack wins
  on bytes/floats round-trip and is the upgrade path for workloads
  that need byte-fidelity. Both decoders pinned to stdlib / audited
  libraries (M1).
- **Schema-bound payloads**: **v2.** v1 ships caps + format
  validation only (M1's hard caps are sufficient defense for the
  immediate threat surface). v2 derives JSON Schema from type hints
  (Python `pydantic` / TS `zod`) and validates inbound bytes before
  user code runs.
- **Granular network IR fields**: **v2.** v1 ships the deny-default
  flip with the existing one-bit `network.mode`. v2 lands the
  granular `egress` / `peers` / `ingress` / `dns` grants. The
  breaking change is flipping the default to deny, which lands now;
  the granular surface is additive and can grow later.
- **HMAC key rotation policy** (mvm-side): never rotate
  `~/.mvm/snapshot.key`. Warm pools regenerate; operational
  simplicity beats crypto-agility for a local-host-only HMAC key.
- **`--reset` mode** (mvm-side): wire the flag in W3, no-op until
  the session-pool plan lands.
- **Network deny-default scope**: function-entrypoint workloads
  only. Other workload kinds keep their current default; flipping
  them is a separate ADR.

## Status

Plan approved 2026-05-04. Specs extracted:

- `specs/adrs/007-function-call-entrypoints.md` (this repo)
- `specs/plans/41-function-call-entrypoints.md` (this repo, impl
  tracker)
- `specs/plans/41-function-entrypoints-design.md` (this file —
  comprehensive design rationale + 16 mitigations)
- `/Users/auser/work/rust/mine/decorationer/specs/adrs/0009-function-entrypoints.md`
- `/Users/auser/work/rust/mine/decorationer/specs/plans/0003-function-entrypoint-runtime.md`

CLAUDE.md memory entries saved:
- `feedback_build_time_everything.md`
- `feedback_explicit_permissions_only.md`
- `project_decorationer_is_mvmforge.md`
