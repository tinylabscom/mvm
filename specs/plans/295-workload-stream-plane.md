# Plan 295 — Workload stream plane

**Status:** Proposed.

Streaming stdout/stderr for every workload, while it runs and when it exits,
across CLI, library, SDK, and fleet consumers — plus a default-deny input
channel so an external consumer can feed a running workload.

Companion ADR: `specs/adrs/035-workload-stream-plane.md` (deliverable of this
plan, not a prerequisite).

## Requirement

For all workloads, stdout and stderr must be capturable while the workload is
running and when it exits, and the capture must be streaming. The user must be
able to see what a workload is doing without a shell in production. This is a
hard requirement, not a nice-to-have, and the observability it provides is the
reason these workloads exist.

Consumption must be available from the CLI, from library code, and
programmatically from the SDKs. In a fleet, one microVM must be able to receive
another's output as input; `mvmd` owns the fleet topology, `mvm` must expose the
primitives it composes.

## What is broken today

Streaming exists only on the `interactive`-gated `do_exec` path
(`crates/mvm-agentd/src/exec_stream.rs`), which claims 4 and 15 deliberately
exclude from production builds. Everything a production workload can reach is
one of these four:

1. **The agent buffers to exit.** `entrypoint.rs:612` runs `poll_for_exit`, then
   joins the drain threads at `:614-616`. No byte leaves the guest until the
   child is dead. `response_payloads.rs:288` states it outright: *"Buffered
   output is split into bounded `Stdout` and `Stderr` events."* The wire is
   streaming-shaped; the producer is not.
2. **Output is capped at 1 MiB per stream and the cap kills the workload.**
   `entrypoint.rs:403-404` sets `stdout_max`/`stderr_max`; a breach yields
   `CallOutcome::PayloadCap`. A workload is terminated for producing output.
3. **`mvmctl machine logs` cannot reach the native backends.** It routes to
   `microvm::logs` (`observe.rs:19`), which calls `require_linux_env()` and then
   `tail -f` *inside the builder VM* (`observe.rs:51-58`) — the legacy
   Firecracker-in-Linux-VM path. `VmBackend::logs`
   (`workload_runner/runner.rs:1031-1034`) reads `console.log` whole with
   `read_to_string`: no tail, no follow, and nothing wires the CLI to it.
4. **`machine run` never attaches to output.** It prints "attach with `machine
   shell`", which is the dev-only interactive path barred in production by
   claim 15.

So in production a user gets output at exit, truncated at 1 MiB, or a console
file the CLI cannot reach.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | Both console capture and vsock entrypoint frames feed one stream, tagged by source | vsock alone goes dark before the agent starts and after it dies — exactly when a boot failure, verity refusal, or agent OOM needs explaining. Console alone cannot separate stdout from stderr. |
| D2 | Ordering is by host-side monotonic receive stamp; interleaving between sources is best-effort, ordering within a source is exact | The two sources traverse different paths with different latencies. A total order across them is not something the transport can deliver, so it is not promised. |
| D3 | Retention is a ring: drop oldest, record an explicit gap marker, never kill or throttle the workload | A workload silenced or killed at a byte cap is unobservable exactly when it is most interesting. Inverts the requirement. |
| D4 | Each chunk carries the prior chunk's hash; the sealed Merkle root still covers the capture at exit | A live follower detects a rewrite or a silent gap before the capture seals. Mirrors `verify_audit_chain` semantics already in the tree. Cost is one hash per chunk. |
| D5 | Output is always-on and ungranted; input is default-deny and plan-bound | Same asymmetry egress already has. Reuses claim 12's machinery instead of inventing a parallel authorization path. |
| D6 | Input reaches the entrypoint's stdin; a single writer holds a lease | stdin is what makes ordinary programs work without SDK support. Two concurrent writers to one byte stream produce interleaved garbage, so concurrency is arbitrated, not merged. |
| D7 | `--prod` refuses the *input grant* when the plan's entrypoint resolves to a shell | Output streaming stays unconditional. Keeps claim 15's boundary crisp: a sealed prod workload can be fed data, never commands. |
| D8 | stdout/stderr are stored verbatim as opaque bytes; `tracing` is an adapter on read, never a storage format | Byte-exactness is load-bearing because the record is hash-chained. Convert on write and the original bytes are unrecoverable. |
| D9 | Retention mode lives in the signed `ExecutionPlan`, defaults to persist, and is chain-signed at admission | Claim 8 makes the plan the single place capability is decided. An unaudited opt-out would make an absent transcript indistinguishable from a suppressed one — the ambiguity plan 280 refused for v1 manifests. |
| D10 | Redaction runs before the hash-chain | Keeps redaction at one seam. Consequence, documented rather than discovered: the chain proves what was *shown*, not what the workload *wrote*. |

## Architecture

```
guest                            host                          consumers
─────                            ────                          ─────────
entrypoint child
  stdout ──┐                ┌──────────────────┐
  stderr ──┤ pump ──vsock──►│  OUT: ingest     │──► redact ──► hash-chain ──► append
  fd-3   ──┘                │  2 sources,      │                                 │
kernel ────console─────────►│  host-stamped    │                                 ▼
                            └──────────────────┘                    ┌────────────────────┐
                                                                    │  stream broker     │
  stdin  ◄───vsock──────────┌──────────────────┐◄───────────────────│  N readers         │
         (single writer)    │  IN: grant check │                    │  1 writer (lease)  │
                            │  secret gate     │                    └────────────────────┘
                            │  bounded + audit │                       ▲   ▲   ▲
                            └──────────────────┘                       │   │   │
                                                          mvmctl ──────┘   │   └────── SDKs
                                                          mvm-client ──────┘
                                                            (and mvmd, same protocol)
```

Five units, each independently testable.

### `mvm-protocol::stream` (no_std + alloc)

`StreamRecord { seq, source, stream, host_unix_nanos, prev_hash, payload }`
where `source ∈ {Console, Entrypoint}` and `stream ∈ {Stdout, Stderr, Trace}`;
plus `InputFrame` and `CloseInput`. Chain verification is a pure function, so
the same code checks a chain in the CLI, in `mvmd`, and in a browser — the crate
already builds on `wasm32-unknown-unknown` for the audit-log verifier.

### Guest pump (`mvm-agentd`)

The only behavioural change inside the guest. `drain_capped` plus
join-after-`poll_for_exit` becomes a pump that emits an `EntrypointEvent` per
read. `PayloadCap` stops meaning "kill the workload" and starts meaning
"ring-prune and mark a gap". fd-3 gets its first emitter — the `Control` variant
has shipped without one since `response_payloads.rs:320`. No tokio; the sealed
agent's default closure stays as it is.

### Stream store (`mvm-core::transcript`, extended)

The durable, tamper-evident, encrypted store already exists and is reused, not
rebuilt. `TranscriptWriter` (`transcript.rs:308`) writes AEAD-encrypted chunks
to disk on every push, hashes the ciphertext into a `ChunkRecord`, bounds the
capture with `CaptureBudget`, and seals a `TranscriptManifest` carrying an
RFC-6962 Merkle `sealed_root_hex` that plan 280 anchors in the chain-signed
audit log. `verify_chunks`, `verify_sealed_root`, and `export` are reused
unchanged. `PiiRedactor::redact` (`pii_redactor.rs:354`) is the redaction
engine.

Four mismatches this plan closes:

- **`Direction` is `{Egress, Ingress}`** (`transcript.rs:29-32`) — network-shaped.
  Gains stdout/stderr/trace variants.
- **`seal()` consumes `self` and only runs at end of capture**
  (`transcript.rs:400`), so the manifest, sealed root, and audit anchor do not
  exist while the workload runs. `ChunkRecord` gains `prev_hash` so a live
  follower has something to verify against before the seal (D4).
- **Bounds fail closed** (`BoundExceeded`, `transcript.rs:99`). Correct for a
  forensic egress capture, fatal for logs. Log captures get ring semantics (D3).
- **One file per chunk** (`{seq}.chunk`, `transcript.rs:376`) and capture is
  *"never tenant-wide by default; it is armed for a specific binding"*
  (`transcript.rs:53-54`). A continuous stream needs size-or-interval batching
  and an always-on default, so retention becomes an explicit signed decision
  (D9) rather than a silent reversal of that stance.

### Stream broker (`mvm-hostd`)

Resident in the existing per-tenant broker daemon — *"one daemon per tenant, not
one process per VM"* (`broker/daemon.rs:3`). It ingests both sources, stamps the
host-monotonic sequence, runs redaction outbound and the secret gate inbound,
fans one producer out to N readers, arbitrates the input lease, and emits
chain-signed audit on subscribe, input-session-open, and input-refusal — never
payload bytes.

**Correction, found during execution.** Earlier drafts cited
`audit_chain_carries_no_payload_bytes` as the inherited guard here. That test
does not exist — not on this branch, not on main. It is named only in
`CLAUDE.md`'s claim-12 narrative, which is stale. The real ledger row
(`specs/adrs/001-microvm-security-posture.md:476`) names
`fn:unbound_service_returns_not_bound` and
`fn:service_call_rejects_unknown_envelope_fields`, so
`xtask check-claim-catalog` was never broken. Payload-freedom has no inherited
guard; this plan must supply its own.

Redaction lives here and only here. Mirrors `EgressGate` as the sole claim-10
decision point: if redaction were per-consumer, every new consumer would be a
new leak path.

### Consumers

`mvmctl logs -f`, attach-by-default on `run`/`up`, live `invoke`, a library
trait, the language SDKs, and — in slice 2 — `host.stream.v1`.

**Correction to the crate map.** `CLAUDE.md` describes `mvm-client` as a facade
behind one `dyn MvmClient`. That trait does not exist: `crates/mvm-client/src/`
holds `boot.rs`, `connect.rs`, `lib.rs`, `local.rs`, `readiness.rs`,
`registration.rs` and zero `pub trait`, and the CLI uses `AnyBackend` directly.
This plan does not depend on that facade landing. Wire DTOs live in
`mvm-protocol`; consumers speak a UDS protocol to the resident broker;
`mvm-client` gains one small self-contained trait for that; `mvmd` fronts the
identical protocol remotely.

## Input plane

|  | Output | Input |
|---|---|---|
| Default | always on | **denied** |
| Authorization | none | signed `ExecutionPlan.services` grant |
| Concurrency | N followers | 1 writer, leased with timeout |
| Gate | PII redaction | secret-material refusal |
| Audit | on subscribe | on session open **and** on every refusal |
| Termination | seal at exit | explicit `CloseInput` → EOF |

A host→guest input path is not new: `RunEntrypoint` already carries
`stdin_data`, and `entrypoint.rs:590-594` writes it into the child and closes
the pipe. What is new is that it becomes continuous.

The grant slot is real. `ExecutionPlan.services: Vec<ServiceId>`
(`plan/synthesis.rs:174`) already exists, and the broker registry's resting
state is refusal — *"until any are registered every call returns
`Err(NotBound)`"* (`broker/mod.rs:6`) — so `host.stream.v1` inherits default-deny
without new machinery.

Explicit EOF (D6) is a correctness trap worth naming: today stdin is written
once and closed, so read-to-EOF programs terminate. Continuous input without a
`CloseInput` frame hangs every `cat`-shaped workload forever.

## Tracing posture

The goal is one tool and one timeline, not one format.

One transport carries two payload kinds. `Stdout` and `Stderr` are opaque
verbatim bytes, never parsed or reframed. `Trace` carries a structured fd-3
record shaped like a tracing event — level, target, fields, span id, monotonic
timestamp — so a host-side `tracing-subscriber` bridge can republish the stream
into a consumer's existing setup. `mvmctl logs -f` renders both kinds
interleaved in one view without involving `tracing` at all.

Routing stdout/stderr *through* `tracing` is rejected. It forces a framing
choice, and line-framing mangles `\r` progress output, partial lines, binary
payloads, and JSON-on-stdout. Byte-exactness matters here specifically because
the record is hash-chained: if the stored bytes are not the produced bytes, the
chain proves the wrong thing. `tracing` events also carry level/target/fields
that stdout does not have, so the conversion invents metadata and then commits
the invention to a Merkle root.

The dependency is not the objection. `tracing` is already a workspace dep and
already listed in `crates/mvm-agentd/Cargo.toml:198-199`, though unused in the
guest agent bin and in `entrypoint.rs`. Store verbatim, adapt at the edge.

## Security analysis

### Unaffected

Claims 1–3 (host-fs access, uid 0 elevation, verity) — input reaches a pipe, not
a filesystem. Claim 4 — no exec path is added. Claim 10 — no NIC, vsock only;
`xtask check-vsock-only-egress` and `check-uniform-vsock-egress` stay green.

### Strengthened

Claims 8 and 9 — input becomes a plan-bound capability covered by existing
admission, signing, and audit, rather than an ambient ability.

### Weakened, deliberately

**Claim 15 moves from structural to policy.** Today there is no production input
path at all, so "no interactive access to a sealed production microVM" holds by
*absence*. After this it holds by grant-check plus shell-refusal. Absence is a
strictly stronger guarantee than policy, and the ADR must record this as a trade
rather than assert parity.

What still holds structurally: the entrypoint program is fixed at admission,
read from `/etc/mvm/entrypoint`, validated at boot, and is the only program
`RunEntrypoint` will spawn (`vsock/request.rs:82-84`). Input bytes cannot select
a program, alter argv or env, or spawn anything. The distinction is `run -i`,
not `exec -it sh`.

Per the decision on the claims ledger, claim 15 is **reworded** to state what it
now guarantees, and **claim 17** covers the input channel's own properties, so
each is backed by its own witnesses rather than bundling two properties under
one number.

**Ledger location, corrected.** `CLAUDE.md` names `specs/claims/catalog.md` as
the contiguous ledger. That file does not exist. `xtask/src/claims_ledger.rs:50-52`
parses the claims table inside `specs/adrs/001-microvm-security-posture.md`,
currently rows 1–16 (row 16 at status `Preview`), with witnesses named
`fn:<test_name>` or `ci:<job_name>`. Claim 17 is the next free row, and
`xtask check-claim-catalog` gates its witnesses there.

**Shell-shaped entrypoint, defined.** D7 needs a rule an implementation can
apply, so the `--prod` input-grant refusal fires when any of these hold for the
plan's resolved entrypoint: the basename matches a known shell
(`sh`, `bash`, `dash`, `ash`, `busybox`, `zsh`, `ksh`, `fish`); the file is a
script whose shebang interpreter's basename matches that set; or the entrypoint
argv invokes an interpreter with an inline-command flag (`-c`). Per R1 this is a
heuristic and is documented as one — it raises the cost of laundering
interactive access, it does not prove the absence of it.

### Residual risks

- **R1 — Shell detection is a heuristic, not a proof.** A wrapper script, a
  `#!/bin/sh` shebang, or a program that `exec`s a shell defeats a basename
  check. D7 is defense in depth. Moving input to a side fd does not help: a
  shell can read fd 4 and pipe it to itself. The control is the grant.
- **R2 — The secret gate is evadable by frame-splitting** unless it scans a
  sliding window across frame boundaries, and is best-effort even then. Claim
  13's strength remains that the host has no reason to send a secret; the gate
  is a backstop against client error, not a defense against a hostile host
  (out of scope per ADR-001).
- **R3 — A new frame parser lands in the sealed agent.** It joins the claim-5
  fuzz targets rather than shipping unfuzzed.
- **R4 — Lease liveness.** A consumer that takes the input lease and dies blocks
  all input. Requires a timeout and heartbeat.
- **R5 — The chain proves what was shown, not what was written** (D10). The
  original pre-redaction bytes are unprovable after the fact. Accepted as the
  price of a single redaction seam.
- **R6 — Always-on capture is a data-retention change.** Output that previously
  evaporated is now persisted encrypted at rest. Mitigated by AEAD, redaction,
  ring bounds, `~/.mvm` mode 0700, and the signed ephemeral opt-out (D9).

## Slices

### Slice 1 — the vertical slice (this plan)

Both directions end-to-end for external consumers. Guest pump, extended store,
resident broker, CLI surfaces, library trait, SDK surface, input grant with
lease and secret gate and explicit EOF, ADR-035, website documentation, claim
ledger changes.

### Slice 2 — fleet fan-out (own plan, own claim work)

Pure composition once slice 1 ships both halves: bind one workload's output
stream to another's input stream. The broker is already the only place bytes
cross, so it is already the single authorization point.

The invariant that keeps this from eroding the vsock-only posture: **a guest
never addresses another guest.** VM B names a binding from its own signed plan;
the host resolves that binding to VM A and copies bytes between two independent
vsock channels. A and B never share a transport, never learn each other's
identity, and neither gains a NIC.

`mvmd` declares fleet edges. `mvm` exposes exactly two primitives that
composition needs — a plan-bound output subscription and a plan-bound input
grant — and never needs to know what a fleet is.

**Four decisions settled during Phase 2, to be carried into the slice-2 spec as
design rather than open questions.**

*Redaction is a property of the edge, defaulting to redacted.* Neither global
answer works: always-redact corrupts a pipeline where the second stage needs
what the first computed, and never-redact makes every edge a leak path around
the single seam. The edge declaration in the signed plan carries the posture,
the default is redacted, and fidelity requires an explicit signed opt-out that
is audited — the same shape as default-deny egress with an explicit grant. On an
opt-out edge the consumer receives raw bytes while the durable transcript still
stores the redacted copy and the divergence is audited, mirroring how `invoke`
returns its caller's own bytes without weakening the artifact that outlives the
run.

*The single-writer lease stays; fan-in is a merge node.* Two producers
interleaving into one stdin produce corrupted records, and stdin carries no
framing to recover them. The lease is the honest shape of a byte stream, not a
limitation to remove. A workflow needing fan-in expresses a merge stage, which
is itself a workload the fleet can already declare. Because an edge consumes the
consumer's single input slot, a consumer cannot simultaneously take operator
stdin — that must be a diagnosable admission error, not a runtime surprise.

*Backpressure: never stall, never silently lose.* With finite memory a producer
that outruns its consumer forces a choice, and this plan already chose never to
stall a workload. Edges therefore declare a mode. `lossy` is the default and
behaves exactly as the reader queues do — ring, evict oldest, mark the gap,
audit it. `reliable` keeps the producer unstalled but fails the edge loudly when
its buffer fills, so overflow surfaces as a visible workflow error rather than
silent record loss. A mode named `reliable` must never quietly drop records.

*The topology is a DAG, enforced at admission.* A cycle breaks termination,
because EOF propagates downstream and a workload whose input is downstream of
itself never closes. Combined with lossy eviction a cycle does not even deadlock
— it degrades into a silently churning loop. It also makes provenance
unanswerable: every edge hash-chains, so a cycle leaves no order in which to ask
what a workload actually saw. The fleet topology is declared, so the graph is
static: validate once at admission and refuse a cyclic declaration before
anything boots. Iteration, where genuinely needed, belongs to an external
orchestrator re-invoking the DAG, which keeps termination and provenance
intact.

## Error handling

Failures degrade the stream, never the workload. A workload that dies because
logging broke inverts the requirement.

- Broker down or slow → the guest pump keeps draining into its bounded ring and
  drops oldest with a gap marker. It never blocks the child's pipe, because a
  blocked pipe stalls the workload.
- Redaction failure → fail closed, drop the chunk, record a redaction-failure
  marker. A byte that cannot be checked does not ship.
- Input refused (no grant, lease held, secret material, shell entrypoint under
  `--prod`) → refuse the frame, audit the refusal, leave the workload untouched.
- Chain break on read → surface loudly and keep streaming. `mvmctl logs` exits
  nonzero on a verify failure, mirroring `mvmctl trust audit verify`.
- Console source unavailable on a backend → degrade to entrypoint-only and say
  so, rather than failing the whole follow.

## Testing

Per unit, since each is independently testable:

- Chain verify in `mvm-protocol`: roundtrip, tampered chunk, reordered chunks,
  gap marker, wasm target build.
- Guest pump: bytes arrive *before* child exit under a slow producer. This is
  the regression that catches a silent revert to buffering.
- Ring prune: newest retained, gap marker recorded, workload never killed.
- Redaction and secret gate: positive and negative paths, frame-split evasion.
- Broker: fan-out to N readers, single-writer lease contention, lease timeout.
- EOF delivery so a `cat`-shaped workload terminates.
- Backend uniformity: console source present on Firecracker, libkrun, HVF, QEMU.

Claim-facing witnesses, registered as `fn:`/`ci:` names in the claims table in
`specs/adrs/001-microvm-security-posture.md` so `xtask check-claim-catalog`
gates them:

- Input refused without a plan grant.
- Input refused under `--prod` with a shell-shaped entrypoint.
- Secret material refused inbound, including split across frames.
- A stream-plane audit entry carries no payload bytes. This plan writes the
  test; the guard earlier drafts cited does not exist.
- `following_the_console_never_writes_to_it` still passes — the console capture
  keeps no host input fd.
- Retention mode recorded in `plan.admitted`, so "was this run recorded?" is
  answerable from the chain alone.

## Deliverables

- [x] `specs/adrs/035-workload-stream-plane.md` — posture, the tracing
      boundary, the redaction trade, and the three shipped limits. The claim-15
      trade and the input asymmetry stay with the input plane (T11–T16), which
      is where that decision is actually made.
- [x] Claim 15 reworded and claim 17 added to the claims table in
      `specs/adrs/001-microvm-security-posture.md`, each with `fn:`/`ci:`
      witnesses that `xtask check-claim-catalog` resolves.
- [x] `CLAUDE.md` corrected on three drifts this plan had to work around: the
      claims ledger lives in ADR-001, not `specs/claims/catalog.md`;
      `mvm-client` has no `dyn MvmClient` facade; and the claim-12 narrative
      names `audit_chain_carries_no_payload_bytes` as a witness, which exists
      nowhere in the tree. The ADR-001 ledger row is correct, so
      `check-claim-catalog` never caught it — only the prose is wrong. Audit the
      rest of that narrative for the same failure while fixing it.
- [x] Website documentation (Phase 1 half):
      `public/src/content/docs/guides/workload-output-streaming.md` (following
      output live and after exit, the verification model, the `--stream`
      filter, what a truncation or gap notice means, and the three limits); the
      stream surfaces added to
      `public/src/content/docs/reference/cli-commands.md`. Feeding a running
      workload, the claim-15 rewording, and claim 17 belong to T15–T16.
- [x] Website documentation (Phase 2 half):
      `public/src/content/docs/guides/workload-input.md` — the grant, the
      single-writer lease, the secret scan and what it is worth, explicit EOF,
      the `--prod` shell refusal stated as the heuristic it is, the claim-15
      trade, and the four limits. A sibling page rather than a section of the
      output guide, because output is on by default and the input channel has
      no operator surface; one page must not lend the other its "this works"
      framing. The sealed-prod verb table in
      `public/src/content/docs/reference/guest-agent.md` gains the stdin verbs
      it had drifted from.
- [x] `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` updated in the same
      change as each workstream lands.

## Open questions

None blocking. Slice 2's claim analysis is deferred to its own plan by design,
not by omission.

---

# Implementation plan

> **For agentic workers:** use `superpowers:subagent-driven-development` or
> `superpowers:executing-plans` to work this task-by-task. Steps are `- [ ]`
> checkboxes.

**Goal:** every workload's stdout and stderr stream live to CLI, library, and
SDK consumers while it runs and after it exits, and a plan-authorized external
consumer can feed a running workload.

**Architecture:** two producers (guest vsock frames, host console capture) feed
one host-resident broker that redacts, hash-chains, and appends into the
existing transcript store, then fans out to N readers. Input is the mirror path
with the opposite default: denied unless the signed plan grants it.

**Tech stack:** Rust, `mvm-protocol` (`no_std` + alloc), `mvm-core::transcript`
(AEAD + RFC-6962 Merkle), `mvm-hostd` broker daemon, vsock, `cargo nextest`.

**Phase boundary:** Phase 1 (T1–T5, T5b, T6–T10) ships standalone — live output
on every backend. Phase 2 (T11–T16) adds the input plane. Two PRs is a
legitimate split.

## Global constraints

Every task inherits these. They are repo-wide gates, not suggestions.

- **No spec references in code comments.** `Plan NNN`, `ADR-NNN`, `#NNNN`, `W#`
  are banned in Rust comments and gated by `cargo run -p xtask
  check-no-spec-refs-in-comments`. Describe the behaviour, not the paperwork.
- **No `#[allow(clippy::…)]`.** `clippy::too_many_arguments` is banned outright;
  introduce a params struct with a builder instead.
- **No `.unwrap()` and no `panic!()` in production code.** Use `.expect("reason")`
  with a reason that explains the invariant. One carve-out, tests only: the
  else-arm of an exhaustive match in a test may `panic!` with the unexpected
  value, because `assert!(matches!(..))` discards it from the failure message.
- **Production files cap at 1500 lines** (`check-file-size`; trailing test
  modules are exempt). `crates/mvm-agentd/src/entrypoint.rs` is already 1276
  lines — new logic goes in new modules.
- **`mvm-core` stays tokio-free** (`check-core-runtime-free`) and **the sealed
  guest agent stays runtime-free** (`check-guest-agent-runtime-free`). No async
  runtime in T1–T4 or T13.
- **All `~/.mvm` paths go through `mvm_core::config` helpers.** Never build them
  from `$HOME`; `check-single-home` and `check-test-home-isolation` gate it, and
  inline paths break `MVM_HOME` worktree isolation.
- **No hardcoded IPs or addresses** (`check-no-network-literals`).
- **`cargo xtask` is a global stub — always `cargo run -p xtask <gate>`.**
- **`cargo fmt --all`** (CI Lint uses nightly rustfmt; run nightly locally).
- `mvm-agentd` tests flake under full parallelism — run that crate with
  `-j 6` and re-run in isolation before blaming a change.

- **`--workspace --all-targets` DOES NOT COMPILE EVERYTHING.** Targets behind
  `required-features` are silently skipped, `mvm-conformance`'s BDD test target
  among them (`required-features = ["bdd"]`). CI compiles it in a separate lane,
  so a green local run can still merge red. Task 6b broke exactly this way: a
  new struct field made the conformance target fail `E0063` while every gate the
  implementer ran reported clean. Any change to a shared type must compile the
  feature-gated lane too.
- **Off-by-default *features* have the same blind spot as `required-features`
  targets.** `--all-targets` selects targets, not features, so an off-by-default
  module compiles in no default gate at all. Task 8 added `mvm-client`'s
  `tracing-bridge`; a task that touches a feature-gated module must run that
  feature explicitly or it is shipping code nothing built.

Per-task gate command, run before every commit:

```sh
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo clippy -p mvm-conformance --tests --features bdd -- -D warnings && \
cargo nextest run -p <crate> && \
cargo nextest run -p mvm-client --features tracing-bridge && \
cargo run -p xtask check-no-spec-refs-in-comments
```

The conformance line is not optional padding — it is the only one of these that
compiles a `required-features` target, and it is where a shared-type change
surfaces.

Full gate before any push: `just ci` plus `cargo run -p xtask check-file-size`,
`check-claim-catalog`, `check-core-runtime-free`, `check-guest-agent-runtime-free`,
`check-vsock-only-egress`, `check-uniform-vsock-egress`.

## File structure

| File | Responsibility |
|---|---|
| `crates/mvm-protocol/src/stream/record.rs` | `StreamRecord`, `StreamSource`, `StreamKind`, `GapMarker` DTOs |
| `crates/mvm-protocol/src/stream/chain.rs` | pure `verify_chain` over a record slice |
| `crates/mvm-protocol/src/stream/input.rs` | `InputFrame`, `CloseInput` DTOs (Phase 2) |
| `crates/mvm-core/src/transcript.rs` | `Direction` variants, `ChunkRecord.prev_hash` |
| `crates/mvm-core/src/transcript/ring.rs` | ring retention, prune, gap accounting |
| `crates/mvm-agentd/src/stream_pump.rs` | unbuffered stdout/stderr/fd-3 pump |
| `crates/mvm-agentd/src/stream_input.rs` | inbound frames → child stdin, EOF (Phase 2) |
| `crates/mvm-hostd/src/stream/broker.rs` | ingest, fan-out, reader registry |
| `crates/mvm-hostd/src/stream/console_source.rs` | console-capture tail source |
| `crates/mvm-hostd/src/stream/input_gate.rs` | grant check, lease, secret gate (Phase 2) |
| `crates/mvm-cli/src/commands/vm/logs.rs` | `logs -f` against the broker |
| `crates/mvm-core/src/stream_client/` | consumer trait, opts/filter, batch frame, framed reader |
| `crates/mvm-hostd/src/stream/serve.rs` | the per-VM broker socket followers connect to |
| `crates/mvm-client/src/stream.rs` | consumer surface over the broker UDS (re-export) |
| `crates/mvm-client/src/stream_tracing.rs` | feature-gated `tracing` republishing bridge |
| `crates/mvm-sdk/src/stream.rs` | same reader on the runtime SDK surface (re-export) |

---

## Phase 1 — output plane

### Task 1: stream record DTOs and chain verification

**Files:**
- Create: `crates/mvm-protocol/src/stream/mod.rs`, `stream/record.rs`, `stream/chain.rs`
- Modify: `crates/mvm-protocol/src/lib.rs` (add `pub mod stream;` after `pub mod plan;`)

**Interfaces:**
- Consumes: `mvm_protocol::merkle` (existing).
- Produces: `StreamRecord { seq: u64, source: StreamSource, kind: StreamKind,
  host_unix_nanos: u64, prev_hash: [u8; 32], payload: Vec<u8> }`;
  `StreamSource::{Console, Entrypoint}`; `StreamKind::{Stdout, Stderr, Trace}`;
  `StreamRecord::hash(&self) -> [u8; 32]`;
  `verify_chain(records: &[StreamRecord]) -> Result<(), ChainError>`;
  `ChainError::{SeqGap { expected, got }, HashMismatch { seq }, Empty}`.

- [x] **Step 1: Write the failing tests**

In `crates/mvm-protocol/src/stream/chain.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn chained(n: u64) -> Vec<StreamRecord> {
        let mut out: Vec<StreamRecord> = Vec::new();
        let mut prev = [0u8; 32];
        for seq in 0..n {
            let r = StreamRecord {
                seq,
                source: StreamSource::Entrypoint,
                kind: StreamKind::Stdout,
                host_unix_nanos: 1_000 + seq,
                prev_hash: prev,
                payload: vec![b'a' + seq as u8],
            };
            prev = r.hash();
            out.push(r);
        }
        out
    }

    #[test]
    fn verify_chain_accepts_a_well_formed_chain() {
        assert!(verify_chain(&chained(4)).is_ok());
    }

    #[test]
    fn verify_chain_rejects_a_tampered_payload() {
        let mut rs = chained(4);
        rs[2].payload = vec![b'z'];
        assert!(matches!(
            verify_chain(&rs),
            Err(ChainError::HashMismatch { seq: 3 })
        ));
    }

    #[test]
    fn verify_chain_rejects_a_dropped_record() {
        let mut rs = chained(4);
        rs.remove(2);
        assert!(matches!(verify_chain(&rs), Err(ChainError::SeqGap { .. })));
    }

    #[test]
    fn verify_chain_rejects_reordered_records() {
        let mut rs = chained(4);
        rs.swap(1, 2);
        assert!(verify_chain(&rs).is_err());
    }
}
```

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-protocol stream::chain`
Expected: FAIL — `stream` module unresolved.

- [x] **Step 3: Implement the DTOs and verifier**

`record.rs` defines the three types with `#[derive(Debug, Clone, PartialEq, Eq,
Serialize, Deserialize)]` and `#[serde(deny_unknown_fields)]` on `StreamRecord`
(every host↔guest type carries it — it is what makes unexpected fields
fail closed). `hash()` folds the fields in fixed order through sha2 with a
domain-separation prefix so a record hash can never collide with a Merkle leaf.
`chain.rs` walks the slice asserting `seq` increments by one and each
`prev_hash` equals the previous record's `hash()`; the first record's
`prev_hash` must be all-zero.

- [x] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-protocol stream::`
Expected: PASS, 4 tests.

- [x] **Step 5: Confirm the crate still builds no_std for wasm**

Run: `cargo build -p mvm-protocol --target wasm32-unknown-unknown`
Expected: success. This is the property that lets a browser verify a chain.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-protocol/src/stream crates/mvm-protocol/src/lib.rs
git commit -m "feat(protocol): stream record DTOs and chain verification"
```

---

### Task 2: transcript store gains stream directions and per-chunk linkage

**Files:**
- Modify: `crates/mvm-core/src/transcript.rs:29-32` (`Direction`), `:37-51` (`ChunkRecord`)
- Test: same file's trailing `mod tests`

**Interfaces:**
- Consumes: `TranscriptWriter`, `ChunkRecord`, `verify_chunks` (existing).
- Produces: `Direction::{Egress, Ingress, Stdout, Stderr, Trace}`;
  `ChunkRecord.prev_hash: String` (64-char lowercase hex, `#[serde(default)]`);
  `TranscriptWriter::push` maintaining the linkage.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn stream_directions_round_trip_through_serde() {
    for d in [Direction::Stdout, Direction::Stderr, Direction::Trace] {
        let s = serde_json::to_string(&d).expect("serialize direction");
        let back: Direction = serde_json::from_str(&s).expect("deserialize direction");
        assert_eq!(d, back);
    }
}

#[test]
fn pushed_chunks_link_to_their_predecessor() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut w = writer_at(dir.path());
    w.push(Direction::Stdout, b"one").expect("push one");
    w.push(Direction::Stdout, b"two").expect("push two");
    let m = w.seal();
    assert_eq!(m.chunks[0].prev_hash, "0".repeat(64));
    assert_eq!(m.chunks[1].prev_hash, m.chunks[0].sha256_hex);
}
```

`writer_at` is a local helper building a `TranscriptWriter` with a fixed test
key and `CaptureBounds { max_duration_secs: 60, max_bytes: 1 << 20, max_chunks: 64 }`.

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core transcript::`
Expected: FAIL — `Direction::Stdout` does not exist.

- [x] **Step 3: Implement**

Add the three variants to `Direction`. Add `prev_hash: String` to `ChunkRecord`
with `#[serde(default)]`. In `push_inner`, set `prev_hash` from the previous
chunk's `sha256_hex` (all-zero for `seq == 0`) before pushing the record.

- [x] **Step 4: Re-pin the deterministic root vector, and witness the re-pin**

`sealed_root_hex` covers the ordered chunk records, so adding `prev_hash`
changes the root and the pinned deterministic vector must be updated. A silent
re-pin is also how a genuine accidental root change would hide, so pin both
directions in the same commit:

```rust
#[test]
fn the_pre_linkage_root_vector_no_longer_verifies() {
    // Guards the re-pin itself: if this ever passes again, the chunk-record
    // layout silently reverted and the new vector is meaningless.
    let m = manifest_with_root(PRE_LINKAGE_ROOT_HEX);
    assert!(matches!(
        verify_sealed_root(&m),
        Err(TranscriptError::SealedRootMismatch)
    ));
}
```

- [x] **Step 5: Run to verify it passes**

Run: `cargo nextest run -p mvm-core transcript::`
Expected: PASS. Every existing sealed-root and `verify_chunks` test stays green.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-core/src/transcript.rs
git commit -m "feat(transcript): stream directions and per-chunk linkage"
```

---

### Task 3: ring retention replaces fail-closed bounds for stream captures

**Files:**
- Create: `crates/mvm-core/src/transcript/ring.rs`
- Modify: `crates/mvm-core/src/transcript.rs` (add `mod ring; pub use ring::*;`)

**Interfaces:**
- Consumes: `CaptureBounds`, `ChunkRecord`, `TranscriptError`.
- Produces: `RetentionPolicy::{FailClosed, Ring}`;
  `RingState::new(bounds) -> Self`;
  `RingState::admit(&mut self, size: u64) -> Admission`;
  `Admission::{Accept, AcceptAfterPruning { pruned_seqs: Vec<u64>, dropped_bytes: u64 }}`;
  `GapMarker { after_seq: u64, dropped_chunks: u64, dropped_bytes: u64 }`.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn ring_accepts_until_the_byte_bound_is_reached() {
    let mut r = RingState::new(bounds(/* max_bytes */ 100, /* max_chunks */ 8));
    assert!(matches!(r.admit(60), Admission::Accept));
    assert!(matches!(r.admit(30), Admission::Accept));
}

#[test]
fn ring_prunes_oldest_rather_than_refusing() {
    let mut r = RingState::new(bounds(100, 8));
    r.admit(60);
    r.admit(30);
    match r.admit(50) {
        Admission::AcceptAfterPruning { pruned_seqs, dropped_bytes } => {
            assert_eq!(pruned_seqs, vec![0]);
            assert_eq!(dropped_bytes, 60);
        }
        other => panic!("expected pruning, got {other:?}"),
    }
}

#[test]
fn a_chatty_workload_stays_observable_forever() {
    // The regression this whole task exists for: the store must never refuse.
    let mut r = RingState::new(bounds(10, 2));
    let mut newest_accepted = 0u64;
    for i in 0..50u64 {
        match r.admit(9) {
            Admission::Accept | Admission::AcceptAfterPruning { .. } => newest_accepted = i,
        }
    }
    assert_eq!(newest_accepted, 49, "the newest write must always win");
}

#[test]
fn a_chunk_larger_than_the_whole_bound_is_still_accepted() {
    let mut r = RingState::new(bounds(100, 8));
    r.admit(60);
    match r.admit(500) {
        Admission::AcceptAfterPruning { pruned_seqs, .. } => assert_eq!(pruned_seqs, vec![0]),
        other => panic!("expected pruning, got {other:?}"),
    }
}
```

`Admission` has no refusing variant, so the exhaustive match in the third test
is itself the type-level guarantee that a bound can never silence a workload.

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core transcript::ring`
Expected: FAIL — module does not exist.

- [x] **Step 3: Implement**

`RingState` tracks live bytes and chunk count. `admit` prunes oldest entries
until the incoming size fits both bounds, returning the pruned sequence numbers
so the caller can unlink the chunk files and emit one `GapMarker`. A single
chunk larger than `max_bytes` prunes everything and is still accepted — the
newest data always wins.

- [x] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-core transcript::ring`
Expected: PASS, 3 tests.

- [x] **Step 5: Commit**

```sh
git add crates/mvm-core/src/transcript/ring.rs crates/mvm-core/src/transcript.rs
git commit -m "feat(transcript): ring retention for continuous stream captures"
```

---

### Task 4: guest pump emits output as it is produced

**Files:**
- Create: `crates/mvm-agentd/src/stream_pump.rs`
- Modify: `crates/mvm-agentd/src/entrypoint.rs:596-622` (replace drain-then-join),
  `crates/mvm-agentd/src/lib.rs` (add `pub mod stream_pump;`)

**Interfaces:**
- Consumes: `EntrypointEvent` (existing, `mvm_agentd::vsock`).
- Produces: `pump_child(child: &mut Child, sink: &mut dyn FnMut(EntrypointEvent),
  caps: &CallCaps) -> PumpOutcome`;
  `PumpOutcome::{Exited(i32), Crashed { signal: i32 }, Timeout}`.

This is the task that satisfies the hard requirement. Everything else is
plumbing around it.

- [x] **Step 1: Write the failing test**

```rust
#[test]
fn stdout_reaches_the_sink_before_the_child_exits() {
    // A child that prints, holds the process open, then exits. If the pump
    // buffers, the sink stays empty until the sleep completes.
    let mut child = Command::new("/bin/sh")
        .arg("-c")
        .arg("printf early; sleep 3")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn child");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut sink = |e: EntrypointEvent| {
            let _ = tx.send(e);
        };
        pump_child(&mut child, &mut sink, &CallCaps::default())
    });

    let first = rx
        .recv_timeout(Duration::from_millis(1500))
        .expect("a chunk must arrive well before the child exits");
    match first {
        EntrypointEvent::Stdout { chunk } => assert_eq!(chunk, b"early"),
        other => panic!("expected stdout, got {other:?}"),
    }
}
```

The 1500 ms timeout against a 3 s child is the whole point: it fails on any
implementation that waits for exit.

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-agentd stream_pump -j 6`
Expected: FAIL — `pump_child` not found.

- [x] **Step 3: Implement the pump**

One reader thread per fd (stdout, stderr, fd-3) doing bounded reads into a
64 KiB buffer and emitting an event per read, plus the existing `poll_for_exit`
for the child. Threads send through a channel the caller drains, so the sink is
invoked on one thread and ordering within a stream is preserved. A cap breach
prunes and emits a gap marker instead of killing the child.

- [x] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-agentd stream_pump -j 6`
Expected: PASS.

- [x] **Step 5: Rewire `execute()` and keep existing behaviour green**

Replace `entrypoint.rs:596-622` with a `pump_child` call. `CallOutcome::PayloadCap`
loses its kill semantics; update the tests that assert termination on breach to
assert a gap marker instead.

Run: `cargo nextest run -p mvm-agentd -j 6`
Expected: PASS across the crate.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-agentd/src/stream_pump.rs crates/mvm-agentd/src/entrypoint.rs crates/mvm-agentd/src/lib.rs
git commit -m "feat(agent): stream entrypoint output as it is produced"
```

---

### Task 5: fd-3 control records get their first emitter

**Files:**
- Modify: `crates/mvm-agentd/src/stream_pump.rs`
- Test: same file

**Interfaces:**
- Consumes: `EntrypointEvent::Control { header_json, payload }` (already shipped
  without an emitter).
- Produces: fd-3 framing decoder
  `decode_fd3_frame(buf: &[u8]) -> Result<(usize, EntrypointEvent), Fd3Error>`;
  `Fd3Error::{HeaderTooLarge, PayloadTooLarge, NonUtf8Header, Incomplete}`.

- [x] **Step 1: Write the failing tests**

Cover: a well-formed frame decodes to `Control` with the header verbatim; a
header longer than 64 KiB is refused; a non-UTF-8 header is refused; a truncated
frame reports `Incomplete` without consuming bytes.

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-agentd fd3 -j 6` — FAIL.

- [x] **Step 3: Implement the decoder**

Frame layout is fixed by the protocol doc comment: `header_len: u32 LE` (max
64 KiB), `header_json` bytes, `payload_len: u32 LE`, `payload` bytes. The agent
validates UTF-8 and the length bounds and does no further parsing — record
semantics belong to the host.

- [x] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-agentd fd3 -j 6`

- [x] **Step 5: Commit**

```sh
git commit -am "feat(agent): decode and emit fd-3 control records"
```

---

### Task 5b: stream the entrypoint RPC response

Added during execution. Task 4 proved the plan was wrong to assume this was
free: the pump streams to its sink, but `execute()`'s sink accumulates into
`CapturedOutput` and `handle_run_entrypoint` replays the buffers after
`execute()` returns. So the producer is unbuffered and the transport is not —
no user sees live output until this lands.

**Files:**
- Modify: `crates/mvm-agentd/src/bin/mvm-guest-agent/handlers.rs`
  (`handle_run_entrypoint_request`)
- Modify: `crates/mvm-agentd/src/entrypoint.rs` (`execute` sink seam)
- Test: `crates/mvm-agentd/src/vsock/rpc.rs` trailing tests

**Interfaces:**
- Consumes: `pump_child`, `PumpOutcome` (T4); `EntrypointEvent` (existing).
- Produces: `execute_streaming(req, sink: &mut dyn FnMut(EntrypointEvent))` —
  the streaming form. The retaining form stays for callers that genuinely want
  a buffered outcome (warm-pool prewarm, probes); it becomes a thin wrapper
  that passes a collecting sink, so there is one execution path, not two.

- [x] **Step 1: Write the failing test**

```rust
#[test]
fn entrypoint_rpc_frames_reach_the_host_before_the_child_exits() {
    // Same shape as the pump's regression guard, one layer up: the transport
    // must not re-buffer what the pump took care to stream.
    let (mut host, guest) = loopback_pair();
    std::thread::spawn(move || {
        serve_one_run_entrypoint(guest, "printf early; sleep 3")
    });
    let first = host
        .read_frame_timeout(Duration::from_millis(1500))
        .expect("a frame must arrive well before the child exits");
    match first {
        GuestResponse::EntrypointEvent(EntrypointEvent::Stdout { chunk }) => {
            assert_eq!(chunk, b"early")
        }
        other => panic!("expected a stdout frame, got {other:?}"),
    }
}
```

- [x] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-agentd rpc::entrypoint -j 6`
Expected: FAIL — the frame arrives only after the child exits, so the read
times out.

- [x] **Step 3: Implement**

Thread the response writer into the sink so each `EntrypointEvent` is framed
and written as it arrives. Preserve the two contracts the wire already has:
ordering within a stream is exact, and exactly one terminal `Exit` or `Error`
event ends the response per call. Interleaving between stdout and stderr now
reflects arrival order rather than replay order — that is the intended change,
not a regression.

- [x] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-agentd -j 6`
Expected: PASS across the crate, including the warm-pool and probe callers that
still want a buffered outcome.

- [x] **Step 5: Confirm a slow host does not stall the workload**

The host reading slowly must not block the guest's child. Add a test with a
deliberately slow frame reader asserting the child still exits on time.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(agent): stream entrypoint events over the RPC as they arrive"
```

---

### Task 6: host broker ingests, redacts, chains, and fans out

**Files:**
- Create: `crates/mvm-hostd/src/stream/mod.rs`, `stream/broker.rs`
- Modify: `crates/mvm-hostd/src/lib.rs`

**Interfaces:**
- Consumes: `StreamRecord` (T1), `RingState` (T3), `TranscriptWriter` (T2),
  `PiiRedactor::redact` (`pii_redactor.rs:354`).
- Produces: `StreamBroker::new(vm: &str, writer: TranscriptWriter, redactor: PiiRedactor) -> Self`;
  `StreamBroker::ingest(&mut self, source: StreamSource, kind: StreamKind, bytes: &[u8])`;
  `StreamBroker::subscribe(&mut self) -> ReaderHandle`;
  `ReaderHandle::recv(&mut self) -> Option<StreamRecord>`.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn every_subscriber_sees_every_record() {
    let mut b = broker_for("vm-a");
    let mut r1 = b.subscribe();
    let mut r2 = b.subscribe();
    b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"hello");
    assert_eq!(r1.recv().expect("r1 record").payload, b"hello");
    assert_eq!(r2.recv().expect("r2 record").payload, b"hello");
}

#[test]
fn redaction_runs_before_the_chain_so_no_reader_sees_raw_matches() {
    let mut b = broker_for("vm-a");
    let mut r = b.subscribe();
    b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"card 4111111111111111 end");
    let got = r.recv().expect("record");
    assert!(!got.payload.windows(16).any(|w| w == b"4111111111111111"));
}

#[test]
fn ingested_records_form_a_verifiable_chain() {
    let mut b = broker_for("vm-a");
    let mut r = b.subscribe();
    for i in 0..5u8 {
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, &[i]);
    }
    let records: Vec<_> = std::iter::from_fn(|| r.recv()).take(5).collect();
    verify_chain(&records).expect("broker output must verify");
}

#[test]
fn a_chunk_that_cannot_be_redacted_is_dropped_not_forwarded() {
    // Fail closed: a byte that cannot be checked does not ship.
    let mut b = broker_with_failing_redactor("vm-a");
    let mut r = b.subscribe();
    b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, b"unscannable");
    let got = r.recv().expect("a marker still arrives");
    assert_eq!(got.kind, StreamKind::Trace);
    assert!(!got.payload.windows(11).any(|w| w == b"unscannable"));
}

#[test]
fn a_slow_reader_does_not_stall_ingest() {
    let mut b = broker_for("vm-a");
    let slow = b.subscribe(); // deliberately never drained
    let started = Instant::now();
    for i in 0..10_000u32 {
        b.ingest(StreamSource::Entrypoint, StreamKind::Stdout, &i.to_le_bytes());
    }
    // Fail loudly rather than hanging until the harness timeout kills us.
    assert_eq!(b.ingested_count(), 10_000, "every ingest must be accepted");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "ingest must never wait on a reader"
    );
    assert!(slow.dropped_count() > 0, "the undrained reader must show its gap");
}
```

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-hostd stream::broker` — FAIL.

- [x] **Step 3: Implement**

`ingest` redacts, admits through `RingState`, assigns `seq` and
`host_unix_nanos`, sets `prev_hash` from the last record, appends via
`TranscriptWriter`, then pushes to every reader's bounded queue. A full reader
queue drops that reader's oldest and marks its gap — never blocks ingest. This
is the one place redaction runs.

- [x] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-hostd stream::` — PASS, 34 tests
  (the 5 required plus fan-out ring bounds, gap anchoring, transcript
  round-trip, persist-failure isolation, and the payload-free subscribe audit).

- [x] **Step 5: Commit**

```sh
git add crates/mvm-hostd/src/stream crates/mvm-hostd/src/lib.rs
git commit -m "feat(hostd): stream broker with redaction, chaining, and fan-out"
```

- [x] **Step 6: Review fixes (round 1)** — three defects, all closed:

1. *A pruned reader could not verify its own window.* `ReaderQueue` now keeps
   the hash of the newest evicted record, and `ReaderHandle::anchor()` returns
   it once a loss has happened, so `verify_chain_from(window, handle.anchor())`
   works for a lone follower. `attach_anchor()` exposes the pre-loss value.
2. *`seal()` discarded the truncation evidence.* `TranscriptWriter` counts
   every chunk it refused, `TranscriptManifest` carries `refused_chunks` /
   `refused_bytes` + `is_truncated()`, and the sealed root commits to both, so
   the count cannot be filed off. Manifest format version 3 → 4, so an old
   capture is refused as old rather than as tampered.
3. *The single redaction seam was a convention.* `StreamRedaction` is a
   newtype over a private `Box<dyn StreamRedactor>` whose only production
   constructor installs the curated ruleset; `with_redactor` is gone.
   `xtask check-stream-redaction-seam` pins the seam shape, the broker's one
   door, and every construction site.

Folded in with them: the persistence warning is logged once per outage
(`StreamCounters::persist_lapses`) instead of once per record; the module doc
no longer claims ingest is free of the durable write's ~200 µs; and
`RingState::admit_counted` gives the fan-out an allocation-free admission.

---

### Task 6b: batch chunks so the durable store can hold a continuous stream

Added during execution. The design's store section requires chunks to "batch by
size-or-interval instead of one file per push", but no task implemented it, and
Task 6's review showed why that is not a performance footnote:

`TranscriptWriter::push_inner` writes one file per chunk, so `max_chunks` is the
only thing standing between a chatty workload and inode exhaustion. Task 6 set
`DEFAULT_CAPTURE_BOUNDS.max_chunks = 4096` for exactly that reason — and 4096
chunks is under a second of output at the guest pump's per-pipe-read rate. The
same constant is what makes D3 false of the durable copy: past it the writer
fails closed and the transcript stops, which is the fail-closed behaviour this
plan set out to replace. Task 6's fix round made that stop *visible* — the
sealed manifest carries `refused_chunks` and `is_truncated()` — but visible is
not the same as not happening. The cap cannot be lifted without batching, and
batching cannot be deferred past the first real caller.

**Files:**
- Modify: `crates/mvm-core/src/transcript.rs` (`push_inner`, segment accounting)
- Modify: `crates/mvm-hostd/src/stream/` (bounds, persist path)

**Interfaces:**
- Consumes: `TranscriptWriter`, `ChunkRecord`, `RingState`.
- Produces: size-or-interval batching where one on-disk segment carries many
  logical chunks, with `ChunkRecord` still addressing individual chunks so
  `verify_chunks` and the sealed root keep their current meaning.

- [x] **Step 1: Write the failing tests**

Cover: 100k one-byte chunks produce a bounded number of files, not 100k; a
sealed manifest over batched segments still passes `verify_sealed_root` and
`verify_chunks`; `export` reproduces the original byte stream in order across
segment boundaries; a torn final segment fails closed rather than silently
truncating. Added beyond the brief: a tampered byte *inside* a shared segment
is still attributed to its own chunk, and the sealed root still breaks when
one chunk's digest or offset is edited on its own.

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-core transcript` — FAIL.

- [x] **Step 3: Implement.** Preserve the chunk-level `prev_hash` linkage and
  the ciphertext-digest semantics; batching changes the file layout, not what
  the root commits to.

`crates/mvm-core/src/transcript/segment.rs` holds the layout: a segment is an
append-only run of chunk ciphertexts in one file, rolling on ciphertext size
(1 MiB) or chunk count (1024) — both content-derived, never wall-clock, since
`file` and `offset` are inside the sealed root and a time-based roll would give
two captures of the same byte stream two different roots. `ChunkRecord` gained
`offset` and still carries its own ciphertext digest and its own `prev_hash`.
Verification checks each segment's length *before* hashing anything, so a torn
capture reads as short rather than as tampered, and requires the records to
tile their segment exactly — no gap, no overlap, no trailing byte nothing
accounts for. Manifest format version 4 → 5.

- [x] **Step 4: Raise the broker's chunk bound** now that files no longer scale
  with chunk count, and make the durable path ring rather than fail closed, so
  D3 holds of the persisted copy and not only of the reader queues.

`DEFAULT_CAPTURE_BOUNDS.max_chunks` 4 096 → 65 536; the binding constraint is
now the sealed manifest's own size (one ~250-byte record per chunk), not the
inode count. `RetentionPolicy` (already in `transcript::ring`, previously
unused) is now a `TranscriptWriterConfig` field sealed into the root, and
`stream_capture_config` is the one door that pairs the shipped budget with
`RetentionPolicy::Ring`. Ring eviction unlinks whole sealed segments oldest
first — the only granularity an append-only file can free — never the active
one, so the newest write always lands. The manifest gained `evicted_chunks` /
`evicted_bytes` beside `refused_chunks` / `refused_bytes`: a ring window is a
*suffix* of the capture, a refused one is a *prefix*, and a consumer needs to
know which end is missing.

- [x] **Step 5: Run to verify it passes**

Run: `cargo nextest run -p mvm-core transcript && cargo nextest run -p mvm-hostd stream::`
Result: PASS — 76 transcript tests, 37 stream tests; 8 691 workspace tests green.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(transcript): batch stream chunks into segments"
```

---

### Task 7: console capture becomes a broker source on every backend

**Files:**
- Create: `crates/mvm-hostd/src/stream/console_source.rs`
- Test: `crates/mvm-hostd/src/stream/console_source.rs` trailing tests

**Interfaces:**
- Consumes: `StreamBroker::ingest`.
- Produces: `ConsoleSource::follow(path: &Path, broker: SharedBroker) -> ConsoleSourceHandle`;
  `ConsoleSourceHandle::stop(self)`.

- [x] **Step 1: Write the failing tests**

Cover: bytes appended to the file after `follow` starts reach the broker tagged
`StreamSource::Console`; a file that does not yet exist is tolerated and picked
up when created (the VM state dir is populated during boot); `stop` terminates
the follower without losing already-read bytes.

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-hostd console_source` — FAIL.

- [x] **Step 3: Implement**

A polling tail holding a read offset. Polling rather than an OS watch keeps it
identical across macOS and Linux and across all four backends, which each
already write `<state_dir>/console.log`.

- [x] **Step 4: Run to verify it passes** — PASS.

- [x] **Step 5: Wire the source into workload start, by inversion**

**Corrected during execution.** This step originally said to modify
`crates/mvm-runtime/src/workload_runner/runner.rs` to call `ConsoleSource::follow`
directly. That is architecturally impossible: `ConsoleSource` needs
`StreamBroker`, which lives in `mvm-hostd`, and the dependency edge runs
`mvm-hostd → mvm-runtime` only. `mvm-runtime` cannot name anything in
`mvm-hostd`.

Invert it instead, the way this file already solves the same problem twice.
`EndpointSpawner` and `BrokerRegistrar` are both existing cases of "mvm-runtime
needs the per-tenant daemon to act": a trait declared in `mvm-runtime` with a
default no-op, implemented in `mvm-hostd`. Add a third of the same shape — new
trait, optional field, builder method on `WorkloadRunner`, no generic-parameter
churn across its call sites.

The hook must be **unconditional**, not admission-gated. `BrokerRegistrar` is a
different, same-named host-services broker that no-ops for unadmitted VMs;
reusing its gating would silently drop console capture on local and unadmitted
dev runs — exactly the runs where a boot failure is most likely and the operator
has the fewest other ways to see what happened. That would defeat the always-on
property this task exists to provide.

Teardown must stop the follower without discarding already-read bytes, and the
wired path — not only the direct call — must exercise that.

Verify no net device is introduced:

Run: `cargo run -p xtask check-vsock-only-egress && cargo run -p xtask check-uniform-vsock-egress`
Expected: both clean.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(hostd): follow console capture as a stream source"
```

---

### Task 8: client consumer trait, tracing bridge, SDK surface

Ordered before the CLI because the CLI consumes this trait.

**Files:**
- Create: `crates/mvm-core/src/stream_client/{mod,opts,wire,reader}.rs`,
  `crates/mvm-hostd/src/stream/serve.rs`, `crates/mvm-client/src/stream.rs`,
  `crates/mvm-client/src/stream_tracing.rs`, `crates/mvm-sdk/src/stream.rs`
- Modify: `crates/mvm-client/src/lib.rs`, `crates/mvm-client/Cargo.toml`,
  `crates/mvm-sdk/src/lib.rs`, `crates/mvm-sdk/Cargo.toml`,
  `crates/mvm-core/src/{lib,config}.rs`, `crates/mvm-core/src/transcript/ring.rs`,
  `crates/mvm-hostd/src/stream/{mod,fanout}.rs`

**Interfaces:**
- Consumes: `StreamRecord`, `verify_chain_from` (T1), `ReaderHandle` (T6).
- Produces: `trait StreamReader { fn next_record(&mut self) -> Result<Option<StreamRecord>>; }`;
  `connect_stream(vm: &str, opts: StreamOpts) -> Result<Box<dyn StreamReader>>`;
  `StreamOpts { follow: bool, from_seq: Option<u64>, kinds: KindFilter }`;
  `republish_to_tracing(reader: Box<dyn StreamReader>)` behind a `tracing-bridge`
  feature; `ReaderHandle::drain_verified() -> DrainedWindow`;
  `serve_stream(path, broker) -> io::Result<StreamServerHandle>`;
  `config::vm_stream_socket(vm)`.

This is the seam `mvmd` fronts remotely. It does not depend on the unlanded
`dyn MvmClient` facade.

**Placement, resolved during execution.** The trait cannot live in `mvm-client`
and also reach the SDK: `mvm-client` → `mvm-hostd` → `mvm-sdk`, so an SDK
dependency on `mvm-client` closes a cycle. It lives in `mvm-core` and both
crates re-export it — the same split `mvm-client`'s own manifest already
documents for the `MvmClient` trait, and the reason `mvm-sdk` can enable
`mvm-core/client` at all. A consumer still writes `mvm_client::stream::…`.

**The broker socket is part of this task.** The brief said "implement the UDS
client against the broker protocol"; no such protocol existed, and a client
tested only against a server written in its own test file cannot falsify the
assumption it encodes. Both ends ship here. T9 still owns the process-lifetime
story — who calls `serve_stream` and when — exactly as T7 left `ConsoleSource`.

- [x] **Step 1: Write the failing tests**

Cover: `from_seq` resumes at the requested sequence; `follow: false` terminates
at the last record; `KindFilter` excludes non-matching kinds; a broken chain
surfaces as an error rather than silently truncating. Plus the bridge:

```rust
#[test]
fn the_bridge_preserves_stdout_bytes_verbatim() {
    // Adapt at the edge, store verbatim: the bridge may format, but the bytes
    // it was handed must survive unaltered into the event it emits.
    let raw = b"progress\r50%\r100%\x00\xff".to_vec();
    let events = capture_tracing_events(reader_yielding(StreamKind::Stdout, &raw));
    assert_eq!(events[0].raw_payload(), raw);
}
```

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-client stream` — FAIL.

- [x] **Step 3: Implement** the UDS client against the broker protocol, plus the
  bridge that maps `Trace` records to real `tracing` events and `Stdout`/`Stderr`
  to events carrying the bytes unaltered. The bridge is feature-gated so a
  consumer that does not want `tracing` does not link it.

  Two properties the implementation turns on. **Verify, then filter**: a
  `KindFilter` or a `from_seq` resume removes records from the middle of a
  window, so the reader checks the whole delivered batch before narrowing it,
  and the broker filters nothing. **`drain_verified` under one lock**: `recv`
  then `anchor` then `gap` as three acquisitions lets an eviction land between
  two of them, and the resulting mismatch is indistinguishable from tampering
  to the consumer.

  `tracing` has no byte-typed field, so the bridge carries the payload as
  base64 in `payload_b64` and `decode_payload` returns the exact bytes. An
  encoding, not a reframing: nothing is line-split, escaped, or dropped.

- [x] **Step 4: Run to verify it passes** — PASS. 29 `mvm-core` stream_client, 24 `mvm-hostd` stream::{serve,fanout}, 27 `mvm-client` (bridge on), 326 `mvm-sdk`.

- [x] **Step 5: Expose the reader on the SDK runtime surface** so a workload
  author can consume a stream programmatically without shelling out.

Run: `cargo nextest run -p mvm-sdk`
Expected: PASS.

- [x] **Step 6: Commit**

```sh
git add crates/mvm-client/src/stream.rs crates/mvm-client/src/stream_tracing.rs crates/mvm-client/src/lib.rs crates/mvm-client/Cargo.toml crates/mvm-sdk
git commit -m "feat(client): stream consumer trait, tracing bridge, and SDK surface"
```

---

### Task 9: `mvmctl logs` reads the broker *and* the transcript; `run` attaches

**Status: COMPLETE.**

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/logs.rs`
- Create: `crates/mvm-core/src/stream_client/output.rs` (source resolution + splice)
- Create: `crates/mvm-core/src/stream_client/console.rs` (console-capture fallback)
- Modify: `crates/mvm-core/src/transcript.rs` (`export_chunks`, `load_kek`,
  `MANIFEST_FILENAME`)
- Modify: `crates/mvm-core/src/config.rs` (`vm_stream_transcript_dir`, `vm_hypervisor_log`)
- Modify: `crates/mvm-core/src/stream_client/reader.rs` (`StreamReader::gap`)
- Modify: `crates/mvm-runtime/src/microvm/observe.rs` (delete `logs` + `show_log_file`)
- Modify: `crates/mvm-cli/src/commands/machine/runtime.rs` (attach on run)
- Test: `crates/mvm-cli/src/commands/machine/tests.rs`

**Interfaces:**
- Consumes: `mvm_core::stream_client::{connect_stream, StreamOpts, StreamReader}` (T8)
  plus `mvm_core::transcript::{export_chunks, verify_sealed_root, verify_chunks}`.
- Produces: `mvm_core::stream_client::open_vm_output` → `VmOutputStream`
  (history spliced ahead of live, with `StreamAvailability` + `Truncation`);
  `logs::run` honouring `--follow`, `--lines`, and a new
  `--stream <stdout|stderr|trace|all>` filter defaulting to `all`; `machine run`
  attaching to the stream unless `--detach`.

**Why this is three things, not one.** `subscribe()` attaches at the broker's
*live head*, so a non-following read of an idle VM returns nothing — the history
is in the durable transcript, not in the fan-out queue. And an exited VM has no
broker at all, so the after-exit half of the requirement cannot come from the
socket. The task therefore owns live following, a **history splice** from the
transcript, and a **transcript-only** path for an exited VM.

**Correction to this plan's premise, found during T9.** "`mvmctl machine logs`
cannot reach the native backends" (above, under *What is broken today*) is only
true on macOS 26+. `require_linux_env()` is `Ok(())` unconditionally
(`microvm/mod.rs`), and `create_linux_env()` returns `NativeEnv` — i.e. runs on
the host — on Linux and macOS 13-25. So the retired path was a host-local
`tail` at `<vm_state_dir>/console.log` on two of three tiers, and a dead end
only on the third. Deleting it with nothing behind it would therefore have been
a regression, not a cleanup: no boot path builds a broker or writes a stream
transcript yet, so both new sources are empty on a real VM. T9 keeps the
capability by reading that same console file **directly**, as a third
fail-open-to-nothing source used only when neither of the others answers. The
bug the plan wanted gone — a shell-out through an environment abstraction — is
gone; the data is not.

- [x] **Step 1: Write the failing tests**

Cover: `--stream stderr` parses and filters; `logs -f` on a VM with no capture
exits nonzero with a message naming the VM; a chain verification failure exits
nonzero (mirroring `trust audit verify`); `machine run` without `--detach`
attaches; `machine run --detach` does not and prints the machine id. Plus, for
the scope above: history is returned for an idle VM; an exited VM's logs are
readable with no broker running; a truncated transcript is reported as
truncated rather than shown as complete.

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-cli logs` — FAIL.

- [x] **Step 3: Implement and delete the dead path**

`open_vm_output` **attaches before reading history** — the order is
load-bearing: subscribing first pins a live start point, so a record produced
during the transcript read is still delivered, and the resulting overlap is
suppressed by sequence number. The reverse order would drop it. Durable records
carry `RecordOrigin::Durable` rather than an invented `StreamSource` and
timestamp, because the transcript records a chunk's channel and order and
nothing else. The two sources keep their own integrity proofs: `verify_chain_from`
for the live window, `verify_sealed_root` + `verify_chunks` for the durable one.

Replace `runtime.rs`'s "attach with `machine shell`" hint — that points at the
dev-only interactive path barred in production — with a real attach to the
output stream. Delete `microvm::logs` and `show_log_file`: the
`require_linux_env` + in-VM `tail -f` path cannot reach the native backends and
must not survive as a fallback, or the bug reappears.

`TranscriptManifest::is_truncated()` and the live reader's `gap()` are both
rendered as stderr notices; a chain failure exits nonzero, a pruned window does
not. `StreamReader::gap` moved onto the trait so a consumer holding a
`Box<dyn StreamReader>` can see a loss at all, and the gap is polled *inside*
the read loop because a following read has no end at which to check.

**Known limits, recorded rather than papered over:**

- The dial-then-read order narrows but does not close the window between the
  two sources: the broker subscribes on its own accept thread up to one accept
  tick after `connect` returns, and a record ingested inside that gap is in
  neither the transcript snapshot nor any follower's queue. Closing it needs
  the broker to state a follower's start sequence on the wire — a change to the
  batch DTO, which belongs with the broker rather than the reader.
- The transcript manifest is written at `seal()`, so durable history is only as
  current as the last seal. A live VM has none to splice, and a VM that was
  killed never seals. Keeping a manifest current is the writing side's job —
  but the *reader* no longer hides the consequence; see fix round 1 below.
- Neither source has a producer yet: nothing binds `serve_stream` or writes
  `vm_stream_transcript_dir`. The console fallback is what makes the command
  useful in the meantime.

- [x] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-cli` — PASS.

- [x] **Step 5: Confirm `invoke` streams end to end**

Task 5b wired the RPC response; this step only proves the CLI end is honest.
Added a per-event flush at the CLI's handler — Rust's stdout is block-buffered
off a terminal, so without it `mvmctl … | tee` showed nothing until exit,
reinstating buffer-to-exit at the last hop — and a test asserting the
write/flush order per chunk rather than only the final buffer contents.

Run: `cargo nextest run -p mvm-cli invoke`
Result: PASS.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(cli): stream logs from the broker and attach on run"
```

- [x] **Fix round 1: three defects on the paths T9b makes hot**

Nothing constructs a broker yet, so the console path is the only path a real VM
takes today — which turned two of these from corner cases into live behaviour.

1. **A filtered-empty history read as "no capture".** Availability keyed off
   surviving *filtered* records rather than the transcript's existence, so
   `machine logs vm --stream stderr` on an exited stdout-only run discarded a
   healthy, verified capture, fell into the `ConsoleOnly` arm, and dumped the
   whole merged console under a note claiming the VM had no output capture.
   `read_history` now reports presence (`Ok(Some(..))`) separately from what
   matched, and `EmptyHistory` says *why* a present capture replayed nothing —
   empty, filtered out, or not asked for. Only the first two are announced.
2. **The console tail ignored `opts` while the warning said otherwise.** The
   `Tail::Console` arm applied neither the kind filter nor `from_seq`, stamped
   everything `Stdout`, and `logs.rs` warned that "nothing will match". Both
   available answers to a channel selection are wrong — showing everything
   returns bytes the caller excluded, showing nothing hides the only output the
   VM has — and a stderr note correcting either is invisible to a script
   reading stdout. So a console-only read now **refuses** what it cannot
   supply: `StreamError::ConsoleCannotFilter` naming a `ConsoleUnsupported`
   (`ChannelSelection` or `ResumePoint`). `--stream all` is unaffected, so
   `machine run`'s attach and a bare `logs` keep working; "no capture anywhere"
   still outranks the refusal. The console-only note now also states that `-n`
   is approximated in bytes, the third thing that source cannot do exactly.
3. **The history-to-live hole was silent.** Live records at or below the
   history high-water mark were suppressed, but nothing checked whether the
   first live record *followed* the last durable one. Since a manifest is only
   written at seal, a running VM shows history to seq N then live from seq M ≫
   N with everything between rendered as though it never existed.
   `VmOutputStream::splice_gap` reports it, and `pump` prints it before the
   record on the far side of the hole. Detection is gated on an unnarrowed
   request (`splice_detectable`): under a channel filter the reader drops
   records before the consumer sees them, so a jump in sequence numbers is the
   ordinary shape of the request and claiming a hole would cry wolf on every
   narrowed read. `-n` does not interfere — the tail trim pops from the front,
   so the newest history record always survives.

Also folded in: `announce` writes through the `Sinks` seam rather than
`eprintln!`, which both makes every notice assertable end to end and stops a
diagnostic panicking on a closed stderr (`mvmctl logs vm 2>&-`).

Each fix has a test proven to go red against the pre-fix code, and the
end-to-end ones drive `show_into` over a real sealed transcript and a real
listening socket, so deleting the `pump` wiring or reverting `announce` to
`eprintln!` fails them.

Run: `cargo nextest run -p mvm-cli` / `cargo nextest run -p mvm-core stream_client` — PASS.

---

### Task 9b: construct the stream plane in production

Added during execution. Every piece of the plane now exists and **nothing runs
it**: `StreamBroker::new` and `serve_stream` have zero non-test callers, and
`ConsoleStreamer` has no real implementation. Tasks 6 and 7 each deferred the
production wiring to Task 9; Task 9 found the same gap and deferred it again.
Phase 1's exit criterion cannot be met until this lands, because a `logs -f`
with no broker to read falls through to the degraded host-local console tail
every time.

**Files:**
- Modify: `crates/mvm-hostd/src/broker/daemon.rs` (per-tenant resident daemon)
- Modify: `crates/mvm-hostd/src/stream/` (a real `ConsoleStreamer` impl)
- Modify: the per-VM start path that already registers standing sockets

**Interfaces:**
- Consumes: `StreamBroker::new(vm, writer, StreamRedaction::curated())`,
  `serve_stream`, `ConsoleSource::follow`, `stream_capture_config`.
- Produces: a broker per running VM, its socket served at
  `config::vm_stream_socket`, and the console source attached — created on VM
  start, torn down on stop.

- [x] **Step 1: Write the failing test**

An integration test that starts a workload through the normal path and asserts
a stream socket exists and serves records, without the test constructing a
broker itself. It must fail today.

- [x] **Step 2: Run to verify it fails** — FAIL, no socket.

- [x] **Step 3: Implement the lifetime.** The broker is resident per tenant
  (`broker/daemon.rs:3` — "one daemon per tenant, not one process per VM"), so
  a per-VM broker's life is bounded by VM registration, not by a process.
  Construct through `stream_capture_config`: it is the single door for ring and
  bounds and still has no production caller, so nothing yet forces the ring
  semantics the durable path depends on.

- [x] **Step 4: Attach the console source** through the real `ConsoleStreamer`
  impl that Task 7's trait inversion exists for — unconditionally, never
  admission-gated.

- [x] **Step 5: Tear down cleanly.** A stopped VM releases its broker, seals its
  transcript, and stops its follower without losing buffered bytes or wedging
  on a follower that stopped reading.

- [x] **Step 6: Verify the degraded fallback is now the exception.** With a real
  producer, `logs -f` must read the broker rather than the host-local console
  tail. Assert which source served the read.

- [x] **Step 7: Commit**

```sh
git commit -am "feat(hostd): construct the stream plane on VM start"
```

**Landed.** `StreamPlane` (`crates/mvm-hostd/src/stream/plane.rs`) is the
assembly: one map entry per running VM holding its broker, the socket serving
it, and the console follower feeding it. `attach` clears the VM's capture dir,
mints a data key wrapped under the host KEK, builds the writer through
`stream_capture_config` (its first production caller, so the durable path now
really runs ring retention), binds `config::vm_stream_socket`, and follows the
console. `release` stops the follower, stops the socket, then seals the
manifest — in that order, so nothing already read is dropped and a consumer
that stopped reading cannot hold teardown open.

The lifetime is a **map entry in the host process that owns the VM's
lifecycle**, not a process and not a tenant registration. It could not be
bounded by the per-tenant host-agent daemon's registration as the step
suggested: that daemon only registers *admitted* VMs, and the console hook is
required to be unconditional — an unadmitted local run is the case with the
fewest other ways to see a boot failure. The socket bind is the registration
token, so a second host process refuses rather than racing the first for the
transcript. Residual: a detached `machine run -d` exits after boot, and the
broker goes with it — the VM keeps running and `logs` falls back to the sealed
transcript or the console until a resident host process owns the plane.

The `ConsoleStreamer` impl reaches `WorkloadRunner` through a process
registration (`mvm_runtime::workload_runner::console_stream`), installed by
`mvmctl` at startup beside `register_inhouse_builder` — the runtime crate sits
below `mvm-hostd` and the runner's constructors take no arguments, so a
registration is the only wiring that reaches all four backends at once.

Also: the console follower now takes a bounded final drain when it is told to
stop, so the last thing a dying workload wrote is in the record rather than in
a file nobody reads; and `transcript::TRANSCRIPT_KEK_RECIPIENT` names the
wrapping scheme both writers now share.

Run: `cargo nextest run -p mvm-hostd -p mvm-runtime -p mvm-cli` — PASS
(1280 / 1237 / 1482).

---

### Task 9c: feed the entrypoint source into the broker

Added during execution. The design's whole premise is two sources feeding one
stream. Only one is wired. `console_source` is the only production caller of
`StreamBroker::ingest`, and it tags every record `StreamKind::Stdout`, so
**nothing ever feeds `StreamSource::Entrypoint`**. The guest's actual stdout and
stderr — the thing this plan is named for — reach `mvmctl invoke` directly over
the RPC and never touch the plane.

Two visible consequences today: `mvmctl logs --stream stderr` returns empty
forever while a plane is up, and the "the console merges stdout and stderr"
notice that would have explained it is suppressed, because the read resolves
`LiveOnly` rather than `ConsoleOnly`.

**Files:**
- Modify: `crates/mvm-hostd/src/stream/plane.rs`, and the host side that
  consumes `EntrypointEvent` frames from the guest RPC
- Modify: `crates/mvm-cli/src/commands/vm/logs.rs` (the now-false suppressed notice)

**Interfaces:**
- Consumes: `EntrypointEvent::{Stdout, Stderr, Control}` from the guest;
  `StreamBroker::ingest`.
- Produces: entrypoint frames ingested as `StreamSource::Entrypoint` with their
  true `StreamKind`, so stdout and stderr stay separable.

- [x] **Step 1: Write the failing test** — with a plane up, a workload writing
  to stderr is readable via `--stream stderr`, and stdout and stderr are
  distinguishable. Must fail today (returns empty).

- [x] **Step 2: Run to verify it fails.** Five `captured_tests` in
  `invoke.rs` red against a sink that never reaches a broker — every one
  reporting an empty capture, which is today's symptom exactly.

- [x] **Step 3: Implement the ingest.** **Routed, not teed.** `StreamBroker::ingest`
  now returns the record it sealed, and `EntrypointSink` (the entrypoint sibling
  of `console_source`) hands that back to the RPC consumer, which writes *those*
  bytes to the caller's fds. One ingest per frame is the only fan-out point, so
  nothing arrives twice. `invoke` does **not** subscribe as a follower: the
  reader queues are bounded rings that evict, and putting the answer to a
  synchronous call behind one would lose exactly the bytes an SDK is waiting on.

- [x] **Step 4: Redaction and chaining still apply.** Entrypoint bytes cross the
  same seam as console bytes, and the caller can only print what came back
  through it. A VM this process holds no broker for (an attach into a machine
  another process booted) gets a redact-only sink rather than a raw passthrough,
  so "no capture" never silently means "no redaction". The fail-closed marker
  substitution moved to one shared `redact::clear_for_display` rather than being
  spelled out per ingest path.

- [x] **Step 5: Correct the suppressed notice** so it reflects what the read
  can actually deliver. A channel-narrowed read now says that console-sourced
  records are recorded as stdout, so a `--stream stderr` read shows only what
  the entrypoint call separated.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(hostd): ingest entrypoint output into the stream plane"
```

#### Task 9c fix round 1

Review found step 3 had gone one step too far, plus two smaller defects.

- [x] **Fix 1: `invoke` returns the caller's own bytes.** Routing the frame
  *through* the capture is right; handing the caller back the masked copy was
  not. Whoever ran the call has code execution inside the workload that produced
  the bytes, so masking their own return value protects nothing and breaks the
  contract — `{"email":"a@b.com","id":4111111111111111}` came back as
  `{"email":"XXX","id":XXX}`, which no JSON parser accepts. The persisted and
  fanned-out copy stays masked; `ShownChunk` now carries `RecordedCopy`, and
  `invoke` reports on stderr, under a fixed `[mvmctl-stream]` prefix, that the
  recorded copy differs and which rules fired. `EntrypointSink::unrecorded`
  redacts nothing, because with no second copy there is nobody to redact for.

- [x] **Fix 1b: the plane honours the launch's `RedactionPolicy`.** `attach`
  hardcoded `StreamRedaction::curated()`, ignoring the policy the same launch
  hands the substitution endpoint. `ConsoleStreamer::start` now takes a
  `ConsoleCapture` carrying it. `curated` reads `default.pii` and falls back to
  the full ruleset when the policy would leave nothing scanning — a workload
  does not get to opt its own transcript out of the seam.

- [x] **Fix 2: the durable append is off the RPC read thread.** Measured on an
  M-series host, release build, per frame: the inline append cost 20 µs at 64 B,
  78 µs at 4 KiB and 212 µs at 64 KiB, against 1.2–7.6 µs for the bare
  write+flush it replaced — 15–28×, of which over 95% is the segment store's
  per-chunk stat, open, write and close. The guest's pump never back-pressures
  its child, so a slower host reader raises *guest*-side eviction instead of
  coalescing frames. `StreamBroker` now hands the append to a per-broker writer
  thread over a 256-deep queue, matched to the guest's own per-stream retention
  ring. Burst cost on the read thread is back to bare-write parity (1.07 µs at
  64 B, 4.9 µs at 4 KiB). Sustained throughput past the queue is unchanged
  (~23 µs/frame) — the writer does the same syscalls.
  - [x] **Deferred:** `SegmentStore::append` opens and closes the active segment
    per chunk, and that is the remaining lever on the sustained figure. Out of
    scope here: the store is shared with the forensic egress capture, whose
    disturbance detection depends on the path-based `stat` that would have to
    stay, so holding the handle open is a change to that contract rather than a
    local optimisation.

- [x] **Fix 2b: the hand-off sheds, it does not block.** The first cut of Fix 2
  used a `sync_channel` whose `send` waits when the queue fills, which put a
  slow disk back in front of ingest by a different door — the same stall a slow
  reader used to cause, and the failure
  `a_slow_reader_does_not_stall_ingest` and
  `a_follower_that_stopped_reading_does_not_slow_the_ingest_down` caught under a
  loaded host. `push` now `try_send`s and drops the record when the writer is a
  full queue behind. Nothing dropped is silent: `TranscriptWriter::note_unwritten`
  folds the shed chunk and byte totals into the manifest's
  `refused_chunks`/`refused_bytes` before the sealed root is computed, so
  `is_truncated()` reports a transcript that lost records instead of one that
  verifies clean while being incomplete. `StreamCounters::persist_shed` separates
  a slow disk from a full one. The durable half moved to
  `crates/mvm-hostd/src/stream/durable.rs`; only the durable copy sheds, live
  followers and `invoke`'s return value are untouched.

- [x] **Fix 3: the console-merge notice is per channel.** It fired with
  stderr-shaped wording for every non-`All` selector, so `--stream stdout` was
  told output was hidden from it when the merge *adds* console output to that
  channel. Stdout gets its own wording; stderr and trace keep theirs.

- [x] **Fix 4 (minors):** `is_recorded()` has a production caller — `invoke`
  tells the operator when a call's output reached no capture. The sink holds the
  broker `Weak` and upgrades per frame, so a `release` racing a dispatch still
  seals. `invoke.rs`'s module docs describe the seam.

---

### Task 9d: seal the transcript for every workload shape

Added during execution. `plane.rs:299` is the only sealer, and `release`
no-ops for a VM the current process never attached, so a transcript is written
**only when one process both starts and stops the VM**. `machine run -d`,
`--json`, `up`, a later `machine stop`, and foreground `machine run` after the
documented Ctrl-C detach all write no manifest. `read_history` then returns
`None` and `logs` resolves `ConsoleOnly`, so the verifiable durable half is dead
weight for every workload shape except a foreground transient run — and
"capturable when it exits" is met by the unchained console file rather than by
the chained transcript.

**Files:**
- Modify: `crates/mvm-hostd/src/stream/plane.rs`
- Modify: the VM stop path, and whatever owns per-VM state across processes

- [x] **Step 1: Write the failing tests** — `machine run -d` then `machine stop`
  leaves a sealed, verifying transcript; the same for `up`; and a foreground run
  detached with Ctrl-C still seals when the VM later stops. All must fail today.
  Landed as `a_detached_start_is_sealed_by_the_later_stop_that_ends_the_vm`,
  `an_entrypoint_run_whose_caller_exits_is_sealed_by_the_stop_that_follows`, and
  `a_foreground_run_detached_part_way_through_still_seals_when_the_vm_stops` in
  `crates/mvm-hostd/tests/workload_stream_plane.rs`, modelling the process
  boundary with two `StreamPlane`s (the registration is a `OnceLock`, so one
  test binary cannot hold two process-global planes).

- [x] **Step 2: Run to verify they fail.** All three failed on
  `ConsoleOnly != HistoryOnly` with the adopt path stubbed out.

- [x] **Step 3: Give the plane a lifetime that outlives one CLI process.** Not
  the plane — the *seal*. A `TranscriptWriter`'s chunk records live only in the
  writing process's memory and the segment files carry no framing, so a later
  process cannot reconstruct a manifest from the ciphertext alone. So the
  durable writer thread now mirrors each landed chunk into an append-only
  journal beside the segments (`crates/mvm-hostd/src/stream/journal.rs`), and
  `StreamPlane::release` seals from that mirror for a VM this process never
  attached. The mirror is written by the writer thread, never a producer, so
  the no-stall invariant is untouched; `DurableSink`'s `Drop` joins that thread
  under the same 3s bound `seal` uses, so a process exiting normally leaves a
  complete journal.

- [x] **Step 4: Keep the console hook unconditional.** Nothing moved to the
  per-tenant daemon; the plane is still the process-wide registration
  `install_host_console_streamer` installs, and `ConsoleStreamer::start` is
  still called on every boot regardless of admission. The new lifetime is a
  file in the capture directory, which no admission gate touches.
  `the_console_hook_is_wired_for_an_unadmitted_workload` still passes.

- [x] **Step 5: Fold in the teardown defects found reviewing the prior task.**
  `WorkloadRunner::stop` kills before releasing the capture (and releases
  unconditionally, so a failed kill still seals —
  `the_console_capture_outlives_the_kill_so_a_dying_guests_output_is_recorded`,
  `a_kill_that_fails_still_releases_the_console_capture`); the same reorder
  applies to the refused-standby-child path. The manifest is written through
  `atomic_write`, and `load_manifest` degrades to "no durable half" on a
  manifest that does not *parse* while still failing closed on one that parses
  and does not verify.

- [x] **Honesty of a rebuilt seal.** `TranscriptManifest` grew `adopted`
  (inside the sealed root, format version 5 -> 6). Nothing on disk records what
  a departed process shed between its last durable append and its exit, so a
  manifest rebuilt from the journal always sets it, `is_truncated()` reports
  it, and `mvmctl logs` says the counts are a floor. An adopted seal never
  overwrites an owner's exact seal, and never runs while another process is
  still answering on the VM's stream socket.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(hostd): seal the stream transcript for detached workloads"
```

---

### Task 10: retention mode in the signed plan, plus Phase 1 documentation

**Files:**
- Modify: `crates/mvm-core/src/plan/synthesis.rs:170-176`, `crates/mvm-cli/src/commands/vm/up/admission.rs`
- Create: `specs/adrs/035-workload-stream-plane.md`,
  `public/src/content/docs/guides/workload-output-streaming.md`
- Modify: `public/src/content/docs/reference/cli-commands.md`, `CLAUDE.md`,
  `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`

**Interfaces:**
- Produces: `ExecutionPlanInput.stream_retention: StreamRetention`;
  `StreamRetention::{Persist, Ephemeral}` defaulting to `Persist`.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn stream_retention_defaults_to_persist() {
    assert_eq!(PlanFixture::new().build().stream_retention, StreamRetention::Persist);
}

#[test]
fn admission_records_the_retention_mode_in_the_chain() {
    let entries = admit_and_read_chain(PlanFixture::new().stream_retention(StreamRetention::Ephemeral));
    let admitted = entries.iter().find(|e| e.kind == "plan.admitted").expect("plan.admitted");
    assert_eq!(admitted.detail_field("stream_retention"), "ephemeral");
}
```

The second test is the property that makes an absent transcript attributable
rather than ambiguous.

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-core plan::` plus
  `cargo nextest run -p mvm-hostd` (the emitter, and therefore the chain
  assertion, lives in `mvm-hostd`, not `mvm-core`) — FAIL.

- [x] **Step 3: Implement**

Add the field with `#[serde(default)]`, thread it into `plan.admitted`, and have
the broker skip `TranscriptWriter` (live fan-out only) under `Ephemeral`.

As landed: `StreamRetention` lives in `mvm-protocol::plan::types` beside
`NetworkMode`; the field is **always serialized** rather than omitted at its
default, so the signed bytes state the decision instead of implying it by
absence. `StreamBroker::live_only` is the ephemeral constructor, `seal()`
returns `Option<TranscriptManifest>` (no manifest, rather than an empty one
asserting the workload printed nothing), and `StreamPlane::attach` never
creates a capture directory for an ephemeral run — while still discarding a
previous recording boot's transcript, so nobody else's recording can be read as
this run's. The mode reaches the plane off the launch config's own copy of the
admitted plan (`egress_shared::plan_stream_retention`), which answers `Persist`
for every uncertain case.

The plan-payload-freedom witness this plan owed itself is
`stream_audit_entries_carry_the_binding_and_no_payload_bytes`: it pins the
*exhaustive* label set of a `stream.subscribed` entry, so a future label
carrying captured bytes fails whatever it is called.

- [x] **Step 4: Run to verify it passes** — the same two — PASS.

- [x] **Step 5: Write ADR-035 and the guide**

ADR-035 records: the two-source architecture and why vsock-only goes dark on
boot failure; ring retention over fail-closed bounds; hash-chain plus seal;
redaction before chaining and its consequence (the chain proves what was shown,
not what was written); the tracing boundary; the always-on retention default and
its signed opt-out. The guide covers following output live and after exit, the
verification model, and the `--stream` filter.

Correct `CLAUDE.md`'s drifts: the claims ledger is the table in
`specs/adrs/001-microvm-security-posture.md`, not `specs/claims/catalog.md`;
`mvm-client` has no `dyn MvmClient` facade; and the claim-12 narrative names
four tests, three `xtask check-handler-*` gates, and a `fuzz_service_call.rs`
target that **none of** exist. The audit of "the rest of that narrative" found
the same failure in claim 13 (all six named tests absent), claim 10
(`test_resolve_network_policy_default_is_deny_all` absent), and five dead
`specs/` paths. All corrected against the ADR-001 rows, which were right
throughout.

- [x] **Step 6: Run the doc gates**

Run: `cargo run -p xtask check-doc-claims && cargo run -p xtask check-adr-coverage && cargo run -p xtask check-no-overclaim && cargo test --workspace --doc`
Expected: clean.

- [x] **Step 7: Commit**

```sh
git commit -am "feat(plan): signed stream retention mode, ADR-035, and the streaming guide"
```

**Phase 1 exit criterion:** `mvmctl logs -f <vm>` shows a running workload's
output live on Firecracker, libkrun, HVF, and QEMU, and shows it again after
exit. Run `just ci` before opening the PR.

---

## Phase 2 — input plane

### Task 11: input frame DTOs and the plan grant

**Files:**
- Create: `crates/mvm-protocol/src/stream/input.rs`
- Modify: `crates/mvm-core/src/plan/synthesis.rs` (services already exist at `:174`)

**Interfaces:**
- Produces: `InputFrame { seq: u64, payload: Vec<u8> }`; `CloseInput`;
  `ServiceId::parse("host.stream.v1")` as the grant token.

- [x] **Step 1: Write the failing tests** — serde round-trip both types; unknown
  fields rejected; a plan without `host.stream.v1` reports `grants_input() == false`.

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-protocol stream::input` — FAIL.

- [x] **Step 3: Implement** with `#[serde(deny_unknown_fields)]`.

- [x] **Step 4: Run to verify it passes** — PASS.

- [x] **Step 5: Commit** — `git commit -am "feat(protocol): workload input frame DTOs"`

---

### Task 12: input gate — grant, lease, secret scan

**Files:**
- Create: `crates/mvm-hostd/src/stream/input_gate.rs`

**Interfaces:**
- Produces: `InputGate::open(vm: &str, plan: &ExecutionPlan) -> Result<InputSession, InputRefusal>`;
  `InputSession::write(&mut self, frame: InputFrame) -> Result<(), InputRefusal>`;
  `InputSession::close(self)`;
  `InputRefusal::{NotGranted, LeaseHeld { holder: String }, SecretMaterial { category: &'static str }, LeaseExpired}`.

- [x] **Step 1: Write the failing tests**

```rust
#[test]
fn input_is_refused_without_a_plan_grant() {
    let plan = PlanFixture::new().build(); // no host.stream.v1
    assert!(matches!(InputGate::open("vm-a", &plan), Err(InputRefusal::NotGranted)));
}

#[test]
fn a_second_writer_is_refused_while_the_lease_is_held() {
    let plan = PlanFixture::new().services(vec![stream_service()]).build();
    let _first = InputGate::open("vm-a", &plan).expect("first session");
    assert!(matches!(
        InputGate::open("vm-a", &plan),
        Err(InputRefusal::LeaseHeld { .. })
    ));
}

#[test]
fn secret_material_split_across_frames_is_still_refused() {
    // A scanner that inspects one frame at a time is trivially evaded by
    // splitting; the gate must carry a sliding window across frames.
    let mut s = granted_session_with_known_secret("AKIAIOSFODNN7EXAMPLE");
    s.write(InputFrame { seq: 0, payload: b"AKIAIOSFODNN".to_vec() }).expect("prefix alone is not a match");
    assert!(matches!(
        s.write(InputFrame { seq: 1, payload: b"7EXAMPLE".to_vec() }),
        Err(InputRefusal::SecretMaterial { .. })
    ));
}

#[test]
fn every_refusal_is_audited() {
    let plan = PlanFixture::new().build();
    let _ = InputGate::open("vm-a", &plan);
    let entries = read_chain("vm-a");
    assert!(entries.iter().any(|e| e.kind == "stream.input_refused"));
}
```

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-hostd input_gate` — FAIL.

- [x] **Step 3: Implement**

Grant check first, then lease acquisition with an expiry the caller refreshes,
then the sliding-window secret scan over a buffer at least as long as the
longest known secret minus one byte. Every refusal emits a chain-signed audit
entry carrying the reason and no payload bytes.

- [x] **Step 4: Run to verify it passes** — PASS, 4 tests.

- [x] **Step 5: Assert the chain carries no payload**

Write the test — do not assume one exists. Earlier drafts pointed at
`audit_chain_carries_no_payload_bytes`, which is absent from the tree; running
that filter exits 0 having executed nothing, so the step was vacuously green.
Assert that an input-refusal entry records the reason and the binding but no
frame bytes, including the refused secret material.

Run: `cargo nextest run -p mvm-hostd stream_input_audit`
Expected: PASS, and the filter must match a nonzero number of tests.

- [x] **Step 6: Commit** — `git commit -am "feat(hostd): plan-gated, leased, secret-scanned workload input"`

---

### Task 13: agent delivers input to the child and closes stdin on EOF

**Files:**
- Create: `crates/mvm-agentd/src/stream_input.rs`
- Modify: `crates/mvm-agentd/src/stream_pump.rs` (stdin handle ownership)

**Interfaces:**
- Produces: `InputSink::new(stdin: ChildStdin) -> Self`;
  `InputSink::write_frame(&mut self, f: InputFrame) -> io::Result<()>`;
  `InputSink::close(self)`.

- [x] **Step 1: Write the failing test**

```rust
#[test]
fn close_input_delivers_eof_so_a_read_to_end_child_terminates() {
    // Without an explicit EOF this hangs forever — the trap this test exists for.
    let mut child = Command::new("/bin/cat")
        .stdin(Stdio::piped()).stdout(Stdio::piped())
        .spawn().expect("spawn cat");
    let mut sink = InputSink::new(child.stdin.take().expect("piped stdin"));
    sink.write_frame(InputFrame { seq: 0, payload: b"hi".to_vec() }).expect("write");
    sink.close();
    let status = child.wait().expect("cat must exit after EOF");
    assert!(status.success());
}
```

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-agentd stream_input -j 6` — FAIL.

- [x] **Step 3: Implement.** `close` drops the `ChildStdin`, which closes the fd.

- [x] **Step 4: Run to verify it passes** — PASS.

- [x] **Step 5: Confirm the agent stays runtime-free**

Run: `cargo run -p xtask check-guest-agent-runtime-free`
Expected: clean.

- [x] **Step 6: Commit** — `git commit -am "feat(agent): deliver streamed input to the entrypoint with explicit EOF"`

---

### Task 13b: route input frames from the gate to the guest sink

Added during execution, and confirmed independently by Task 13's review. The
input plane has a host gate, a guest sink, and **nothing between them**.
`InputSink` has zero production call sites, and no remaining task wires one — so
without this, Phase 2 would ship documented and policy-gated with no code path
connecting an `InputFrame` to a workload's stdin. Phase 2's exit criterion
cannot be met.

This mirrors the output half exactly, where the broker, the console source and
the entrypoint source each landed correct and unreachable until a task was added
to construct them.

**Files:**
- Modify: `crates/mvm-agentd/src/vsock/` (a request arm for input frames)
- Modify: `crates/mvm-hostd/src/stream/` (drive `take_admitted` toward the guest)
- Modify: the per-VM plane wiring that already owns the broker's lifetime

**TWO GUARANTEES THIS SEAM CAN SILENTLY DESTROY.** Both were established at real
cost in earlier tasks; neither is enforced by a type across this boundary.

1. **Acceptance order.** The gate scans for secret material by concatenating
   bytes in the order it accepted them, and deliberately does not reassemble by
   `seq`. Feed `InputSink::write_frame` with what `take_admitted` yields, in that
   order, never re-batched or reordered across polls or across concurrent
   handler invocations. Reorder here and a secret split across two frames scans
   as non-contiguous at the gate and reassembles contiguously in the guest.
2. **The withheld tail.** The gate withholds a live secret-prefix suffix rather
   than shipping it and refusing later. Call `deliver_tail(InputClose.trailing)`
   before `close()`. The guest side already forces that ordering by type —
   `deliver_tail` takes `&mut self`, `close` takes `self` — but nothing forces
   the host side to hand the tail over at all.

- [x] **Step 1: Write the failing test** — a plan-granted consumer writes to a
  running workload's stdin and the workload sees it; an ungranted one is refused
  and the refusal is in the chain. Must fail today for want of a route.

- [x] **Step 2: Run to verify it fails.**

- [x] **Step 3: Implement the route.** Input travels the same vsock transport as
  everything else; the guest has no NIC and gains none here.

- [x] **Step 4: Preserve both guarantees above**, with a test for each that fails
  if the order or the tail is dropped.

- [x] **Step 5: Never stall.** A child not reading stdin must not block the host,
  and a slow host must not stall the child's output.

- [x] **Step 6: Commit**

```sh
git commit -am "feat(stream): route granted input frames to the workload's stdin"
```

---

### Task 14: `--prod` refuses the input grant for shell-shaped entrypoints

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up/admission.rs`

**Interfaces:**
- Produces: `entrypoint_is_shell_shaped(plan: &ExecutionPlan) -> bool`.

- [x] **Step 1: Write the failing tests**

Cover each limb of the rule from the design section: basename in
`{sh, bash, dash, ash, busybox, zsh, ksh, fish}`; a script whose shebang
interpreter basename is in that set; argv carrying `-c`. Plus: a non-shell
entrypoint with the grant is admitted under `--prod`, and a shell entrypoint
*without* the grant is admitted (output streaming stays unconditional).

- [x] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-cli admission` — FAIL.

- [x] **Step 3: Implement.** Refuse before any network or boot work.

- [x] **Step 4: Run to verify it passes** — PASS.

- [x] **Step 5: Commit** — `git commit -am "feat(cli): refuse the input grant for shell entrypoints under --prod"`

---

### Task 15: claims ledger — reword 15, add 17

**Files:**
- Modify: `specs/adrs/001-microvm-security-posture.md` (claims table, rows 15 and 17)
- Modify: `crates/mvm-agentd/fuzz/fuzz_targets/` (add an input-frame target)

- [x] **Step 1: Reword claim 15**

State what it now guarantees — no shell, no exec, no argv or env control, no
PTY on a sealed image — rather than implying no input path exists.

- [x] **Step 2: Add claim 17** with witnesses naming the T12 and T14 tests:
  `fn:input_is_refused_without_a_plan_grant`,
  `fn:a_second_writer_is_refused_while_the_lease_is_held`,
  `fn:secret_material_split_across_frames_is_still_refused`,
  `fn:every_refusal_is_audited`, and the `--prod` shell-refusal test
  (`fn:a_shell_entrypoint_with_the_grant_is_refused_and_names_the_reason`).

  Shipped at status **`Preview`**, not `Shipped`. Three of the four legs have
  no production caller — the known-secret set is empty on every real VM
  (`InputGate::bind` is test-only), the shell-entrypoint refusal is dormant
  (every call site passes an empty `entrypoint_argv`), and the granted half
  has no operator surface. Only the ungranted-refusal half is proven end to
  end, against a real `admit_for_run` and `verify_audit_chain`. The four
  limits are written into the ledger as a "Preview 17 limits" note so the row
  cannot be read as enforced; promotion needs limits 1–3 to close. Row 17
  also required `model/claims.toml` (`MVM-SEC-17`), a
  `features/suites/s26_workload_input/` scenario, a regenerated
  `CONFORMANCE.md`, and a re-pinned `xtask/mutation-witness-baseline.json`
  (the surface gained `input_gate.rs` and `up/admission.rs`).

- [x] **Step 3: Add the input-frame fuzz target** so the new parser joins claim 5.

`fuzz_input_frame` covers `InputFrame` and `CloseInput`; wired into the
`fuzz` job in `security.yml` and named as `ci:fuzz_input_frame` on row 5.

- [x] **Step 3b (folded in): drop the `D7` decision-row IDs from Rust comments.**
Five comments in `crates/mvm-cli/src/commands/vm/up/admission.rs` cited the
plan's decision-row ID by name. `check-no-spec-refs-in-comments` did not catch
them — its regex matches `Plan N` / `ADR-N` / `W#` / `#NNNN`, not a bare
two-character token — so they would have become dangling labels once this plan
is archived. Reworded to describe the rule.

- [x] **Step 4: Run the ledger gates**

Run: `cargo run -p xtask check-claim-catalog && cargo run -p xtask check-claim-witness-freshness && cargo run -p xtask check-no-overclaim`
Expected: every named witness resolves.

- [x] **Step 5: Verify the untouched claim-15 witnesses still pass**

Run: `cargo nextest run --workspace -E 'test(console_refused_on_sealed_image) or test(following_the_console_never_writes_to_it)'`
Expected: PASS — the console capture still has no host input fd.

- [x] **Step 6: Commit** — `git commit -am "docs(claims): reword claim 15 and add claim 17 for the input channel"`

---

### Task 16: input documentation

**Files:**
- Modify: `public/src/content/docs/guides/workload-output-streaming.md`,
  `public/src/content/docs/reference/cli-commands.md`,
  `specs/adrs/035-workload-stream-plane.md`, `specs/SPRINT.md`,
  `specs/REFACTOR-STATUS.md`

- [x] **Step 1: Document the input half** — the grant, the single-writer lease,
  the secret gate, explicit EOF, and the `--prod` shell refusal, including the
  honest statement that shell detection is a heuristic.

- [x] **Step 2: Record the claim-15 trade in ADR-035** — enforced-by-absence
  becomes enforced-by-policy, and why that was worth it.

- [x] **Step 3: Tick this plan's boxes and update the rollups**, bumping
  `REFACTOR-STATUS.md`'s "Last updated".

- [x] **Step 4: Run the full gate**

Run: `just ci && cargo run -p xtask check-doc-claims && cargo run -p xtask check-file-size`
Expected: clean.

- [x] **Step 5: Commit** — `git commit -am "docs: workload input plane guide and claim-15 trade"`

**Phase 2 exit criterion:** a plan-granted external consumer feeds a running
workload's stdin and sees its output in the same stream; an ungranted one is
refused and the refusal is in the chain.

**Phase 2 status (as of this plan; superseded — see plan 293 WS1 for the secret
scan, and ADR-001's Preview 17 limits note for the current state). Met in the
harness, not on a VM.** Both halves are covered by
`crates/mvm-hostd/tests/workload_input_plane.rs` against a real `admit_for_run`,
a real chain and `verify_audit_chain`. Neither is met by an operator, because
`StreamPlane::open_input` is the only route into the gate and has no caller
outside that test: no CLI verb opens an input stream, `mvmctl invoke` always
sends `stream_input: false`, and nothing refreshes the lease client-side. So the
secret scan's known-secret set is empty on every real VM, and the
shell-entrypoint refusal never sees an entrypoint to classify because every
production admission passes an empty `entrypoint_argv`. ADR-001 carries this as
claim 17 at `Preview` with those limits. Closing them is a follow-on plan, and
it must land the operator surface and a live entrypoint resolver in the same
change — otherwise the refusal ships as a label rather than as a control.

---

### Task 17: make stdin reachable

Added during execution. Phase 2 built every layer of the input plane and left it
unreachable. This task closes that, and it is the task the plan's own closing
paragraph says must land the operator surface and a live entrypoint resolver
**together**.

**The surface already exists.** `mvmctl invoke` has a `--stdin` flag that reads a
file or `-` (mvmctl's own stdin) and sends it as a one-shot payload at call time
(`invoke.rs:48-51`, `:266`). This task upgrades that flag from one-shot to
streaming rather than inventing a second verb — a caller who pipes into
`mvmctl invoke --stdin -` should have their bytes reach the workload as they
arrive, and EOF on their end should close the workload's stdin.

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/invoke.rs` (`:221` services, `:631`
  `stream_input`, the stdin read path)
- Modify: `crates/mvm-runtime/src/vm/exec_builder.rs:319` (`stream_input`)
- Modify: `crates/mvm-cli/src/commands/vm/up/admission.rs` (live entrypoint
  resolution, replacing the empty `entrypoint_argv`)

**Interfaces already in place — wire to these, do not rebuild:**
`StreamPlane::{open_input, write_input, refresh_input, close_input}`
(`plane.rs:263-330`); `InputGate::open(vm, &AdmittedPlan)`; `InputFrame`,
`CloseInput`; `INPUT_GRANT_SERVICE` (`host.stream.v1`).

- [x] **Step 1: Write the failing test.** Landed as a different shape than
  written, because the brief's premise was stale: there is no `mvmctl invoke`
  verb and no `--stdin` flag on the entrypoint action — stdin is auto-read at
  the `machine run --entrypoint` dispatch site. The surface added is `machine
  run --entrypoint --stdin <PATH|->`, mirroring `session attach --stdin`'s
  existing value grammar, where `-` streams and a path stays one-shot. Tests
  cover the pump (`stdin_stream.rs`) and the grant/refusal join
  (`invoke.rs::stdin_grant_tests`).

- [x] **Step 2: Run to verify it fails.** The pump tests fail to compile
  against the pre-task tree (no `stdin_stream` module); the grant tests fail
  against it because `admit_entrypoint_boot` passed `services: Vec::new()`
  unconditionally, so nothing was ever refused.

- [x] **Step 3: Grant the service.** `invoke.rs:221` passes `services:
  Vec::new()`. Add `host.stream.v1` **only when the caller actually requested
  streaming stdin** — a plan that did not ask for input must keep granting
  nothing, because default-deny is the property the whole gate rests on.

- [x] **Step 4: Flip `stream_input`** at both sites, driven by the same request
  rather than unconditionally.

- [x] **Step 5: Resolve a live entrypoint.** Every admission call site passes an
  empty `entrypoint_argv`, so the `--prod` shell refusal cannot fire. Resolve the
  real entrypoint at admission. **This must land in this change**, not after: a
  grant that goes live while the refusal is still dormant ships a control that
  cannot fire.

- [x] **Step 6: Pump, refresh, close.** Stream from the caller's stdin through
  `write_input` in arrival order, `refresh_input` before the 30s lease expires,
  and `close_input` on EOF so a read-to-EOF workload terminates.

- [x] **Step 7: Prove the refusals still bite.** An ungranted caller is refused
  and audited; a shell entrypoint with the grant is refused under `--prod`; a
  second concurrent writer is refused by the lease.

- [x] **Step 8: Update the docs and the claim.** The guide, `cli-commands.md`,
  and ADR-001's Preview-17 limits all currently state that no operator surface
  exists. Correct them to what ships, and reassess whether claim 17 still belongs
  at `Preview` — the secret scan stays inert until `InputGate::bind` has a
  production caller, so say plainly which limits closed and which did not.

- [x] **Step 9: Commit**

```sh
git commit -am "feat(cli): stream stdin into a running workload"
```
