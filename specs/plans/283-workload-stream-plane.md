# Plan 283 — Workload stream plane

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
payload bytes, so `audit_chain_carries_no_payload_bytes` keeps passing.

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
- `audit_chain_carries_no_payload_bytes` still passes with the stream plane live.
- `prod_console_attachment_has_no_input` still passes — the console capture
  keeps no host input fd.
- Retention mode recorded in `plan.admitted`, so "was this run recorded?" is
  answerable from the chain alone.

## Deliverables

- [ ] `specs/adrs/035-workload-stream-plane.md` — posture, the claim-15 trade
      stated plainly, the input asymmetry, the tracing boundary, residual risks.
- [ ] Claim 15 reworded and claim 17 added to the claims table in
      `specs/adrs/001-microvm-security-posture.md`, each with `fn:`/`ci:`
      witnesses that `xtask check-claim-catalog` resolves.
- [ ] `CLAUDE.md` corrected on two points this plan had to work around: the
      claims ledger lives in ADR-001, not `specs/claims/catalog.md`; and
      `mvm-client` has no `dyn MvmClient` facade.
- [ ] Website documentation:
      `public/src/content/docs/guides/workload-output-streaming.md` (following
      output live and after exit, the retention and verification model, feeding
      a running workload); the stream surfaces added to
      `public/src/content/docs/reference/cli-commands.md`; and the claim-15
      rewording plus claim 17 reflected under
      `public/src/content/docs/security/`.
- [ ] `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` updated in the same
      change as each workstream lands.

## Open questions

None blocking. Slice 2's claim analysis is deferred to its own plan by design,
not by omission.
