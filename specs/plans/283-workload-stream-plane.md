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
- [ ] `CLAUDE.md` corrected on three drifts this plan had to work around: the
      claims ledger lives in ADR-001, not `specs/claims/catalog.md`;
      `mvm-client` has no `dyn MvmClient` facade; and the claim-12 narrative
      names `audit_chain_carries_no_payload_bytes` as a witness, which exists
      nowhere in the tree. The ADR-001 ledger row is correct, so
      `check-claim-catalog` never caught it — only the prose is wrong. Audit the
      rest of that narrative for the same failure while fixing it.
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

Per-task gate command, run before every commit:

```sh
cargo fmt --all -- --check && \
cargo clippy --workspace --all-targets -- -D warnings && \
cargo nextest run -p <crate> && \
cargo run -p xtask check-no-spec-refs-in-comments
```

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
| `crates/mvm-client/src/stream.rs` | consumer trait over the broker UDS |
| `crates/mvm-client/src/stream_tracing.rs` | feature-gated `tracing` republishing bridge |

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

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-protocol stream::chain`
Expected: FAIL — `stream` module unresolved.

- [ ] **Step 3: Implement the DTOs and verifier**

`record.rs` defines the three types with `#[derive(Debug, Clone, PartialEq, Eq,
Serialize, Deserialize)]` and `#[serde(deny_unknown_fields)]` on `StreamRecord`
(every host↔guest type carries it — it is what makes unexpected fields
fail closed). `hash()` folds the fields in fixed order through sha2 with a
domain-separation prefix so a record hash can never collide with a Merkle leaf.
`chain.rs` walks the slice asserting `seq` increments by one and each
`prev_hash` equals the previous record's `hash()`; the first record's
`prev_hash` must be all-zero.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-protocol stream::`
Expected: PASS, 4 tests.

- [ ] **Step 5: Confirm the crate still builds no_std for wasm**

Run: `cargo build -p mvm-protocol --target wasm32-unknown-unknown`
Expected: success. This is the property that lets a browser verify a chain.

- [ ] **Step 6: Commit**

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

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core transcript::`
Expected: FAIL — `Direction::Stdout` does not exist.

- [ ] **Step 3: Implement**

Add the three variants to `Direction`. Add `prev_hash: String` to `ChunkRecord`
with `#[serde(default)]`. In `push_inner`, set `prev_hash` from the previous
chunk's `sha256_hex` (all-zero for `seq == 0`) before pushing the record.

- [ ] **Step 4: Re-pin the deterministic root vector, and witness the re-pin**

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

- [ ] **Step 5: Run to verify it passes**

Run: `cargo nextest run -p mvm-core transcript::`
Expected: PASS. Every existing sealed-root and `verify_chunks` test stays green.

- [ ] **Step 6: Commit**

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

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-core transcript::ring`
Expected: FAIL — module does not exist.

- [ ] **Step 3: Implement**

`RingState` tracks live bytes and chunk count. `admit` prunes oldest entries
until the incoming size fits both bounds, returning the pruned sequence numbers
so the caller can unlink the chunk files and emit one `GapMarker`. A single
chunk larger than `max_bytes` prunes everything and is still accepted — the
newest data always wins.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-core transcript::ring`
Expected: PASS, 3 tests.

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write the failing test**

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

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-agentd stream_pump -j 6`
Expected: FAIL — `pump_child` not found.

- [ ] **Step 3: Implement the pump**

One reader thread per fd (stdout, stderr, fd-3) doing bounded reads into a
64 KiB buffer and emitting an event per read, plus the existing `poll_for_exit`
for the child. Threads send through a channel the caller drains, so the sink is
invoked on one thread and ordering within a stream is preserved. A cap breach
prunes and emits a gap marker instead of killing the child.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-agentd stream_pump -j 6`
Expected: PASS.

- [ ] **Step 5: Rewire `execute()` and keep existing behaviour green**

Replace `entrypoint.rs:596-622` with a `pump_child` call. `CallOutcome::PayloadCap`
loses its kill semantics; update the tests that assert termination on breach to
assert a gap marker instead.

Run: `cargo nextest run -p mvm-agentd -j 6`
Expected: PASS across the crate.

- [ ] **Step 6: Commit**

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

- [ ] **Step 1: Write the failing tests**

Cover: a well-formed frame decodes to `Control` with the header verbatim; a
header longer than 64 KiB is refused; a non-UTF-8 header is refused; a truncated
frame reports `Incomplete` without consuming bytes.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-agentd fd3 -j 6` — FAIL.

- [ ] **Step 3: Implement the decoder**

Frame layout is fixed by the protocol doc comment: `header_len: u32 LE` (max
64 KiB), `header_json` bytes, `payload_len: u32 LE`, `payload` bytes. The agent
validates UTF-8 and the length bounds and does no further parsing — record
semantics belong to the host.

- [ ] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-agentd fd3 -j 6`

- [ ] **Step 5: Commit**

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

- [ ] **Step 1: Write the failing test**

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

- [ ] **Step 2: Run to verify it fails**

Run: `cargo nextest run -p mvm-agentd rpc::entrypoint -j 6`
Expected: FAIL — the frame arrives only after the child exits, so the read
times out.

- [ ] **Step 3: Implement**

Thread the response writer into the sink so each `EntrypointEvent` is framed
and written as it arrives. Preserve the two contracts the wire already has:
ordering within a stream is exact, and exactly one terminal `Exit` or `Error`
event ends the response per call. Interleaving between stdout and stderr now
reflects arrival order rather than replay order — that is the intended change,
not a regression.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo nextest run -p mvm-agentd -j 6`
Expected: PASS across the crate, including the warm-pool and probe callers that
still want a buffered outcome.

- [ ] **Step 5: Confirm a slow host does not stall the workload**

The host reading slowly must not block the guest's child. Add a test with a
deliberately slow frame reader asserting the child still exits on time.

- [ ] **Step 6: Commit**

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

- [ ] **Step 1: Write the failing tests**

Cover: bytes appended to the file after `follow` starts reach the broker tagged
`StreamSource::Console`; a file that does not yet exist is tolerated and picked
up when created (the VM state dir is populated during boot); `stop` terminates
the follower without losing already-read bytes.

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-hostd console_source` — FAIL.

- [ ] **Step 3: Implement**

A polling tail holding a read offset. Polling rather than an OS watch keeps it
identical across macOS and Linux and across all four backends, which each
already write `<state_dir>/console.log`.

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Wire the source into workload start**

Modify `crates/mvm-runtime/src/workload_runner/runner.rs` where `console_log` is
set (`:252`) so starting a workload also starts a `ConsoleSource`. Verify no net
device is introduced:

Run: `cargo run -p xtask check-vsock-only-egress && cargo run -p xtask check-uniform-vsock-egress`
Expected: both clean.

- [ ] **Step 6: Commit**

```sh
git commit -am "feat(hostd): follow console capture as a stream source"
```

---

### Task 8: client consumer trait, tracing bridge, SDK surface

Ordered before the CLI because the CLI consumes this trait.

**Files:**
- Create: `crates/mvm-client/src/stream.rs`, `crates/mvm-client/src/stream_tracing.rs`
- Modify: `crates/mvm-client/src/lib.rs`, `crates/mvm-client/Cargo.toml`
- Modify: `crates/mvm-sdk/sdks/` runtime surface for the host-side stream consumer

**Interfaces:**
- Consumes: `StreamRecord`, `verify_chain` (T1).
- Produces: `trait StreamReader { fn next_record(&mut self) -> Result<Option<StreamRecord>>; }`;
  `connect_stream(vm: &str, opts: StreamOpts) -> Result<Box<dyn StreamReader>>`;
  `StreamOpts { follow: bool, from_seq: Option<u64>, kinds: KindFilter }`;
  `republish_to_tracing(reader: Box<dyn StreamReader>)` behind a `tracing-bridge`
  feature.

This is the seam `mvmd` fronts remotely. It does not depend on the unlanded
`dyn MvmClient` facade.

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-client stream` — FAIL.

- [ ] **Step 3: Implement** the UDS client against the broker protocol, plus the
  bridge that maps `Trace` records to real `tracing` events and `Stdout`/`Stderr`
  to events carrying the bytes unaltered. The bridge is feature-gated so a
  consumer that does not want `tracing` does not link it.

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Expose the reader on the SDK runtime surface** so a workload
  author can consume a stream programmatically without shelling out.

Run: `cargo nextest run -p mvm-sdk`
Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add crates/mvm-client/src/stream.rs crates/mvm-client/src/stream_tracing.rs crates/mvm-client/src/lib.rs crates/mvm-client/Cargo.toml crates/mvm-sdk
git commit -m "feat(client): stream consumer trait, tracing bridge, and SDK surface"
```

---

### Task 9: `mvmctl logs -f` reads the broker; `run`/`up` attach by default

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/logs.rs`
- Modify: `crates/mvm-runtime/src/microvm/observe.rs:18-59` (retire `logs`)
- Modify: `crates/mvm-cli/src/commands/machine/runtime.rs:153` (attach on run)
- Test: `crates/mvm-cli/src/commands/machine/tests.rs`

**Interfaces:**
- Consumes: `mvm_client::stream::{connect_stream, StreamOpts, StreamReader}` (T8).
- Produces: `logs::run` honouring `--follow`, `--lines`, and a new
  `--stream <stdout|stderr|trace|all>` filter defaulting to `all`; `machine run`
  attaching to the stream unless `--detach`.

- [ ] **Step 1: Write the failing tests**

Cover: `--stream stderr` parses and filters; `logs -f` on a VM with no capture
exits nonzero with a message naming the VM; a chain verification failure exits
nonzero (mirroring `trust audit verify`); `machine run` without `--detach`
attaches; `machine run --detach` does not and prints the machine id.

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-cli logs` — FAIL.

- [ ] **Step 3: Implement and delete the dead path**

`logs::run` connects to the broker and streams. Replace `runtime.rs:153`'s
"attach with `machine shell`" hint — that points at the dev-only interactive
path barred in production — with a real attach to the output stream. Delete
`microvm::logs` and `show_log_file`: the `require_linux_env` + in-VM `tail -f`
path cannot reach the native backends and must not survive as a fallback, or
the bug reappears.

- [ ] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-cli` — PASS.

- [ ] **Step 5: Confirm `invoke` streams end to end**

Task 5b wired the RPC response; this step only proves the CLI end is honest.
Add a test that output appears before the child exits, not merely that it
appears.

Run: `cargo nextest run -p mvm-cli invoke`
Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git commit -am "feat(cli): stream logs from the broker and attach on run"
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

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-core plan::` — FAIL.

- [ ] **Step 3: Implement**

Add the field with `#[serde(default)]`, thread it into `plan.admitted`, and have
the broker skip `TranscriptWriter` (live fan-out only) under `Ephemeral`.

- [ ] **Step 4: Run to verify it passes** — `cargo nextest run -p mvm-core plan::` — PASS.

- [ ] **Step 5: Write ADR-035 and the guide**

ADR-035 records: the two-source architecture and why vsock-only goes dark on
boot failure; ring retention over fail-closed bounds; hash-chain plus seal;
redaction before chaining and its consequence (the chain proves what was shown,
not what was written); the tracing boundary; the always-on retention default and
its signed opt-out. The guide covers following output live and after exit, the
verification model, and the `--stream` filter.

Correct `CLAUDE.md`'s two drifts: the claims ledger is the table in
`specs/adrs/001-microvm-security-posture.md`, not `specs/claims/catalog.md`; and
`mvm-client` has no `dyn MvmClient` facade.

- [ ] **Step 6: Run the doc gates**

Run: `cargo run -p xtask check-doc-claims && cargo run -p xtask check-adr-coverage && cargo run -p xtask check-no-overclaim && cargo test --workspace --doc`
Expected: clean.

- [ ] **Step 7: Commit**

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

- [ ] **Step 1: Write the failing tests** — serde round-trip both types; unknown
  fields rejected; a plan without `host.stream.v1` reports `grants_input() == false`.

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-protocol stream::input` — FAIL.

- [ ] **Step 3: Implement** with `#[serde(deny_unknown_fields)]`.

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(protocol): workload input frame DTOs"`

---

### Task 12: input gate — grant, lease, secret scan

**Files:**
- Create: `crates/mvm-hostd/src/stream/input_gate.rs`

**Interfaces:**
- Produces: `InputGate::open(vm: &str, plan: &ExecutionPlan) -> Result<InputSession, InputRefusal>`;
  `InputSession::write(&mut self, frame: InputFrame) -> Result<(), InputRefusal>`;
  `InputSession::close(self)`;
  `InputRefusal::{NotGranted, LeaseHeld { holder: String }, SecretMaterial { category: &'static str }, LeaseExpired}`.

- [ ] **Step 1: Write the failing tests**

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

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-hostd input_gate` — FAIL.

- [ ] **Step 3: Implement**

Grant check first, then lease acquisition with an expiry the caller refreshes,
then the sliding-window secret scan over a buffer at least as long as the
longest known secret minus one byte. Every refusal emits a chain-signed audit
entry carrying the reason and no payload bytes.

- [ ] **Step 4: Run to verify it passes** — PASS, 4 tests.

- [ ] **Step 5: Assert the chain carries no payload**

Write the test — do not assume one exists. Earlier drafts pointed at
`audit_chain_carries_no_payload_bytes`, which is absent from the tree; running
that filter exits 0 having executed nothing, so the step was vacuously green.
Assert that an input-refusal entry records the reason and the binding but no
frame bytes, including the refused secret material.

Run: `cargo nextest run -p mvm-hostd stream_input_audit`
Expected: PASS, and the filter must match a nonzero number of tests.

- [ ] **Step 6: Commit** — `git commit -am "feat(hostd): plan-gated, leased, secret-scanned workload input"`

---

### Task 13: agent delivers input to the child and closes stdin on EOF

**Files:**
- Create: `crates/mvm-agentd/src/stream_input.rs`
- Modify: `crates/mvm-agentd/src/stream_pump.rs` (stdin handle ownership)

**Interfaces:**
- Produces: `InputSink::new(stdin: ChildStdin) -> Self`;
  `InputSink::write_frame(&mut self, f: InputFrame) -> io::Result<()>`;
  `InputSink::close(self)`.

- [ ] **Step 1: Write the failing test**

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

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-agentd stream_input -j 6` — FAIL.

- [ ] **Step 3: Implement.** `close` drops the `ChildStdin`, which closes the fd.

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Confirm the agent stays runtime-free**

Run: `cargo run -p xtask check-guest-agent-runtime-free`
Expected: clean.

- [ ] **Step 6: Commit** — `git commit -am "feat(agent): deliver streamed input to the entrypoint with explicit EOF"`

---

### Task 14: `--prod` refuses the input grant for shell-shaped entrypoints

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/up/admission.rs`

**Interfaces:**
- Produces: `entrypoint_is_shell_shaped(plan: &ExecutionPlan) -> bool`.

- [ ] **Step 1: Write the failing tests**

Cover each limb of the rule from the design section: basename in
`{sh, bash, dash, ash, busybox, zsh, ksh, fish}`; a script whose shebang
interpreter basename is in that set; argv carrying `-c`. Plus: a non-shell
entrypoint with the grant is admitted under `--prod`, and a shell entrypoint
*without* the grant is admitted (output streaming stays unconditional).

- [ ] **Step 2: Run to verify it fails** — `cargo nextest run -p mvm-cli admission` — FAIL.

- [ ] **Step 3: Implement.** Refuse before any network or boot work.

- [ ] **Step 4: Run to verify it passes** — PASS.

- [ ] **Step 5: Commit** — `git commit -am "feat(cli): refuse the input grant for shell entrypoints under --prod"`

---

### Task 15: claims ledger — reword 15, add 17

**Files:**
- Modify: `specs/adrs/001-microvm-security-posture.md` (claims table, rows 15 and 17)
- Modify: `crates/mvm-agentd/fuzz/fuzz_targets/` (add an input-frame target)

- [ ] **Step 1: Reword claim 15**

State what it now guarantees — no shell, no exec, no argv or env control, no
PTY on a sealed image — rather than implying no input path exists.

- [ ] **Step 2: Add claim 17** with witnesses naming the T12 and T14 tests:
  `fn:input_is_refused_without_a_plan_grant`,
  `fn:a_second_writer_is_refused_while_the_lease_is_held`,
  `fn:secret_material_split_across_frames_is_still_refused`,
  `fn:every_refusal_is_audited`, and the `--prod` shell-refusal test.

- [ ] **Step 3: Add the input-frame fuzz target** so the new parser joins claim 5.

- [ ] **Step 4: Run the ledger gates**

Run: `cargo run -p xtask check-claim-catalog && cargo run -p xtask check-claim-witness-freshness && cargo run -p xtask check-no-overclaim`
Expected: every named witness resolves.

- [ ] **Step 5: Verify the untouched claim-15 witnesses still pass**

Run: `cargo nextest run --workspace -E 'test(console_refused_on_sealed_image) or test(prod_console_attachment_has_no_input)'`
Expected: PASS — the console capture still has no host input fd.

- [ ] **Step 6: Commit** — `git commit -am "docs(claims): reword claim 15 and add claim 17 for the input channel"`

---

### Task 16: input documentation

**Files:**
- Modify: `public/src/content/docs/guides/workload-output-streaming.md`,
  `public/src/content/docs/reference/cli-commands.md`,
  `specs/adrs/035-workload-stream-plane.md`, `specs/SPRINT.md`,
  `specs/REFACTOR-STATUS.md`

- [ ] **Step 1: Document the input half** — the grant, the single-writer lease,
  the secret gate, explicit EOF, and the `--prod` shell refusal, including the
  honest statement that shell detection is a heuristic.

- [ ] **Step 2: Record the claim-15 trade in ADR-035** — enforced-by-absence
  becomes enforced-by-policy, and why that was worth it.

- [ ] **Step 3: Tick this plan's boxes and update the rollups**, bumping
  `REFACTOR-STATUS.md`'s "Last updated".

- [ ] **Step 4: Run the full gate**

Run: `just ci && cargo run -p xtask check-doc-claims && cargo run -p xtask check-file-size`
Expected: clean.

- [ ] **Step 5: Commit** — `git commit -am "docs: workload input plane guide and claim-15 trade"`

**Phase 2 exit criterion:** a plan-granted external consumer feeds a running
workload's stdin and sees its output in the same stream; an ungranted one is
refused and the refusal is in the chain.
