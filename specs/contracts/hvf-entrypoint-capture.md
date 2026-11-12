# HVF entrypoint capture into the protected owner

Status: **Proposed requirements for runtime/security review. No capture
producer endpoint, credential, wire version or positive authorization is
enabled by this document.**

Scope: [#5265](https://github.com/tinylabscom/mvm/issues/5265).
The issue owns approval provenance and remaining work. This is not a capture
fix, a demo-success claim, or an extension of mailbox reporting.

## Baseline and governing boundaries

The inspected MVM source baseline is
`34ac9e41ef104a2b9924fc43c57fede591a0d6be`. Studio's reproduced baseline remains
`592c0b8280d5b4d343269708ed70d237353fa4f9`; this proposal does not advance its pin.

- Both [ordinary dispatch](../../crates/mvm-client/src/entrypoint/dispatch.rs)
  and [the owned entrypoint path](../../crates/mvm-client/src/entrypoint/boot.rs)
  obtain a caller-local `EntrypointSink::for_vm`. The current
  `CaptureReport.recorded` samples whether that local capture exists at call
  start; it is not a per-frame receipt or durability barrier.
- The existing entrypoint event route records fd-3 control headers as
  `StreamKind::Trace` when a caller-local broker is present. This proposal
  does not convert control headers or their payloads into mailbox messages.
- [`StreamPlane::attach`](../../crates/mvm-hostd/src/stream/plane.rs)
  deliberately skips `supervisor_owned` capture, even when the supervisor
  socket is absent. Starting a second writer is not a repair.
- [`CaptureOwner`](../../crates/mvm-hostd/src/stream/protected.rs)
  owns the protected broker, retention and sealing. Its current bounded input
  receives console bytes and labels them console/stdout, not entrypoint frames.
- [`open_vm_output`](../../crates/mvm-core/src/stream_client/output.rs)
  already distinguishes verified live records, verified durable history and
  unchained console fallback. A durable `OutputRecord` does not expose the live
  source/timestamp fields. Do not invent those fields at the Studio edge.

[ADR-035](../adrs/035-workload-stream-plane.md) governs one broker, original
caller bytes versus the redacted recorded copy, channel/source separation,
bounded shedding, retention and chain verification. Its historical
caller-local/console-file descriptions do not establish a cross-process HVF
producer. This proposal preserves those guarantees rather than enabling a
legacy plaintext fallback.

[The cold entrypoint owner](hvf-entrypoint-owner.md) and
[its recovery/lifetime contract](hvf-owner-recovery-lifetime.md) separately own
original execution custody and recovery. Their source-only recovery requests
and possession proofs do not authorize capture writes. Nothing here adds a
start/dispatch verb to recovery or relaxes those contracts' activation gates.

## Recommended integration

Keep execution and the authenticated guest channel where the admitted call
already owns them. Send a separate, run-authorized typed capture copy from
`mvm-client` to the existing supervisor's `CaptureOwner`. The first positive
producer is limited to **owned HVF entrypoint calls** through the original
authenticated native channel. Ordinary name-resolved and session dispatch
receive no new producer, writer, fallback or positive recorded-copy claim from
this proposal; their existing behavior is unchanged. Any later path needs its
own reviewed authorization under its original execution custody.

The owner is the only redaction, sequence/chain, persistence and fan-out seam.
Studio continues to call typed `mvm-client` operations through Tauri and reads
output through the existing client reader. It acquires neither a capture
writer nor MVM storage paths.

Moving execution into the supervisor would change guest-channel custody,
dispatch and cancellation merely to connect recording; that broader change is
not recommended. A caller-local broker, console scrape, raw-byte relay into
history, or mailbox message republished as output is rejected.

Typed workload `result`/`error` messages belong to the separately authorized
[mailbox reporting design](https://github.com/tinylabscom/mvm/issues/5260),
not this capture path. Stdout/stderr remain diagnostics, never automatically
published as application results. Mailbox destination acceptance, delivery,
consumer ACK and publication verdict do not follow from an entrypoint frame,
fd-3 control header, guest exit or capture receipt. Conversely, a mailbox
receipt does not prove the protected stream was captured or durably readable.
The mailbox work may evolve independently; this contract adds no mailbox
grant, envelope, key, recipient or storage dependency to HVF capture.

## Required producer authority

The receiving owner must authorize a producer against independently retained
context for the exact owned HVF boot, native generation and entrypoint call:

- controlling principal/enrollment and tenant;
- actual admitted plan/effective configuration, not caller-declared hashes;
- original owner incarnation, native instance and protected capture run;
- one admitted call identity and its allowed stdout/stderr operation;
- fresh connection and monotonically ordered producer frames.

These are bindings to verify, not credentials. A VM name, same UID, socket
path, public run ID, source label or successful output-reader connection is
insufficient. The receiver must authenticate the original owner to the
producer as well as the producer to the owner; a forwarded endpoint must not
gain authority. Refused authentication changes no capture state.

Reuse the existing admitted launch/owner custody where it can establish these
facts, but do not repurpose caller-registration, recovery, signing or
read-access proof domains. Existing `CaptureAuthority` provisions the owner;
it does not grant arbitrary later IPC callers entrypoint ingest.

**Activation blocker:** runtime/security review must select the concrete proof
and verifier, their establishment point under original launch custody, and
their replay/restart/handoff rules before any receiver or production wiring is
added. This draft allocates no bearer token or signing purpose. Neither
knowledge of the binding above nor acceptance of this document fills that
proof gap. If existing custody cannot authorize a path, that path remains
explicitly unrecorded; it must not silently discover name-only write access.

## Capture and acknowledgement semantics

1. Accept only bounded typed stdout/stderr frames for the authorized call.
   Derive `Entrypoint` provenance from that admitted operation; do not accept
   arbitrary source labels or treat console's merged bytes as stderr.
   The existing fd-3 control/Trace route is not a mailbox transport and is
   not included in this first cross-process producer. Its existing observer
   behavior remains unchanged; the first producer does not claim parity for
   control records or silently turn them into application results. Any later
   capture of control headers needs its own closed, bounded schema, with
   payload, host-exit and execution-completion authority excluded.
2. Preserve the caller's returned stdout/stderr byte for byte. Redact only
   inside the protected owner before hashing, persistence or follower fan-out.
   Report masking rule names, withholding and loss without returning raw
   sensitive values in receipts or diagnostic logs.
3. A producer frame's transport enqueue is not an owner receipt. An owner
   receipt must bind this run/call and exact producer sequence to its
   recorded-copy disposition and, when accepted, owner sequence. Duplicate
   delivery cannot append twice; conflicting reuse refuses. Reconnecting
   never dispatches the guest call again.
4. Distinguish owner acceptance, redaction/divergence, lost/unconfirmed frames,
   admitted live-only retention and verified durable readback. Owner acceptance
   does not prove disk persistence or successful sealing.
5. The current boolean alone cannot express partial acceptance or mid-call
   owner loss. Review the typed `mvm-client` report change for the owned path
   before upgrading its meaning; no new legacy/name-resolved producer or
   compatibility path is required. Do not synthesize `recorded = true` from
   connection success, returned bytes, guest exit, queue admission or a
   fixture. A client claiming a complete recorded call must account for every
   output frame; uncertainty is explicit rather than a clean report.

The chain attests to the protected, possibly redacted host record. It is not
off-host cryptographic proof that arbitrary bytes supplied by a host producer
were authored by the guest.

## Bounds, failure and lifetime

Before activation, the implementation review must specify exact frame,
aggregate queue, connection, handshake and final-receipt/flush bounds and their
pre-allocation enforcement points. Reuse existing capture budgets where
applicable; the console queue's geometry is not automatically an IPC contract.
Zero never means unlimited.

- No follower or storage wait can block guest output indefinitely. Capture
  pressure sheds with explicit byte/frame loss, without killing or throttling
  execution merely to satisfy recording. Cancellation/control cannot queue
  behind output. A full recorder queue is a capture loss, not an execution
  output-limit event. If the cold owner's separately proposed 16 MiB
  stdout/stderr qualification bound is approved and activated, count guest
  output bytes at the execution boundary independently of recorder admission:
  exceeding that bound requests cancellation even when capture sheds bytes.
  This proposal neither enables nor relaxes that owner qualification profile.
- Reject oversized, malformed, unsupported, wrong-run, stale and replayed
  traffic before broker mutation. Per-call frame order and broker sequence
  remain authoritative; cross-source ordering is still best-effort host
  receive order, not guest-clock ordering.
- A failed handshake, full queue, lost receipt, owner failure or deadline
  exhaustion becomes explicit unavailable/unconfirmed/loss evidence, never a
  plaintext fallback, a second writer or a guessed successful flush.
- Keep existing admitted `Persist`/`Ephemeral` policy, encryption, rotation,
  audited opening/sealing, retention and reader verification. Ephemeral
  acceptance cannot imply retained durable history.
- Retire producer authority when its call or owner/run ends. A late producer
  cannot write into a replacement run with the same VM name. Serialize
  retirement, accepted-frame draining, bounded final receipt and sealing;
  disclose any accepted frames not durably retained.
- Capture acknowledgement is not execution completion, guest storage flush,
  successful stop, resource-release authority, a mailbox publication or ACK.
  Conversely, native terminal proof does not prove host capture flushed.

## Tests and evidence required

### Current-boundary regression tests, not a capture fix

The source-only tests in this proposal exercise current production components:

- `supervisor_owned_capture_never_starts_a_competing_launcher_writer`:
  with no owner/socket, both retention modes leave caller stdout/stderr
  unchanged and `NotRecorded`, without creating capture files or a writer.
- `a_vm_name_does_not_grant_entrypoint_ingest_into_a_protected_owner`:
  with a real protected owner/socket, a same-name caller-local plane still
  cannot record either channel. After owner finish, the public reader returns
  only the owner's synthetic console marker as verified durable history;
  caller-only and post-exit frames never enter it.

These tests boot no VM, authenticate no new producer and establish no positive
entrypoint-capture path. They must remain distinct from future tests of the
reviewed run-authorized producer.

### Implementation acceptance, not yet witnessed by this proposal

| Studio use case | Required test before claiming support |
| --- | --- |
| Show both output channels for an actual owned HVF call | Original owned dispatch to protected owner to public reader; separate stdout/stderr, one record per accepted frame, correct live provenance; no invented durable source fields. Ordinary name-resolved/session dispatch has no new producer in this slice. |
| Separate returned bytes from the protected copy | Real owner masks/withholds under admitted policy; caller bytes unchanged; owner-confirmed divergence reaches `mvm-client`; no unredacted follower or persisted copy. |
| Refuse unrelated/stale producers | Real transport refuses absent/wrong principal, tenant, plan, owner, native generation, capture run or call; forwarded/replayed proofs and stale frames cause no append or sequence consumption. |
| Stay responsive and report incomplete capture | Saturated queue, slow reader, blocked storage, malformed/oversized frames, disconnect and owner death; bounded waits and memory, execution/control remains responsive, losses/unconfirmed acceptance are visible. |
| Reopen retained output honestly | Persisted encrypted history verifies after sealing/rotation; ephemeral has no durable payload; retention gaps and persistence/seal failure remain explicit. Duplicate frames/receipts never duplicate records. |
| Repeat the demo safely | Real owner teardown/restart with the same logical name cannot inherit a stale producer, receipt or history identity; cleanup remains owned by the original execution path. |

After implementation review, build matching runtime artifacts from a clean
candidate Git revision. Pass Studio's one-workload native HVF captured-output
smoke first, then three workloads and two complete run-owned cleanup
repetitions, followed by an interactive Mac rehearsal. Keep the current smoke's
recorded-copy/readback assertion: mailbox reporting, direct returned bytes,
UI fixtures and non-boot CI cannot satisfy it.

The existing reproduced `capture.recorded = false` remains a failure, not an
expected-success demo. A Studio pin update is a separate reviewed change after
the real HVF witness and candidate Studio checks pass.
