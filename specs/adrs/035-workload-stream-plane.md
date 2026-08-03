# ADR-035: The workload stream plane

## Status

Accepted for the output half. Implemented by plan 283 phase 1: the guest pump
(`mvm-agentd`), the stream store (`mvm-core::transcript`), the host broker
(`mvm-hostd::stream`), and the consumers (`mvmctl machine logs`, `machine run`
attach, `mvm-client`/SDK readers).

The input half — a plan-bound, default-deny channel to a running workload's
stdin — is designed in plan 283 and **not decided here**. It changes claim 15
from a structural guarantee to a policy one, which is a separate decision with
its own ledger work.

Three limits below (§"What this does not do") are stated as limits, not as
future work. They are true of the shipped code.

## Context

A production microVM has no shell. Claim 4 removes `do_exec` from the agent
and claim 15 removes the console from a sealed build, both deliberately. That
leaves the workload's own stdout and stderr as the only thing an operator can
read, and until this plane none of it was reachable in a usable form:

- The agent buffered every byte until the child exited, then shipped it in one
  response. The wire was streaming-shaped; the producer was not.
- Output was capped at 1 MiB per stream and a breach **killed the workload**.
  A program was terminated for talking.
- `machine logs` reached a console file through a host-local tail with no
  channel separation and no integrity story, and `machine run` printed a hint
  pointing at the interactive path production bars outright.

So the observability that is the reason these workloads exist arrived late,
truncated, or not at all. That is what this ADR's decisions are answering.

## Decision

### Two sources, one stream

Both the guest's entrypoint frames (over vsock) and the VMM's console capture
feed one broker, and each record carries which source it came from.

A vsock-only design is the obvious one and it is wrong in exactly the case
that matters. The vsock channel exists between the moment the guest agent
starts and the moment it dies. A kernel panic, a dm-verity refusal, an OOM
that takes the agent with it, a wedged post-restore handshake — every one of
them produces output on the console and nothing on vsock. A stream that goes
dark precisely when a boot failure needs explaining is not an observability
feature.

The console alone is equally insufficient: it is one merged byte stream, so it
cannot say which fd wrote what. Console-sourced records are therefore recorded
as stdout whichever fd produced them, and a narrowed read says so rather than
silently withholding. Two sources, because neither one covers the run.

Ordering is by host-side receive stamp, and interleaving *between* sources is
best-effort. The two paths have different latencies; a total order across them
is not something the transport can deliver, so it is not promised. Ordering
*within* a source is exact, and the sequence number — not the clock — is the
ordering authority.

### Ring retention, never a fail-closed bound

The transcript store this reuses was built for forensic egress capture, where
refusing at a bound is correct: an incomplete evidence artifact should fail
loudly. Applied to logs it inverts the requirement. The moment a workload
stops being observable — a crash loop, a runaway process, a retry storm — is
the moment its output matters most, and those are exactly the moments that
blow through a byte budget.

So a stream capture drops its oldest records to make room for its newest, and
records an explicit gap marker where it did. The type signature carries the
rule: the ring's admission decision has no refusing variant, so a bound cannot
silence a workload even by mistake. Nothing in this path can kill, throttle,
or block the producer either: a slow disk sheds rather than waits, and a
follower that stops reading loses its own oldest records and nobody else's.

A window is not silently passed off as a whole run. The sealed manifest
carries what the ring evicted and what never reached the store, and a reader
that finds either prints a warning naming both counts.

### Hash chain per record, sealed Merkle root at exit

Each record carries the previous record's hash, and the capture seals to an
RFC-6962 Merkle root at exit. The chain is the live half and the root is the
durable half; both are needed.

The root alone cannot help a follower, because it does not exist until the
capture seals — and a live follower is precisely the consumer who needs to
know that what it is being handed has not been rewritten or silently skipped.
The chain alone cannot survive the run, because a chain with no anchor is only
self-consistent. One hash per record buys the first; the seal that plan 280's
audit anchoring already covers buys the second.

**The verifier is anchored, not genesis-rooted.** A genesis-rooted verifier
was the first shape and it was unusable: ring retention prunes, and a
follower attaches mid-stream, so the ordinary read is a *window* whose first
record has a predecessor the reader never saw. Verification takes an explicit
anchor for that predecessor, and the genesis form is the special case rather
than the other way round. A reader keeps its own running anchor and only
falls back to the broker's when a loss actually moved, so a broker cannot
re-anchor a continuing stream onto a value of its choosing.

Verification runs before filtering, always. `--stream stderr` and `--from-seq`
remove records from the middle of a window, which breaks the chain by
construction; the reader verifies the whole delivered batch and narrows
afterwards. The broker filters nothing.

A verification failure exits nonzero, mirroring `mvmctl trust audit verify`. A
pruned window does not: that is the ring doing its job, and it surfaces as a
gap notice.

### Redaction before chaining — and what that costs

Redaction runs at ingest, before the record is hashed, and at that one seam
only. The alternative — redacting per consumer — makes every new consumer a
new leak path, which is the failure mode `EgressGate` exists to prevent for
egress. One seam is worth having.

**The consequence, stated rather than discovered: the chain proves what was
*shown*, not what the workload *wrote*.** The original pre-redaction bytes are
never hashed and never stored, so after the fact they are unprovable. A
dispute about whether the mask fired correctly cannot be settled from the
transcript, because the transcript is the masked copy. This is the price of a
single seam and it is accepted, not mitigated.

The seam is pinned by an `xtask` gate rather than by convention: a
constructor that could hand the broker a no-op redactor would satisfy the same
signature, so `check-stream-redaction-seam` fails the build if any production
path can reach one.

### `invoke` returns the caller's own bytes unmasked

`mvmctl invoke` prints the entrypoint's output to the caller's own fds. Those
bytes are **not** masked, while the copy that is fanned out and persisted is.

This looks like a hole and is not. The caller of `invoke` has code execution
in the workload that produced those bytes: they wrote the function, they can
print whatever they like from inside it, and masking their own return value
protects nothing from anyone. What it *would* do is break the function
contract — a function whose legitimate return happens to look like a card
number would come back mutilated.

The masked copy still exists. One ingest per frame is the only fan-out point,
so the broker seals and records the cleared bytes while handing back what the
seam decided; `invoke` prints its own bytes and `logs` shows the masked ones,
from a single pass. A call made against a VM this process did not start finds
no broker and falls back to a redact-only path rather than raw passthrough:
"not recorded" must never quietly mean "not redacted".

### Always on, with a signed opt-out

Capture is on for every workload, ungranted. The asymmetry with the input
half is deliberate: output is a property of running a workload, input is a
capability.

Always-on capture is a data-retention change — output that used to evaporate
is now written to disk, encrypted. The opt-out for that is
`ExecutionPlan.stream_retention`, defaulting to `Persist`, with `Ephemeral`
meaning "fan out live, keep nothing". An ephemeral run gets an identical
broker, an identical socket, identical redaction and chaining and fan-out; it
just never creates a capture directory. Sealing an ephemeral capture yields no
manifest rather than an empty one, because a manifest with zero chunks asserts
that the workload printed nothing, which is a different and false claim.

**The mode is in the signed plan, not on a command line.** A CLI flag would
make an absent transcript ambiguous: nobody reading the evidence later could
tell a run that was admitted not to keep one from a run whose recording was
lost or removed. That is the same ambiguity plan 280 refused when it made a
stale manifest fail as *old* rather than as *tampered*. Admitting the mode and
writing it into the `plan.admitted` chain entry settles it: **you can always
prove whether a run was recorded, even when you cannot prove what it printed.**

The stream plane's own audit entries carry the reason and the binding — which
VM, which reader, which sequence number — and never a payload byte. Signing
per record would cost a signature per write and turn the audit chain into a
second copy of the workload's output.

### Store verbatim, adapt at the edge

stdout and stderr are stored as opaque bytes, never parsed, never reframed.
`tracing` is an adapter available on read, not a storage format.

Routing stdio *through* `tracing` forces a framing choice, and line framing
mangles `\r` progress output, partial lines, binary payloads, and JSON on
stdout. Byte-exactness is load-bearing here specifically because the record is
hash-chained: if the stored bytes are not the produced bytes, the chain proves
the wrong thing. `tracing` events also carry level, target and fields that
stdout does not have, so the conversion invents metadata and then commits the
invention to a Merkle root.

The structured channel exists separately. A workload that wants levels and
fields writes a `Trace` record on fd 3, which is shaped like a tracing event
because it *is* one. The host bridge republishes both kinds into a consumer's
subscriber, carrying the payload as base64 so the exact bytes survive — an
encoding, not a reframing. stderr is not promoted to `WARN`: that severity
would be invented, and the channel already travels as a field.

The `mvm.` record-kind namespace is reserved and refused on ingest from fd 3.
Framing separation is not authorship: without that gate a workload could write
its own gap marker and make a verifier bless a chain that skips a range it
excised itself.

## What this does not do

Three limits. Each was found while building this, each is true of the shipped
code, and each would be dishonest to leave out.

### 1. The single-seam claim is conditional

The transcript is redacted. The console fallback is **not** — reading
`console.log` reads the raw bytes the guest wrote, because that file is the
VMM's, written before anything in this plane sees it. When a recording exists
but does not cover the whole run, `mvmctl logs` now shows the recording and
then splices the console behind it, so both appear in one read.

This exposure is not new; the console-only path always read raw bytes. What
changed is its reach: it went from a rare edge case to every ordinary `machine
run -d` followed by a later `machine stop`. So the honest statement is *the
broker has one redaction seam and every consumer of the broker sees masked
output* — not *no consumer sees unredacted output*. The second sentence is
false while the console fallback exists.

### 2. The follow half is open for detached workloads

The console follower lives in the process that started the VM. `machine run
-d` returns as soon as the machine is up, and the follower dies with it. The
VM keeps running, and everything it prints after that point reaches no broker.

The transcript that exists is real and verifies; it just covers the beginning
of the run rather than the run. It is sealed by whichever later invocation
stops the machine, rebuilt from a journal the departed writer mirrored, and
marked as a reconstruction — it cannot account for whatever that process
dropped on its way out, and the read side says so.

The operator still sees the missing output, via the spliced console file, with
none of the guarantees. Closing this properly needs a resident host process
that owns the plane for the machine's whole life. This repository does not
have one. That is a lifetime change, not a wiring change, and it is not in
this ADR.

### 3. A spliced read repeats its adopted prefix

The recorded half is indexed by transcript sequence number and the console
half by byte offset in a file. The two share no common coordinate, so there is
no way to resume the console exactly where the recording stopped.

The splice therefore overlaps rather than risking a hole: the console half
starts from the beginning of what it can show, so the part the recording
already displayed appears twice. Duplicated, not lost — the direction chosen
deliberately, because a reader who sees a line twice is inconvenienced and a
reader who never sees it is misled. The notice printed before a spliced read
says the repetition is expected.

## Security posture

**Unaffected.** Claims 1–3 (host-fs access, uid 0, verity): a stream is a read
of a file the host already writes and a read of frames the host already
receives. Claim 4: no exec path is added. Claim 10: no NIC anywhere on this
path; `check-vsock-only-egress` and `check-uniform-vsock-egress` stay green.
Claim 15: the console capture is opened read-only and the trait cannot hand
out a writable handle, so `prod_console_attachment_has_no_input` continues to
hold — this plane adds a reader, never an input fd.

**Extended.** Claim 8's admitted plan gains one more decision it binds, and
one more label in the chain.

**Not strengthened, despite appearances.** The reader-side anchoring rule
defeats a *buggy* broker, not a hostile one: nothing cross-checks a claimed
loss point against the delivered records, so a broker sending monotonically
increasing loss markers keeps re-anchor control. That is fine and in scope —
ADR-001 puts a malicious host outside the threat model — but it should not be
read as a defence it is not.

## Alternatives rejected

**Route stdio through `tracing`.** Rejected: framing, and inventing metadata
that then gets hashed. See §"Store verbatim".

**Fail closed at the retention bound.** Rejected: it is the forensic-capture
policy, correct for discrete evidence frames and exactly backwards for logs.
Both policies still exist in the store; a stream capture selects the ring
through the single constructor that pairs it with the stream budget, so a
config assembled by hand cannot silently get the fail-closed default.

**Subscribe `invoke` as an ordinary follower.** Rejected: the reader queues are
bounded rings that evict, so the answer to a synchronous call would be lossy
under back-pressure.

**Tee the entrypoint frames — one copy to the caller, one to the broker.**
Rejected: it leaves `invoke` printing raw bytes while `logs` shows the masked
copy, which is a leak path around the single seam. Routing both through one
ingest keeps the seam intact.

**Serial-console passthrough as a second interactive transport.** Rejected
earlier under claim 15 and unchanged here: fatal on an input-less console.

**A per-VM broker process.** Rejected: brokers are map entries in whatever
host process owns the VM's lifecycle, matching the per-tenant daemon's
"registrations, not processes" posture. The socket bind is the registration
token, so two processes can never interleave one transcript.

## References

- `specs/plans/283-workload-stream-plane.md` — the design and its
  implementation sequence.
- ADR-001 — threat model, per-backend tier matrix, and the claims ledger table
  this ADR's security section refers to.
- ADR-014 — signed, audited execution plans (claim 8), which
  `stream_retention` extends.
- ADR-023 — the redaction and substitution posture the stream seam mirrors.
