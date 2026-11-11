# Owned HVF capture: concrete protocol proposal

Status: **Proposed for runtime/security review; not an enabled protocol.**
Scope: [#5265](https://github.com/tinylabscom/mvm/issues/5265), refining
[the capture requirements](hvf-entrypoint-capture.md). Issue comments own
approval and delivery status. No receiver, signing operation, startup field,
wire version or public client report is activated by this proposal.

Source baseline: `57b55a804ec60e2fba6f6ce5baef65a97546f0e6`.
Studio's pin remains `592c0b8280d5b4d343269708ed70d237353fa4f9`.
The original guest call/channel and native completion/cleanup stay unchanged.
Mailbox reporting, fd-3 control capture, warm handoff and name-resolved
dispatch are not part of this slice.

Existing seams to extend only after review:
[original child and guest-channel custody](../../crates/mvm-backends/src/driver/hvf/cold_channel.rs#L367),
[connected supervisor/lifetime checks](../../crates/mvm-vmm/src/host/hvf_stop.rs#L198),
[kernel peer identity](../../crates/mvm-vmm/src/host/uds_peer.rs#L14),
[independently retained enrollment](../../crates/mvm-hostd/src/supervisor/caller_registration.rs#L28),
and [the sole protected recorder](../../crates/mvm-hostd/src/stream/protected.rs#L68).
None currently implements the capture proof proposed below.

## Recommendation and alternatives

Use a fresh connected local Unix stream in the original supervisor, the
existing original-child/native-generation checks, and a **separate
capture-purpose caller-possession proof** against a one-call permit provisioned
by the trusted admitted launcher. No arbitrary signing oracle or new private
key is given to Studio, the webview or the recorder.

| Approach | Decision for review |
| --- | --- |
| Fresh connection, kernel peer/lifetime checks, explicit one-call permit and separate possession purpose | Recommended: existing native identity primitives plus narrowly scoped new write authorization. |
| Pre-created inherited socketpair as sufficient peer proof | Not selected: peer-identity behavior differs by platform and still does not establish lifetime or one-call write authorization. A descriptor-custody design needs its own native qualification. |
| VM name, same UID, private pathname, reader grant, registration or recovery proof alone | Rejected: none authorizes this call's capture writes. |
| Moving guest dispatch into the recorder | Rejected: changes execution custody rather than connecting its diagnostic copy. |

The local socket is a new compatibility/security surface, not a mailbox or
public discovery endpoint. Runtime and security maintainers must approve the
following establishment, signing purpose and limits before adding it.

## Establish authority under original launch custody

1. Before native effects, the trusted launcher retains the final admitted
   plan and full enrolled caller identity. It provisions one non-cloneable
   capture permit for one newly generated call UUID through the same
   authorized cold-start custody boundary that supplies checked boot inputs.
   A generic signed plan or producer request cannot install this permit.
2. The permit binds the complete enrollment, tenant, actual plan ID/nonce,
   registration instance/run/producer/session IDs, intended call UUID, and SHA-256 of
   the exact bounded startup-configuration bytes sent to the child. The
   supervisor computes that digest from its own original startup input after
   normal admission/input validation; it does not trust a producer's digest.
   A different serialization is a different startup binding, not an alias.
   Hold the existing supervisor-configuration byte string unchanged and
   transport the capture permit as a separate bounded startup record. Hash
   only that held configuration, not a containing envelope or the permit
   itself: the digest must not depend on its own encoded field. The new
   registered owned-startup envelope needs explicit decoder/compatibility
   review; the legacy startup format is unchanged and grants no capture.
3. The supervisor binds the permit to its own actual `HvfInstance`, including
   boot nonce, and protected capture run. These facts are fixed once before
   producer admission. They cannot be overwritten by a handshake. Initial
   implementation supports only an original registered cold owner with this
   explicit permit; other owned calls remain unrecorded, not newly authorized.
4. For this direct-spawn-only slice, the supervisor samples its kernel parent
   with `getppid` before native effects or spawning any supporting process.
   Arm a lifetime observer for that parent, then recheck the parent and its
   non-exit event before installing the permit. Require the same live parent
   as the connecting producer. A saved/configured PID is only a consistency
   check, never the source of custody. Reparenting, a missing observer or an
   already-exited parent refuses capture; a replacement PID cannot resurrect
   the retired permit. Qualify this against the real checked cold-spawn path
   before activation; mediated launches and handoff are unsupported.
5. Create the capture listener in the supervisor's private run state, mode
   0600. Its path is only a locator. Keep no endpoint registry, reconnect
   credential, key file or producer-selected registration path.

Existing consumed registration supplies independently checked identity facts,
not capture-write authority. The new permit and proof are separate. No
caller-registration, recovery or stop proof bytes are accepted as this proof.
No owner factory, keyless-lifecycle prerequisite or publisher verification
requirement is relaxed.

## Authenticate the actual connection in both directions

The producer must retain the original `ColdHvfOwner`/native child, not attach
by VM name. Before and after opening the capture stream it must perform the
same original-child, signed-native-generation and lifetime checks used by
`OwnedInstance::open_agent_bridge`. Check the **capture stream's** kernel peer
PID against that retained child; do not merely authenticate another socket.
Continue to observe the original child's lifetime while receiving receipts.

The receiver checks the connecting peer against the retained original
launcher process and enrollment. A different same-user process, proxy
connector or replacement incarnation refuses before parsing payload frames.
PID comparison alone is insufficient: require live process observation and
the fresh possession exchange below on this same connection.

Proposed separate signing domain: `mvm.owned-hvf.capture-possession.v1` followed
by a NUL byte. This is a review candidate, not an allocated production purpose.
Add a closed credential-subsystem operation only after approval; never export
private key material or expose sign-arbitrary-bytes.

The signed message is the domain followed by this fixed field order:

- protocol candidate number one, one unsigned byte;
- enrollment installation UUID (16 bytes) and public key (32 bytes);
- tenant and native VM name, each a big-endian u16 byte length followed by
  UTF-8, each at most 512 bytes;
- plan ID (decoded 32-byte content address), plan nonce decoded from its
  canonical lowercase hex into 16 bytes, and startup SHA-256 (32 bytes);
- registration instance, run, producer, session and call UUIDs (16 bytes each);
- native boot nonce (32 bytes) and protected capture run as a length-prefixed
  UTF-8 value, at most 128 bytes;
- kernel-observed producer and supervisor PIDs, unsigned big-endian u32;
- a fresh receiver-generated 32-byte connection challenge;
- receiver issuance and expiry seconds, unsigned big-endian u64.

Every field is compared with independently retained context before signature
acceptance. The credential operation validates the same context and bounds
before signing. The challenge expires within 30 seconds and within the
registration validity interval; future issuance refuses. A separate monotonic
exchange deadline cannot be extended by peer traffic or wall-clock movement.
Consume the permit exactly once after successful authentication and before
the first append. Failed authentication consumes no producer sequence.

### One-call spend and retirement

A UUID labels the call; it does not enforce one-call use. Neither a
non-cloneable launcher handle nor a successful signature check is the
receiver's spend decision. The receiver must serialize these transitions in
one owner state, before any append:

| State | Permitted transition |
| --- | --- |
| Bound | The trusted original startup has installed one permit. Reserve at most one bounded authentication attempt for the actual expected peer. |
| Authorizing | Validate against the retained permit, native generation and live peer. Invalid proof releases only the transient reservation; cancellation, parent death or retirement must not be undone by late verification. |
| Spent | Atomically consume Bound/Authorizing into this exact connection and call **before Ready**. Initialize sequence/counters in the same transition. A competing successful verifier cannot also spend the permit. |
| Closing | After valid Finish, stop accepting data; serialize final disposition/counters and retire before publishing Final. |
| Retired | Absorbing. Reject every later proof/frame even if an alias keeps the socket open. No transition returns to Bound. |

The atomic spend must recheck that the permit, native generation, peer and
lifetime are still current; checking them before acquiring the state is not
sufficient. Loss of Ready, zero output, parser failure, timeout, cancellation
or loss of Final never refunds a spent permit. A replacement or restarted
owner cannot reconstruct it from serialized startup/receipt bytes; it needs
fresh admission and distinct original native custody.

The trusted client must bind capture to the actual owned dispatch, not merely
sign a caller-selected UUID. Create the call ID before native effects, retain
it with that invocation's admission/frozen configuration and original guest
channel, and consume its capture preparation only in that invocation's
before-dispatch path. Public VM names, DTOs and receipt IDs cannot mint or
recover this handle. If capture preparation fails and dispatch proceeds
unrecorded, that invocation cannot later reopen capture as a complete replay.
These constructor/dispatch constraints need runtime qualification alongside
the receiver's atomic spend.

Reuse the existing
[`ColdHvfChannel::entrypoint` phase guard](../../crates/mvm-runtime/src/workload_runner/runner/cold_hvf_channel.rs#L318):
it requires Activated, enters Uncertain before the native request, and only
then records Dispatched. Do not add a second guest-dispatch lifecycle or
retry after uncertainty. That existing guard limits guest invocation; it
does not spend the new receiver-side capture permit. One authorized call
may produce many fragments, each appended at most once.

A copied proof fails under a new challenge, peer, run or call. A byte-relaying
proxy is rejected by actual-connector identity. **Do not claim this prevents
an authorized process deliberately exporting an already-connected FD or its
credential.** The FD policy below is an implementation qualification boundary,
not a malicious-holder confinement or host-blind guarantee.

### FD custody, aliases and subprocesses

Both listener and connected endpoints must have close-on-exec protection
from creation/acceptance, including every cancellation or worker alias. Use
the platform's atomic mechanism or a qualified spawn-synchronized fallback;
a later `fcntl` alone does not close a concurrent-spawn race. The current
flag tests do not prove creation-time atomicity.

Keep the endpoints under one internal custody group, with an explicit list
of any indispensable aliases. Do not expose raw/owned capture FDs, serialize
them, pass them over `SCM_RIGHTS`, redirect them into child stdio, or give a
generic helper a capture-stream accessor. Lifetime/peer inspection may borrow
the endpoint without transferring ownership. Every permitted internal alias
must be close-on-exec and share cancellation/retirement ownership.

Audit every exec/re-exec path while capture is live. In particular,
[`inherit_descriptors`](../../crates/mvm-vmm/src/host/restore_image.rs#L300)
intentionally clears close-on-exec in the selected child. Capture endpoints
and all aliases must be excluded from that allowlist, boot/DATA/writable
descriptor vectors, startup diagnostics, signing helpers, re-exec keep
sets, snapshot/restore and handoff. Do not identify aliases solely by a saved
FD number, which can be reused after close.

Close-on-exec has **no effect before exec in a forked child**. Any supported
fork path must close capture copies before running another role; arbitrary
post-fork user callbacks or deliberate exports are unsupported. Qualify
fork-to-exec/re-exec behavior, not only flags in the parent.

Retirement first revokes the receiver's right to append, then cancels I/O,
shuts down the connection and closes every tracked alias within its bound.
Do not wait for last-FD EOF to revoke authority: an alias can delay EOF. A
timed-out join/close remains unconfirmed; it cannot become a clean Final,
successful native stop or permission to release execution resources. Socket
peer identity is not proof of the process currently using a transferred FD.

## Finite first-slice limits

These are proposed enforcement ceilings, not measured performance:

| Surface | Ceiling / behavior |
| --- | --- |
| Active producer | One connection and one call per original registered boot; no reconnect, resumed upload or second producer. |
| Authentication and receipt/control record | 4096 encoded bytes, length rejected before allocation; strict closed fields and versions. |
| Stdout/stderr fragment | 1..16384 payload bytes plus fixed type/sequence/length header. Skip empty output events and split larger returned chunks without changing caller bytes. |
| Client queued payload | 64 fragments and 1 MiB total, whichever is reached first; non-waiting offer. |
| Owner pending payload | One fragment, at most 16 KiB; does not consume console, lifecycle or cancellation credits. |
| Per-end parser staging | One maximum frame plus one 4096-byte control buffer. |
| Unconfirmed transport window | One fragment; the worker receives its disposition before sending the next fragment. The guest callback never waits for this exchange. |
| Receipt bookkeeping | Fixed counters, one bounded receipt slot, and bounded disposition identifiers; never an unbounded per-frame map. |
| Authentication deadline | Two seconds total, monotonic, including incomplete frames and credential response. |
| One frame exchange | Two seconds total in the asynchronous capture worker; expiry retires capture, not execution. |
| Final receipt deadline | 250 ms total after guest terminal, not per frame or reset on progress. |
| Owner teardown | Existing five-second owner-join bound; inability to finish stays explicit. |

Proposed framing is a big-endian u32 count of the following one-byte closed
record tag and body. Reject the declared count before allocation. A data body
is a big-endian u64 sequence followed by raw bytes: 13 bytes of framing plus
at most 16 KiB payload. An authentication body is the fixed-order signed
fields above and a 64-byte Ed25519 signature; it never carries a raw key.
Control/authentication/receipt counts must also fit their 4096-byte encoded
ceiling, including framing. Unknown tags, lengths, phases, trailing fields,
invalid UTF-8 or truncated records refuse without a partial append.

Candidate closed record tags, not allocated production values:

| Tag | Record / body |
| --- | --- |
| 1 | Challenge: fixed-order fields above, without signature. |
| 2 | Proof: those same fields plus the 64-byte signature. |
| 3 | Ready: the 32-byte connection challenge, only after permit consumption. |
| 4 / 5 | Stdout / stderr: u64 sequence, then raw payload. |
| 6 | Accepted: connection challenge, u64 producer sequence, u64 actual broker sequence, and one disposition. |
| 7 | Dropped: connection challenge, u64 producer sequence, u32 payload bytes, closed capacity/unavailable reason. |
| 8 | Finish: connection challenge and five u64 values: last queued sequence, offered fragments, offered bytes, local-drop fragments, local-drop bytes. |
| 9 | Final: connection challenge and seven u64 values: last processed sequence, owner-accepted fragments/bytes, owner-dropped fragments/bytes, masked fragments, withheld fragments. Retires the call; not a durable receipt. |

A disposition has a one-byte kind: identical (1), masked (2, followed by one
u8 rule count and u8-length-prefixed ASCII names), or withheld (3, followed
by a one-byte detector-failure reason). Dropped reasons are capacity (1) or
recorder unavailable (2). Other detector failures collapse to a single generic
withheld reason (1), without error text. Unknown values refuse. The client
associates every validated receipt with its independently retained run/call
binding; a nonce alone is never write authority. Final owner counts do not
attest to the caller-declared offered/local-drop counts in Finish.

Owner acceptance/redaction receipts must not block the guest callback or the
supervisor's stop path. Service other ready sources after each entrypoint
fragment. The client counts dropped copies without creating a local writer
or terminating the workload.
The cold owner's proposed 16 MiB execution-output policy remains inactive.
Integer overflow disables capture with unconfirmed/loss status, never wrap,
unlimited allocation or an execution-success projection.

## Ordering, receipts and client result

Give successfully queued fragments strictly increasing u64 sequence numbers
starting at one. Count offered output and locally shed fragments/bytes
separately; sequence numbers are not a claim that no original output was lost.
The receiver accepts only its next expected complete fragment. A duplicate,
conflicting, reordered or exhausted sequence refuses and retires the
connection without another append. The first slice never retries frames or
guest dispatch after an uncertain reply.

Only the existing protected broker may redact and append. A receipt binds
this connection, native generation, capture run, call and producer sequence
to the **actual broker record sequence** and its identical/masked/withheld
disposition, or to an explicit owner-side drop. Do not guess a record sequence
from queue length. Restrict rule identifiers to 32 names of at most 64 ASCII
bytes each; withholding uses closed non-sensitive reason codes, never raw
payloads or arbitrary detector error text. The single-fragment transport
window lets the client accumulate each disposition without a replay map or
an overwritable receipt queue. A lost disposition leaves that fragment
unconfirmed and retires capture; queued, provably unsent fragments become
local drops.

After guest terminal, send a bounded finish record with last queued sequence
and offered/local-loss counters. Retire the producer under the same owner
serialization as accepted-frame draining. Return a final counts-only summary
after all earlier fragments have dispositions. The final deadline cancels any
longer frame-exchange wait; do not join an uninterruptible worker on the
guest-callback thread. A lost final reply remains unconfirmed even if
individual accepted frames were observed.

At terminal, first close the local offer side and freeze the offered/queued
accounting cut. Drain only that already-queued prefix within the **single**
250 ms final budget; Finish describes that cut, not counters sampled while
another producer is still appending. On deadline or cancellation, classify
provably unsent copies as local drops and any possibly sent fragment without
its validated disposition as unconfirmed. Validate Final's call/challenge,
last sequence and counts against retained state before reporting completion;
a short, conflicting or lost summary cannot project success. Runtime tests
must race terminal/cancellation with a full local queue and an in-flight
owner append, and independently verify the protected readback.

Proposed owned-path client result has independent fields for:

- availability/refusal reason and final-close confirmation;
- offered frames/bytes, local drops, owner drops, accepted and unconfirmed;
- masked/withheld divergence and admitted live-only/persist retention.

All output must be accounted for before describing a call as completely
accepted, and any drop or uncertainty prevents that description. No receipt
has a durable-success variant: verified durable history still comes through
the existing reader after its normal integrity/retention checks. Keep
returned stdout/stderr, guest terminal, capture status and native completion
independent. Review the owned-path public report shape before changing the
existing `CaptureReport.recorded` meaning or its callers.

EOF, parent/owner exit, timeout, protocol refusal or capture-close completion
retires the permit. Guest terminal starts the bounded frozen-prefix drain;
it does not authorize another call or require pretending that unsent copies
were already recorded. In-flight or unacknowledged copies remain unconfirmed
unless the owner has reported a disposition. Replacement, handoff and restart
cannot inherit this permit or reconnect it to another recorder.

## Executable evidence and remaining activation gates

`mvm-vmm`'s `host::uds_peer::process_tests` exercises real owned subprocesses.
A fresh connection identifies both actual processes; EOF and reaped child
status remain separate from retained socket identity. Fixtures hold the
child on an explicit release event until live identity queries complete;
a lookup after peer exit may refuse and cannot prove successful shutdown.
The inherited-pair test checks the platform distinction: Darwin reports the
child after its write; Linux retains the creator identity. The Darwin branch was exercised
locally; the Linux branch requires the Linux test lane. Neither identity
result grants capture authority. These are socket-identity prerequisite
tests, **not** capture authorization, signature, recorder or HVF-boot witnesses.

The FD export prerequisite test checks real socket aliases across exec:
ordinary children do not see close-on-exec aliases, but an explicitly
allowlisted child does, without changing flags in the parent. This
demonstrates why flags alone are not a capture-FD exclusion policy. It does
not exercise a capture worker, actual supervisor/signing re-exec, raw fork,
descriptor passing or retirement of runtime aliases.

### Test-only reference qualification

[`entrypoint_source::qualification`](../../crates/mvm-hostd/src/stream/owned_capture_qualification_tests.rs#L1)
is an executable reference model compiled only in tests. It exercises
serialized spend/retirement, competing completed-verifier callbacks, sequence
refusal, bounded frame/byte accounting, a frozen terminal cut, unsent versus
unconfirmed copies, and validation/loss of final replies.

Its binding values and connection IDs are **fixtures**, not the canonical
proof encoding, enrolled identities, verified peers, original child handles
or startup permits. It assumes the verifier's facts; it authenticates no
one. The queue and receiver driver are a small deterministic reference
model, not the production callback/IPC implementation. It does not qualify
clock deadlines, counter overflow, append-versus-retirement concurrency,
signature/session verification or the complete public divergence report.

Component cases pass queued synthetic bytes through the existing
`EntrypointSink`/`StreamBroker`: returned bytes remain unchanged, the actual
broker supplies record sequences, masked copies reach its real encrypted
transcript, and a deliberately lost reply stays unconfirmed even though the
broker appended. The fixture's known test key and self-consistent seal are
not an independently authenticated host audit anchor or public reader
witness. This is not the actual supervisor's `CaptureOwner`, an admitted
guest, a durable publication receipt or a second production recorder.

The socket alias lifetime test separately observes that dropping one local
handle does not produce peer EOF while an alias is retained, and that
explicit socket shutdown invalidates that local connection. It does not
establish that the actual runtime revokes its permit, finds every alias or
shuts down its own FD group correctly.

Passing these tests advances component/reference qualification only. The
real supervisor/HVF witness and all activation gates below remain required.

Before production wiring, obtain runtime/security approval of:

1. The exact permit establishment, signing encoding/purpose, actual peer and
   lifetime chain, including the explicit FD non-delegation boundary.
2. Every limit/enforcement point, fair scheduling, sequence retirement and
   receipt/loss accounting, including the public owned-call report.
3. Real transport tests for correct/wrong enrollment, tenant, configuration,
   native generation, call, challenge and peer; registration/recovery proof
   substitution; forwarding, replay, oversized/incomplete frames and teardown.
4. Competing handshakes, cancellation during verification, lost Ready, an
   empty call, duplicate Finish and lost Final: one atomic spend, no second
   Ready or append from a competing/replayed connection, and no refund.
   Normal fragments on the winning connection still append once each.
   Wrong proof consumes no output sequence.
5. Actual producer/owner FD inventories before/after signing helpers,
   re-exec, cancellation and teardown; exclusion of every alias from export
   and inheritance paths, original-process death/reparenting, attempted
   handoff/restart, and receiver refusal after retirement even with an FD
   deliberately kept open.

Then implement the approved connection into the existing owner, prove both
channels and protected redaction/readback, and run the clean-revision native
HVF smoke before any Studio pin change. Passing these prerequisite tests
does not satisfy that smoke or close #5265.
