# Owned HVF capture: concrete protocol proposal

Status: **Proposed for runtime/security review; not an enabled protocol.**
Scope: [#5265](https://github.com/tinylabscom/mvm/issues/5265), refining
[the capture requirements](hvf-entrypoint-capture.md). Issue comments own
approval and delivery status. The experimental library feature below implements
the possession primitive only. No receiver, startup field, wire negotiation or
public client report is activated.

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
None currently connects the capture proof proposed below to execution.

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

### Experimental startup envelope

**Experimental implementation requirements; startup integration not enabled.**
The serialized-once and host–helper compatibility requirements below are
mandatory before sending this format. The experimental possession library does
not implement the native startup or helper negotiation path. The
[held configuration type and bounded envelope codec](../../crates/mvm-core/src/protocol/hvf_startup/mod.rs#L1)
implement data handling only. The existing cold launcher now uses one held JSON
serialization for its saved config and legacy startup input; retaining that
object with the intended owned call remains integration work. The current
[`read_config_input`](../../crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs#L142)
accepts at most 8 MiB of raw UTF-8 configuration; the
[`startup_mode`](../../crates/mvm-hostd/src/bin/mvm-hvf-supervisor.rs#L228)
check requires kernel, image descriptors and registration together for checked
startup. Keep those rules and the legacy format intact.

The [configuration/envelope tests](../../crates/mvm-core/src/protocol/hvf_startup/tests.rs#L1)
count serializer invocations, check shared immutable byte storage, preserve
original whitespace/UTF-8, exercise exact limits and every truncation, and
reject malformed fields, digest mismatches and invalid inner JSON even when its
digest matches. A mock socket roundtrip exercises codec bytes, not authenticated
startup or native FD custody. The actual helper still accepts only its legacy
startup format and does not advertise envelope support. Its current version
must not be taken as experimental-startup compatibility. The mandatory version
bump and positive helper-support preflight remain required with that integration.

Recommend a versioned binary envelope on the **existing original startup
input**, not a new inherited descriptor, environment variable, state file,
registration field or producer handshake. Binary framing preserves the exact
held configuration bytes without JSON escaping or reparsing/reserializing them.
The alternative of adding a permit to `HvfSupervisorConfig` is not selected:
it changes a widely constructed startup type and makes excluding that field
from its own configuration hash an implicit serialization rule.

The proposed complete input, in order, is:

| Field | Exact encoding |
| --- | --- |
| Discriminator | Eight bytes `MVMOCAP\0` (`4d 56 4d 4f 43 41 50 00`). |
| Envelope version | One unsigned byte, value `1`. |
| Configuration length | Big-endian u32, 1..8388608 bytes. |
| Configuration | That many original UTF-8 `HvfSupervisorConfig` JSON bytes, unchanged. |
| Permit-record length | Big-endian u16, value `53` for this version. |
| Permit version | One unsigned byte, value `1`. |
| Intended call | Nonnil UUID, its 16 network-order bytes. |
| Configuration digest | SHA-256 of only the preceding configuration bytes, 32 bytes. |
| Original launcher PID | Big-endian u32, greater than one; a consistency check only. |

The fixed overhead is 68 bytes; the whole envelope is at most 8388676 bytes.
Use checked arithmetic. Reject declared lengths before allocating, short
records, invalid UTF-8/JSON, unknown versions, wrong fixed permit length and
trailing bytes before descriptor adoption, diagnostics publication, signing
helpers or native execution. Retain the 8 MiB inner-config limit and the
separate 4096-byte connected control-frame limit; neither is enlarged by this
outer envelope. Once the discriminator is recognized, no parse/admission
failure may retry the input as legacy JSON.

The fixed permit record intentionally does not duplicate enrollment, tenant,
plan or registration claims. Its configuration digest commits to their exact
startup encoding. The child must independently derive and retain those claims
from normal checked admission and the consumed caller launch, then combine
them with the intended call and its own native instance/capture run. Neither
matching a digest nor parsing this record establishes admission. The actual
original startup custody supplies the separate permit-installation authority.

Before native effects, the trusted owned invocation creates and retains the
call ID and capture preparation. **Serialize the final supervisor config
exactly once**, after all launch-time fields are fixed, into one held immutable
byte string. Use that same byte string for the envelope's startup-config
payload, the SHA-256 input and the retained invocation/call binding. Lengths
also come from that held byte string. Do not independently serialize a copy
for any of these purposes, even if it currently produces equal JSON or equal
bytes. The child hashes the exact inner bytes it received, never its parsed
config reserialization. A request DTO, generic plan, recovered handle or
name-resolved dispatch cannot construct the retained invocation capability.

Implementing this input format **requires a host–helper contract-version
bump in the same change as the encoder, decoder and launcher preflight**.
Advance the then-current
[`HOST_HELPER_CONTRACT_VERSION`](../../crates/mvm-vmm/src/host/helper_contract.rs#L25)
rather than treating the envelope's own version byte or the unchanged JSON
shape pin as sufficient. No bump or claim of envelope support is made by this
document or by the possession-only feature.

Before launching the workload supervisor or sending any envelope bytes, the
launcher must require the selected helper's exact bumped host–helper contract
version through the existing
[`resolve_verified`](../../crates/mvm-vmm/src/host/aux_bin.rs#L170)
boundary **and positively establish that this actual helper build supports
the experimental envelope version**. A version match alone cannot distinguish
feature-enabled and feature-disabled binaries from the same source tree.
Feature-disabled helpers must not advertise envelope support. Missing, stale,
malformed or unsupported responses refuse envelope startup before native
effects; an allowed source rebuild must pass these same checks afterward.
Never send the envelope to an old/feature-disabled helper to discover support
from its parse error. Receiver-side rejection remains defense in depth, not
the compatibility negotiation. Do not silently retry as a legacy launch.

Before any helper spawn, the child samples its actual parent and arms/rechecks
the parent's lifetime observer. The record's PID must equal that sampled live
parent; it must not choose which process to observe. Envelope parsing creates
only untrusted data. Installation additionally requires successful checked
startup and consumed caller admission, verified boot inputs, the actual native
instance and the existing protected owner. Legacy, partial checked, builder,
restore, replay/re-exec and handoff paths must not install this permit.
Replaying serialized bytes cannot restore a spent or retired permit.

Required compatibility/authority tests before activation:

- Old raw JSON follows its unchanged path and never installs capture. Launcher
  preflight refuses old, feature-disabled, wrong-version, unresponsive and
  malformed-response helpers before workload spawn or any envelope write.
  In particular, a feature-disabled helper with the correct bumped global
  version is still refused. A failed support check never retries as legacy;
  a rebuilt helper must pass preflight again.
- A serialization-counting regression observes exactly one final config
  serialization. Startup payload, digest input and retained call binding all
  originate from the same held bytes. A serializer producing different output
  on a second invocation must not be invoked twice. This checks construction
  provenance, not just equality of independently serialized values.
- A supporting experimental decoder preserves the exact inner bytes, including
  whitespace and multibyte UTF-8. Equal JSON values with different bytes produce
  different startup digests.
- Every prefix truncation, forged length, unknown version, trailing byte,
  nil call, invalid PID and configuration-digest mismatch refuses without
  adopting/closing supplied descriptors or launching a guest.
- A well-framed envelope containing an invalid/unadmitted registration,
  mismatched plan, incomplete boot inputs or unsupported startup mode never
  installs a permit or falls back.
- Actual original-parent exit/reparenting between sampling, observer arming,
  admission and installation refuses. A supplied PID, native-instance DTO or
  possession proof cannot substitute for that custody chain.
- The retained invocation consumes capture preparation only for its original
  dispatch. Fatal startup failures still refuse boot. If capture preparation or
  authentication fails after a valid launch and dispatch is allowed to proceed,
  that call is explicitly unrecorded; no retry reconstructs complete capture
  from serialized bytes.

These requirements limit implementation and qualification to the experimental
path. They are not production capture approval or evidence that startup,
authenticated ingest or HVF recording works. The one-call spend, no-refund,
FD-custody and real readback gates below remain unchanged. The original
guest-dispatch lifecycle and sole protected writer remain the owners of their
existing operations.

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
- the **complete canonical registration instance string**, a big-endian u16
  byte length followed by 1..512 UTF-8 bytes, including its VM prefix and `/`;
- registration run, producer, session and call UUIDs (16 bytes each);
- native boot nonce (32 bytes) and protected capture run as a big-endian u16
  byte length followed by 1..128 UTF-8 bytes;
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

Validate the instance with the existing
[`RegistrationBinding::instance_vm`](../../crates/mvm-core/src/crypto/entrypoint_delegation.rs#L81-L95)
rule and require its VM component to equal the separately bound native VM name.
Sign the entire original canonical `vm/uuid` string, not only its UUID suffix.
Uppercase, unhyphenated, braced or otherwise alternate UUID spellings and nil
instance UUIDs refuse; do not normalize them before signing or comparison.

All UUID fields use the 16 bytes returned by `Uuid::as_bytes`, in network byte
order, and must be nonnil. All integer fields above are unsigned big-endian.
Length prefixes count UTF-8 **bytes**, not characters; tenant/native VM labels
are nonempty and bounded by 512 bytes, with control characters refused.
The native VM must also pass the existing instance VM-name rule. The plan ID
must be `sha256:` followed by exactly 64 lowercase hex digits; only its decoded
digest is encoded. The nonce likewise decodes exactly 32 lowercase hex digits.
Capture-run text is nonempty, at most 128 bytes and control-free. PIDs must
exceed one. The connection challenge and native boot nonce must be nonzero.
Reject invalid/truncated UTF-8, oversized or inconsistent lengths, unknown
versions/tags and trailing bytes without accepting a partial proof.

Require `registration.not_before <= issued <= now < expires <=
registration.not_after` and `0 < expires - issued <= 30`, using checked
arithmetic. The registration validity interval comes from retained context,
not additional producer-selected wire fields. The separate monotonic deadline
still bounds the exchange. The signed message is exactly the NUL-terminated
domain plus these fields; it excludes the outer frame length/tag and the
signature itself. A Proof frame carries the fields followed by exactly 64
signature bytes. Its declared length counts tag plus body, not its four-byte
length prefix. Even at the field ceilings it is at most **2022 encoded bytes**,
including framing, within the unchanged 4096-byte ceiling.

### Deterministic encoding vectors

The [complete golden messages and signatures](../../crates/mvm-core/src/crypto/owned_capture/proof_vectors.json)
are test data, not runtime credentials or receiver receipts. Concatenate each
`message_hex` array in order; it includes the NUL-terminated domain and all
signed fields, not outer framing. The experimental
[library codec tests](../../crates/mvm-core/src/crypto/owned_capture/tests.rs#L1)
use the public RFC 8032 test-vector key and the actual `RegistrationBinding`
type/instance validator. An independent Python Ed25519 encoder generated the
fixed expected bytes/signatures; the Rust tests must reproduce them exactly,
not regenerate expected values from the encoder being tested.

Common fixture inputs:

- installation UUID `00112233-4455-6677-8899-aabbccddeeff`;
  public key `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`;
- native VM `vm-a`; complete instance
  `vm-a/11223344-5566-7788-99aa-bbccddeeff00`;
- plan digest 32 bytes `0x22`, plan nonce 16 bytes `0x33`,
  startup digest 32 bytes `0x44`, native boot nonce 32 bytes `0x55`;
- run/producer/session UUIDs `Uuid::from_u128(2)`, `Uuid::from_u128(3)` and
  `Uuid::from_u128(4)`, respectively; capture run text `4242`,
  producer/supervisor PIDs `1234/5678`;
- issuance/expiry `110/120`; retained registration validity `100/200`;
  verification time `111`.

| Vector | Tenant | Call UUID | Challenge | Signed message bytes | SHA-256 of signed message |
| --- | --- | --- | --- | --- | --- |
| ASCII | `tenant-a` | `Uuid::from_u128(5)` | 32 bytes `0x66` | 382 | `e927e890e94ac9ecac6c1ea53955b339c6515d3db5f509179f29cf51ea6c8d8b` |
| UTF-8 byte length | `tenant-é` | `Uuid::from_u128(6)` | 32 bytes `0x77` | 383 | `bb349c869d2500d1bc44ce6e26036b3514f9d20cbf524971939f846f3bca3784` |

Negative cases reject alternate instance spelling, nil instance UUID, VM
mismatch, zero/oversized/inconsistent/truncated lengths, malformed UTF-8,
unknown tag/version, trailing bytes, changed binding/challenge and another
signing domain. Invalid canonical instances are rejected even with a valid
fixture-key signature over their unnormalized bytes. These are deterministic
encoding/validation and signature-math checks only: they do not authorize
installation or authenticate a real socket/peer.

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
guest-callback thread. A lost final reply leaves **final close unconfirmed**;
it does not erase validated per-frame dispositions.

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

### Original-payload units and conservation

An offered fragment is one nonempty stdout/stderr fragment after splitting at
16 KiB, not one guest write/event. Every byte counter counts its original
payload **before redaction**, excluding framing and receipt bytes. A masked
copy or withheld marker may have a different stored length. Count a withheld
fragment's original bytes as owner acceptance with a withheld disposition,
not as an additional drop or as the marker's length.

Freeze the set of offered fragments and its totals at terminal. Within the
single 250 ms ceiling, settle each fragment in that frozen set **exactly once**:

- `L`: provably unsent local drop, including queued fragments abandoned at the
  deadline;
- `D`: owner drop with a validated Dropped receipt;
- `A`: owner acceptance with a validated Accepted disposition;
- `U`: possibly sent without a validated disposition, therefore unconfirmed.

For both fragment counts and original-payload byte totals, require:

```text
offered = L + D + A + U
A = identical + masked + withheld
```

The accepted subcategories are mutually exclusive and exhaustive; they are
not extra fragments/bytes to add to the first equation. During draining,
queued/provably-unsent and in-flight slots are transitional bookkeeping,
not permission to declare the four-way settlement complete. On cancellation
or deadline, classify those slots as `L` or `U` respectively. Use checked
addition, subtraction and counter advancement. Overflow, inconsistency or
an unsettled slot refuses a confirming summary; never wrap or silently cap
counts into a success result.

Send Finish only after all queued fragments have validated dispositions.
For a normal confirming Final, require all of the following:

1. Finish was sent for this retained call/connection and its frozen cut;
   compare Final's challenge against that exact connection's retained nonce.
   The nonce maps to the independently retained run/call, not to a new
   caller-supplied binding. An unsolicited, duplicate, late or conflicting
   Final cannot confirm completion.
2. Final's last processed sequence equals Finish's last queued sequence and
   the checked sum of accepted plus owner-dropped **fragment** counts.
   `U` is zero and no queued/in-flight slot remains.
3. Final's accepted/dropped fragment and original-byte totals exactly match
   the locally accumulated, validated per-frame dispositions.
4. Final's masked/withheld fragment counts exactly match those dispositions.
   Infer identical fragments by checked subtraction from accepted fragments;
   their subcategory sum must equal accepted fragments. Retain the original
   byte subcategories locally from the per-frame dispositions; Final does not
   add new masked/withheld byte fields or attest to the client's local drops.
5. The settled four-way partition and accepted-subcategory equation hold for
   both fragments and original bytes. Client-offered and local-drop totals
   remain client observations, not independently attested owner facts.

If Final is lost after every frame disposition was validated, retain `A`,
`D` and accepted subcategories as known. Set final-close confirmation to
unconfirmed; **do not add their payload again to `U`**. A possibly sent
fragment lacking its own validated disposition remains in `U`, even if the
owner may have appended it. A later readback is separate evidence, not an
invented lost receipt. A valid Final may confirm close with known drops;
that still does not mean all output was accepted, retained or durable.

The 250 ms budget is a ceiling, not a promise to drain 64 queued fragments or
finish an exchange allowed up to two seconds. Exhaustion keeps conservative
loss/final-close status. Recorder pressure never cancels guest execution.

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

### Experimental library boundary

The off-by-default `experimental-owned-capture` feature exposes
[`mvm-core::crypto::owned_capture`](../../crates/mvm-core/src/crypto/owned_capture/mod.rs#L1)
and the closed
[`CallerCredential::prove_capture`](../../crates/mvm-hostd/src/caller_identity/mod.rs#L53)
operation. It adds no dependencies, native key store, generic signing API,
listener or execution path. Load the credential through the existing identity
worker; this operation uses that already loaded credential without another
keychain request. It refuses a challenge for a different process PID or full
enrollment. A PID check alone does not qualify fork safety or native custody.

Bindings are immutable validated data, not permits. Challenge decoding requires
independently retained launch/native/peer context; registration validity comes
only from that context. Proof decoding requires the receiver's exact retained
challenge, followed by strict Ed25519 verification under the separate purpose.
Whole-frame length is bounded before field parsing; this slice accepts an
already supplied byte slice, not a socket length prefix or allocation request.
The future receiver must enforce bounds before reading/allocating the frame.
Wall-clock validation is not the required monotonic transport deadline.

The original independently generated golden corpus now checks the actual
library codec rather than a second test-only implementation. Tests cover both
Challenge and Proof roundtrips, exact bytes/signatures, canonical instances,
binding/purpose substitution, malformed input, freshness, and mock socket I/O.
The credential test uses the real identity worker with its private in-memory
test store, not the macOS keychain. Re-verifying a proof does not consume it;
only the future receiver's atomic one-call spend may authorize writes.

Run the library and credential checks explicitly:

```sh
cargo test -p mvm-core --features experimental-owned-capture --lib crypto::owned_capture::tests
cargo test -p mvm-hostd --features experimental-owned-capture --lib caller_identity::tests
```

This is experimental implementation, not production approval or evidence of
authenticated transport, admission, concurrent spend/retirement, inherited-FD
custody, recorder finalization or live HVF/readback. No code in this slice sets
`capture.recorded = true`, changes Studio's pin or closes #5265.

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

The receiver model's binding values and connection IDs are **fixtures**, not
enrolled identities, verified peers, original child handles or startup
permits. It assumes the verifier's facts; it authenticates no one. The separate
experimental library tests above exercise the actual possession primitive,
not its use by a real receiver or authenticated session.
The [reconciliation cases](../../crates/mvm-hostd/src/stream/owned_capture_reconciliation_tests.rs#L1)
check original fragment/byte conservation, checked overflow refusal, accepted
subcategories, nonce/call/sequence/count conflicts, in-flight loss and lost
Final without double-counting known dispositions. They include actual broker
withholding where the marker's stored length differs from the input count.
The queue/receiver driver is still a deterministic reference model, not the
production callback/IPC implementation. These tests do not qualify runtime
clock deadlines/overflow paths, actual permit establishment, signature/session
peer authentication, append-versus-retirement concurrency, native FD custody
or the complete public divergence report.

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
