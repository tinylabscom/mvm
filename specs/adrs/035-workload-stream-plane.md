# ADR-035: The workload stream plane

## Status

Accepted for the output half. Implemented by plan 295 phase 1: the guest pump
(`mvm-agentd`), the stream store (`mvm-core::transcript`), the host broker
(`mvm-hostd::stream`), and the consumers (`mvmctl machine logs`, `machine run`
attach, `mvm-client`/SDK readers).

Accepted for the input half, with its cost recorded in §"Claim 15 becomes a
policy, and what that bought". Implemented by plan 295 phase 2: the input frame
DTOs and the plan grant (`mvm-protocol::stream::input`), the gate
(`mvm-hostd::stream::input_gate`), the route to the guest sink, agent-side
delivery with explicit EOF (`mvm-agentd::stream_input`), and the sealed-tier
refusal of the grant for a shell-shaped entrypoint.

The input half is **reachable**: `mvmctl machine run --entrypoint --stdin -`
opens the route through `StreamPlane::open_input` under the plan that boot was
admitted under, pumps the caller's stdin through the gate in acceptance order,
and closes the workload's stdin on the caller's EOF. Only the invocation that
admits and boots a workload can stream into it — `--attach` and `session
attach` hold no admitted plan and refuse. The gate's secret scan is populated
too: the per-VM substitution endpoint fingerprints each secret it resolves and
`StreamPlane::open_input` installs that set — see §"What binding a fingerprint
discloses". ADR-001's claim 17 stays at status `Preview`, now not because a leg
is dormant but because of what the enforcement is: a fingerprint match is a
length-and-hash match, and encoding, derivation and a window-straddling split
defeat the scan permanently.

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
meaning "fan out live, keep no chained, verifiable transcript". An ephemeral
run gets an identical broker, an identical socket, identical redaction and
chaining and fan-out; it just never creates a capture directory. Sealing an
ephemeral capture yields no manifest rather than an empty one, because a
manifest with zero chunks asserts that the workload printed nothing, which is
a different and false claim.

`Ephemeral` does not mean no bytes reach disk. The backend still writes its
own `console.log` into the VM state dir — outside this plane and untouched by
the retention mode, though no longer unredacted: the reader masks each chunk
before a consumer sees it — and `mvmctl machine logs` still falls back to
reading it once the broker is gone. An operator choosing `Ephemeral` to
keep sensitive output off disk needs to know that choice does not do that;
it only forgoes the audited, hash-chained copy.

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

### Claim 15 becomes a policy, and what that bought

The input half costs a claim its shape, so the trade is recorded here rather
than left to be discovered in the ledger.

**Before.** Claim 15 held by *absence*. A sealed production microVM had no
host→guest byte path at all: no shell, no `do_exec`, no PTY, and nothing else
that carried a byte inward. "Nobody can drive it" needed no policy, no gate and
no code to be true, which is the strongest form a claim can take — there was
nothing to get wrong.

**After.** There is a path. Refusing to use it is a decision host code makes,
against a signed document, at run time. That is strictly weaker: a policy can
have a bug, a policy can be misconfigured, and a policy is only as good as the
code that evaluates it. Nothing about the new claim is as strong as the old one,
and the ledger says so in those words rather than in softer ones.

**What survives, and it is not nothing.** The channel writes into a pipe, not
into a launcher. It cannot select a program, alter argv or the environment, or
spawn anything, because the entrypoint is fixed at admission and the bytes reach
a descriptor of a process that is already running. So the *interactive-access*
half of claim 15 — the half the claim is named for — is unchanged by
construction, not by policy. What became policy is narrower: whether a granted
workload receives stdin at all.

**Why that was worth it.** The alternative to a plan-bound channel is not "no
input". It is input arriving some other way, unaudited. Every workload shape
this repository is built for — a function invoked with an argument, a filter fed
a document, a REPL-less program that reads a request off stdin and writes a
response — needs bytes to travel inward. Absence was buying its strength by
declaring those workloads out of scope, and they are not out of scope; they are
the product. Refusing to build the channel would have pushed the same bytes into
a share, a volume, a config drive or a network hop, each of which is a path with
*less* structure than this one: no grant in the signed plan, no single-writer
arbitration, no per-decision audit entry, and no fixed entrypoint standing
between the bytes and a launcher.

So the trade is a strong claim over a narrow surface exchanged for a weaker
claim over the surface the product actually has. The mitigation is that every
weakening is written down: the grant is in the signed plan, both outcomes are in
the chain, and ADR-001 carries the claim at `Preview` with five limits rather
than promoting it on the strength of the tests alone.

### What binding a fingerprint discloses

The gate refuses stdin that carries one of the host's own secrets, and
recognising a byte sequence means having it. But the gate runs in the CLI
process while the substitution endpoint that resolves raw credentials runs as a
separate process, and that separation is load-bearing — it is what claims 12 and
13 rest on. Copying plaintext into the CLI to populate a scan would create a new
plaintext location in a process that has none, in order to close a gap on a
different claim. That trade is not worth making.

So the endpoint computes a **fingerprint** — a length, a 64-bit rolling hash and
a category — for each secret it resolves, and reports the fingerprints on its
ready handshake. Only the fingerprints cross. The rolling hash is what makes the
scan affordable: it slides over the stream at one multiply-add per byte and
tests every offset, which is how a secret split across two writes is still found.

**What it discloses, stated rather than buried.** Whoever holds a fingerprint
learns the secret's **length** and holds a 64-bit hash of it. For a high-entropy
credential that is not a recovery path; for a short low-entropy one, a hash and a
length are guessable offline. The set lives in the memory of the process that
booted the VM, is never written to disk, and is dropped when the endpoint is
reaped. Two disclosures that would be worse were rejected outright: persisting
the set to the per-VM state dir (which would widen it to every reader of
`~/.mvm` to buy reachability nothing uses — only the booting invocation can
stream), and binding fingerprints of each secret's *prefixes*.

**What the memory-only choice rests on, and what breaking it looks like.** It
rests on limit 3: only the invocation that admitted and booted a workload may
stream into it, so the process that spawned the endpoint is the process that
later opens the gate. Should that stop being true — the resident per-tenant
daemon this project is heading toward would do it, with boot in one process and
`stream` in another — the registry read returns an empty set, the gate binds an
empty set, and the scan silently reverts to matching nothing. That is limit 1
re-opening, and **nothing goes red when it does**: an empty read is
indistinguishable from a plan that carried no secrets, and both are legitimate.
The failure is therefore invisible by construction, not merely untested, and
splitting boot from stream must come with a registry that spans the split or
with a gate that refuses when it cannot tell the two cases apart.

**Why the carry is blanket, and why that is the safe choice.** Without prefix
fingerprints the scanner cannot ask "could this tail still become a secret", so
it withholds a fixed `longest_secret - 1` bytes of every write rather than the
exact live prefix. That reads as the lazy option and is the load-bearing one.

Precision here would be a **prefix oracle**. The withhold-or-deliver decision is
observable — anyone holding the input grant writes a byte and sees whether
anything came out — so a scanner that withheld only what could still complete a
secret would be answering, for each byte offered, "is this a live prefix?". Walk
that: 256 tries recover byte 0, 256 more recover byte 1, and a 40-byte
credential falls in about 40·256 probes instead of 256^40. That is a
secret-extraction path against precisely what row 13 protects, and it is
strictly worse than any amount of withholding. A blanket carry leaks nothing
*because* it is blanket: the decision carries no information about the content.
The imprecision is the mechanism, not a shortcut.

Binding prefix fingerprints — the tempting repair, and what the plaintext
scanner effectively had — is the same mistake with an extra disclosure on top.
Under this polynomial hash the prefix chain *is* the plaintext: `h(k) =
h(k-1)·BASE + s[k-1] (mod 2^64)`, so `s[k-1] = h(k) − h(k-1)·BASE` recovers each
byte by subtraction, and `h(1)` is literally the first byte. Changing the hash
does not save it: any function a scanner can evaluate, code in that same process
can evaluate, so an *exact* prefix-membership test over a byte alphabet is a
decoder in 256·L tries whatever the hash. Precision about short tails and
non-disclosure of short prefixes are the same quantity; you cannot buy one
without selling the other.

**What the blanket carry cost, and how that cost is paid.** Left alone it is a
deadlock rather than latency. With a 40-byte bound secret the carry is 39, so an
operator running a line-oriented workload under `machine run --entrypoint
--stdin -` and typing an 11-byte request line delivers **zero** bytes: the
workload never sees a line, never answers, so the operator never writes again,
and the tail ships only at EOF. "A program that reads a request off stdin and
writes a response" is a shape this plane exists for, so that was not a tolerable
resting place.

The gate therefore **releases the withheld tail after 50ms of writer silence**
(`DEFAULT_IDLE_FLUSH_AFTER`). Two properties make this the right shape rather
than a quiet weakening of the paragraph above, and both have witnesses:

- **The release is content-independent.** It fires on elapsed time since the
  scanner last took bytes and on nothing else — never on what the withheld bytes
  are. So it opens no oracle: an observer learns when they stopped writing,
  which they already knew. Witnessed by
  `fn:the_idle_release_does_not_depend_on_what_the_withheld_bytes_are` and
  `fn:what_is_withheld_is_a_length_and_never_a_verdict_about_the_bytes`, which
  drive a genuine live prefix of a bound secret and an innocent payload of the
  same length through the whole path and require the two to be
  indistinguishable.
- **The release can never hand over a secret.** What the scanner holds already
  survived a scan of the buffer it came from, so no window inside it matches.
  What is lost is *context*: a secret split across the silence is no longer
  contiguous and is missed. That needs the sender to pause mid-credential — a
  confused caller does not, and a determined one has no reason to, since base64
  defeats the scan outright. It therefore falls inside the existing "backstop,
  not a defence" limit and does not widen it. Witnessed from both sides by
  `fn:a_secret_split_across_two_writes_inside_the_threshold_is_still_refused`
  and `fn:a_secret_split_across_the_idle_gap_is_missed_and_that_is_the_price`.

50ms sits between two gaps that differ by orders of magnitude: the gap inside
one writer's burst (a buffer copy and one vsock round trip — microseconds to low
milliseconds, and the split a confused caller actually produces, which must stay
covered) and the gap a human or a request/response peer leaves, which is at
minimum the workload's own think time. It is roughly fifty times the first and
half the ~100ms at which delay becomes perceptible. The CLI's idle attendant
visits every half-threshold, so a released line reaches the guest within about
one and a half thresholds of the last keystroke.

Exact live-prefix precision *within* a burst is still available without the
oracle — anchoring the carry to a delimiter no bound secret contains, or moving
the scan into the process that holds the plaintext. Both are costed in
`specs/plans/293-stream-plane-followups.md`; neither is needed for the shapes
the plane serves today.

**And a match is not an identity.** Two byte sequences of the same length can
hash alike. The gate refuses on a match anyway, because failing closed is the
right direction, but its refusal says a fingerprint matched rather than that the
bytes are the secret. An operator told the stronger thing when it was not true
would spend hours proving a negative.

**What is explicitly not claimed.** The sealed-tier refusal of the grant for a
shell-shaped entrypoint is a *heuristic* and is documented as one. A wrapper
that `exec`s a shell, a program that spawns one, or an interpreter under an
unfamiliar name all pass it, and moving input onto a side descriptor would not
help because a shell can read fd 4 and pipe it into itself. No argv test
separates "reads stdin" from "will interpret stdin as commands"; that is a
property of the program. The refusal raises the cost of laundering interactive
access through a plan that looks ordinary. The control is the grant.

## What this does not do

Three limits. Each was found while building this, each is true of the shipped
code, and each would be dishonest to leave out.

### 1. The single-seam claim is conditional

The transcript is redacted. The console fallback is **not** — reading
`console.log` reads the raw bytes the guest wrote, because that file is the
VMM's, written before anything in this plane sees it. When a recording exists
but does not cover the whole run, `mvmctl logs` now shows the recording and
then splices the console behind it, so both appear in one read.

**Closed.** The console reader now applies the same detector before handing
bytes to a consumer, read-side, so the file the VMM owns is unchanged. What
survives is narrower and worth stating exactly: redaction is applied per 64 KiB
read, so a value straddling a read boundary is two partial matches and neither
fires. Carrying a tail across reads would close that and withhold the newest
bytes from a follower until more arrived — a worse defect on the path
operators reach for when nothing else works.

So the honest statement is now *every consumer sees masked output, with a
documented gap at read boundaries on the console path* — stronger than the
previous *the broker has one seam and every consumer of the broker sees masked
output*, and still not *no unmasked byte can ever reach a consumer*.

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
receives. Claim 4: no exec path is added — the input half writes to a fixed
entrypoint's stdin and cannot start a process. Claim 10: no NIC or second
network protocol exists on this path; `check-single-network-path` and
`check-one-guest-protocol` stay green.

**Weakened, deliberately.** Claim 15. The console capture is still opened
read-only and the trait still cannot hand out a writable handle, so
`following_the_console_never_writes_to_it` continues to hold; the *output* half
adds a reader and never an input fd. The *input* half adds a host→guest byte
path that did not exist, which moves the claim from enforced-by-absence to
enforced-by-policy. §"Claim 15 becomes a policy, and what that bought" records
the trade; ADR-001 carries the reworded row and the new claim 17 at `Preview`.

**Extended.** Claim 8's admitted plan gains two more decisions it binds — the
retention mode and the input grant — and matching labels in the chain.

**Unweakened, and worth saying why.** Claims 12 and 13 keep raw secrets inside
the substitution endpoint's address space. Populating the input gate's scan does
not move any of that: what leaves the endpoint is a length and a hash, the CLI
gains no API that could hold a value, and the endpoint's own store reads are
unchanged. §"What binding a fingerprint discloses" states what the length and
the hash are worth to a reader of them.

**Not strengthened, despite appearances.** The reader-side anchoring rule
defeats a *buggy* broker, not a hostile one: nothing cross-checks a claimed
loss point against the delivered records, so a broker sending monotonically
increasing loss markers keeps re-anchor control. That is fine and in scope —
ADR-001 puts a malicious host outside the threat model — but it should not be
read as a defence it is not.

## Stream edges: what they guarantee, and what they do not

An edge connects one workload's output to another's stdin. It is a different
authorization shape from the per-plan input grant, so it is deliberately **not
claim 17 with more rows**, and it carries no numbered claim of its own.

### Holds by construction, and is tested

- **A guest never addresses another guest.** The consumer's plan names a
  binding; the host resolves it. Neither workload learns the other's identity,
  and neither can enumerate the fleet by guessing names — an ungranted binding
  and a nonexistent one give the same refusal.
- **No new path out of a guest.** Bytes cross inside the host between two
  independent vsock channels. No workload path gains a NIC, a tap or a gateway,
  and both `xtask` vsock gates cover the code that would.
- **Refused before boot:** a duplicate binding, fan-in, a cycle of any length,
  and an edge on a workload that also takes operator stdin.
- **A raw edge is refused, not downgraded.** Redaction runs before hashing, so
  no unmasked copy survives to a reader. Serving masked bytes under a fidelity
  label would leave a consumer computing on the mask while believing it had the
  value.
- **Defaults are safe and cannot be lost by omission.** Both postures are
  serde-defaulted, so a plan written before the field existed deserializes to
  redacted and lossy.
- **The producer cannot be stalled by a consumer.** Inherited from the reader's
  bounded queue rather than re-implemented, and re-verified at the edge.

### Not claimed

- **That any of it fires in production.** None of these refusals has a caller
  in this repository, and will not: `mvmd` declares the edges. They are
  declared dormant in `xtask/dormant-controls.toml`, and the gate fails if that
  stops being true in either direction. A refusal with no caller is a refusal
  that has never refused anything.
- **Anything about what a consumer does with the bytes.** An edge delivers to
  stdin. Downstream handling is the consumer workload's business and is covered
  by whatever claims apply to that workload.
- **Exactly-once delivery.** `lossy` marks gaps, `reliable` fails the edge;
  neither replays.

### Claim 17 stays at `Preview`

An edge would be the input plane's second production caller, and the question
of whether that is enough to promote claim 17 is deferred until one exists.
Promoting on the strength of a caller nobody has written is exactly the drift
the ledger gates exist to catch — the claim would be true of code, and false of
the system.

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

- `specs/plans/295-workload-stream-plane.md` — the design and its
  implementation sequence.
- ADR-001 — threat model, per-backend tier matrix, and the claims ledger table
  this ADR's security section refers to.
- ADR-014 — signed, audited execution plans (claim 8), which
  `stream_retention` extends.
- ADR-023 — the redaction and substitution posture the stream seam mirrors.
