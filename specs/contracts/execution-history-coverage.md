# Execution history: coverage, append-only evidence, and replay

Backing: preview
Validation: none — this is a design contract; the acceptance witnesses below have not been run.

Status: Proposed implementation contract. The design direction is approved for
planning; this document does not promote a security claim or change runtime
behavior. It refines [ADR-062](../adrs/062-workload-actor-lifecycle-and-causal-evidence.md),
tracked by #5544, alongside [ADR-035](../adrs/035-workload-stream-plane.md),
[ADR-057](../adrs/057-mailbox-semantics-and-threat-model.md), and
[ADR-110](../adrs/110-execution-receipt-evidence-archive.md).
[ADR-001](../adrs/001-microvm-security-posture.md) remains the shipped claims
authority. Strict output capture requires an explicit amendment to ADR-035 and
the nonblocking rule in [diagnostic-data-policy](diagnostic-data-policy.md)
before implementation.

## Promise and boundary

Users can inspect and play back recorded execution history within its declared
coverage and retention window. They can verify its integrity, provenance,
append-only extension, and the stated basis of completeness. This does not mean
every instruction, memory mutation, syscall, file write, or application action
inside a VM was observed. Stdout/stderr are output channels, not all L7 activity;
OSI layer numbers and OCI image layers are not coverage specifications.

The adversary is an untrusted workload on a trusted host. Guest-originated
claims may be false. Host signatures authenticate the recording authority, not
the truth of guest statements. A compromised host holding signing keys can
fabricate new records; external witnesses constrain retrospective rewriting,
not the truth or completeness of unobserved activity.

## One history, separate responsibilities

Capture output, persist bounded encrypted chunks, commit their identities into
the evidence journal, and optionally deliver authorized mailbox notifications.

- The evidence journal owns host-observed decisions and output commitments.
- Existing protected transcript facilities own sensitive output bytes.
- Mailboxes carry application messages and optional evidence notifications,
  not the sole copy of evidence or the bulk log stream.
- `tracing` and OpenTelemetry are presentation/export adapters. Subscriber
  filters, sampling, or exporter failure cannot affect required evidence.
- Readback and verification use `mvm-client`; frontends do not create their own
  recorder or bypass custody by reading stores directly.

Output flooding must not consume the reserved evidence capacity needed to
refuse effects or record degradation. Notification delivery is independently
bounded and authorized; notification failure cannot invalidate an already
committed record. A digest or retrieval locator grants no read authority.

## Coverage contract

Every admitted run binds a versioned coverage manifest to its signed plan,
backend, workload identity, execution epoch, and measured recipe. It declares
each source as required, optional, unsupported, or intentionally disabled.
An unavailable required source refuses admission. Provisioned, active,
degraded, and stopped are distinct states; an empty timeline is not proof that
nothing happened.

| Event family | Authoritative observation boundary | Required history and limits |
| --- | --- | --- |
| Admission and policy | Host admission/enforcement owner | Plan identity, effective policy identity, allow/refuse reason, backend capabilities; no effect precedes its required committed authorization. |
| Mailbox | Canonical mailbox owner and authorized endpoints | Separate send intent, durable acceptance, delivery, application acknowledgement/reply, expiry and failure. Bind message and causation identities. Acceptance never proves execution. Routing authority does not acquire plaintext authority. |
| Host services | Binding gate and handler boundary | Request identity, authorization decision, dispatch intent and observed outcome. An interrupted call has unknown outcome until reconciled, not fabricated success or failure. |
| Network | Canonical host egress enforcement path | Connect/datagram/DNS decisions and observed flow outcomes with scoped identities. Payload capture is a separately authorized source; encrypted traffic is not automatically application plaintext. |
| Lifecycle | Host lifecycle owner | Admission, launch, readiness, exit, kill, restart, quarantine, and supported park/restore transitions. Report observation versus requested action, and crashes without a final record as incomplete. |
| Workload stdout/stderr | Supervised descriptor capture | Separate byte channels, source sequence and offsets, committed chunk identities. Coverage starts when bytes reach owned pipes; userspace-buffered bytes and output redirected elsewhere are outside this source. |
| Console and supervisor diagnostics | Backend-owned capture | Declare each producer separately, including boot coverage and shutdown drain. Console cannot reconstruct stdout/stderr separation. Missing backend capture is not an empty stream. |
| Structured application telemetry | Authenticated guest telemetry ingress | Guest-asserted events and spans, host-assigned origin and receive sequence, explicit loss. A statement's integrity does not certify its truth. |
| Files, memory and internal execution | No general observer in this contract | Not captured by default. State reconstruction requires separately admitted snapshots, journals or instrumentation with their own coverage and witnesses. |

The manifest records finite quotas, retention, redaction version, capture
start/end boundaries and durability class. Capture from before guest launch
is required for sources advertised as covering boot. Guest identity fields
cannot override host-bound origin. Cross-source wall clocks are presentation
data, not proof of a global execution order.

## Evidence and output loss policies

### Required security evidence

Persist authorization/dispatch intent before permitting a mediated effect.
Persist the observed outcome before returning a successful result. If the
journal cannot commit, refuse new effects requiring it and enter the declared
degraded/containment state. An already dispatched external effect cannot be
undone by withholding its response.

Intent and outcome have one operation identity. Recovery reconciles unresolved
intents where possible and otherwise labels them unknown. This is not a
distributed transaction or an exactly-once guarantee. Emergency containment
must remain possible even if storage is unavailable; inability to record it
must leave an incomplete history, not prevent the safety action.

### Ordinary diagnostics

Preserve bounded, nonblocking capture with explicit eviction and drop records.
Report known counts/ranges; use unknown where the producer failed before a
count could be observed. Retention expiry and collection loss are different
events. A valid retained window is not a complete-run recording.

### Optional strict output

A signed strict policy requires durable capture at the declared boundary,
bounded backpressure, finite resource reservations, and a finite failure
deadline followed by stop/refusal rather than silent shedding. Admission
refuses unsupported backends or insufficient resources. It cannot promise
uninterrupted execution under indefinite storage failure.

Specify the durability acknowledgement precisely: a successful application
write to a pipe is not a durable-storage acknowledgement. If callers need a
durable application-level acknowledgement, they must use an explicit protocol
for it. Uncommitted pipe bytes at host failure remain an uncertain suffix.

## Cryptographically verifiable append-only history

Use the existing RFC 6962 Merkle machinery and signed evidence formats, with
versioned extensions rather than a new cryptographic format.

1. Canonically encode and domain-separate each evidence leaf. Bind journal
   identity, sequence, epoch, operation identity and typed observation. Output
   leaves commit to protected chunk identities, ciphertext digests, channel,
   sequence/byte ranges and redaction policy. Do not expose plaintext digests
   of low-entropy secrets.
2. Persist chunks before committing references that claim they are durable.
   Crash recovery distinguishes orphan chunks from missing committed chunks;
   neither may be presented as a complete recording.
3. Sign periodic checkpoints containing the journal identity, tree size, root,
   schema, signer/key identity and predecessor checkpoint identity. A signature
   time is not trusted wall time merely because it is signed.
4. Supply inclusion proofs for records and Merkle consistency proofs between
   checkpoints. Inclusion proves membership; consistency proves that the newer
   tree extends the older tree without rewriting its prefix. A chain of signed
   roots alone does not establish this extension.
5. Readers retain previously verified checkpoints. A configured independent
   witness retains and verifies checkpoint extension and issues authenticated
   receipts. Comparing checkpoints across readers/witnesses detects incompatible
   histories; isolated readers cannot detect every split view.
6. Define the anchoring interval and maximum unwitnessed suffix in signed
   policy. If witnessed durability is required, acknowledgement waits for the
   required witness; failure invokes that policy's refusal/containment rule.
   Local operation without a witness remains supported and explicitly weaker.
7. Authorize signer rotation through the existing trust authority and link old
   and new checkpoint histories. A bundled public key alone does not establish
   a trusted recording authority.

Append-only means verifiable extension, not that a disk cannot be erased.
Witnesses detect rollback relative to retained checkpoints; they do not recover
deleted payloads. Backup/replication and key custody are separate availability
requirements. Audit metadata, checkpoints and retirement evidence survive
payload expiry under their own declared retention policy. Pruning never
silently relabels the remaining suffix as the whole journal.

Verification reports separate results for signature/integrity, inclusion,
append-only consistency, witness freshness, payload availability and coverage.
Preserve ADR-110's distinction between host-attested and verifier-derived
completeness. Complete coverage of a committed tree is not proof that all
real-world events entered it. A missing final seal is incomplete/unknown even
when every available signature verifies.

The supported wording, after witnesses pass, is "cryptographically verifiable,
signed, append-only execution history for the declared capture boundaries."
"Certified" must name the certifying authority and property; a Merkle root
alone is neither certification nor a proof of complete VM behavior.

## Rewind and replay

| Capability | Meaning | Prerequisites and limit |
| --- | --- | --- |
| Timeline playback | Scrub through recorded output, decisions, spans and causal message edges without running the workload | Verified evidence plus retained, decryptable payloads; render redaction, loss, expiry and unknown outcomes explicitly. This is the first delivery target. |
| Historical state inspection | Inspect supported state at recorded points | Explicit snapshots or application state journals, immutable inputs and authorized keys. Logs alone cannot reconstruct arbitrary memory or files. |
| Deterministic execution replay | Re-execute to the same internal state and behavior | A separate backend-specific design capturing nondeterministic inputs, clocks, entropy, scheduling, interrupts and device results as needed. Neither this contract nor VM snapshots alone supplies it. |

Timeline playback is read-only: it never resends mail, calls external services,
or repeats network effects. Message identifiers and committed causal links
establish known partial order, not a universal wall-clock order or proof of
unobserved internal causation.

Restoring a snapshot and running again is a new admitted epoch with side effects
disabled unless separately authorized. It is a fork, not a rewrite of recorded
history, and must not replay acknowledgements as new authority. Any future
deterministic replay mode substitutes recorded external responses rather than
repeating real-world effects.

## Acceptance witnesses required before claiming implementation

- Backend-specific coverage tests exercise each required producer and refusal
  when its capture is unavailable; include detached lifetime, boot and teardown.
- Fault injection covers journal/chunk persistence ordering, disk full,
  collector failure, process/VM/host crash, unresolved external effects and
  recovery. Unknown suffixes never receive complete labels.
- Output tests include binary and partial writes, inherited descriptors,
  stdout/stderr distinction, redaction, pipe buffering and blocked descendants.
- Saturation tests prove diagnostic shedding does not starve evidence or
  mailbox work; strict mode proves bounded backpressure and terminal behavior.
- Verification rejects mutation, reordered leaves, missing committed chunks,
  incorrect inclusion/consistency proofs, rollback against a saved checkpoint,
  incompatible witnessed roots and unauthorized key rotation.
- Export accounts for every in-scope leaf, preserves the attested/derived
  distinction, and reports missing, expired, redacted or undecryptable payloads.
- Timeline playback produces no external effects and keeps epoch, causal,
  coverage and retention boundaries visible.
- Live backend runs measure storage throughput and admission/collection cost
  under the project's launch and workload-density requirements.

Implementation order: inventory production coverage and durability seams;
close required-evidence gaps; bind protected output chunks into evidence;
add checkpoint consistency and optional witness receipts; deliver verified
timeline playback; qualify strict output mode. Historical state inspection and
deterministic replay are separate follow-on designs, not implied deliverables.
