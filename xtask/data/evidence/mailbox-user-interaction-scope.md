# Host-signed user mailbox interaction scope

Backing: preview
Validation: none

Source-reviewed at `62603aeffe78be79728ef347204872ae0344fb79`.
Related issues: [#4622](https://github.com/tinylabscom/mvm/issues/4622),
[#4629](https://github.com/tinylabscom/mvm/issues/4629), and
[#5126](https://github.com/tinylabscom/mvm/issues/5126).
This is a design attachment, not an implemented capability or issue-status ledger.
The audit-substrate ownership prerequisite under ADR-061 is separate.

Recovered as a historical design attachment from chronological archived edits.
The source-review statements and design acceptance below describe that record,
not newly verified production behavior or fresh permission to implement or land it.

## Owner design acceptance

The owner accepted the architecture in the design conversation with
"This all looks good to me": host-held signing, general Call/Reply/Cast,
mandatory per-message auditing, journal-backed audit obligations, idempotent
audit publication, bounded backpressure, and installation-owner user access
for the first standalone version. MVMD may add multi-user enrollment and
coordination; MVM retains final local authorization and refusal.
This acceptance records design direction, not proof of implementation,
acceptance of unspecified protocol details, or publication/landing permission.

## Requested behavior and approved identity direction

Mailboxes are a general communication substrate for authorized users, workloads,
and host services, not a user-question-only channel. Call/Reply and one-way Cast
are independent operations. Casts support bounded status/log updates, audit-event
delivery to an authorized collector, and coordination with other VMs.

One concrete Call/Reply flow is a running agent asking an authorized user for
help and the user replying to that exact request. It does not constrain other
authorized sender/recipient combinations. Every message has its own stable
MessageId; retrying does not mint a replacement identity.
Host-held signing is acceptable: it attests host-authorized origin, not a
personal user signature. No presentation interface is included.

Reuse the canonical signed/encrypted envelope, Call/Cast/Reply kinds, message,
correlation and causation IDs, capabilities, and local-durable receipts.
An audit-event Cast carries an attributable claim from its authorized sender;
delivery alone does not make its payload an authoritative assertion about
execution. Keep audit-event transport distinct from the mandatory audit evidence
of every mailbox message's lifecycle, including audit-event Casts themselves.
That evidence must use the audit append path rather than recursively generating
another mailbox Cast. Cross-VM coordination retains destination admission and
scoped grants; knowing another VM's mailbox grants no authority.

## Source evidence and gaps

- `crates/mvm-contract/src/protocol/mailbox.rs` defines envelope correlation,
  causation, kind, ReplyRoute and separate Send/Reply capability operations.
- `crates/mvm-core/src/mailbox/frame.rs::OutboxMessage` carries only recipient,
  MessageId and body, encoded as a raw 64-byte prefix followed by payload.
  It cannot express application-selected Call/Cast/Reply semantics.
- `crates/mvm-hostd/src/mailbox_launch.rs::template_for` currently grants Send
  and Call, not general Cast or user Reply authority.
- `crates/mvm-hostd/src/mailbox_service.rs::GuestSealer` already retains sealed
  source intents for exact retries. It stamps correlation from MessageId rather
  than accepting an application reply relationship.
- `crates/mvm-core/src/mailbox/journal.rs` provides anchored acceptance, lease,
  signed ACK and recovery, but no durable pending-call authorization state or
  audit-delivery outbox. Its AcceptanceIntent is an internal acceptance proof,
  not a host audit-chain publication hook.
- `crates/mvm-client/src/mailbox.rs::recv_at` audits a legacy destructive
  dequeue using counters and byte length. That is neither a per-message audit
  trail nor the required durable user receive/reply API.
- `crates/mvm-hostd/src/mailbox_service/durable.rs` has no host audit emitter.
  Its signing authority is mailbox-scoped, not the host-wide audit signing seed.
- No Signal messaging library was found in the workspace manifests or lockfile.
  OS signal handling is unrelated. Signal integration is not assumed.

## Recommended implementation boundaries

### 1. Local user authority

Define an authenticated local-user-to-mailbox-principal binding before exposing
user Receive or Reply. The first standalone audience is the local installation
owner; multi-user enrollment, remote identities and UI are separate.
The host must derive the principal from checked caller authority, never a
client-supplied username, PID, PrincipalId or knowledge of a request ID.

MVMD may enroll users and coordinate scoped grants, but the destination MVM
verifies configured trust, policy, expiry and revocation before admission.
MVMD is not a required local data path and gains neither plaintext keys nor
permission to bypass host refusal merely by administering users.
Installation-owner authentication identifies a locally authorized account,
not which human is physically operating it.

The existing native caller-identity mechanism is macOS-only possession evidence,
not portable user authorization. The source review did not establish an existing
portable broker identity mapping that can simply be reused. Approval of host
signing alone does not select that authentication mechanism.

### 2. Versioned application operations

Keep legacy outbox bytes and behavior unchanged. Introduce an explicitly
distinguished, bounded operation version for Call, Cast and Reply, with unknown
versions refused. Do not append metadata to the legacy frame: older decoders
would treat it as application payload. Review discriminator collision handling
against all existing raw recipient prefixes before selecting the encoding.

No canonical envelope replacement is needed. Each operation supplies immutable
message identity and bounded typed content; the host resolves allowed recipients
and constructs the authorized envelope. Receive exposes verified message context,
not just body bytes. A transport read or notification is not an application ACK.

### 3. Exact-request reply authorization

Prefer the existing capability schema over a new signed token format.
The host mints and retains a distinct Reply capability scoped to the intended
replier for each accepted Call. Repliers may be authorized workloads, users or
host services. In the user-help case, the host uses the user-subject capability
only after authenticated local-user policy resolution. That user principal is
host-attested: setting the capability subject alone neither authenticates the
local caller nor proves a personal user signature.
Persist its binding to the original MessageId, CorrelationId, exact reply
address, expected replier principal, execution/policy epoch and expiry.

Normal signature, capability and revocation checks still run. Additionally, Reply
admission must match that durable binding, require causation to name the original
request, and consume its pending state atomically with reply acceptance.
Exact transport retries use the original receipt; different content under the
same ID conflicts. A second application reply and a late reply cannot satisfy a
later call. Correlation and an opaque request handle are not authorization.

For the first slice, preserve current epoch fencing. Cross-replacement
conversation continuity remains a separately reviewed #5126/ADR-062 §4.2 concern;
do not weaken stale-epoch rejection to keep a conversation alive.

### 4. Recoverable per-message audit

Owner requirement: every mailbox message must be audit logged. This applies to
Call, Reply and Cast, every authorized sender/recipient combination, and every
purpose, including audit-event delivery and VM coordination. There is no
unaudited message kind or opt-out. Required audit failure must not yield a
successful acceptance or delivery acknowledgement.

ADR-057 forbids plaintext hashes as well as payloads in audit records. Use the
existing ciphertext commitment and a reviewed minimum metadata set. Do not copy
user answers, application logs, secrets, or payload-derived errors into audit.

Persist recoverable audit work with each relevant mailbox journal transition.
Use transition identity (mailbox history, cursor/head and event kind), not just
MessageId, for idempotent publication: acceptance, delivery and ACK are distinct
facts about one message. Checkpoint/compaction must preserve unpublished work.
This requires an audit-side authenticated lookup/deduplication or reconciliation
protocol keyed by that transition identity; no such mailbox publication protocol
is established today. In particular, recovery must resolve a successful audit
append followed by a crash before the journal records publication completion.
Malformed or unauthorized attempts have no trusted sender/message identity;
record bounded typed refusals without trusting their claimed fields.

Publish through narrowly scoped host audit authority, retaining the existing
mailbox-helper key boundary. Never give the helper the host-wide signing seed.
A bare callback after journal commit can lose audit work on crash; a callback
before commit can falsely assert acceptance. Neither is sufficient.

Accepted architectural direction: persist the transition and audit obligation,
then publish
required chain evidence before returning successful acceptance or releasing
delivery. On an ambiguous audit append, reconcile the exact transition rather
than blindly append again. Once the mailbox journal has committed, publication
failure must return a typed unknown/audit-pending outcome, not a definitive
refusal or a claim of rollback. Require exact-ID reconciliation/retry and report
success only after audit completion is durably established. Audit failure must
not destructively consume a message.

The audit owner performs lookup and append under the same chain lock. A missing
transition is appended and durably synced; an identical transition returns the
existing verified evidence reference; conflicting evidence under the same
transition identity is refused. Existing-record reconciliation must establish
durability before returning success, including recovery from an earlier ambiguous
fsync. Any lookup index is derived from verified evidence, not an independent
authority. Pruning retains evidence required by pending work and supported
retry windows.

Reserve message-state and audit-obligation capacity before accepting new work.
Keep capacity for delivery, ACK and expiry of existing messages so new traffic
cannot prevent their completion. Recovery is bounded, and mailbox locks are not
held while waiting for the audit service. Audit-event Casts use the direct audit
append path for their own lifecycle evidence, never recursive Cast publication.

The next validation step is a bounded local crash-injection prototype of this
handshake, before exposing the application operations. It must cover concurrent
retries, conflicting transition reuse, exhausted capacity and audit recovery.
Concrete wire compatibility, index recovery, retention and capacity accounting
remain implementation-design obligations; this direction does not establish
that the existing storage APIs already provide them.

## Acceptance witnesses

Use the real local journal and host signing path, with dummy principals and
payloads, without MVMD or a UI. Demonstrate agent-to-user Call, exact authorized
user Reply, VM-to-VM Call/Reply and Cast, and application status and audit-event
Casts with their distinct admission/ACK outcomes. Verify that audit-event Casts
also receive lifecycle audit evidence without recursive mailbox publication.
Add negative witnesses for wrong user, matching correlation with wrong
capability, wrong request, duplicate/late reply, stale epoch, revoked authority,
expired request, oversized payload, full queue, and audit unavailability.

Inject interruption before/after journal commit, audit append, publication
acknowledgement and reply consumption. Recovery must neither lose audit work nor
deliver a reply twice as a new logical reply. Verify exact receipt retries,
legacy decoding, unknown-version refusal, retained pending audit work across
compaction, and absence of payload/plaintext hashes from audit and diagnostics.

## Remaining design details

### First production audit-publication boundary

Source review recommends an internal operation owned by the existing primary
file signer, not a new public generic append API or signer-helper IPC operation.
It must use the existing tenant-chain sidecar lock for the entire verified
lookup, conflict check, append, verification and durability wait. The existing
recovered-transcript publication path is a precedent for that sequence, not a
mailbox implementation to reuse unchanged.

An identical transition returns its original verified evidence reference;
conflicting evidence refuses. Missing, damaged or insufficiently scanned history
cannot establish absence. The result must identify the actual signed record
across rotation, not just an offset in the active file. Existing signing and
canonical verification remain the only byte-format implementations.

Before this operation can be wired to a production mailbox, resolve:

- Which trusted caller supplies the authorized, durably committed obligation.
  A type named "verified" must not substitute for that verification path.
- Bounded lookup and recovery across active and sealed segments. An optional
  derived index may accelerate verification, never decide authority or absence.
- Retention of evidence for pending obligations and supported retries. Current
  transcript prune pins do not automatically protect mailbox transitions.
- The exact typed event/metadata schema and compatible pending/unknown outcomes.

Do not pass the host-wide audit key into the mailbox helper. Its existing
helper append operation owns a different workload-chain contract; adding
mailbox-to-audit IPC needs its own authorization review.
Do not introduce an unused production API solely to make the prototype look
integrated. Production acceptance requires a real caller and real retained
obligations, plus process-concurrency, kill/restart, rotation, pruning and
ambiguous-sync tests. The local fixture is not evidence for those properties.

### Other remaining details

Specify and validate the local authentication mechanism for the accepted
installation-owner scope, the versioned operation/outcome encoding and bounded
publication/recovery protocol. Identify which Signal library, if any, is intended;
no external messaging dependency is assumed.
Mandatory audit coverage, no successful unaudited acknowledgement and the
journal/audit handshake direction are settled, not open product options.
No mailbox runtime implementation or live witness is claimed by this attachment.
Publication, landing and security-claim promotion remain separate.
