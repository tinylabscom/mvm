# ADR-059 — Queue new dev tasks before signing a replacement-epoch message

Backing: preview
Validation: none — this proposal needs a reviewed protocol decision and native witnesses

**Status:** Proposed
**Tracks:** [#5126](https://github.com/tinylabscom/mvm/issues/5126),
[#4622](https://github.com/tinylabscom/mvm/issues/4622), and
[#4809](https://github.com/tinylabscom/mvm/issues/4809)
**Extends, if accepted:** ADR-057's restart and epoch rules. Until review,
ADR-057 remains authoritative.

## Problem and goals

A developer should stay connected to one logical work session while approved
declarative inputs are rebuilt into a replacement VM. Newly submitted typed
tasks may wait for that VM without a second shell or an in-place guest install.
The waiting experience must not turn an old-epoch message into a new-epoch
message, claim a destination accepted work it never saw, or repeat an
interrupted effect. Production application messages use the same mailbox
authorization rule; an application message cannot authorize a production
rebuild.

## Approaches considered

- **Queue a sender-owned intent before creating a mailbox envelope
  (recommended).** The sender can authenticate the request, retain its
  plaintext under the appropriate custody policy, and seal a new envelope only
  after the replacement is admitted. The queue has its own honest status and
  durability limit. It does not claim destination acceptance.
- **Sign for the old VM and retarget the envelope later.** Rejected: sender,
  recipient, epoch, policy, route binding, and ciphertext commitment are
  authenticated. Rewriting them breaks the signature; relaxing validation
  would make stale authority current.
- **Refuse all sends while rebuilding.** Safe and simple, but loses the
  requested connected workflow. Keep this as the fail-closed behavior if a
  bounded sender outbox cannot be made trustworthy or available.

## Proposed boundary

The outbox belongs to the sender's logical work session, not to the VM being
replaced or the destination mailbox. A pending intent binds its sender
principal, logical task ID, payload commitment, intended workload and target
revision, handler and schema version, deadline, and applicable authorization
policy. It has a finite byte/count/age budget. A committed outbox intent may
be called `queued_for_rebuild`, but never `accepted_ephemeral`,
`accepted_durable`, `delivered`, or `completed`: those are destination and
application facts. Lost outbox-commit responses are reconciled by the same
logical task ID and payload commitment; conflicting reuse is refused.

At cutover the old owner is durably fenced before the new owner may accept
MVM-mediated effects or write shared state. A replacement may be prewarmed
alongside the old VM only if it cannot run effectful workload code before
fencing; otherwise the old VM must stop before the replacement starts. Only
after the new VM and its declared handlers are verified may the sender
recheck current capability, tenant, recipient, policy, handler/schema,
expiry, and route/epoch. The sender, never an intermediary impersonating it,
creates and persists the canonical signed envelope before attempting
transport. The outbox records the task-to-envelope relation and a durable
dispatch-start marker before I/O. Only the destination's actual receipt,
not this marker, could constitute destination acceptance. Retry of an
uncertain send may use the **same signed envelope and message ID** while its
authority and epoch remain valid, relying on destination deduplication; it
must not create a different new-epoch envelope after a possible dispatch. If
the epoch changes or a result cannot be reconciled, report `unknown`.

If the build fails, the old VM remains the active ready owner when possible.
New-revision intents remain visibly queued until a bounded retry, explicit
cancellation, or expiry; they are not silently sent to the old revision.
Unsupported handlers, changed schemas, revoked grants, missing keys,
outbox corruption, quota exhaustion, and failed owner fencing refuse or
block dispatch without treating a pending item as completed. No promise of
continuous service is made when resources cannot overlap two VMs.

Already dispatched or destination-accepted old-epoch messages are a
**different case**. They never move merely because a dev rebuild completed.
ADR-057's stale-epoch refusal stands. #5126's explicit opt-in in both the
conversation and workload plan is a prerequisite even to consider transfer
of an accepted pending conversation; it also needs immutable historical
acceptance, durable old-owner fencing, current consumer authorization and key
release, and a separate authenticated current-epoch delivery decision. The
original ciphertext and signed fields remain unchanged. Invocation-pinned,
expired, revoked, or unprovable items stay pinned or receive a truthful
terminal/uncertain disposition. Neither transfer nor queuing restores process
memory, undoes an external effect, or provides general exactly-once execution.

## Assurance and ownership

One canonical mailbox admission and dispatch rule serves dev and production.
Image provenance, backend isolation, and any requested host-blind assurance
are separate launch gates. The local dev outbox may use a trusted-host
encrypted store with explicitly stated key and host-loss limitations. It
cannot inherit a host-blind claim: that profile needs endpoint-held key
custody and its own witnesses, or must refuse. No plaintext, secret, or
payload-derived error enters shared logs or an ordinary coordinator.

`mvm` owns the standalone mailbox protocol, outbox/destination distinctions,
host-local admission, deduplication, and fencing. `mvmd` may enumerate
vulnerable signed dependency/image provenance across tenants and orchestrate
administrator-authorized staged production rebuilds and rollovers. It does
not mint destination receipts, decrypt host-blind messages, override a local
refusal, or let a workload mailbox task authorize its own rebuild. A
production replacement uses fresh signed artifacts and local MVM admission;
it does not mutate a running guest.

## Evidence before acceptance

Review a finite-state model for outbox commit, build success/failure, old
owner fence, new ready/switch, envelope persistence, dispatch, lost response,
destination receipt, and application outcome. Inject crashes at every
commit/I/O edge; demonstrate the same task ID with conflicting payload is
refused, no old and new owner simultaneously accept effects, and no
uncertain old operation is automatically replayed. Cover malformed or stale
route/epoch, revoked or expired capability, tenant/recipient/handler/schema
mismatch, quota/full conditions, key loss, rollback, cancellation, and
envelope deduplication. A failure to prove durable single-owner custody
keeps the strict pinning/refusal fallback.

Measure build-to-ready, cutover, queued-send latency, destination acceptance,
and cold/warm boot p50/p95/p99 separately on supported native hosts. A warm
shared mailbox service and logical mailbox avoid a per-VM helper or
synchronous preboot disk transaction; these are design constraints, not
measured performance claims. Implementing the local service (#4629) and
durable store (#4630) is prerequisite to an end-to-end witness; cross-host
movement stays under #4631. No unchecked issue criterion or production
mailbox claim is completed by this proposed ADR.
