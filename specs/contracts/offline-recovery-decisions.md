# Offline recovery decisions

Backing: preview
Validation: `just tests::scoped mvm-core host_interface --lib`

This is the bounded A1 contract for [#5120](https://github.com/tinylabscom/mvm/issues/5120)
and [#5097](https://github.com/tinylabscom/mvm/issues/5097). It adopts the
local-recovery direction of ADR-063, merged through PR #5676, without treating
architecture adoption as a runtime/security claim. ADR-001 and ADR-057 remain
authoritative. No production caller enables automatic recovery.

## Signed representation and verification gate

Keep `OfflineLease`, `SignedLease`, `HostPolicy`, signed plans and mailbox
bytes unchanged. Add an opt-in signed companion, not fields to those records.
Its signature covers `mvm-offline-recovery-v1\0` followed by JCS of its body.
The body has a required version of 1, issuer identifier, SHA-256 commitment
to the complete JCS `SignedLease`, SHA-256 commitment to the complete JCS
`SignedHostPolicy`, workload ID, immutable package SHA-256, explicit restart
allowance, connection-attempt limit and dependency-loss action. Unknown fields
and versions refuse. There are no deployment defaults or renewal semantics.

The envelope is `{policy, signature}`. Digests are 32-byte JSON integer
arrays; signatures are 64-byte JSON integer arrays, length-checked before
verification. Nested companion records reject unknown fields. The identity
is SHA-256 of the complete JCS signed companion envelope.

The same resolved trusted public key and issuer identifier must verify both
lease and companion. Duplicate issuer mappings refuse, even if their keys
match. The host policy is independently verified against the caller's trusted
policy issuers. No delegation chain is inferred. History is bound to that
exact companion, not merely to its lease. Independently reissued companions
have no renewal or budget-reset semantics here; a trusted issuer must not
issue overlapping grants with independent budgets for the same authority
lifetime. A1 cannot detect issuance violations across independent consumers.

Restart allowance is either denied, or a positive finite count plus an
inclusive, nonzero, ordered `ExecutionEpoch` range. Count must fit the range
using checked arithmetic. This is a constraint, never an allocator.
Connection attempts are positive and distinct from restart attempts. The
lease retains its allowed operations and queue limit; the first consumer
requires `Mailbox` absent and `max_queued_messages == 0`.
Restart requires `LocalLaunch` both before debit and before launch eligibility;
the companion cannot override its absence. Other lease operations grant no
effects through A1. Caller-supplied host/organization ceilings constrain lease
duration, restart count and connection attempts without invented defaults.
Dependency loss either preserves already-authorized work or requests stop;
expiry always requests capability closure and stop. No isolated-compute
exception is implemented.

Verification requires an explicit node/workload/package/policy expectation,
current active node, signed policy at or above the current floor, equal lease
and policy generation, finite ordered lease times, and compatible policy
scope. The private verified context is neither deserializable nor clonable.
Missing authority refuses; this API has no local-mode fallback. Ordinary
local execution uses its unchanged adapter.
The package digest is not the policy's image digest. Normal admission still
checks actual image, assurance, resources and every required effect grant.

## Time

Time is injected as a bounded Unix-seconds interval and monotonic elapsed
seconds in a named clock continuity domain. Interval endpoints are
conservative bounds, not rounded point estimates. Unknown time, inverted
bounds, or a changed continuity domain refuse. Suspend must be included in
elapsed time or invalidate continuity.

Require `earliest_unix >= issued_at`, `issued_at < not_after`, and
`latest_unix < effective_expiry`. Effective expiry is the lesser of lease
and policy expiry, or the finite lease expiry when policy expiry is `None`.
At verification derive one deadline as monotonic time plus
`effective_expiry - latest_unix`, using checked arithmetic. Equality is
expired; overflow refuses. Every consumed observation checks that fixed
deadline and nondecreasing absolute bounds and monotonic time. Backwards
time or changed continuity blocks the consumer; later clock correction
cannot revive it or reset the deadline.

## Reducer and evidence boundary

One in-memory reducer owns one workload/companion and one recovery transition.
It receives history and ownership observations from a future trusted lifecycle
adapter, not from a workload or wire decoder. These are modeled facts, not
native stop proofs. There is no production adapter in A1.

Initial history binds the companion identity, workload, original instance,
current epoch, per-workload epoch high-water mark, spent restart count and
last operation sequence. Missing history, including a missing workload
entry, refuses. The reducer never calls the local-default ledger getter,
increments an epoch, modifies another workload, or refunds a reservation.

Each request binds a strictly fresh operation sequence, original instance and
epoch, and a proposed epoch supplied by the epoch owner. The epoch must exceed
the supplied high-water mark and fit the signed range. The restart debit uses
checked arithmetic and cannot exceed the signed allowance.
History requires a nonzero current epoch no greater than its high-water mark,
and a spent count no greater than the signed allowance. The request's original
identity must equal history. Impossible history refuses.

The complete transition binding is companion identity, workload, original
instance and epoch, operation sequence, proposed epoch, restart debit and an
exact replacement instance identity supplied before reservation. Replacement
and original instance identities must differ. Every acknowledgement, readiness
or reconciliation observation names this entire binding, including replacement
identity; a workload name alone cannot identify a dispatch.

| Input | State and bounded action |
| --- | --- |
| Valid restart request | Reserving; request atomic reservation/debit persistence. No fencing or launch yet. |
| Matching committed reservation | Reserved; no activation. |
| Begin fencing | Fencing; request exact original-owner and effect-holder retirement. |
| Matching confirmed retirement | Fenced; no launch yet. |
| Request activation | Activating; request activation of the reserved epoch. |
| Matching committed activation | Launching; eligible for fresh normal admission and at most one launch dispatch. |
| Matching ready observation | Ready; report the existing transition, never redispatch. |
| Missing/uncertain fencing or dispatch | Unknown; preserve reservation/custody and request exact-transition reconciliation. |
| Cancellation before possible dispatch | Cancelled; no launch, no refund, preserve any cleanup obligations. |
| Cancellation after possible dispatch | Unknown; reconcile exact-transition custody, never blindly launch again. |
| Expiry, clock uncertainty or loss of required authority | Blocked; close effects and stop/reconcile exact owners, preserving charges. |

Every observation carries the complete transition binding. Stale or changed
bindings refuse without advancing state. Identical repeated requests return
the recorded state with no new action; duplicate acknowledgements do not
emit another action. Invalid ordering refuses. Terminal states cannot be
revived by a late event. Heartbeats/link observations cannot supply retirement
or readiness; dependency loss never itself requests replacement.
Time/authority invalidation precedes duplicate handling in every phase,
including Ready, Cancelled and Unknown. Terminal means no renewed launch
progress, not suppression of safety cleanup. Unknown never resumes launch in
A1. Dependency-loss Stop enters Blocked and requests closure/stop and
exact-owner reconciliation, whether or not dispatch occurred. Cancellation
while reservation persistence is pending retains the complete binding; a late
commit cannot release its charges or resume progress. Blocked, Cancelled and
Unknown retain cleanup obligations, never report cleanup as complete.

Actions are obligations for a future owner, not launch authorization,
persistence receipts, or grants. The reducer performs no I/O and cannot
manufacture ownership evidence. Fresh admission and effect-boundary checks
remain mandatory even after launch eligibility.

## A2 handoff and limits

[#5543](https://github.com/tinylabscom/mvm/issues/5543) owns the only durable
per-workload allocator. A2 must serialize competing consumers; atomically
reserve/debit before acknowledging; retain exact companion, original expiry,
request and disposition; persist activation only after retirement; and retain
idempotency through the authority lifetime. `WorkloadLedger::replace` is not
a reservation operation. Reconstructing this in-memory reducer from guessed,
default, or lost history is forbidden. Unknown dispatch burns the reservation.
The implemented storage boundary is specified separately in
[durable recovery custody](durable-recovery-custody.md).

A2 must define crash restoration at every persistence/dispatch edge before
connecting a real owner. A1 tests do not prove durable history, rollback
resistance, native fencing, owner-death enforcement, channel protection,
reconnect/mailbox reconciliation or launch latency. A3–A5 and capability
qualification remain open; signed-format deployment needs maintainer review
of this companion contract. No defaults, supervisor, socket, issuer renewal,
or backend activation are added by this slice.
