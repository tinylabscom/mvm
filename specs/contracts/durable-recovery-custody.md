# Durable recovery custody

Backing: preview
Validation: `just tests::scoped mvm-core host_interface --lib`

This is the bounded A2 contract for [#5120](https://github.com/tinylabscom/mvm/issues/5120),
owned jointly with [#5543](https://github.com/tinylabscom/mvm/issues/5543).
It consumes the verified A1 context and reducer from PR #5726. It does not
connect a VM lifecycle owner or complete #5543's plan/mailbox type convergence,
launch-path integration or latency qualification.

## One ledger and one per-workload epoch history

Extend the existing `host-interface/workloads.json` ledger. Do not add another
epoch file, counter, audit-derived authority or PID/name inference. The
existing entry epoch is the active epoch. Managed recovery history retains its
never-reusable high-water mark, restart debit and operation sequence, plus at
most one current transition and one last completed transition.

Old entries deserialize with no managed history and preserve ordinary local
defaults. A managed open requires an exact workload entry and history bound to
the verified companion; absence refuses. A separately named establishment
operation may create that history only from a `VerifiedOfflineAuthority` and
trusted modeled `History` whose provenance the caller established independently.
The companion authenticates bounds, not restart history. Establishment is an
explicit trusted bootstrap/migration operation, never fallback from a failed
managed open. Under the lock it requires the supplied active epoch to equal the
existing entry, preserves quarantine, and persists supplied authority; it does
not sign, renew, allocate or infer it. Existing managed history is immutable
under establishment except exact idempotent replay. Lost, corrupt or rolled-back
managed state cannot be repaired from the companion or local defaults. A
different companion, owner or history requires separately reviewed external
reauthorization and cannot reset budget here.

Adding optional fields changes no signed or mailbox bytes. An older binary
with `deny_unknown_fields` refuses a ledger written by this version rather
than silently dropping recovery history. New code rejects malformed,
oversized or inconsistent records instead of defaulting.

## Protected serialized transaction

Every writer of `workloads.json` holds one stable exclusive `workloads.lock`
descriptor from read through durable publication. This includes ordinary
quarantine and replace operations: the old load/mutate/save snapshot sequence
cannot publish stale state over a reservation. Ordinary mutation preserves
managed history, cannot independently advance a managed epoch, and never clears
managed quarantine. Mixed old/new concurrent writer processes are unsupported;
establishment requires old writers to be quiesced. An old binary subsequently
refuses the new entry shape rather than publishing through this version's API.

The host-interface directory, lock and ledger file must be current-user-owned
plain Unix objects at modes 0700 and 0600. Regular files have one link and are
opened without following symlinks. The stable lock is never unlinked or
replaced; use its validated descriptor with `FileLock::acquire_opened`, not the
generic path helper. Trusted ancestors and absence of hostile same-UID
namespace replacement are assumptions: owner-only modes do not protect against
an arbitrary malicious process running as the same user. Unsupported owner-only
platforms refuse managed custody; ordinary pre-existing local reads remain
unchanged.

Publication reuses `atomic_io::write_private`: a fresh owner-only temporary in
the same directory, complete serialization, file sync, atomic rename and
parent-directory sync. A successful acknowledgement follows file and directory
synchronization on a supported filesystem honoring those operations. Process-
crash tests do not establish physical power-loss behavior.
Managed custody requires a durably established host-interface directory. If
establishment creates it, it synchronizes the containing directory before
acknowledging success.

Invalid input, bounds, unsupported platform, and pre-publication lock/open
validation are definite refusals. A publication error is a typed
`CommitUnknown` carrying its I/O source, operation/authority identity and
requested durable step (establishment carries authority/workload without a transition).
Publication may have occurred, so the caller reloads under the lock. A visible
complete new record is not acknowledged until reconciliation successfully
republishes/synchronizes or otherwise establishes durability. No effect repeats
based only on the original error.

Caller-supplied finite limits bound serialized bytes and all map entries.
Reading stops at the byte limit before unbounded allocation; serialization is
enforced while writing to a bounded buffer/writer, before unbounded allocation
and before publication. There are no deployment defaults. The transition shape
retains a constant number of records, though bounded workload strings remain
variable-length; there is no event journal. Blocking lock acquisition is allowed
only on a caller-owned blocking path, never the path responsible for time-
critical effect closure. Networking and VM operations remain outside it.

## Transition custody

The store accepts the complete A1 `TransitionBinding`; it never chooses an
epoch. Reservation validates the companion/workload/original owner, strictly
fresh operation, proposed epoch above the persisted high-water mark and within
the verified delegated range, and exact next restart debit. It durably raises
the high-water mark and debit before returning `Reserved`. A failed,
cancelled, blocked or unknown attempt is not refunded.

The only forward transitions are:

```text
Reserved -> Fencing -> Fenced -> Activating -> Launching -> Ready
```

- `Fencing` is durably recorded before an owner requests retirement.
- `Fenced` records supplied exact-owner retirement evidence; the store does
  not create or authenticate that evidence.
- `Activating` is durably recorded before changing the active epoch.
- `Launching` atomically changes the active epoch to the reserved epoch only
  after `Fenced`; it does not clear quarantine, launch a VM or grant effects.
- `Ready` changes the retained active-owner identity to the replacement and
  moves the transition to the one-entry completed slot.
- cancellation before possible dispatch becomes `Cancelled`; cancellation
  from `Launching` and every uncertain observation becomes `Unknown`.
- expiry, authority/enforcement loss or explicit block becomes `Blocked`.
  `Cancelled`, `Unknown` and `Blocked` are terminal and retain the debit,
  high-water mark and exact cleanup binding.

Every stored transition carries `activation_committed` independently of phase.
Before `Launching` it is false and the active epoch equals the original epoch.
Entering `Launching` atomically sets it true and the active epoch to the
proposed epoch. Terminal transitions preserve that bit: a pre-activation
terminal state retains the original active epoch; a post-activation terminal
state retains the proposed active epoch while still proving neither dispatch
nor readiness. The binding retains both exact owner identities throughout.
Generic history validation never treats the proposed epoch and old owner as one
current owner. A2 never clears quarantine, and no stored epoch/Ready value
bypasses managed admission.

An exact retry of a retained binding or the immediately preceding event returns
recorded status without another write or action. Reuse of a retained operation
with changed input conflicts. Older operations whose complete binding has been
evicted refuse as stale through the persistent sequence watermark; indefinite
outcome retention is not promised. Stale or out-of-order events refuse. An old
completed transition cannot replace current cleanup custody. The last completed
binding remains queryable so a lost `Ready` response cannot reserve or launch
again. A later fresh operation may begin only after `Ready`, using the
replacement as its original owner and the next externally supplied epoch.

Reservation is never activation. The active epoch cannot change before the
fenced state is durably recorded. Updating one map entry cannot change
another workload's active epoch, high-water mark, budget or transition.

## Recovery and evidence limits

History persists effective absolute expiry, the accepted absolute clock bounds,
last accepted monotonic seconds, original monotonic deadline and continuity
domain. In the same trusted domain, opening reconstructs the A1 reducer with the
earlier of the persisted and freshly derived deadlines and requires every value
to be nondecreasing from the last accepted observation. A changed/unprovable
continuity domain blocks launch progress; monotonic values from different
domains are never compared or rebased. A reboot-safe time source is not invented
in A2. Time/authority invalidation precedes duplicate handling, including
`Ready` and terminal phases. A non-authorizing inspection path still returns
exact cleanup custody when current authority cannot be verified.

Opening is a validated no-action restoration:

| Stored phase | Restoration outcome |
| --- | --- |
| `Reserved` | Preserve debit/reservation; emit no external action. |
| `Fencing` | Retirement may have been requested; require exact-owner reconciliation, never infer retirement or issue a blind second request. |
| `Fenced` | Preserve supplied retirement evidence; do not fabricate activation or dispatch. |
| `Activating` | Activation publication may be pending; reconcile storage, do not dispatch. |
| `Launching` | Dispatch may or may not have occurred. Restore as non-dispatchable `Unknown` custody requiring exact replacement reconciliation. Persisting before dispatch deliberately sacrifices availability after a crash. |
| completed `Ready` | Return recorded completion without redispatch. |
| `Cancelled`, `Unknown`, `Blocked` | Retain debit/binding and cleanup custody; never resume launch. |

Only the successful first durable transition into `Launching` can return the
one launch obligation. Concurrent callers and restoration receive status only.
If reservation publication committed but its acknowledgement was lost,
cancellation operates on reloaded custody and cannot erase/default the binding.

Inconsistent phase/binding/history/time, corrupt JSON, lost history, wrong
companion, rollback below the recorded active epoch, or unknown dispatch
remains refused/blocked.

Process-crash tests interrupt every logical publication edge and verify that
reload yields either the complete old state or complete new state. Concurrent
writer tests prove distinct operations cannot both reserve the same next
epoch, ordinary writers cannot erase managed history, and different workloads
remain independent. Storage-fault tests exercise pre-publication refusal and
post-publication uncertainty and require locked reload/reconciliation before
progress.

This local ledger and lock support ordinary process interruption and the stated
sync contract. They do not detect deliberate deletion/rollback by the owning
user/host, hostile same-UID namespace replacement, or malicious whole-host
rollback; prove a drive honored flushes; authenticate native retirement; or
protect against the trusted host. Audit remains evidence, not transition
authority.

## Remaining #5543 and A3 handoff

#5543 still owns one foundation `ExecutionEpoch` type across plan, host
interface and mailbox; durable allocation on every ordinary launch/replace/
wake; admission/mailbox convergence; compatibility; and measured Firecracker
and HVF latency. This slice does not claim those acceptance items complete.

A3 receives a durable store that can reserve/debit and record exact phases.
It must supply authenticated original-instance/effect-holder custody, close
effects at expiry, request stop, verify retirement, and connect fresh normal
admission. No A2 record alone proves a VM stopped or permits dispatch.
