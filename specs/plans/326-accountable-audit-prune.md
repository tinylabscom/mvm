# Plan 326 — Accountable pruning of retired audit segments

**Status: COMPLETE**

Issue: #2390. Follows plan 319 (#2365, rotation), which made removal
*detectable* and left it inaccountable.

## What was wrong

Plan 319 settled retention as keep-everything and wrote that deleting a retired
segment "stays an explicit operator action". No verb existed for that action, so
pruning meant `rm`, which leaves the chain reporting `TruncatedFront` forever
with no way to record that the removal was intended.

That made pruning strictly worse than not pruning. Which means nobody would ever
prune. Which means keep-everything was not a policy choice — it was the only
reachable state, and the plan's sentence overstated what shipped.

## The tension

A "this deletion was intentional" marker is exactly the shape of thing that can
undo the property rotation was built to protect. If a signed record can say
anything, the key holder can relabel an *edit* as a prune and the ledger becomes
editable-with-paperwork.

## The design

**Corroboration.** A `chain.pruned` record may only claim what the surviving
chain independently attests. The lowest surviving segment's `chain.continued`
handoff already names its predecessor's sequence number and final chain hash;
the record must match both, or it is refused as `UncorroboratedPrune`. So the
record cannot reach further than the boundary, and cannot name a tip the chain
disagrees with — which is what stops it covering an edited segment rather than a
removed one.

**Prefix only.** The range is always `1..=through`. A prefix leaves exactly one
boundary between what went and what stayed, and that is the one boundary the
survivors can still check. A middle-range prune would leave two, one of which
nothing corroborates.

**Verify, then record, then delete.** Verifying first is not politeness:
pruning a chain that is already broken would destroy the evidence of whatever
broke it, under the banner of routine maintenance. Recording before deleting
makes a crash safe in the right direction — a record for segments still on disk
is simply unused, while files deleted with no record are indistinguishable from
tampering and unrecoverable.

**Superseding.** Each prune restates the whole prefix from segment 1, so the
newest record is authoritative and an older one being pruned away with its
segment costs nothing.

## What it does and does not corroborate

Only the **upper** boundary of the pruned range is cross-checked. Segments below
it are attested by the signed record alone, because the handoffs that would have
pinned them went away with the segments themselves. The entry count the record
reports is therefore the record's word, not a derived fact.

Tail truncation remains undetectable, unchanged and unaddressed here.

## Reporting: verified-with-gaps, not verified

`verify_segment_set` and `verify_segment_topology` now return `SetVerification`
— the segments plus an optional `pruned`. A pruned chain is intact *and* shorter
than its own history, and a caller that could only say "verified" would report
green for a log with a hole in it. `doctor` names the gap and the entry count
alongside its existing caveats.

This was the open question on #2390; verified-with-gaps is the answer, because a
green check meaning "green except for the parts I deleted" is the quiet
downgrade this whole line of work exists to prevent.

## A bug the tests caught

The prune record is written to the active segment, but it does not stay there:
once enough is appended, that segment is sealed and the record moves into it.
The first implementation only searched the active segment, so a prune followed
by enough writes to rotate made the chain read as truncated again. The search
now runs over the whole surviving set, newest-first, stopping at the first
segment carrying a record.

The honest cost: on a pruned chain the cheap topology check may read interiors
until it finds the record, so it is no longer strictly `O(segments)` there. The
un-pruned case — overwhelmingly the common one — is unchanged.

## Surface

    mvmctl trust audit prune --through <seq> [--tenant <t>] [--ack]

Dry-run without `--ack`, reporting what would go and that those entries stop
being independently verifiable.

## ADR-001

Claim 8's witness set gains the corroboration and refusal witnesses, and the
row's mechanism note records that a chain may now verify *with a deliberate,
corroborated gap* — which is a different statement from verifying whole, and
has to read as one.

## Workstreams

- [x] **W1 — the record.** `chain.pruned` + labels + parse, refusing a
      zero-range claim.
- [x] **W2 — corroboration.** Front gap deferred and adjudicated against the
      surviving handoff; `UncorroboratedPrune` for a claim the chain denies.
- [x] **W3 — the writer.** `prune_through`: verify, record, delete, under the
      chain lock.
- [x] **W4 — set verdict.** `SetVerification` with `pruned`; doctor reports it.
- [x] **W5 — CLI.** `mvmctl trust audit prune`, dry-run by default.
- [x] **W6 — tests.** 11 covering the happy path, the four adversarial cases
      (over-claim, wrong tip, forged signature, unrecorded deletion), the
      broken-chain refusal, double-prune supersession, and the negative case.
- [x] **W7 — ADR-001 + docs.**
