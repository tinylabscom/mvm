# The checkpoint sweep kept checkpoints but reaped what they restore through

Backing: shipped-source
Validation: cargo nextest run -p mvm-runtime -p mvm-cli

Plan: `specs/plans/2026-08-18-durable-agent-sessions.md` (WS5, D4)

## The failure

`mvmctl cache prune` decided each checkpoint on its own: kept if tagged, kept
if younger than the seven-day cut, kept if a live or hibernated session named it
as its resume point, removed otherwise. It never looked at parent links.

Restoring or forking a checkpoint walks the whole parent chain and refuses with
"lineage is broken" when any ancestor's record is missing. So three things the
sweep promised to keep could be left unrestorable by the same pass:

- a tagged checkpoint forked from an untagged parent, once the parent aged out;
- a parked session's resume point, once any untagged ancestor aged out — the
  exact data-loss class the session pin was added to close, one hop further up;
- a young checkpoint whose old parent was due in the same sweep.

`mvmctl machine checkpoint rm` had the same hole by hand: it refused to remove a
session's resume point but would remove the parent of any other checkpoint.

## The rule

Retention is reachability. A checkpoint retained for its own sake — tagged,
inside the cut, or a session resume point (`pins_resume_point` remains the one
session rule) — retains every ancestor it restores through, regardless of their
tag or age. Only checkpoints outside that closure are reaped.

- `mvm_runtime::lineage::ancestors_of` walks parent links over the existing
  `LineageGraph` abstraction. It is the collector's walk, not the verifier's: a
  link that resolves to nothing ends that branch, a revisited digest ends it
  rather than looping, and neither aborts the prune.
- `mvm_runtime::checkpoint::retention_verdicts` pairs every listed checkpoint
  with its `Retention` reason (or none), decided over one listing rather than by
  re-reading the store per hop.
- `cache prune` prints `Kept checkpoint: <id> (ancestor of retained checkpoint
  <descendant>, which restores through it)` for a checkpoint kept only by
  lineage.
- `machine checkpoint rm` refuses a checkpoint any stored checkpoint names as its parent
  (`dependent_children`) and names the descendants. It has no override flag, so
  none was added; removing leaf-first still works.

## Evidence

Written red first. Against the unchanged sweep and `rm`, seven failed:
the tagged-child, session-ancestry, young-child, unrelated-chain, cycle,
real-session and `rm`-descendant cases. The dangling-link case passed before and
after — it guards against the fix turning an unresolvable parent into an aborted
prune, which the old code could not do because it never followed links.

Unit coverage sits on each piece: `ancestors_of` (multi-generation, dangling,
cycle, shared ancestor, root reachable from another root), `direct_retention`
per reason, `retention_verdicts` ordering and precedence, `dependent_children`
excluding a self-parented record, and the two CLI message helpers.

## Left out

The sweep decides against one listing and does not lock the store, so a
checkpoint forked from a reapable parent between the listing and the removal can
still lose that parent. That race predates this change and is not closed by it.

The sweep still keys everything off `meta_digest` as stored; a record whose
digest drifted after sealing is kept or reaped by the digest it claims, the same
lookup a restore uses. Retention classes, expiry, and tier movement remain the
rest of WS5.
