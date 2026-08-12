# Plan 319 — Audit-log rotation with authenticated segment handoff

**Status: COMPLETE**

Issue: #2365. Sits next to plan 2346/#2350 (incremental verification in doctor),
which made the walk survivable but left growth unbounded.

## Measured starting point

Taken on this host, release build, against the real `~/.mvm/audit/local.jsonl`
and the real host verifying key (the chain verifies clean, so these are the
costs of a *successful* full walk, not an early abort):

| entries | bytes | bytes/entry | full walk | per entry |
| ------- | ----- | ----------- | --------- | --------- |
| 4,022 | 4,185,564 | 1,040 | 122 ms | 30.3 µs |

Three runs, warm cache, spread under 3 ms. Two corrections to the numbers this
work was scoped against:

- **30.3 µs/entry, not 115.5 µs.** The 115.5 µs figure comes from
  `crates/mvm-hostd/tests/audit_verify_cost.rs`, which exists only on the
  unmerged `perf/2346-audit-chain-incremental` branch, not on main. Today's log
  costs 122 ms, not 380 ms.
- **715 `*.jsonl` files in `~/.mvm/audit/`, not ~1,040.** The directory holds
  1,043 entries but 328 of them are `gateway-*.sock`. Of the 715 chains, the
  overwhelming majority are zero-byte `*.workload.jsonl` files — one per VM ever
  started. Per-file count is a separate (cosmetic) problem from log growth and
  is out of scope here.

Cost is linear in bytes at roughly 29 ns/byte. The problem is not today's
122 ms; it is that nothing bounds it. At the observed ~1 KB/entry, a 100 MB log
is a 3 s walk on every `mvmctl trust audit verify`, and the file only ever grows.

**The `.forked-2026-05-12` file is not a rotation precedent.** It is a
*quarantine* rename, and it is already documented as such in-tree:
`crates/mvm-core/src/config.rs` carries the test
`a_quarantined_chain_is_out_of_scope`, whose comment states that renaming a
broken chain out of `*.jsonl` is the documented recovery step, so an operator
can clear a finding without deleting evidence. Nobody rotated anything; someone
quarantined a chain that had forked. This plan must not repeat that shape,
because a quarantine deliberately drops the file out of verification scope and a
rotated segment must stay in it.

## The tension

Verification seeds `prev_hash = [0u8; 32]` and requires line 0 to claim it
(`verify_audit_chain_entries`, `crates/mvm-hostd/src/supervisor/audit_file.rs`).
That genesis anchor is exactly what makes removed history detectable: front-
truncate a file and it fails at line 0. So a naively rotated file either fails
verification forever, or rotation has to establish a new authenticated starting
point. Get that wrong and "tamper-evident ledger" quietly becomes "ledger you
can edit by calling it rotation".

## Options considered

**Option A — authenticated segment handoff (chosen).** The retiring segment
ends with a signed `chain.sealed` entry; the new segment begins with a signed
`chain.continued` entry whose envelope `prev_hash` is the retired segment's
final line hash, and which *also* carries that same hash, the predecessor's
sequence number, and its entry count inside the signed entry body. The binding
travels inside the evidence. Verification stays single-file-local: line 0 may
claim a non-genesis predecessor only if it is a `chain.continued` whose signed
body names the identical hash — so forging a handoff needs the signing key,
which is exactly the same bar as forging any other line.

**Option B — independent per-file chains plus a signed manifest.** Each segment
restarts at genesis; a separate signed manifest lists `(seq, file, first_hash,
last_hash, count)`. Rejected: the ordering lives in a second artifact that can
be deleted or replaced independently of the data it orders. Delete the manifest
and you are holding N genesis-anchored files with no way to tell what order they
were written in or whether any are missing. Option A puts the same information
inside the chain, where removing it breaks the chain. A manifest is also a
second thing to keep in sync, and this repo has a documented history of a
narrative and a ledger drifting apart.

**Option C — size/age retention with retired segments kept.** Not an
alternative to A; it is the *policy* that sits on top of A's *mechanism*. Taken
as the default (see below).

**Chosen: A, with C's keep-everything as the default retention policy.**

## What the design does and does not buy

With A + cross-segment checking:

- Editing any line in any segment: caught, as today.
- Front-truncating a segment: caught at line 0, as today — the surviving line 0
  claims a non-genesis predecessor with no matching signed `chain.prev_tip`.
- Re-ordering segments, or splicing a segment behind a different predecessor:
  caught, and needs the signing key to forge.
- Deleting a whole segment from the middle or the front: caught *and named* —
  the surviving successor says which sequence number it continues, and that
  segment is absent. Removal becomes a self-describing hole rather than silence.
- Deleting the newest segments: **not** caught. That is tail truncation, it is
  undetectable today for exactly the same reason (the chain has no external
  anchor and the host holds the key), and this plan does not change it. Said
  plainly here because rotation makes it easier to do by hand.

The host is trusted with the signing key (ADR-001 §"Out of scope": a malicious
host). Rotation does not weaken that; a host that can sign can already rewrite.
What rotation must not do is let a *non-key-holder* remove history silently, and
the handoff is what prevents that.

## Retention policy

**Decided by the maintainer on the issue: keep every segment forever.** Rotation
splits the file and nothing is ever deleted. Disk grows at the same rate it does
today; what becomes bounded is the *active* segment, and therefore the cost of
every check that only needs the live chain. Deleting a retired segment stays
possible, but it is an explicit operator action, never automatic, and never a
side effect of rotation.

**What shipped is narrower than that sentence, and #2390 tracks the rest.**
There is no verb for the explicit operator action: pruning today means `rm`,
which leaves the chain reporting `TruncatedFront` or `MissingSegment` forever
with no supported way to record that the removal was deliberate. Detection is
correct and tested; accountability is missing. Since that makes pruning strictly
worse than not pruning, keep-everything is currently the only reachable state
rather than a chosen one.

**Sweep scope, also decided on the issue: retired segments stay in scope.** They
are named `<tenant>.seg-<NNNNNN>.jsonl`, so `is_host_lifecycle_chain` already
admits them with no change. This is the opposite of the `.forked-` quarantine
precedent, on purpose: a quarantined chain is *known broken and being triaged*,
while a retired segment is *intact evidence* and must keep being checked.

## Layout

    ~/.mvm/audit/
      local.seg-000001.jsonl   sealed, ends with chain.sealed
      local.seg-000002.jsonl   sealed, starts with chain.continued
      local.jsonl              active, starts with chain.continued (seq 3)

The active segment keeps the name it has today, so every existing reader,
`tenant_path`, and the `file:///…` fixed-file destination keep working
unchanged. Rotation renames the active file to its sealed name and starts a
fresh active file. Sequence numbers are zero-padded to 6 digits so lexical order
equals numeric order.

Segment names do not collide with the per-VM workload chains
(`<tenant>.<vm>.workload.jsonl`): `workload_audit_vm_name` requires the
`.workload.jsonl` suffix, which a segment name never has.

## Two-tier verification

The point of bounding the active segment is that the two consumers want
different things, and conflating them is what made this expensive.

- **`mvmctl doctor`** verifies the *active segment in full* plus the *segment
  topology*: for each boundary it verifies the two adjacent boundary lines'
  signatures and checks that the successor's signed `chain.prev_tip` equals the
  hash of the predecessor's final line. That is `O(active segment + number of
  segments)`, reads two lines per sealed segment, and involves **no cache and no
  trust-on-first-use**. It is a real cryptographic answer to a narrower
  question, rather than a cheaper answer to the full one.
- **`mvmctl trust audit verify`** walks every segment interior end to end, by
  design, and reports per-segment counts. Full cost, deliberately.

Doctor must therefore say what it checked. It attests the active segment and the
segment topology; it does not re-attest sealed interiors. That sentence goes in
the output, not only in a doc.

## Merkle interaction

`mvm_hostd::audit::merkle::{read_leaves, build_root_in, build_inclusion_in}`
read exactly one file. Left alone, the published transparency root would
silently narrow to the active segment the first time a host rotates — a root
that covers less than it used to, with no signal. `read_leaves` must span the
ordered segment set so the root keeps covering the whole history, and leaf
indices must stay globally ordered across segments so existing inclusion proofs
keep meaning what they meant.

## Rotation is atomic against concurrent writers

`sign_and_emit` already holds an exclusive `flock` across the read-cursor /
sign / append critical section, precisely because two supervisor processes for
one tenant would otherwise both restore the same `prev_hash` and fork the chain.
Rotation happens inside that same lock, so two processes cannot both rotate.

The crash-safety case that needs a test: a crash between the rename and the
first write to the fresh active file leaves a sealed segment and no active file.
The next emit must recover by finding the highest sealed segment and continuing
from its tip — not by starting a new genesis chain, which would silently orphan
everything before it.

## ADR-001 amendment (explicit, not quiet)

Claim 8's witness `fn:verify_audit_chain` attests something slightly different
after this change and the ADR must say so:

- Before: "an unbroken chain from genesis".
- After: "an unbroken chain from genesis, or from a signed handoff naming its
  predecessor segment and that predecessor's final chain hash".

Claim 14 (`plan.oci_provenance` recorded in the chain-signed audit log) is
unchanged in substance, but a provenance entry may now live in a sealed segment,
so the claim holds over the *segment set* rather than over one file. The row's
mechanism note says so.

New witnesses added to the claim-8 row, all in
`crates/mvm-hostd/tests/audit_chain_rotation.rs`:

- `naively_dropping_old_entries_fails_verification_at_line_zero` — the genesis
  guarantee survives rotation. This is the demonstration test: it shows the
  naive rotation failing, rather than a comment asserting that it would.
- `a_spliced_segment_is_refused` — a segment moved behind a different
  predecessor fails.
- `a_missing_segment_is_named_not_silently_skipped` — a deleted middle segment
  is reported by sequence number.
- `an_interrupted_rotation_continues_history_instead_of_restarting_it` — a
  crash mid-rotation continues the chain rather than starting a new genesis
  one, which is the only failure mode here that would destroy evidence without
  producing an error.

## Workstreams

- [x] **W1 — paths and naming.** `audit_segment_path` /
      `audit_segment_seq` in `mvm-core::config`; tests pinning that segments are
      in `is_host_lifecycle_chain` scope and do not collide with workload chains.
- [x] **W2 — the failing test first.** Demonstrate the failure mode before
      building the fix: a naively rotated file (truncate and keep appending)
      fails verification at line 0, and a hand-rolled handoff without the signed
      `chain.prev_tip` is refused.
- [x] **W3 — handoff records + verifier relaxation.** `chain.sealed` /
      `chain.continued` entries, using the existing `UNBOUND_PLAN_ID` convention
      for entries that are not plan-bound. Line-0 rule relaxed in
      `mvm-hostd`'s verifier and in `mvm-contract`'s wasm mirror, identically.
- [x] **W4 — rotation under the flock.** Size-triggered rotation in
      `sign_and_emit`, crash-recovery path, concurrent-writer test.
- [x] **W5 — `verify_segment_set` + topology check.** Cross-segment
      contiguity, gap naming, splice refusal.
- [x] **W6 — consumers.** `mvmctl trust audit verify` over the set; doctor's
      active + topology check and the sentence describing what it attests;
      Merkle `read_leaves` spanning the set.
- [x] **W7 — ADR-001 amendment**, claim-8 witnesses, `model/claims.toml`,
      SPRINT + REFACTOR-STATUS.
