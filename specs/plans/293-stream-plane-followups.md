# Plan 293 — stream plane follow-ups

**Status:** Proposed.

Close the two reachability gaps plan 283 shipped knowingly, and add the two
gates that would have caught the classes of defect that cost it the most.

Predecessor: `specs/plans/283-workload-stream-plane.md`. Claim status:
`specs/adrs/001-microvm-security-posture.md`, the Preview 17 limits note.

## Why these four together

Plan 283 shipped 22 tasks. Six of them were added mid-execution, and every one
was the same shape: correct, tested machinery with no production caller. Nine
separate times its prose asserted a security property the ledger did not back —
including a witness that existed nowhere in the tree, and five user-facing files
still stating a claim the ADR had already downgraded.

Both classes were caught only by review, which is not a control. WS3 and WS4
turn them into gates. WS1 and WS2 close the two holes that remain visible to a
user or an auditor.

## Workstreams

- [ ] **WS1 — bind the secret set, and close claim 17's last reachability limit.**

  `InputGate::bind` has no production caller, so the cross-frame secret scan
  matches against an empty set on every real VM. The scan is correct and tested;
  it has nothing to scan for.

  Source the workload's known secrets at plane construction and bind them, so
  the scan is operative on a real launch. This is wiring, not new machinery.

  Two things not to lose. The scan is a backstop against a confused caller, not
  a defence against a determined one — encoding, derivation, and splitting
  inside a window boundary all defeat it, and the docs say so. Do not let
  binding a real set turn that honest framing into an overclaim. And the sliding
  window must still span frame boundaries: a secret split across two writes is
  the case the scan exists for.

  Then reassess claim 17. Two of its four limits closed when the channel gained
  an operator surface. This closes a third. State plainly what remains rather
  than promoting on momentum.

- [ ] **WS2 — redact the console fallback.**

  The transcript is redacted; the console fallback is not. The fallback is what
  a detached run resolves to, which is the common shape rather than the corner.

  It is worse than a gap in coverage. The follower stops before `kill()`, so
  shutdown-time output — panics, the last thing a guest says, the most
  diagnostic material there is — lands only in the unredacted file. The moment
  most worth reading is the one least protected.

  Run the same `PiiRedactor` over console bytes on the read path, before they
  reach a consumer. Read-side, so the file the VMM owns is untouched.

  Keep the existing notice honest: it currently tells an operator the console
  merges streams, is unchained, and is unredacted. When the third stops being
  true, the notice must stop saying it.

- [ ] **WS3 — gate prose against the ledger.**

  `check-claim-catalog` reads the claims table in ADR-001. Nothing reads the
  prose around it, which is why nine drifts survived: `CLAUDE.md` cited a
  claim-12 witness that exists nowhere, `README.md` and four other files still
  asserted claim 15 in its absence form after the ADR had downgraded it, and
  ADR-035 contradicted the ledger it cites.

  Scan `README.md`, `public/`, `specs/`, and `CLAUDE.md` for claim-shaped
  assertions — "no interactive access", "there is no ... path", "cannot reach",
  "is not possible" — and require each to sit next to a citation of a ledger
  row. A phrase inventory is enough for a first cut; it would have caught eight
  of the nine.

  Prove it on the history: check out a commit from before each drift was fixed
  and confirm the gate fires. A gate nobody has seen fail is the defect it is
  meant to prevent.

- [ ] **WS4 — gate dormant controls.**

  Six times plan 283 shipped a security-relevant symbol with no production
  caller, each found by review rather than by CI. The failure mode is a control
  that reports present and cannot fire: an admission gate reading an argv nobody
  populates, a broker nothing constructs, a scan whose set is always empty.

  Hold a declared allowlist of security-relevant symbols that have no production
  caller. The gate fails when a symbol not on the list acquires that shape, and
  the allowlist may only shrink. Dormancy stops being an oversight and becomes a
  declaration with a name attached.

  Seed it from what is known dormant today and expect it to surface more. That
  is the point — the six found on plan 283 were the ones review happened to
  reach.

## Sequencing

WS1 and WS2 first: both are visible to a user or an auditor today, and WS1 is
what a reader of claim 17 would reasonably assume already holds.

WS3 and WS4 after, cheap and preventive. WS4 subsumes WS1's failure mode, so
landing WS1 first gives the gate a real closure to record rather than a
hypothetical.

## Out of scope

VM-to-VM fan-out (`specs/plans/292-fleet-stream-fan-out.md`). The deferred
minors in plan 283's ledger — they are individually small and want triage, not a
workstream.
