# Assurance evidence: what the host can actually attest

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md` (W5, partial)

## What landed

`assurance_session::collect_evidence` assembles the `EvidenceSet` the evaluator
consumes. Every field is read from something the host itself did or can check
now — the probes it recorded, the plan it admitted, the state dir it can look
at. Nothing comes from the workload or from the declaration, which is what
makes the result evidence rather than a claim.

`cleanup_verified` reads the state dir through `state_dir_has_live_process` —
the same probe the admission budget trusts, rather than a second liveness
notion that could disagree with it. A VM still carrying a live pid marker has
not been cleaned up, whatever the plan intended. `disposable_target` comes off
the signed plan's `post_run`.

`attestation_verified` stays false because no provider is wired. The evaluator
only consults it when the plan demands attestation, so a `Noop` plan is
unaffected and a demanding one fails closed rather than being waved through.

## The honest limit, stated plainly

`observer_verified` is true when **MVM** recorded a probe and an effect was
attempted. That is real evidence the trial was exercised, and it closes a gap
worth closing: an unexercised session can no longer read as observed.

It is *not* an independent observer corroborating what happened inside the
guest, which is what the assurance contract means by the word. Calling it one
would be the exact overclaim this whole subsystem exists to prevent.

So the remaining gap is narrower and more specific than "W5 is unfinished": it
is a guest-side signal for whether the attempted effect took hold inside the
VM, corroborated host-side. That is tracked as W5b, and it is closer in shape to
W8's provider work than to the evidence plumbing here.

## The test that keeps this honest

`evidence_from_a_real_session_still_evaluates_inconclusive_today` opens a real
session, assembles everything the host can attest, and asserts the verdict is
*still* `INCONCLUSIVE` with reason `ObserverMissing`. It exists so that
assembled evidence is never mistaken for a certifying result, and so that when
W5b lands, the test that changes is the one that should.
