# Admission-bound AI assurance sessions — contract, authority, probe surface

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md`

## What landed

`mvm_contract::assurance` (new module, `protocol`-gated like `plan`) and
`host.assurance.v1` in `mvm-hostd`. 65 new tests, all green.

The load-bearing decisions, and why they are shaped the way they are:

**The envelope is two types, not one.** `AssuranceSessionRequest` is the
untrusted provider half and derives `Deserialize` with `deny_unknown_fields`;
`AiSessionInput` is the assembled envelope and derives `Serialize` only. A
provider that sends an `mvm_binding` key fails parsing, and a forged binding is
not a check that can fail — it is a value that cannot be built. One type with a
runtime check would have put the parser that reads provider bytes and the
parser that can populate admission facts in the same place.

**The AI has no verdict field.** `TrialResultCandidate` reports what was
attempted and what it believes it saw. `PREVENTED` and `CONTAINED` are computed
by `evaluate` from host evidence.

**Disagreement is fatal rather than ignored.** The host observes the same three
facts the candidate reports. The obvious design uses the host's values and
discards the model's; this one compares them and returns `INCONCLUSIVE` on a
mismatch, because a model contradicting the observer is a signal that something
is wrong with the trial, and silently overwriting it throws that signal away.

**Authority is one intersected value.** `EffectiveAuthority::intersect` narrows
extension maximum ∩ request ∩ policy ceiling ∩ signed grant ∩ explicit
approval. Five checks spread across the dispatch path fail open the first time
someone adds a caller and forgets one.

**The probe takes a label, not a destination.** The model names a declared
label; the host resolves it against the campaign's operator-declared table and
calls the live `mvm_core::egress_broker::decide_egress`. An undeclared label
never reaches the policy engine, and the test for that also asserts nothing was
recorded as attempted — so an unrestricted policy cannot become a crossed
boundary by accident.

## Drift corrected against the counterparty

The implementation prompt described `mvm.assurance.trial-result/v1` as the
document the AI returns, carrying five fields. The counterparty's actual
validator (`apps/mvm-security/src/ai_session.rs`) reads that schema as an
exact **eighteen**-key host record including `identity_verified`,
`observer_verified`, `cleanup_verified` and `attestation_verified` — none of
which a model is in a position to assert. Conforming to the code rather than
the prose: the AI's reply is
`mvm.assurance.trial-result-candidate/v1`, and MVM assembles the
eighteen-key `trial-result/v1` document.

Two further shapes were wrong in the prompt and are now conformed:
`mvm_binding` is a flat ten-key block (the grant is projected into
`session_grant_digest` / `expires_at_unix_ms` / `nonce` / `allowed_tools`), and
`authority.deadline_unix_ms` must be `>= 1` — so the envelope reports
*effective* authority, since a request may legitimately carry `0` to mean "no
deadline set". Exact key sets are asserted by test in both directions.

## What this does not prove

No certifying campaign can run. `mvm-security assurance plan` names seven
brokers it cannot reach, the counterparty's broker-backed execution milestone
is unstarted, and the only provider binary that exists anywhere is the
explicitly non-certifying `mvm-security-fixtured`. Observer, cleanup and
receipt evidence are consumed by the evaluator but not yet populated from a
real run, so a live trial evaluates to `INCONCLUSIVE` — correct, fail-closed,
and not a pass. Plan W4–W8 track the rest.
