# Admission-bound AI assurance sessions

Backing: shipped-source
Validation: a_provider_cannot_smuggle_an_mvm_binding_through_the_request_parser

Status: **W1–W4, W6/W7, W7b landed. W5, W8 open.**

An AI workload can drive a Scout-linked assurance campaign from inside an
admitted microVM. This plan is the MVM half of that: the typed envelope the
workload receives, the authority it runs under, the one probe verb it may
call, and the host-derived outcome.

The counterparty is `mvm-assurance` (`mvm-scout` + `mvm-security`). It owns
source analysis, campaign planning, and the final evidence report. It does not
own — and must not simulate — the microVM lifecycle, the isolation controls,
the observer signals, or the admission facts.

## Trust split

Everything crossing into an AI session is an identifier, a digest, or a
reference. No secret value, host path, socket name, or log body appears in any
type in `mvm_contract::assurance`.

Three properties are structural rather than checked at runtime:

- The provider's half of the envelope (`AssuranceSessionRequest`) cannot carry
  admission facts. `deny_unknown_fields` refuses an `mvm_binding` key outright,
  and the assembled `AiSessionInput` has no `Deserialize` at all — it is only
  constructible from an `MvmBinding` derived from a signed `ExecutionPlan`.
- The AI's reply (`TrialResultCandidate`) has no outcome field, so
  "the model wrote PREVENTED" is not a representable state.
- Effective authority is one intersected value (`EffectiveAuthority`), not a
  set of checks spread across the dispatch path.

## Landed

- [x] **W1 — Contract.** `mvm_contract::assurance`: bounded ids/digests/refs,
      the `mvm.assurance.ai-session-input/v1` envelope, the AI candidate, the
      host-assembled `mvm.assurance.trial-result/v1` document, and size,
      length, collection, budget and control-character limits. Nesting depth is
      fixed by the schema — there is no recursive type and no free-form
      `Value` — so there is no depth counter to get wrong.

- [x] **W2 — Admission binding and authority.** `MvmBinding::builder().plan(&plan)`
      quotes the admitted plan; the builder refuses a binding that cites no
      audit entry or no receipt. `EffectiveAuthority::intersect` narrows
      extension maximum ∩ request ∩ policy ceiling ∩ signed grant ∩ explicit
      approval, and a `campaign_probe.v1` without operator approval does not
      survive it.

- [x] **W3 — Probe surface.** `host.assurance.v1` in `mvm-hostd`, registered
      only when `ExecutionPlan.services` names it, exposing one verb. The AI
      selects a declared destination *label*; the host resolves it against the
      campaign's operator-declared table and consults the live
      `mvm_core::egress_broker::decide_egress`. Idempotency-key replay returns
      the first result without burning a step; nonce replay, session/trial
      mismatch, step exhaustion and deadline expiry each refuse distinctly.

- [x] **W3.1 — Counterparty wire conformance.** `assurance::wire` projects the
      exact key sets `apps/mvm-security/src/ai_session.rs` validates, and the
      envelope reports *effective* authority — the counterparty rejects the
      `deadline_unix_ms: 0` a request may carry to mean "none set".

- [x] **W4 — Guest-side API.** `mvm_agentd::assurance::AssuranceCampaign`
      reads the delivered envelope and calls declared probes by *label*. The
      surface offers no method taking a command, path, host, port, or socket —
      not by convention, but because no such parameter exists on it. Local
      guards fire before any round-trip, and nonces are session-scoped and
      single-use. Reading the envelope needed a direction-specific type:
      `AiSessionInput` is serialize-only so the host can never parse admission
      facts out of provider bytes, so the guest reads `DeliveredSession`, and a
      test asserts the two describe the same document.

- [x] **W6/W7 — Audit and receipt emission.** `mvm_hostd::audit::assurance`
      writes `assurance.session_opened`, `assurance.probe` and
      `assurance.trial_completed`; the first and last carry an execution
      receipt. Emission is **fail-closed**: the ordinary emit path treats
      receipts as a derived cache and swallows their errors, which is wrong for
      evidence a claim rests on, so an evidence-bearing emit errors instead. A
      probe whose record cannot be written is refused (`AuditUnavailable`) and
      leaves no trace of an attempt. References are content digests of the
      exact signed entry bytes, and `resolve_audit_ref` finds the line back on
      disk — asserted by test, so a citation is resolvable rather than
      decorative. Records carry the declared *label*, never the host or port
      behind it.

- [x] **W7b — Session lifecycle on the boot path.** `assurance_session::open`
      mints a derived grant, intersects authority, records
      `assurance.session_opened`, builds the binding from those references, and
      opens the session — refusing outright if the plan does not bind
      `host.assurance.v1`, if the campaign declares no edge, or if the record
      could not be written. `AdmitAndStartParams.assurance` carries an
      operator-declared campaign through the real boot path, and a test asserts
      `admit_and_start` produces a live session whose binding quotes the
      admitted plan. Assurance stays off the ordinary launch path: `None` is the
      default and every existing call site takes it.

      The plane is a process-global installed when the broker registry binds the
      service, but `open_on` takes it explicitly — a `OnceLock` admits one
      value, so a decision path only reachable through the global would be
      testable exactly once per process.

## Open

- [ ] **W5 — Observer and cleanup evidence.** `EvidenceSet` is consumed by the
      evaluator but nothing populates `observer_verified` /
      `cleanup_verified` / `attestation_verified` from a real run yet. Until
      that lands every live trial evaluates to `INCONCLUSIVE`, which is the
      correct fail-closed behaviour and not a certifying result.

- [ ] **W8 — Provider binary.** The counterparty's
      `assurance run --provider <path>` spawns a framed-stdio provider speaking
      `mvm.security.campaign-request/v1`. MVM ships no such binary, so no
      certifying campaign can run today. See the blocker note below.

## Cross-repository blocker

`mvm-security assurance plan` reports the brokers it needs and cannot reach:

```
immutable_snapshot, builder_microvm, subject_microvm, guest_observer,
host_observer, execution_receipts, artifact_sealing
```

Seven, of which this plan's landed work addresses none directly — W1–W3 build
the authority and contract layer those brokers would be driven through. The
counterparty's own milestone M3 ("broker-backed execution") is unstarted, and
its plan 006 states plainly that an ordinary `machine run` receipt must remain
`INCONCLUSIVE`. Until W5–W8 and M3 both land, the only provider that exists is
`mvm-security-fixtured`, which is explicitly non-certifying.

## Narrative coverage

The one implemented probe is `egress.admission.v1`, which serves
network-egress narratives. The campaign the reference scan actually emits is
`mvm.boundary.tool-authority.v1`, which it does not serve. Adding a probe is a
new `ProbeInvocation` variant plus its dispatch arm; the enum is closed so a
variant without an arm does not compile.
