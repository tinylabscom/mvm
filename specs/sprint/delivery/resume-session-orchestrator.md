# Resume session orchestrator: re-admission for a parked session

`specs/plans/2026-08-18-durable-agent-sessions.md` D5 sketches resume as a
nine-step sequence and names two of them — synthesis and admission — as the
hard constraint the whole design rests on: admission has to stay cheap
because it now runs once per resume rather than once per task. This branch
delivers those two steps, on top of the session store
`specs/plans/2026-08-18-durable-session-substrate.md` and
`specs/plans/2026-08-18-durable-session-park.md` landed and the ledger-head
fence `specs/plans/2026-08-18-session-approval-head.md` landed —
`specs/plans/2026-08-18-resume-session-orchestrator.md` Tasks 1–2, with no
VM, backend, or async surface involved.

## Delivered

- `mvm_hostd::session_resume::ResumePlanMaterial` — the workload facts a
  session record cannot know: backend name, image name and its sha256,
  kernel sha256, cpu count, memory. Kept separate from
  `AgentSessionRecord` deliberately: the record describes the session,
  material describes the workload, and folding them together would make the
  record a second, staler copy of the plan.
- `synthesis_for_resume(record, material) -> SynthesisInput` — a struct
  literal mirroring `crate::run`'s field choices (the local-run path uses a
  literal rather than `SynthesisInputBuilder`, so this follows suit), with
  the deliberate differences called out in comments: `vm_name` is the
  session id rather than the parent sandbox's name, `destroy_on_exit: false`
  because a resumed session outlives the call that admits it, and
  `audit_labels` carrying `session_id`, `session_generation` (the generation
  the resume *opens* — record generation + 1, since synthesis runs before
  the transition), `session_parent_checkpoint`, and `session_approval_head`
  when the record has one (omitted rather than blanked when absent, so a
  reader of the chain can tell "never recorded" from "recorded empty").
- `resume_session(sessions, checkpoints, req, clock, ledger)` — load →
  require `Hibernated` → resolve `parent_checkpoint` → `verify_content` on
  it → `synthesis_for_resume` → `admit_for_run` → only then
  `AgentSessionStore::resume`. 12 tests, including the ordering property
  itself: `a_refused_admission_leaves_the_session_parked` asserts a host
  ceiling that refuses the workload leaves the on-disk record untouched, and
  the module doc records that this was verified non-vacuous by moving the
  `resume` call ahead of verification and admission and confirming both
  `a_refused_admission_leaves_the_session_parked` and
  `a_tampered_parent_checkpoint_refuses_before_admission` go red before the
  ordering was restored.
- `ResumeRequest` (a params struct: session id, expected generation, current
  approval head, material, signer key dir, wall clock) and `ResumedSession`
  (the advanced record plus the `AdmittedPlan` that authorized it —
  `AdmittedPlan` has only private fields, so holding one is the only proof
  admission ran).

## The ordering property, precisely

The property the tests pin is **no step that can refuse runs after the
record has moved** — not "admission is the last step that can fail". The
store's own generation and approval-head fences run inside
`AgentSessionStore::resume`, *after* `resume_session` has already signed a
plan. That is intentional (duplicating the store's fences here is how the
two copies start disagreeing), and it costs nothing that matters: the store
writes only on success, so a fence-refused resume just burns an admission —
the signed plan is dropped unused and reaches no backend. The module's own
doc comment states this distinction directly, after an earlier version of
the ordering-test comment claimed the stronger, inaccurate version.

## Deliberately not covered

Everything D5 sketches past steps 4 and 5, and one gap inside the two steps
delivered:

- **`verify_content`, not lineage verification.** The resume point is
  checked for content integrity only — a byte-flipped blob refuses. There is
  no `verify_lineage` call against a signed `CheckpointChainAnchor`, so a
  checkpoint that was never audited but is bit-for-bit intact would still be
  accepted; no caller in the workspace holds an anchor to check against.
- **`grants: None`.** `ResumePlanMaterial` has no grant surface, so the
  synthesized plan arms neither a wall-clock timer nor a CPU share. D5's
  step-4 line "grants = exactly the approved scope" has nothing behind it,
  and the `Preview` claim 18 limitation D5 names step 4 as retiring is not
  retired. Adding a grants field to `ResumePlanMaterial` directly is a named
  trap in the plan's "Deferred to later plans" section: `ResumePlanMaterial`
  is caller-supplied, with no relationship to the approval head, so grants
  arriving that way would leave the approval fence checking a digest while
  the grants beside it come from somewhere else. Whoever adds grants has to
  derive them from the approved scope, not take them as a caller argument.
- **Tier selection, `PostRestore` fabric re-registration, credential
  minting at the substitution endpoint, and the chain entry (WS7).** None
  of the four exist on this branch. `resume_session` stops at an admitted
  plan; nothing in the workspace boots a backend, restores a memory image,
  or replays a journal from one.
- **`resume_session` has no caller.** Confirmed exhaustively:
  `grep -rn "resume_session" --include="*.rs" .` outside
  `crates/mvm-hostd/src/session_resume.rs` returns zero matches. It is not
  wired to a CLI verb, a broker handler, or any other host code path, so
  none of the above runs on a real resume yet — only under its own tests.
- **`RunPosture::without_backend(Variant::Dev)` is hardcoded**, not carried
  on `ResumeRequest`. Sound today only because the plan has no grants at
  all — `Dev` and `Prod` diverge on `enforceability_gate`'s treatment of a
  declared grant, and a grantless plan gives that gate nothing to diverge
  on. The same change that adds grants has to move posture onto the
  request, and nothing today would catch it if that were forgotten.
- **Audit-label collision risk for WS7.** `supervisor::audit::for_plan`
  lets a per-event extra override a plan label of the same key. The
  `session.resumed` / `session.parked` emitters this needs must not reuse
  `session_id` or `session_generation` as extras keys, or the signed plan's
  value is silently replaced by the emitter's.
