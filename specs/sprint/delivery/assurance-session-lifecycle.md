# Assurance sessions: the boot-path lifecycle

Plan: `specs/plans/2026-08-17-admission-bound-ai-assurance-sessions.md` (W7b)

## What landed

`open_session` had no production caller, so the probe surface was reachable
only from a test. `assurance_session::open` closes that: it mints a grant,
intersects authority, records `assurance.session_opened`, builds the binding
from those references, and opens the session. `AdmitAndStartParams.assurance`
carries an operator-declared campaign through the real boot path, and a test
asserts `admit_and_start` produces a live session whose binding quotes the
admitted plan.

Assurance stays off the ordinary launch path. `assurance: None` is the default
and every existing call site takes it, so a run that declares no campaign does
no discovery and no work.

**The operator declares the campaign; the plan decides whether any of it is
allowed.** `CampaignDeclaration` carries the destinations, their host/port, the
approved tools and the requested authority — all host-side. It is deliberately
not a signed-plan field: a campaign is chosen per run against a plan that may be
reused, and putting it in the plan would mean re-admitting a workload to
re-point a probe. What the plan decides is whether a session may exist at all;
one that does not bind `host.assurance.v1` gets nothing regardless.

**Identifiers are derived, not random.** The session id and grant nonce are a
digest over plan, VM and campaign, so re-opening the same campaign against the
same plan yields the same session rather than silently a second one — and the
whole path is reproducible in a test. The grant digest covers the grant's own
content, so two grants differing in expiry or scope cannot share one.

**Ordering is the control.** Authority is intersected before anything is
recorded; the session is recorded before it is opened; the open happens after
the VM is running and after `plan.launched`. A session that existed but was
never written down would let a probe run against a binding citing an audit entry
nobody wrote, and a refusal to record fails the boot rather than leaving a
campaign that reports observing nothing.

## Two bugs the real path exposed

Both were invisible to every test written before this one, and both would have
broken the first genuine campaign.

**The binding rejected every real plan.** `MvmBindingBuilder::plan()` parsed
`plan_id` as an identifier, but a plan id is a content address — `sha256:<hex>`
— and `:` is not in the counterparty's identifier grammar. The `fixture-plan`
id used by every prior test sailed through. The separator is now rendered as
`-`, which is unambiguous because hex carries none.

**The handler compared the wrong session identity.** It checked the request's
`session_id` against `ctx.session_id`, the supervisor's workload key. Those are
different things: the supervisor's key is the authoritative *lookup*, while the
binding's id is the assurance identity the guest was told. They were only ever
equal because a test used one string for both. The request is now checked
against the binding, which is what a guest legitimately knows.

## Testability note

The plane is a process-global installed when the broker registry binds the
service, but `open_on` takes it explicitly. A `OnceLock` admits one value, so a
decision path reachable only through the global would be testable exactly once
per process — fine under nextest, silently wrong under `cargo test`.

## What is still not true

No certifying campaign can run. Observer, cleanup and attestation evidence still
have no producer (W5), so a live trial evaluates `INCONCLUSIVE` by design, and
the framed-stdio provider the counterparty spawns exists in neither repository
(W8). There is also no CLI surface yet for supplying a `CampaignDeclaration`:
the boot path accepts one, but only an in-process caller can pass it.
