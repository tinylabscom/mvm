# Session exact replay and retention deadlines

`specs/plans/2026-08-18-durable-agent-sessions.md` WS3, WS4, WS5 and WS7.

Before this, a caller whose `agent-session park` or `resume` applied but whose
response was lost could not retry safely. A retried park refused because the
session was no longer active; a retried resume refused because it was no longer
parked. The caller could not tell "not applied" from "applied, response lost".

## Delivered

- **Transition identity** (`crates/mvm-core/src/session_transition.rs`).
  `TransitionIdentity` is a SHA-256 over the domain tag
  `mvm.agent-session.transition.v1` followed by length-prefixed fields: the
  kind, the session id, the observed generation (8 bytes, big-endian), a section
  of observed state and a section of request inputs. Each section is
  length-prefixed and counted, and each optional value carries a presence byte,
  so an absent input and an empty one hash apart, and `("ab", "c")` never
  collides with `("a", "bc")`. Inputs sit in ordered maps, so the order a caller
  adds them in does not move the digest. Timestamps are never part of it.
  `SessionTransitionDigest` is its own `sha256:<64-hex>` newtype over the shared
  `digest_shape` check, not a reused checkpoint digest or approval head. The
  encoding is pinned by a golden digest, because a moved encoding would stop
  every stored record from recognising its own retries.
- **Recorded last transition** (`crates/mvm-runtime/src/agent_session/mod.rs`).
  `AgentSessionRecord::last_transition` holds the identity, its digest, and the
  admitted plan id for a resume. Only the last transition is kept; a retry of
  anything older is refused as superseded.
- **`classify_retry`** decides replay, conflict or apply, in that order. The
  replay check comes before the generation fence, because a resume that applied
  has already moved the generation its retry observed. The typed
  `TransitionConflict` is either `ChangedRequest` (same step, different inputs,
  each named — `reason: recorded approval_wait, retried operator`) or
  `Superseded` (the record is at another generation, naming the transition that
  moved it).
- **`GenerationFence`** replaces the bare `u64` on `AgentSessionStore::park`.
  `Observed(n)` fences and makes a retry replayable. `ReadCurrent` reads the
  generation at call time, which fences nothing and cannot claim a replay; a
  retry then refuses on the state machine as it did before, now naming the last
  transition.
- **Resume** (`crates/mvm-hostd/src/session_resume.rs`). `resume_claim` covers
  the asserted approval head, every `ResumePlanMaterial` field, and whether the
  resume boots. `resume_session` classifies before the residency check and
  before admission, so a replay signs no second plan. It returns `ResumeOutcome`
  (`Resumed` or `Replayed`), and `ReplayedResume` carries the recorded
  `admitted_plan_id`. The store also classifies at write time, so two retries
  racing past the orchestrator's check still write once.
- **`resume --boot` is refused, never replayed.** The record moves before the
  boot is attempted, so it reads the same whether that boot succeeded, failed,
  or has since exited. Reporting "booted" from it would claim something the
  record does not know, and booting again would start a second sandbox for one
  residency. The refusal says the resume applied, at which generation and under
  which plan, so the caller can tell it apart from a resume that never happened.
- **CLI** (`crates/mvm-cli/src/commands/agent_session.rs`). `park` and `resume`
  take `--expected-generation <n>` and `--json`. A replay prints
  `replay: this park had already applied; nothing was written and no audit entry
  was added`, or `"replayed": true` in the JSON report. A replay chains nothing.
  The help text says that without the flag a retry cannot be recognised.
  `agent-session` JSON output now reserves stdout (`emits_machine_readable_stdout`),
  so a chain warning goes to stderr instead of corrupting the report a retrying
  caller parses.

## Tests

- `mvm-core`: golden digest, identical identities, input-order invariance, every
  field moving the digest, absent against empty, length-prefix boundaries,
  observed against input sections, domain separation, same-slot semantics,
  difference naming, serde round trip, malformed-digest refusal.
- `mvm-runtime`: park replay writes no byte and keeps the original
  `updated_unix`; a changed reason conflicts naming it; a `ReadCurrent` retry
  cannot replay; a `ReadCurrent` park replays for a caller who supplies the
  generation; resume replay after the generation moved; changed material
  conflicts; a superseded retry names the generation; park identity covers every
  input; the hashed reason is the stored spelling; record round trip.
- `mvm-hostd`: resume replay under a host ceiling that would now refuse
  admission (so a replay provably skips admission); changed material refused;
  a `ReadCurrent` retry refuses; the identity ignores the clock and signer; the
  identity covers every material field, boot, head and generation; a retried
  boot resume starts no second sandbox, writes nothing, and leaves exactly one
  `session.resumed` entry; a plain retry of a boot resume conflicts on `boot`.
- `mvm-cli`: a park replay through the real chain writer leaves one
  `session.parked` entry and reports `"replayed": true`; a changed reason
  conflicts and chains nothing; a stale expected generation is refused; resume
  replay and boot-replay refusal at the CLI (`test-support`); report rendering;
  argument parsing for `--expected-generation` and `--json`.
- `tests/cli.rs`: help lists the flags, a non-numeric generation is refused, and
  `open` → `park --json` → identical `park --json` against the real binary
  reports `replayed` false then true, then a changed reason is refused.

## Retention deadlines

A parked session had no deadline, so how long it was kept depended only on pool
TTLs tuned for warm capacity. This change gives each park a deadline.

- **`AgentSessionRecord::retain_until_unix`.** Park sets it to now plus
  `ParkInput::retention_secs()`, which is the explicit `retain_for_secs` or
  `default_retention(reason)`. Resume clears it. The defaults are named
  constants tied to what they stand for: `APPROVAL_WAIT_RETENTION` is
  `MAX_APPROVAL_TTL_MS`, and `IDLE_RETENTION` is `STANDBY_POOL_TTL`.
  `HOST_SHUTDOWN_RETENTION` and `OPERATOR_RETENTION` are 48h, the plan's
  unmeasured starting proposal. `RETENTION_DEMOTION_RETENTION` is 30d. The
  resolved retention is a park identity input, so a retry with another
  `--retain-for` conflicts and names it.
- **`AgentSessionRecord::renew`** moves the deadline only later. It refuses
  `WouldShorten`, `Expired` ("already past its promise"), `NoDeadline`, a closed
  session and an active one. A renewal to exactly the current deadline is not a
  shortening.
- **`AgentSessionStore::renew`** goes through `classify_retry` like park. A
  renewal observes the deadline it extends: `renew_claim` records that deadline
  as observed state, not as an input. Successive renewals share a generation,
  and the observed deadline is what separates a retry of one renewal from the
  next renewal. A replay needs both `--expected-generation` and
  `--expected-deadline`. A deadline that moved since the caller read it is
  refused as `TransitionConflict::ObservedStateMoved`, naming both values.
- **`RetentionStatus`** (`Alive { until_unix, remaining_secs }` /
  `Expired { until_unix, expired_for_secs }`) is derived from the clock, never
  stored. `ls` prints `retention=alive(2h left)` / `retention=expired(3h ago)`.
  `show` prints `retain until:` with the same status. Under `--json` both add a
  `retention` object beside the flattened record.
- **CLI.** `park --retain-for <duration>` and
  `renew <id> --for <duration> [--expected-generation] [--expected-deadline] [--json]`.
  Durations go through the shared `mvm_core::crypto::policy::parse_ttl` (1s to
  30d).
- **Audit.** `AuditEmitter::emit_session_renewed` writes `session.renewed` under
  the member sandbox's persisted plan, as a park is. Its extras are
  `renewed_session`, `renewed_at_generation`, `renewed_until_unix` and
  `renewed_from_unix`, all disjoint from the signed plan labels. The park entry
  gains `park_retain_until_unix`. The event is registered in the lifecycle
  classification test and in `tests/audit_total_coverage.rs`, and a replayed
  renewal adds no entry.

### Not delivered: automatic demotion on expiry

No scheduler acts on an expired deadline, and none was wired, because no
demotion today is truthful. `AgentSessionRecord::demote` rewrites `storage_tier`
and nothing else. `SupervisorStandbyPool::demote_to_saved_state` clears a pool
standby's pid and child, but no session record names a standby. A scheduler
calling either would report RAM or a memory image released when neither was.
An expired session is therefore reported and refuses renewal, but still resumes
and still pins its resume point. The plan tracks the scheduler as an unchecked
WS5 item.

### Tests

- `mvm-runtime`: every reason's default maps to its constant, and the approval
  and idle constants equal what they are tied to; park sets the default or the
  explicit deadline; resume clears it; renew extends; a shortening, an expired
  session, and a closed or active session all refuse; renewing to exactly the
  current deadline is not a shortening; the alive/expired boundary; a store renew
  replay writes nothing; a renew from the new deadline is a new renewal; another
  extension from the same deadline conflicts naming it; a moved deadline refuses
  naming both values; a renew without an observed deadline cannot replay; a
  store renewal of an expired session writes nothing; the renew identity ignores
  the clock; record round trip; the park identity covers the retention.
- `mvm-hostd`: `session.renewed` is chain-signed and keeps the plan labels.
- `mvm-cli`: `--retain-for` sets the deadline, the default applies without it,
  and a malformed value is refused before the record moves; a changed retention
  conflicts; renew through the real chain writer leaves one `session.renewed`
  after an exact retry; shortening, expired, closed, active and a malformed
  duration are refused; renew extras do not collide with plan labels; `ls`/`show`
  report alive and expired in text and JSON; an active session reports no
  retention; park extras carry the deadline; argument parsing for `renew` and
  `--retain-for`.
- `tests/cli.rs`: renew and park help list the flags. Against the real binary,
  open → park `--retain-for 1h` → `show --json` (alive) → an exact renew twice
  (`replayed` false, then true) → a shortening renew refused.
