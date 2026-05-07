# Plan 51 — `mvmctl session {set-timeout, kill, info}` verbs

Status: **Proposed.**

## Background

mvmforge ships a typed `Session` class with three operations the
substrate doesn't yet expose at the CLI:

- `Session.set_timeout(seconds)` → `mvmctl session set-timeout <s> -- <id>`
- `Session.kill()` → `mvmctl session kill -- <id>`
- `Session.info()` → `mvmctl session info -- <id>` (JSON on stdout)

mvm's session machinery exists in
`mvm/crates/mvm-runtime/src/vm/lifecycle.rs` (`boot_session_vm`,
`dispatch_in_session`, `tear_down_session_vm`) per Sprint 43 / plan 32
PRs #21–#22. Currently consumed only by `mvmctl invoke`. There is no
`mvmctl session` subcommand yet — these verbs are net-new CLI surface
on top of existing runtime primitives.

mvmforge's test fixture at
`mvmforge/tests/fixtures/fake-mvm` implements `session start` and
`session stop` today (lines 154-193); set-timeout, kill, and info are
not yet implemented there — they're placeholders awaiting upstream.

## Goal

Add the three lifecycle verbs as a new `mvmctl session` subcommand
group. Plan 52 will add `attach`, `exec`, `run-code` to the same
group.

## Implementation

### Step 1: Subcommand directory

Create `mvm/crates/mvm-cli/src/commands/session/`:

```
mvm/crates/mvm-cli/src/commands/session/
├── mod.rs              # subcommand router (clap derive)
├── set_timeout.rs      # this plan
├── kill.rs             # this plan
├── info.rs             # this plan (read-only; audit-emit exempt)
├── attach.rs           # plan 52
├── exec.rs             # plan 52
└── run_code.rs         # plan 52
```

Register in `mvm/crates/mvm-cli/src/lib.rs` alongside existing
subcommand groups.

### Step 2: `session set-timeout`

Argv shape: `mvmctl session set-timeout <seconds> -- <session-id>`.

- Parse seconds; clamp to `[1, 86400]` (1 day max — matches existing
  TTL bounds in `crates/mvm-security/src/policy/ttl.rs:38-76`).
- Read session registry; if session id not found, exit 1 with
  envelope `kind="session-not-found"`.
- Update session's `idle_timeout_secs` field; write registry
  atomically.
- The existing reaper (or session reaper, if separate) picks up the
  change on its next walk.
- Audit emit: new `LocalAuditKind::SessionSetTimeout { session_id,
  old_timeout_secs, new_timeout_secs }`.

### Step 3: `session kill`

Argv: `mvmctl session kill -- <session-id>`.

- Read session registry; if missing, exit 1 with `session-not-found`.
- Invoke `tear_down_session_vm(session_id)` from
  `mvm-runtime/src/vm/lifecycle.rs`.
- In-flight invokes against this session resolve as failures —
  envelope `kind="session-killed"`. Plan 52's fd-3 work delivers
  the envelope shape; until then, exit code + stderr per existing
  convention.
- Audit emit: `LocalAuditKind::SessionKill { session_id }`. Reuse
  existing `Kill` variant if it covers this case (per
  `audit.rs:81-107` lists a reserved `Kill` for plan 37); otherwise
  add a fresh `SessionKill` variant.

### Step 4: `session info`

Argv: `mvmctl session info -- <session-id>`.

- Read session registry.
- Emit JSON on stdout with the agreed schema (TBD with mvmforge —
  surface a draft and ask for sign-off).

Draft schema (subject to mvmforge agreement):

```json
{
  "session_id": "ses-abc123",
  "workload_id": "adder",
  "state": "running" | "paused" | "killed",
  "mode": "prod" | "dev",
  "created_at": "2026-05-06T12:34:56Z",
  "last_invoke_at": "2026-05-06T12:35:01Z",
  "invoke_count": 42,
  "idle_timeout_secs": 300,
  "tags": {"key": "value"}
}
```

Read-only verb; exempt from audit-emit gate per the read-only
suffix list (`info.rs` is on the exempt list per `mvm/CLAUDE.md`).

### Step 5: New `LocalAuditKind` variants

Modify `mvm/crates/mvm-core/src/policy/audit.rs`:

```rust
SessionSetTimeout { session_id: String, old_timeout_secs: u64, new_timeout_secs: u64 },
SessionKill       { session_id: String },
// SessionAttach, SessionExec, SessionRunCode added in plan 52
```

Update CLI audit-emit checker (`scripts/check-cli-audit-emit.sh`)
to recognize the new kinds; ensure `info.rs` stays exempt.

## Critical files

- New: `mvm/crates/mvm-cli/src/commands/session/{mod,set_timeout,kill,info}.rs`
- Modified: `mvm/crates/mvm-cli/src/lib.rs` (register subcommand)
- Modified: `mvm/crates/mvm-core/src/policy/audit.rs` (new kinds)
- New: `mvm/tests/session_verbs.rs` integration test
- Reference: mvmforge `tests/fixtures/fake-mvm` for argv shape;
  mvmforge `sdks/python/tests/test_session.py` as e2e validation
  (point `MVMFORGE_MVM_BIN` at the mvm build).

## Acceptance

- Each verb returns exit 0 on success, non-zero with structured
  envelope on failure.
- `info`'s JSON schema agreed with mvmforge before merging.
- mvmforge's `test_session.py` suite passes against real `mvmctl`.

## Verification

- Unit tests for argv parsing + clamp logic.
- Integration test: spawn a session via `mvmctl invoke` (existing
  path), then exercise each new verb against it.
- e2e: point `MVMFORGE_MVM_BIN` at the new build and run mvmforge's
  Python and TS session test suites.

## Pushback to mvmforge

- Session-info JSON schema. Surface the draft above and lock in
  before merge. The user's brief explicitly says: "if the substrate
  wants a stable schema, propose one and we'll codify it on the
  mvmforge side."

## Effort

~1 sprint.

## Out of scope

- `session attach`, `session exec`, `session run-code`. Plan 52.
- Cross-host session operations. mvmd's concern, not mvm's.
- Session-mode transitions (prod ↔ dev). Mode is fixed at
  session-start time per ADR-0009.
