---
title: "ADR-011: Function-entrypoint runtime control protocol — fd-3, session attach, dev verbs"
status: Proposed
date: 2026-05-06
supersedes: none
related: ADR-007 (function-call entrypoints); ADR-002 (security posture); plan 52-fd3-control-channel-and-session-attach; mvmforge ADR-0010 §B3-B5; mvmforge plan-0010 §B3-B5
---

## Status

Proposed. Largest substrate change in the upstream coordination
workstream.

## Context

The function-entrypoint wire contract (ADR-007 + mvmforge ADR-0009)
currently relies on stderr scanning for a `MVMFORGE_ENVELOPE: {...}`
marker to convey structured errors from the in-VM wrapper to the
host. User code can print this marker on stderr and forge errors —
documented in mvmforge plan-0010 §B4. The fix is a separate fd-3
control channel.

Concurrently, mvmforge's typed `Session` class wants three
operations the substrate doesn't yet expose: `attach` (re-attach a
fresh client to a warm session), `exec_cmd` (run an ad-hoc command),
and `run_code` (run an ad-hoc code snippet). The latter two are
dev-only; production sessions never open them.

The fd-3 channel and the new session verbs share the same wire path
(`mvmctl invoke` extended with a control fd; `session attach`
reuses the dispatch loop) and so are decided together.

## Decision

### fd-3 control channel

Extend `mvmctl invoke`'s vsock protocol so the agent's wrapper
writes:

- **User stdout/stderr to fd 1/fd 2 unmodified**.
- **Structured control records to fd 3** (inherited from parent via
  `pass_fds` / `RawFd`).

Frame format on fd 3: length-prefixed records, each with a small
JSON header followed by raw bytes. Header schema:

```json
{ "stream": "envelope" | "log_out" | "log_err",
  "len": <u32>,
  "ts_ns": <u64> }
```

Bytes follow the header. The full record framing is
`<header_len:u32_le><header_json><payload_len:u32_le><payload_bytes>`,
chosen so the host can read deterministically without parsing JSON
to find boundaries.

The wrapper emits exactly one `envelope` record on error (replacing
today's `MVMFORGE_ENVELOPE:` stderr scan) and zero or more `log_*`
records when `capture_logs=true` is set in
`/etc/mvm/wrapper.json`. The host parses fd 3 in a dedicated
reader; user stdout/stderr can never impersonate the control
channel.

### `session attach`

`mvmctl session attach -- <session-id>` connects a fresh client to
an existing warm session and dispatches one or more invokes against
it.

**Trust model:** session ids are trusted within the local-machine
substrate boundary — anyone with filesystem/process access to the
control socket already has equivalent privileges. Cross-host attach
requires authentication, which is mvmd's concern, not mvm's.

**Implementation:** `attach` reuses the existing
`dispatch_in_session(session_id, ...)` runtime primitive in
`crates/mvm-runtime/src/vm/lifecycle.rs`. It does not boot a new
VM, does not increment a refcount that would prevent teardown, and
does not modify the session's idle-timer.

### Dev-only `session exec` and `session run-code`

`mvmctl session exec -- <session-id> [--] <command> [args...]` and
`mvmctl session run-code -- <session-id> <code>` run ad-hoc
operations against a warm session. These verbs are **refused unless
the session was started with `mode=dev`** (per mvmforge ADR-0009's
two-mode wrapper config). On a `mode=prod` session, both verbs
return non-zero with a structured envelope `kind="session-not-dev"`.

The session's mode is fixed at session-start time and recorded in
the session registry. Verbs check the registry before dispatch.

## Invariants

- fd 3 is **never** allocated for non-function-entrypoint
  invocations — legacy command-entrypoint workloads see exactly the
  same I/O topology they see today (stdin/stdout/stderr only).
- The fd-3 reader has a hard cap on cumulative log bytes per
  invocation (default 1 MiB; configurable via wrapper config). Beyond
  the cap, the wrapper emits a single truncation record and stops.
- `session attach` from a fresh process must dispatch a call against
  a session started by another process (cross-process session id is
  the contract).
- `session exec` and `session run-code` on a `mode=prod` session are
  **hard refusals at the substrate layer** — not gated on client-side
  checks alone. Production sessions never grant these capabilities.
- Audit emit: `session attach`, `session exec`, `session run-code`
  each get their own `LocalAuditKind` variant
  (`SessionAttach`, `SessionExec`, `SessionRunCode`). `attach` is
  recorded even for read-only invokes because it's a session-state
  observation worth auditing.
- `#[serde(deny_unknown_fields)]` on every new vsock type (W4
  invariant). Fuzz corpus extended with `ControlRecord` shapes.

## Consequences

- The wrapper templates (Plan 49) need a parallel update to write
  control records to fd 3 instead of stderr-scanning. Coordinated
  with mvmforge's cleanup PR for the host-side reader.
- **Spoof-attempt regression test:** a function that prints
  `MVMFORGE_ENVELOPE: {...}` to stderr is **not** treated as an
  envelope by the host; the literal bytes appear in captured logs
  and the call returns the function's actual value.
- **New attack-surface review.** fd 3 is a privileged channel from
  the guest's perspective. The agent must treat fd-3 framing as
  untrusted-input deserialization (same `deny_unknown_fields`
  posture as the rest of the vsock protocol per W4).
- Backward-compat fallback: if fd 3 is not opened by the parent
  (legacy invoke), wrappers fall back to stderr-marker behavior.
  Lets old hosts keep working until they upgrade.
- **Out of scope:** cross-host `session attach` (mvmd's concern),
  session mode change after start (rejected — mode is fixed at
  session-start), fd-3 for non-function-entrypoint invocations.

## Pushback opportunities

- **fd-3 frame format.** mvmforge plan-0010 §B4 sketches "len:bytes"
  with JSON headers. The format above is more concrete; confirm with
  mvmforge before locking in.
- **session-info JSON schema** (plan 51, related). Surface a draft
  and ask mvmforge for sign-off.
- **Temp-dir layout** for archive extraction (plan 50, related).
  Document on the substrate side and ask mvmforge to reference.
