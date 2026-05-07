# Plan 52 — fd-3 control channel + `session attach` + dev verbs

Status: **Proposed.** Implements ADR-011. Largest substrate change in
the upstream coordination workstream.

## Background

Three coupled deliverables sharing a wire-protocol concern:

1. **fd-3 control channel** for `mvmctl invoke` — fixes the spoof-able
   `MVMFORGE_ENVELOPE:` parsing on stderr (mvmforge plan-0010 §B4).
2. **`mvmctl session attach -- <session-id>`** — re-attach to an
   existing session from a fresh `mvmctl invoke` (mvmforge plan-0010
   §B3, ADR-0010 §B3).
3. **Dev-only `session exec` / `session run-code`** — ad-hoc execution
   against a warm session, refused unless session was started in
   `mode=dev` (mvmforge plan-0010 §B5).

The fd-3 channel and the new session verbs share the same wire path
(`mvmctl invoke` extended with a control fd; `session attach` reuses
the dispatch loop) and so are sequenced in one plan.

## Phasing

### Phase 1: fd-3 protocol extension in vsock

Modify `mvm/crates/mvm-guest/src/vsock.rs` (lines 43-320 hold the
`GuestRequest` enum today):

- Extend `RunEntrypoint` request with a new field
  `control_channel: bool`. `false` preserves today's behavior;
  `true` activates fd-3 framing on the response side.
- Define a new response variant:

  ```rust
  EntrypointEvent::ControlRecord {
      stream: ControlStream,
      payload: Vec<u8>,
      ts_ns: u64,
  }

  pub enum ControlStream { Envelope, LogOut, LogErr }
  ```

- Existing `Stdout` / `Stderr` / `Exit` / `Error` events continue
  unchanged.
- `MAX_FRAME_SIZE = 256 KiB` (vsock.rs:31) cap applies per record.
- `#[serde(deny_unknown_fields)]` on the new shapes per W4
  invariants.
- Update fuzz corpus seeds at `crates/mvm-guest/fuzz/`.

Agent-side change in `mvm/crates/mvm-guest/src/entrypoint.rs`:

- Spawn the wrapper with an inherited fd 3 (Unix pipe).
- Read fd 3 in a dedicated thread alongside the existing stdout/stderr
  readers.
- Forward each record from fd 3 as a `ControlRecord` event.
- If `control_channel=false` (legacy), don't open fd 3; preserve
  today's stderr-marker behavior.

Host-side change in `mvm/crates/mvm-cli/src/commands/vm/invoke.rs`:

- When dispatching a function-entrypoint workload, set
  `control_channel=true` in the `RunEntrypoint` request.
- Stream `ControlRecord` events; parse `Envelope` records as
  structured errors; route `LogOut`/`LogErr` records to wherever
  the existing host-side log stream goes.
- Remove the `MVMFORGE_ENVELOPE:` stderr scan in the same PR.

### Phase 2: Wrapper-template updates

Modify the wrappers from Plan 49 (post-relocation):

- `mvm/nix/wrappers/python-runner.py`: write envelope record to fd 3
  on error, replacing the existing stderr marker print. Emit
  `log_out`/`log_err` records when `capture_logs=true` in
  `wrapper.json`.
- Same for `node-runner.mjs` and `wasm-runner.sh`.

Frame format on fd 3 (proposed — confirm with mvmforge before lock-in):

```
<header_len:u32_le><header_json><payload_len:u32_le><payload_bytes>
```

Header schema:

```json
{
  "stream": "envelope" | "log_out" | "log_err",
  "len": <u32>,
  "ts_ns": <u64>
}
```

Backward-compat fallback: if fd 3 is not opened by the parent
(legacy invoke), wrappers fall back to stderr-marker behavior. Lets
old hosts keep working until they upgrade.

In-VM log buffer cap: wrappers cap cumulative log bytes per
invocation (default 1 MiB; configurable via wrapper config). Beyond
the cap: emit a single truncation record and stop.

### Phase 3: `session attach`

New file `mvm/crates/mvm-cli/src/commands/session/attach.rs`. Argv:
`mvmctl session attach -- <session-id>` (subsequent args treated as
a fresh invoke against the existing session).

- Look up session by id.
- Invoke `dispatch_in_session(session_id, ...)` from
  `mvm-runtime/src/vm/lifecycle.rs` (existing primitive). Don't
  boot a new VM; don't increment a refcount that prevents teardown;
  don't modify the session's idle-timer.
- Inherits the fd-3 plumbing from Phase 1.
- Trust model: session ids are trusted within the local-machine
  substrate boundary. Cross-host attach requires authentication —
  that's mvmd's concern.
- Audit emit: `LocalAuditKind::SessionAttach { session_id }`.

### Phase 4: dev-only `session exec` / `session run-code`

New files `mvm/crates/mvm-cli/src/commands/session/exec.rs` and
`run_code.rs`.

- Both check the session registry's `mode` field.
- If `mode=prod`: return non-zero with structured envelope
  `kind="session-not-dev"`. Hard refusal at the substrate layer.
- If `mode=dev`: dispatch via the wrapper-spawn path with a different
  entrypoint (`exec` runs an arbitrary argv; `run_code` runs a code
  snippet — language inferred from session's wrapper config).
- Audit emit: `LocalAuditKind::SessionExec { session_id, argv }`,
  `LocalAuditKind::SessionRunCode { session_id, code_hash }`.

## Critical files

- Modified: `mvm/crates/mvm-guest/src/vsock.rs` (request/response
  shape; fuzz corpus updates per W4).
- Modified: `mvm/crates/mvm-guest/src/entrypoint.rs` (fd-3 handling
  on the agent side).
- Modified: `mvm/crates/mvm-cli/src/commands/vm/invoke.rs` (fd-3
  reader on host side; remove stderr-marker scan).
- New: `mvm/crates/mvm-cli/src/commands/session/{attach,exec,run_code}.rs`.
- Modified: `mvm/nix/wrappers/python-runner.py` (Phase 2).
- Modified: `mvm/nix/wrappers/node-runner.mjs` (Phase 2).
- Modified: `mvm/nix/wrappers/wasm-runner.sh` (Phase 2).
- Modified: `mvm/crates/mvm-core/src/policy/audit.rs` (3 new kinds:
  `SessionAttach`, `SessionExec`, `SessionRunCode`).
- New: spoof-attempt test in `mvm/tests/`.
- New: `attach`/`exec`/`run_code` integration tests.
- Reference: mvmforge ADR-0010 §B3-B5; mvmforge plan-0010 §B3-B5;
  `mvmforge/sdks/python/tests/test_session.py` as e2e validation.

## Acceptance

- **Spoof-attempt regression test** passes: a function that prints
  `MVMFORGE_ENVELOPE: {"kind":"fake"}` to stderr is **not** treated
  as an envelope by the host; the literal bytes appear in captured
  logs and the call returns the function's actual value.
- `Session.attach()` from a fresh process dispatches a function call
  against a session started by another process.
- `Session.exec_cmd(["ls"])` returns a `ProcessResult` only on a
  `Session(dev=True)`; raises on `mode=prod`.
- mvmforge `test_session.py` and `session.test.ts` suites pass
  against real `mvmctl` (point `MVMFORGE_MVM_BIN`).

## Pushback to mvmforge

- **fd-3 frame format.** mvmforge plan-0010 §B4 sketches "len:bytes"
  with JSON headers. The plan above proposes a more concrete
  `<header_len:u32_le><header_json><payload_len:u32_le><payload_bytes>`
  framing. Confirm with mvmforge before locking in.

## Verification

- Unit tests on fd-3 framing (header parse, length-prefixed payload,
  cap enforcement).
- Integration test: invoke a function whose body writes
  `MVMFORGE_ENVELOPE:` to stderr; assert the host treats it as plain
  log bytes.
- Cross-process attach test: process A starts a session via
  `mvmctl invoke --session`; process B calls
  `mvmctl session attach -- <id>` and dispatches an invoke; assert
  it succeeds without booting a new VM.
- Mode-gated test: start a `mode=prod` session; attempt
  `mvmctl session exec`; assert refusal with `kind="session-not-dev"`.
- Fuzz: extend existing vsock fuzz corpus with `ControlRecord`
  shapes.

## Effort

~2-3 sprints. Phase 1 and 2 are the riskiest (protocol change in
vsock; wrapper template updates that must coordinate with the
mvmforge cleanup PR).

## Out of scope

- Cross-host `session attach` (mvmd's concern).
- Session mode change after start (rejected — mode is fixed at
  session-start).
- fd-3 for non-function-entrypoint invocations. Legacy command-
  entrypoint workloads see exactly the same stdin/stdout/stderr
  topology they see today.
