# Design — Plan 159 WS-5 E: truly streamed `exec`

> **Status (2026-06-08):** Brainstormed, approved. Scoping/design artifact
> for **Plan 159 WS-5 E** — the last substantive Plan-152-independent item
> on the vz DX/UX parity checklist. The numbered implementation plan is
> produced from this via writing-plans.
>
> **Naming:** the inspiration project's `StreamExecOutput` is referred to
> obliquely ("the reference"); oblique key in auto-memory
> `reference_objc2_vz_external_references`.

## Goal

Make `mvmctl exec` / `mvmctl run` stream the guest command's
stdout/stderr **as they are produced, in arrival order**, plus the exit
code — instead of the current capture-then-return (output lands all at
once after the command exits). Matches the reference's live
`StreamExecOutput`. `exec` is dev-only (`dev-shell`-gated, claim 4); this
improves the dev inner loop for long-running commands.

## Decisions (from brainstorm)

- **D1 — Level B (truly progressive), not wire-shape only.** The guest
  reads the child's stdout/stderr pipes incrementally and emits chunks as
  they arrive. (Level A — multi-frame wire shape but still
  `wait_with_output()` on the guest — was rejected: it changes the wire
  but not what the user sees, so it wouldn't close the parity gap. Note:
  the existing `RunEntrypoint` path is only Level A today; WS-5 E does
  *not* change that — separate concern.)
- **D2 — dedicated `ExecEvent`** (not reuse `EntrypointEvent`). `Exec`
  (dev-only, arbitrary shell command) keeps its own event type, distinct
  from `EntrypointEvent` whose variants (`Control` fd-3 records,
  `RunEntrypointError` taxonomy) are prod-entrypoint-specific and
  meaningless for a raw exec.
- **D3 — capture accumulates the stream.** The guest always streams; the
  host has two consumers — `run()` prints live, `run_captured()`
  accumulates chunks into `ExecOutput`. The single-frame `GuestResponse::
  ExecResult` is **removed** (dev-only surface, no back-compat per
  `feedback_no_backcompat_first_version`). Capture keeps per-stream order
  in its two-field shape; cross-stream interleaving is preserved only in
  live mode (expected, not a regression).

## Current state (exploration 2026-06-08)

- Guest `do_exec` (`mvm-guest-agent.rs`) runs `/bin/sh -c <command>`,
  `wait_with_output()` → captures full stdout/stderr (with a
  `MAX_EXEC_OUTPUT` truncation) → returns one
  `GuestResponse::ExecResult { exit_code, stdout, stderr }`. Gated
  `#[cfg(feature = "dev-shell")]`; absent-feature arm returns an error.
- Host `crates/mvm-cli/src/exec.rs`: `run_in_guest` → `send_request`
  (single req/resp) → on `ExecResult`, prints stdout/stderr *after* the
  whole response, returns exit code. `run()` = interactive; `run_captured()`
  = capture for `--json`/`--receipt`/MCP.
- The **proven streaming machinery already exists** for `RunEntrypoint`:
  `EntrypointEvent` + `GuestResponse::EntrypointEvent`, guest
  `write_response()` per frame, host `send_run_entrypoint(stream, …,
  on_event)` reads frames in a loop until terminal
  (`invoke.rs::dispatch_inner` is the live consumer). WS-5 E mirrors this
  shape for exec.
- Framing: length-prefixed JSON (`[4-byte BE len][JSON]`); multiple
  response frames per request are already supported (entrypoint proves it).

## Protocol (`crates/mvm-guest/src/vsock.rs`)

```rust
/// One event in the response stream of an `Exec` call (dev-shell only).
/// The agent emits a sequence terminated by `Exit`. Plan 159 WS-5 E.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExecEvent {
    /// Bytes from the command's stdout, as they arrive.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the command's stderr, as they arrive.
    Stderr { chunk: Vec<u8> },
    /// Command exited. Terminal.
    Exit { code: i32 },
}
```

- `chunk: Vec<u8>` (raw bytes) so partial-UTF-8 / binary output streams
  correctly (the host writes bytes through; capture lossily converts to
  `String` at the boundary, as `ExecResult` did).
- Add `GuestResponse::ExecEvent(ExecEvent)`; **remove**
  `GuestResponse::ExecResult`.
- `ExecEvent::is_terminal()` → `true` for `Exit`.
- Host reader: `pub fn send_exec_streaming(stream, command, stdin,
  timeout_secs, on_event) -> Result<ExecEvent>` — writes the `Exec`
  request frame, then loops reading frames, invoking `on_event(&ExecEvent)`
  for non-terminal chunks, returning the terminal `Exit`. Mirrors
  `send_run_entrypoint`.

## Guest side (`crates/mvm-guest/src/bin/mvm-guest-agent.rs`)

Replace `do_exec` with `do_exec_streaming(file: &mut File, command,
stdin, timeout_secs) -> GuestResponse` (returns the terminal frame; writes
intermediate frames directly — same contract as `handle_run_entrypoint`):

- Spawn `/bin/sh -c <command>` with `stdin` piped (write `stdin` as today),
  stdout+stderr piped. Write stdin then drop it (EOF).
- Set both pipe fds non-blocking; **`libc::poll` loop** over the two fds:
  on each readable fd, read a chunk (bounded buffer, e.g. 32 KiB) and
  immediately `write_response(file, &GuestResponse::ExecEvent(
  ExecEvent::Stdout|Stderr { chunk }))` (flushes per frame). Single-thread
  poll → chunks emitted in readiness/arrival order = true source-order
  interleaving, no threads/mutex.
- When both pipes hit EOF, reap the child and **return** the terminal
  `GuestResponse::ExecEvent(ExecEvent::Exit { code })`
  (`status.code().unwrap_or(-1)`).
- **Spawn failure** → write one `Stderr` chunk (`"failed to spawn: {e}"`)
  + return `Exit { code: -1 }` (preserves today's `-1`+message behavior).
- **Total-byte safety cap** (today's `MAX_EXEC_OUTPUT`): a running counter
  across both streams; once exceeded, write a final `Stderr` chunk
  (`"... (truncated)"`) and return `Exit` early (kill the child). Protects
  an unbounded `run_captured` accumulation.
- Stays under `#[cfg(feature = "dev-shell")]`; the `not(dev-shell)` arm
  still returns the "exec not available" error (a single `GuestResponse::
  Error`, no stream).
- Dispatch arm: `GuestRequest::Exec { .. } => do_exec_streaming(file, …)`
  (the dispatcher already passes `file` for the streaming `RunEntrypoint`
  path).

## Host side

- `crates/mvm-cli/src/exec.rs`:
  - `run_in_guest` switches from `send_request` (single) to
    `send_exec_streaming` (loop). The inbound-RPC audit emit
    (`scope=rpc,direction=in,kind=vsock,verb=exec`) stays, emitted once
    before the stream.
  - `run()` (interactive): `on_event` writes `Stdout`→stdout,
    `Stderr`→stderr, flushing per chunk. Returns the terminal `Exit.code`.
  - `run_captured()` (capture): `on_event` appends `chunk` bytes into
    `ExecOutput.stdout` / `.stderr` (convert to `String` at the end, as
    `ExecResult` did). Returns `ExecOutput { exit_code, stdout, stderr }`.
    Shape unchanged → `--json`/receipt/MCP consumers unaffected.
- `crates/mvm-cli/src/commands/vm/console.rs`: the `console --command`
  one-shot path currently sends `GuestRequest::Exec` and matches
  `ExecResult`. Update it to consume the `ExecEvent` stream (it can use
  `send_exec_streaming` and print chunks live, mirroring `run()`), since
  `ExecResult` is gone.

## Error / timeout / caps

- Terminal is always `Exit { code }` (spawn-fail → `-1`).
- **Timeout:** preserve current behavior — today `do_exec` ignores
  `timeout_secs`. WS-5 E does not add enforcement (noted as a follow-up);
  the host transport read still bounds a totally-silent stream.
- The total-byte cap bounds capture-mode memory.

## Testing

- **Guest unit:** `do_exec_streaming` over a script that interleaves
  stdout+stderr emits chunk frames then `Exit` (assert ordering +
  terminal); cap truncation emits the note + `Exit`; spawn-fail →
  `Stderr` + `Exit{-1}`. (Use a temp `File`/pipe seam mirroring existing
  agent tests.)
- **Host unit:** `send_exec_streaming` loop terminates on `Exit` and
  invokes `on_event` per chunk over a mock socket (mirror the existing
  `send_run_entrypoint` tests).
- **CLI:** `exec`/`run` return the exit code; `--json`/receipt capture
  shape unchanged (`run_captured` accumulation).
- **Live E2E (libkrun host):** `mvmctl exec '<prints, sleeps 2s, prints
  more>'` shows the first output **before** the sleep elapses (progressive,
  not all-at-once); exit code propagates. Isolate with
  `MVM_CACHE_DIR`/`MVM_DATA_DIR` (`project_dev_host_runs_builder_via_vz`).
  Never run `core_demo_e2e` unbounded.
- **Gates:** `rustup run nightly cargo fmt --all -- --check`,
  `cargo clippy --workspace -- -D warnings`, `cargo nextest run`
  (mvm-backend excluded locally per
  `reference_mvm_backend_test_binary_macos_codesign_sigkill`),
  `cargo test --doc`.

## Scope / non-goals

- **In:** progressive `ExecEvent` streaming for `Exec` (dev-only); host
  live (`run`) + capture (`run_captured`) consumers; `console --command`
  consumer; removal of `ExecResult`.
- **Out:** progressive upgrade of `RunEntrypoint` (separate concern — its
  v1 buffering is unchanged); enforcing exec `timeout_secs` (preserve
  current behavior); any prod surface (`exec` stays `dev-shell`-gated —
  claim 4 / claim 15 posture intact).

## References

- Parent: `specs/plans/159-vz-inspired-macos-dx.md` (WS-5 E).
- `crates/mvm-guest/src/vsock.rs` — `GuestRequest`/`GuestResponse`,
  `EntrypointEvent`, `send_run_entrypoint` (the pattern to mirror),
  `read_frame`/`send_request` framing.
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — `do_exec`,
  `handle_run_entrypoint`, `write_response`, the dispatch.
- `crates/mvm-cli/src/exec.rs` — `run`/`run_captured`/`run_in_guest`/
  `send_request`.
- `crates/mvm-cli/src/commands/vm/exec.rs` — `exec`/`run` subcommands +
  capture (`--json`/`--receipt`) path.
- `crates/mvm-cli/src/commands/vm/invoke.rs` — `dispatch_inner` (live
  stream consumer reference).
- `crates/mvm-cli/src/commands/vm/console.rs` — `console --command`
  one-shot Exec consumer (must update).
</content>
