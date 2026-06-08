# Design — enforce `exec` `timeout_secs` (streamed-exec path)

> **Status (2026-06-08):** Brainstormed, approved for spec review. Follow-on
> to Plan 159 WS-5 E (streamed `exec`, PR #712 / `specs/plans/172-plan-159-wse-streamed-exec.md`).
> The numbered implementation plan is produced from this via writing-plans.

## Goal

Make `mvmctl exec` / `run` / `console --command` / `session run-code` honor a
per-command timeout. Today the value is plumbed all the way to the guest as
`GuestRequest::Exec { timeout_secs: Option<u64> }` but the agent **discards it**
(`timeout_secs: _`) and `stream_exec` has no deadline — a non-terminating guest
command runs until the 1 MiB output cap trips, or forever if it's quiet.

## Why this path specifically

The repo has **three** streaming-response families; two already enforce timeouts,
which is exactly why this one is the genuine gap (and gives us the pattern to copy):

- `ProcWaitEvent` (Plan 169 proc/wait) — `process_rpc::handle_proc_wait` sets
  `deadline = Instant::now() + timeout`, kills the **pgroup** on overrun, returns
  the dedicated terminal `ProcWaitEvent::TimedOut`. Spawns children with
  `cmd.process_group(0)`. **This is the template.**
- `RunEntrypointError::Timeout` (warm-pool / entrypoint dispatch) — the wrapper
  enforces and emits `EntrypointEvent::Error { Timeout }`.
- `ExecEvent` (Plan 159 WS-5 E) — `{ Stdout, Stderr, Exit }` only. **No
  enforcement.** ← this design.

## Non-goals / invariants (do not regress)

- **Claim 4 stays intact.** `stream_exec` and `ExecEvent` are `dev-shell`-gated;
  the prod agent links neither. No new symbol reaches a sealed agent.
- The transient `run`/entrypoint leg's existing host-side timeout (the
  `exec_timeout_secs` config consumed by the wrapper, enforced via
  `RunEntrypointError::Timeout`) is **untouched** — this slice only closes the
  ad-hoc `send_exec_streaming` leg.
- No change to the buffered→streamed tail-loss discipline from WS-5 E
  (drain threads are joined on child exit before emitting the terminal).
- Semantics decision **(b)**: an *unset* `--timeout` means **no per-command kill**
  for user-facing interactive/ad-hoc exec. The killer arms only when the user
  passes `--timeout`, or when an internal caller passes an explicit bound (the
  health probe). This avoids silently killing long-running dev commands that
  "worked" before purely because the value was ignored.

## Design

### 1. Protocol — `ExecEvent::TimedOut`

Add a dedicated terminal variant mirroring `ProcWaitEvent::TimedOut`:

```rust
pub enum ExecEvent {
    Stdout { chunk: Vec<u8> },
    Stderr { chunk: Vec<u8> },
    /// Command exited with this code. Terminal.
    Exit { code: i32 },
    /// `timeout_secs` elapsed; agent killed the process group. Terminal.
    TimedOut,
}
```

`is_terminal()` returns true for `Exit` **and** `TimedOut`. Not `Exit { code: 124 }`
on the wire — the repo idiom is a distinct terminal event, and it keeps "timed out"
unambiguous and serde-checked. The host maps `TimedOut` → exit code **124** (GNU
`timeout(1)` convention) at the CLI boundary, not in the protocol.

### 2. Guest enforcement — `crates/mvm-guest/src/exec_stream.rs`

`stream_exec` gains a `timeout_secs: Option<u64>` parameter.

- Spawn the child with `cmd.process_group(0)` (it currently does not), so the
  whole tree is reapable as one pgroup. Child is the group leader ⇒ `pgid == child.id()`.
- `let deadline = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));`
- In the existing sleep-poll loop, after the drain step: if
  `deadline.is_some_and(|d| Instant::now() >= d)` and the child hasn't exited →
  `libc::killpg(child.id() as i32, libc::SIGKILL)` (same primitive
  `process_rpc::handle_proc_signal(_, 9)` uses), then fall through to the existing
  drain-remaining + join-drain-threads path and return `ExecEvent::TimedOut`.
- `None` ⇒ today's unbounded behavior.
- The existing 1 MiB cap-kill branch switches from `child.kill()` to the same
  pgroup kill, so a chatty command's children are reaped too (consistency).

### 3. Dispatch — stop discarding (`crates/mvm-guest/src/bin/mvm-guest-agent.rs`)

Both arms funnel through `do_exec_streaming → stream_exec` and currently drop the
timeout:

- `GuestRequest::Exec { command, stdin, timeout_secs }` — pass `timeout_secs` to
  `do_exec_streaming`.
- `GuestRequest::RunCode { code, timeout_secs }` — `do_run_code` currently takes
  `_timeout_secs`; thread it through (`RunCode.timeout_secs` is `u64`; wrap as
  `Some` since RunCode always carries an explicit value).
- `do_exec_streaming(file, command, stdin, timeout_secs)` forwards to `stream_exec`.

### 4. Host — `Option` pass-through + (b) (`crates/mvm-guest/src/vsock.rs`)

`send_exec_streaming` and `GuestRequest::{Exec,RunCode}` carry `timeout_secs: Option<u64>`
(`Exec` already does; `RunCode` is widened to match). `send_exec_streaming` passes the
`Option` straight through (today it force-wraps `Some`).

**Mechanism for "unset ⇒ unbounded": the `Option<u64>` type, not clap `ValueSource`.**
The user-facing per-command `--timeout` flags drop their `default_value` and become
`Option<u64>` (clap derive: absent ⇒ `None`). This is the idiomatic, robust way to
distinguish unset-from-default across the **three** commands that share the verb
(`exec`/`run`, `session exec`/`run-code`, plus `console`), and it avoids threading
`ArgMatches` into the engine. `--timeout` on `exec`/`run` is overloaded — it *also*
feeds the **signed `ExecutionPlan.exec_timeout_secs`** (claim-8 admission) and the
receipt/preflight display. Those legs call `args.timeout.unwrap_or(60)`, so an unset
flag keeps their existing default-60 byte-for-byte; an explicit `--timeout N` flows to
*both* the admitted plan and the ad-hoc stream (consistent intent). The engine's
`ExecRequest.timeout_secs` and `dispatch_in_session(timeout_secs)` widen to `Option<u64>`
and carry only the ad-hoc value.

Per-caller policy:

| Caller | Today | New |
|---|---|---|
| `exec.rs::run_in_guest` (`exec`/`run` ad-hoc) | `req.timeout_secs: u64` | `Option` — `None` unless `--timeout` set |
| `exec.rs::dispatch_in_session` (`session run-code`/`exec`, MCP) | `timeout_secs: u64` | `Option` — `None` unless set; MCP passes `Some(clamped)` |
| `commands/vm/console.rs` (`console --command`) | hard-coded `30` | `None` (interactive; unbounded) |
| `base/linux_env.rs::exec_via_vsock` (setup scripts, bounds 60/300) | ignored `u64` | `Some(timeout_secs)` — enforce the *existing* deliberate bounds; `TimedOut ⇒ Err` |
| `commands/env/apple_container.rs:475` (`uname -r` probe) | `5` | `Some(5)` — a hung probe *should* die |

The signed-plan / admission / receipt / display legs are **not** widened — they read
`args.timeout.unwrap_or(60)` and are otherwise untouched (no claim-8 behavior change
when unset).

### 5. Host — terminal mapping

Every caller's `match terminal { Exit { code } => …, other => bail!(…) }` gains a
real `TimedOut` arm:

- **User-facing (`exec`, `run`, `console`):** print `command timed out after {N}s`
  to stderr, exit code **124**. Define `const EXEC_TIMEOUT_EXIT_CODE: i32 = 124;`
  (mvm-cli).
- **`linux_env` (infrastructure):** return `Err(anyhow!("command timed out after {N}s"))`
  — **not** a fabricated `Output { status: 124 }`. A timed-out provisioning script
  is a hard failure that must propagate via `?` (the call site already
  `.with_context(...)`s); synthesizing a 124 `Output` would let a hung step
  masquerade as "ran, exited 124" to condition-checking callers (silent-failure smell).
- **`apple_container` probe:** already a boolean context — `TimedOut` reads as
  probe-failed, no special arm needed beyond not matching `Exit { code: 0 }`.

## Testing

- `exec_stream.rs` unit tests (dev-shell):
  - `sleep 5` with `Some(1)` → returns `TimedOut`.
  - the killed command's **backgrounded grandchild** is also dead (proves pgroup
    kill, not just child kill).
  - `Some(N)` large / `None` → command completes normally with `Exit`.
  - output emitted before the deadline still arrives in the stream (no tail loss).
- `vsock.rs`: `read_exec_stream` returns `TimedOut` as terminal; `is_terminal()`
  covers it.
- `tests/cli.rs`: `--timeout` explicit-vs-unset parsing; the `ValueSource` branch.
- Claim 4: prod-agent symbol grep already asserts `stream_exec`/console absence —
  no new prod symbol introduced (the variant is on a `dev-shell`-gated enum path
  that prod never constructs; the enum itself is shared but unconstructed in prod).
- Gates: `cargo nextest run --workspace`, `cargo test --workspace --doc`,
  `rustup run nightly cargo fmt --all -- --check`, `cargo clippy --workspace -- -D warnings`.
  mvm-backend test bins can codesign-SIGKILL on this macOS host
  (`reference_mvm_backend_test_binary_macos_codesign_sigkill`) — lean on Linux CI
  for those; run `-E 'not package(mvm-backend)'` locally.

## Live verification (this Vz/libkrun host)

Reuse the WS-5 E recipe: a long-lived dev guest, then
`mvmctl console <vm> --command "sleep 30" --timeout 2` → exits 124 with the
timeout message in ~2s; `--timeout` omitted → `sleep 2` completes normally.
Isolate with `MVM_CACHE_DIR`/`MVM_DATA_DIR` (`project_dev_host_runs_builder_via_vz`).

## Files

- `crates/mvm-guest/src/vsock.rs` — `ExecEvent::TimedOut` + `is_terminal()`;
  `send_exec_streaming` → `Option<u64>`.
- `crates/mvm-guest/src/exec_stream.rs` — timeout param + pgroup kill + deadline.
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — thread timeout through both
  dispatch arms + `do_exec_streaming`/`do_run_code`.
- `crates/mvm-cli/src/exec.rs` — `None`-default + `TimedOut`→124 arm + constant.
- `crates/mvm-cli/src/commands/vm/console.rs` — `None`-default + `TimedOut`→124.
- `crates/mvm-cli/src/commands/env/apple_container.rs` — `Some(5)` probe.
- `crates/mvm-backend/src/base/linux_env.rs` — pass-through + `TimedOut`→`Err`.

## References

- `specs/plans/172-plan-159-wse-streamed-exec.md` — parent (streamed exec).
- `crates/mvm-guest/src/process_rpc.rs:240-640` — the timeout+pgroup-kill template.
- `specs/notes/plan-159-dx-152-independent-slice-design.md` — WS-5 lineage.
