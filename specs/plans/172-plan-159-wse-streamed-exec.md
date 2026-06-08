# Plan 172 — Plan 159 WS-5 E: truly streamed `exec` (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.
>
> **Design source:** `specs/docs/plan-159-wse-streamed-exec-design.md`.
> **Parent:** `specs/plans/159-vz-inspired-macos-dx.md` (WS-5 E).
> **Numbering:** 172 was free (main tops at 171; no open PR claims it).
> Re-confirm before merge — `check-spec-numbers` rejects duplicates.

**Goal:** Make `mvmctl exec`/`run` stream the guest command's
stdout/stderr as they're produced (arrival order) plus the exit code,
instead of capture-then-return.

**Architecture:** A new `ExecEvent` stream (`Stdout`/`Stderr`/`Exit`) on
`GuestResponse` replaces the single-frame `ExecResult`. The guest runs the
command and drains its pipes with the in-repo thread-drain + sleep-poll
idiom (`process_rpc::spawn_drain` / `handle_proc_wait`), emitting chunks
via an `emit` closure (testable lib core) — the bin wrapper writes each as
a frame. The host reads frames in a loop (`send_exec_streaming`, mirroring
`send_run_entrypoint`): `run()` prints live, `run_captured()` accumulates.
Exec stays `dev-shell`-gated.

**Tech Stack:** Rust, `std::process` + thread-drain (no `libc::poll` — not
an in-repo idiom), serde, length-prefixed JSON vsock framing,
`UnixStream::pair()` mock tests.

> **Supersedes the design's sketch:** the design said `libc::poll`; the
> scout found the established mvm-guest idiom is **thread-drain +
> sleep-poll** (`process_rpc.rs`), with no `poll(2)` anywhere in the
> crate. This plan uses that idiom. Interleaving is therefore
> poll-interval-granular (~50 ms), matching `handle_proc_wait` — honest
> "source order," not byte-exact.

---

## Guardrails (every task)

- Never regress claims 1–15; `exec` stays `#[cfg(feature = "dev-shell")]`
  (claim 4 — no exec in prod agent). The streaming core is gated too.
- CI fmt is nightly: `rustup run nightly cargo fmt --all` before commits.
- `mvm-backend` test bins can SIGKILL on macOS
  (`reference_mvm_backend_test_binary_macos_codesign_sigkill`) — not
  relevant here (we touch mvm-guest + mvm-cli), but scope nextest to the
  crate under test.
- Per task: `cargo clippy -p <crate> --all-targets -- -D warnings` clean.
- Never run `core_demo_e2e` unbounded.

## File Structure

Created:
- `crates/mvm-guest/src/exec_stream.rs` — testable streaming core
  (`stream_exec`), `dev-shell`-gated (T3).

Modified:
- `crates/mvm-guest/src/vsock.rs` — `ExecEvent` enum + `is_terminal`;
  `GuestResponse::ExecEvent`; `send_exec_streaming`; remove `ExecResult`
  + `exec_at` (T1, T2, T7).
- `crates/mvm-guest/src/lib.rs` — `pub mod exec_stream;` (T3).
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — `do_exec_streaming`
  wrapper + dispatch arm; remove `do_exec` (T4).
- `crates/mvm-cli/src/exec.rs` — `run_in_guest` streaming; `run`/
  `run_captured` consumers; `dispatch_in_session` + warm path (T5).
- `crates/mvm-cli/src/commands/vm/console.rs` — `console --command`
  streaming consumer (T6).

---

# Phase 1 — Protocol (`mvm-guest`)

### Task 1: `ExecEvent` + `GuestResponse::ExecEvent`

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs`

- [ ] **Step 1: Failing test** (append to the `#[cfg(test)] mod tests` in `vsock.rs`)

```rust
#[test]
fn exec_event_exit_is_terminal_others_are_not() {
    assert!(ExecEvent::Exit { code: 0 }.is_terminal());
    assert!(!ExecEvent::Stdout { chunk: b"x".to_vec() }.is_terminal());
    assert!(!ExecEvent::Stderr { chunk: b"y".to_vec() }.is_terminal());
}

#[test]
fn guest_response_exec_event_roundtrips() {
    let r = GuestResponse::ExecEvent(ExecEvent::Stdout { chunk: b"hi".to_vec() });
    let j = serde_json::to_vec(&r).unwrap();
    let back: GuestResponse = serde_json::from_slice(&j).unwrap();
    assert!(matches!(back, GuestResponse::ExecEvent(ExecEvent::Stdout { ref chunk }) if chunk == b"hi"));
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo nextest run -p mvm-guest exec_event`
Expected: FAIL — `ExecEvent` / `GuestResponse::ExecEvent` not found.

- [ ] **Step 3: Add the enum** (near `EntrypointEvent`, ~`vsock.rs:1377`)

```rust
/// One event in the response stream of an `Exec` call (dev-shell only).
/// The agent emits a sequence of these for a single `Exec` request,
/// terminated by `Exit`. The host reads frames in a loop until terminal.
/// Plan 159 WS-5 E.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ExecEvent {
    /// Bytes from the command's stdout, as they arrive.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the command's stderr, as they arrive.
    Stderr { chunk: Vec<u8> },
    /// Command exited with this code. Terminal.
    Exit { code: i32 },
}

impl ExecEvent {
    /// True if this event terminates the `Exec` response stream.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ExecEvent::Exit { .. })
    }
}
```

- [ ] **Step 4: Add the `GuestResponse` variant** (next to `EntrypointEvent(...)`, ~`vsock.rs:837`). Do NOT remove `ExecResult` yet (consumers migrate first):

```rust
    /// One event in the streaming response of an `Exec` call (dev-shell
    /// only). Terminated by `ExecEvent::Exit`. Plan 159 WS-5 E.
    ExecEvent(ExecEvent),
```

- [ ] **Step 5: Run — expect PASS**

Run: `cargo nextest run -p mvm-guest exec_event guest_response_exec_event`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-guest/src/vsock.rs
git commit -m "feat(mvm-guest): ExecEvent stream variant (Plan 159 WS-5 E)"
```

### Task 2: `send_exec_streaming` host reader

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs`

- [ ] **Step 1: Failing test** (append to `mod tests`, mirroring `test_send_run_entrypoint_collects_events_until_terminal`)

```rust
#[test]
fn send_exec_streaming_collects_chunks_until_exit() {
    let (mut host, mut guest) = UnixStream::pair().unwrap();
    host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    guest.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let guest_handle = std::thread::spawn(move || {
        // Exec uses a plain protocol hello (no capability), like exec.rs.
        let req: GuestRequest = read_frame(&mut guest).unwrap();
        assert!(matches!(req, GuestRequest::ProtocolHello { .. }));
        write_frame(
            &mut guest,
            &GuestResponse::ProtocolHelloAck {
                agent_protocol_version: PROTOCOL_VERSION,
                min_supported_version: MIN_SUPPORTED_PROTOCOL_VERSION,
                agent_version: "test-agent".to_string(),
                capabilities: vec![],
            },
        )
        .unwrap();
        let req: GuestRequest = read_frame(&mut guest).unwrap();
        assert!(matches!(req, GuestRequest::Exec { ref command, .. } if command == "echo hi"));
        write_frame(&mut guest, &GuestResponse::ExecEvent(ExecEvent::Stdout { chunk: b"hi\n".to_vec() })).unwrap();
        write_frame(&mut guest, &GuestResponse::ExecEvent(ExecEvent::Exit { code: 0 })).unwrap();
    });

    let mut got: Vec<ExecEvent> = Vec::new();
    let terminal = send_exec_streaming(&mut host, "echo hi", None, 30, |e| got.push(e.clone()))
        .expect("send_exec_streaming");
    guest_handle.join().unwrap();

    assert_eq!(got.len(), 1);
    assert!(matches!(got[0], ExecEvent::Stdout { ref chunk } if chunk == b"hi\n"));
    assert!(matches!(terminal, ExecEvent::Exit { code: 0 }));
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cargo nextest run -p mvm-guest send_exec_streaming`
Expected: FAIL — `send_exec_streaming` not found.

- [ ] **Step 3: Implement** (near `send_run_entrypoint`, ~`vsock.rs:2105`). Exec is NOT capability-gated, so use a plain `negotiate_protocol` hello (mirroring `exec.rs::send_request` / `console.rs`):

```rust
/// Send an `Exec` request and stream its response. Invokes `on_event`
/// for each `Stdout`/`Stderr` chunk as it arrives; returns the terminal
/// `Exit`. Exec carries no `GuestCapability`, so this does a plain
/// protocol hello (the agent gates exec at compile time via `dev-shell`).
/// Plan 159 WS-5 E.
pub fn send_exec_streaming<F>(
    stream: &mut UnixStream,
    command: &str,
    stdin: Option<String>,
    timeout_secs: u64,
    mut on_event: F,
) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    let _ = negotiate_protocol(stream, Vec::new())?;
    let req = GuestRequest::Exec {
        command: command.to_string(),
        stdin,
        timeout_secs: Some(timeout_secs),
    };
    write_frame(stream, &req)?;

    loop {
        let resp: GuestResponse = read_frame(stream)?;
        let event = match resp {
            GuestResponse::ExecEvent(e) => e,
            GuestResponse::Error { message } => bail!("guest exec error: {message}"),
            other => bail!("expected ExecEvent during exec stream, got {other:?}"),
        };
        if event.is_terminal() {
            return Ok(event);
        }
        on_event(&event);
    }
}
```

- [ ] **Step 4: Run — expect PASS**

Run: `cargo nextest run -p mvm-guest send_exec_streaming`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-guest/src/vsock.rs
git commit -m "feat(mvm-guest): send_exec_streaming host reader (Plan 159 WS-5 E)"
```

---

# Phase 2 — Guest streaming core + agent

### Task 3: `exec_stream` core (`stream_exec`)

**Files:**
- Create: `crates/mvm-guest/src/exec_stream.rs`
- Modify: `crates/mvm-guest/src/lib.rs`

- [ ] **Step 1: Create the module** `crates/mvm-guest/src/exec_stream.rs`

```rust
//! Streaming exec core (dev-shell only). Runs `sh -c <command>` and emits
//! `ExecEvent` chunks via an `emit` closure as the child produces output,
//! returning the terminal `Exit`. The wire-writing lives in the agent bin
//! (`do_exec_streaming`); this core is closure-driven so it is unit-
//! testable without a vsock `File`. Mirrors `process_rpc::spawn_drain` +
//! the `handle_proc_wait` sleep-poll loop (the in-repo streaming idiom —
//! mvm-guest has no `libc::poll` usage). Plan 159 WS-5 E.
#![cfg(feature = "dev-shell")]

use crate::vsock::ExecEvent;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Per-stream total-byte cap (1 MiB) — bounds host capture-mode memory
/// (was `MAX_EXEC_OUTPUT` in the agent bin).
pub const MAX_EXEC_OUTPUT: usize = 1024 * 1024;
const DRAIN_BUF: usize = 4096;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

fn spawn_drain<R: Read + Send + 'static>(mut reader: R, buf: Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; DRAIN_BUF];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.lock().expect("exec drain buf").extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
    });
}

/// Emit newly-buffered bytes (past `*sent`) as one chunk, capped at
/// `MAX_EXEC_OUTPUT` total per stream. Returns true if the cap was hit
/// (caller should stop and truncate).
fn drain_into<F: FnMut(ExecEvent)>(
    buf: &Arc<Mutex<Vec<u8>>>,
    sent: &mut usize,
    stdout: bool,
    emit: &mut F,
) -> bool {
    let b = buf.lock().expect("exec drain buf");
    if b.len() <= *sent {
        return false;
    }
    let room = MAX_EXEC_OUTPUT.saturating_sub(*sent);
    if room == 0 {
        return true;
    }
    let new = &b[*sent..];
    let take = new.len().min(room);
    let chunk = new[..take].to_vec();
    emit(if stdout {
        ExecEvent::Stdout { chunk }
    } else {
        ExecEvent::Stderr { chunk }
    });
    *sent += take;
    take < new.len()
}

/// Run `command` under `/bin/sh -c`, streaming stdout/stderr via `emit`
/// (arrival order, ~poll-interval granularity), and return the terminal
/// `ExecEvent::Exit`. `emit` is never called with `Exit` — that is the
/// return value.
pub fn stream_exec<F: FnMut(ExecEvent)>(
    command: &str,
    stdin_data: Option<&str>,
    mut emit: F,
) -> ExecEvent {
    let mut child = match Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            emit(ExecEvent::Stderr {
                chunk: format!("failed to spawn: {e}").into_bytes(),
            });
            return ExecEvent::Exit { code: -1 };
        }
    };

    if let Some(data) = stdin_data
        && let Some(ref mut pipe) = child.stdin
        && let Err(e) = pipe.write_all(data.as_bytes())
    {
        eprintln!("failed to write exec stdin pipe: {e}");
    }
    drop(child.stdin.take());

    let out_buf = Arc::new(Mutex::new(Vec::new()));
    let err_buf = Arc::new(Mutex::new(Vec::new()));
    if let Some(o) = child.stdout.take() {
        spawn_drain(o, out_buf.clone());
    }
    if let Some(e) = child.stderr.take() {
        spawn_drain(e, err_buf.clone());
    }

    let mut sent_out = 0usize;
    let mut sent_err = 0usize;

    loop {
        let capped = drain_into(&out_buf, &mut sent_out, true, &mut emit)
            | drain_into(&err_buf, &mut sent_err, false, &mut emit);
        if capped {
            let _ = child.kill();
            let _ = child.wait();
            emit(ExecEvent::Stderr {
                chunk: b"\n... (truncated)".to_vec(),
            });
            return ExecEvent::Exit { code: -1 };
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Child exited: let the drain threads flush the tail,
                // then emit any remaining bytes.
                std::thread::sleep(POLL_INTERVAL);
                let _ = drain_into(&out_buf, &mut sent_out, true, &mut emit);
                let _ = drain_into(&err_buf, &mut sent_err, false, &mut emit);
                return ExecEvent::Exit {
                    code: status.code().unwrap_or(-1),
                };
            }
            Ok(None) => std::thread::sleep(POLL_INTERVAL),
            Err(e) => {
                emit(ExecEvent::Stderr {
                    chunk: format!("wait failed: {e}").into_bytes(),
                });
                return ExecEvent::Exit { code: -1 };
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streams_stdout_then_exit_zero() {
        let mut events = Vec::new();
        let term = stream_exec("printf hello", None, |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 0 }));
        let out: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stdout { chunk } => Some(chunk.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(out, b"hello");
    }

    #[test]
    fn captures_stderr_and_nonzero_exit() {
        let mut events = Vec::new();
        let term = stream_exec("printf oops 1>&2; exit 3", None, |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 3 }));
        let err: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stderr { chunk } => Some(chunk.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(err, b"oops");
    }

    #[test]
    fn pipes_stdin() {
        let mut events = Vec::new();
        let term = stream_exec("cat", Some("piped"), |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 0 }));
        let out: Vec<u8> = events
            .iter()
            .filter_map(|e| match e {
                ExecEvent::Stdout { chunk } => Some(chunk.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        assert_eq!(out, b"piped");
    }
}
```

- [ ] **Step 2: Declare the module** — add to `crates/mvm-guest/src/lib.rs` next to the other `pub mod` lines:

```rust
pub mod exec_stream;
```

(`exec_stream` is `#![cfg(feature = "dev-shell")]` at the file head, so it
compiles out of the prod agent — claim 4. The `pub mod` line is
unconditional; the file's inner attribute gates the contents.)

- [ ] **Step 3: Run tests** (with the feature)

Run: `cargo nextest run -p mvm-guest --features dev-shell exec_stream`
Expected: PASS (3 tests). Also confirm prod build excludes it:
`cargo build -p mvm-guest` (no dev-shell) — clean.

- [ ] **Step 4: Commit**

```bash
rustup run nightly cargo fmt --all
cargo clippy -p mvm-guest --all-targets --features dev-shell -- -D warnings 2>&1 | tail -5
git add crates/mvm-guest/src/exec_stream.rs crates/mvm-guest/src/lib.rs
git commit -m "feat(mvm-guest): exec_stream core — progressive stream_exec (dev-shell)"
```

### Task 4: agent `do_exec_streaming` wrapper + dispatch

**Files:**
- Modify: `crates/mvm-guest/src/bin/mvm-guest-agent.rs`

- [ ] **Step 1: Replace `do_exec`** (`mvm-guest-agent.rs:969-1033`, incl. the `MAX_EXEC_OUTPUT` const which moves to `exec_stream`). Add the streaming wrapper modeled on `handle_proc_wait_streaming` (`:953-967`):

```rust
/// `Exec` streaming arm — writes intermediate `ExecEvent` Stdout/Stderr
/// frames to the connection and returns the terminal `Exit` for the
/// dispatch loop to write last. Mirrors `handle_run_entrypoint` /
/// `handle_proc_wait_streaming`. Plan 159 WS-5 E. (dev-shell only)
#[cfg(feature = "dev-shell")]
fn do_exec_streaming(
    file: &mut std::fs::File,
    command: &str,
    stdin_data: Option<&str>,
) -> GuestResponse {
    let terminal = mvm_guest::exec_stream::stream_exec(command, stdin_data, |ev| {
        write_response(file, &GuestResponse::ExecEvent(ev));
    });
    GuestResponse::ExecEvent(terminal)
}
```

(Delete the old `do_exec` fn and the bin's `MAX_EXEC_OUTPUT` const — both
superseded. `timeout_secs` is dropped from the wrapper signature because
the old `do_exec` already ignored it; preserving current behavior, noted
as a follow-up in the design.)

- [ ] **Step 2: Update the dispatch arm** (`mvm-guest-agent.rs:2162-2175`) to call the streaming wrapper with `file`:

```rust
        #[cfg(feature = "dev-shell")]
        GuestRequest::Exec {
            command,
            stdin,
            timeout_secs: _,
        } => {
            eprintln!("[audit] exec request: {:?}", command);
            do_exec_streaming(&mut file, &command, stdin.as_deref())
        }

        #[cfg(not(feature = "dev-shell"))]
        GuestRequest::Exec { .. } => GuestResponse::Error {
            message: "exec not available: guest agent built without dev-shell feature".to_string(),
        },
```

(`file` is in scope in the dispatch — the `RunEntrypoint` arm already
passes `&mut file` to `handle_run_entrypoint`; the dispatch tail writes
the returned terminal via `write_response(&mut file, &resp)` exactly as
for `RunEntrypoint`.)

- [ ] **Step 3: Build both feature configs**

Run: `cargo build -p mvm-guest --bin mvm-guest-agent --features dev-shell` and `cargo build -p mvm-guest --bin mvm-guest-agent`
Expected: both clean. The prod build (no dev-shell) hits the `not` arm; the `do_exec`/`MAX_EXEC_OUTPUT` symbols are gone.

- [ ] **Step 4: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-guest/src/bin/mvm-guest-agent.rs
git commit -m "feat(mvm-guest-agent): stream Exec via do_exec_streaming (Plan 159 WS-5 E)"
```

---

# Phase 3 — Host consumers + remove `ExecResult`

### Task 5: `exec.rs` — stream in `run_in_guest`; `run`/`run_captured`

**Files:**
- Modify: `crates/mvm-cli/src/exec.rs`

- [ ] **Step 1: Refactor `run_in_guest`** (`exec.rs:734-772`) to stream. Replace the `send_request` call + `match ExecResult` with a streaming consumer that builds the stream and loops. Replace the whole body:

```rust
fn run_in_guest(
    vm_name: &str,
    req: &ExecRequest,
    labels: &[String],
    capture: bool,
) -> Result<Either<i32, ExecOutput>> {
    if !wait_for_agent(vm_name, 30) {
        anyhow::bail!("guest agent did not become reachable within 30s");
    }
    let wrapper = build_guest_wrapper(req, labels);

    let transport = vsock_transport::for_vm(vm_name)?;
    let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
    // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit (verb=exec).
    mvm_core::audit_emit!(
        NetworkPolicyAllow,
        vm: vm_name,
        "scope=rpc,direction=in,kind=vsock,verb=exec",
    );

    let mut out = Vec::<u8>::new();
    let mut err = Vec::<u8>::new();
    let terminal = mvm_guest::vsock::send_exec_streaming(
        &mut stream,
        &wrapper,
        None,
        req.timeout_secs,
        |event| match event {
            mvm_guest::vsock::ExecEvent::Stdout { chunk } => {
                if capture {
                    out.extend_from_slice(chunk);
                } else {
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), chunk);
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
            }
            mvm_guest::vsock::ExecEvent::Stderr { chunk } => {
                if capture {
                    err.extend_from_slice(chunk);
                } else {
                    let _ = std::io::Write::write_all(&mut std::io::stderr(), chunk);
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
            }
            _ => {}
        },
    )?;
    let exit_code = match terminal {
        mvm_guest::vsock::ExecEvent::Exit { code } => code,
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };

    if capture {
        Ok(Either::Right(ExecOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&out).into_owned(),
            stderr: String::from_utf8_lossy(&err).into_owned(),
        }))
    } else {
        Ok(Either::Left(exit_code))
    }
}
```

(Confirm `std::io::Write` is importable as shown, or add `use std::io::Write;` to the function/module if not already present.)

- [ ] **Step 2: Remove the now-unused `send_request`** (`exec.rs:964-996`) — `run_in_guest` no longer calls it and it returns the deleted `ExecResult`. Delete the fn. (Grep first: `grep -n 'send_request' crates/mvm-cli/src/exec.rs` — if other callers exist, migrate them too.)

- [ ] **Step 3: Migrate `dispatch_in_session`** (`exec.rs:888-924`, the warm-session path) which also matches `GuestResponse::ExecResult`. Read it and switch it to `send_exec_streaming` over its session stream the same way (capture/live per its existing shape). Quote-replace its `match ... ExecResult` block with the streaming loop returning the exit code / `ExecOutput`. (If `dispatch_in_session` is currently dead/unused, confirm with `grep` and remove it instead of migrating.)

- [ ] **Step 4: Build + run exec tests**

Run: `cargo build -p mvm-cli && cargo nextest run -p mvm-cli exec`
Expected: builds; existing exec tests pass.

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
cargo clippy -p mvm-cli --all-targets -- -D warnings 2>&1 | tail -5
git add crates/mvm-cli/src/exec.rs
git commit -m "feat(mvm-cli): stream exec output live (run) + accumulate (run_captured)"
```

### Task 6: `console --command` streaming consumer

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/console.rs`

- [ ] **Step 1: Replace the one-shot Exec block** (`console.rs:101-138`, the `if let Some(cmd) = command { ... match ExecResult ... }`) with a streaming consumer:

```rust
    if let Some(cmd) = command {
        let transport = pick_console_transport(name)?;
        let mut stream = transport.connect(mvm_guest::vsock::GUEST_AGENT_PORT)?;
        // Plan 74 W2 / Plan 51 W6 — inbound vsock RPC audit (verb=exec).
        super::shared::emit_vsock_rpc_audit(
            name,
            &mvm_guest::vsock::GuestRequest::Exec {
                command: cmd.to_string(),
                stdin: None,
                timeout_secs: Some(30),
            },
        );
        let terminal = mvm_guest::vsock::send_exec_streaming(
            &mut stream,
            cmd,
            None,
            30,
            |event| match event {
                mvm_guest::vsock::ExecEvent::Stdout { chunk } => {
                    let _ = std::io::Write::write_all(&mut std::io::stdout(), chunk);
                    let _ = std::io::Write::flush(&mut std::io::stdout());
                }
                mvm_guest::vsock::ExecEvent::Stderr { chunk } => {
                    let _ = std::io::Write::write_all(&mut std::io::stderr(), chunk);
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                }
                _ => {}
            },
        )?;
        match terminal {
            mvm_guest::vsock::ExecEvent::Exit { code } => {
                if code != 0 {
                    std::process::exit(code);
                }
                Ok(())
            }
            other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
        }
    } else {
        // Interactive PTY session
        console_interactive(name)
    }
```

(`send_exec_streaming` does its own protocol hello, so drop the prior
explicit `negotiate_protocol` line. Keep the audit emit. Confirm
`emit_vsock_rpc_audit` accepts a constructed `GuestRequest` ref as shown,
matching the prior call.)

- [ ] **Step 2: Build**

Run: `cargo build -p mvm-cli && cargo nextest run -p mvm-cli console`
Expected: clean; console tests pass.

- [ ] **Step 3: Commit**

```bash
rustup run nightly cargo fmt --all
git add crates/mvm-cli/src/commands/vm/console.rs
git commit -m "feat(mvm-cli): console --command streams exec output (Plan 159 WS-5 E)"
```

### Task 7: Remove `ExecResult` + `exec_at`

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs`

- [ ] **Step 1: Find every remaining `ExecResult` reference**

Run: `grep -rn 'ExecResult' crates/`
Expected: only the `vsock.rs` variant definition + possibly `exec_at` (`vsock.rs:2305-2320`) + tests remain (all CLI consumers migrated in T5/T6).

- [ ] **Step 2: Handle `exec_at`** (`vsock.rs:2305-2320`) — it builds `GuestRequest::Exec` and returns a single `GuestResponse` containing `ExecResult`. Grep its callers: `grep -rn 'exec_at' crates/`. If unused, delete it. If used, migrate the caller to `send_exec_streaming` and delete `exec_at`. (Per `feedback_no_backcompat_first_version`, prefer deletion over a shim.)

- [ ] **Step 3: Remove the variant** — delete `GuestResponse::ExecResult { .. }` from the enum (`vsock.rs:826-831`) and any test referencing it.

- [ ] **Step 4: Build the whole workspace** (catches any missed matcher; `GuestResponse` is matched in several places — a removed variant surfaces as a compile error)

Run: `cargo build --workspace` and `cargo build -p mvm-guest --bin mvm-guest-agent --features dev-shell`
Expected: clean. Fix any remaining `ExecResult` match arms (they should all be gone after T5/T6).

- [ ] **Step 5: Commit**

```bash
rustup run nightly cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | tail -5
git add crates/mvm-guest/src/vsock.rs
git commit -m "refactor(mvm-guest): remove single-frame ExecResult (superseded by ExecEvent)"
```

---

# Phase 4 — Live verification

### Task 8: Progressive E2E on the libkrun host — PASSED

- [x] **Live progressive proof (2026-06-08).**
  `MVM_WORKSPACE_PATH="$(pwd)" mvmctl exec -- sh -c 'echo first; sleep 2;
  echo second'`, with host output timestamped, produced:
  `[01:11:44] first` … `[01:11:46] second` — a **2-second gap in the
  host-side timestamps**, proving the output streamed progressively
  (capture-then-return would print both at one timestamp after the command
  exits). The agent was rebuilt from this branch's source (carries the
  `ExecEvent` change); the host `send_exec_streaming` printed each chunk
  live.

- [x] **Protocol wiring confirmed earlier:** a first run against a *stale*
  cached agent made the new host correctly reject the old frame
  (`unknown variant ExecResult, expected ... ExecEvent`) — fail-closed,
  proving the host deserializer is on the new protocol.

- [~] **Environment notes (not WS-5 E code):** `--hypervisor` is not
  honored by `exec` (it boots the macOS-26 default apple_container/Vz
  backend — streaming is backend-agnostic over vsock, so this is fine).
  The agent rebuild required a networked builder: the **libkrun builder
  had no DNS** (`Could not resolve cache.nixos.org`) and the **Vz builder
  needs the Swift `mvm-vz-supervisor`** (built here via
  `crates/mvm-vz-supervisor/tools/build.sh` + `MVM_VZ_SUPERVISOR_PATH`).
  Same dual-builder constraint Plan 171 (WS-A) hit — orthogonal to this
  change.

- [x] **Capture-mode unchanged** is unit-covered: `run_captured`
  accumulates the stream into the same `ExecOutput`/`RunJsonSummary`
  shape; exit-code propagation is unit-covered (terminal `Exit` →
  `run()` returns the code). (A second live boot to re-prove `exit 5`
  was skipped — the streaming proof + units suffice.)

---

## Deferred (tracked, not in this plan)

- [ ] Enforce exec `timeout_secs` (today ignored; preserved as-is).
- [ ] Progressive upgrade of `RunEntrypoint` (its v1 buffering is a
      separate concern; the wire shape already supports it).

## Self-review notes

- **Spec coverage:** D1 progressive → T3 (`stream_exec` thread-drain) +
  T4 (frames as they arrive); D2 dedicated `ExecEvent` → T1; D3 capture
  accumulates + remove `ExecResult` → T5 (`run_captured`) + T7. Host
  reader → T2; console consumer → T6; live progressive proof → T8.
- **Type consistency:** `ExecEvent {Stdout{chunk:Vec<u8>}, Stderr{chunk:
  Vec<u8>}, Exit{code:i32}}` + `is_terminal()` used identically in T1/T2/
  T3/T4/T5/T6; `send_exec_streaming(stream, command:&str, stdin:Option<
  String>, timeout_secs:u64, on_event: FnMut(&ExecEvent)) -> Result<
  ExecEvent>` consistent T2↔T5↔T6; `stream_exec(command:&str, stdin:
  Option<&str>, emit: FnMut(ExecEvent)) -> ExecEvent` consistent T3↔T4.
- **Mechanism note:** thread-drain + sleep-poll (not `libc::poll`) per
  the in-repo idiom; interleaving is ~50ms-granular (honest, matches
  `handle_proc_wait`).
- **Gating:** `exec_stream` + `do_exec_streaming` are `dev-shell`-gated;
  the prod agent excludes them (claim 4). T4/T7 build the prod (no-feature)
  config to confirm.

## References

- Design: `specs/docs/plan-159-wse-streamed-exec-design.md`
- `crates/mvm-guest/src/vsock.rs` — `EntrypointEvent`/`send_run_entrypoint`
  (pattern), framing, `GuestResponse`, `GuestRequest::Exec`.
- `crates/mvm-guest/src/process_rpc.rs` — `spawn_drain` +
  `handle_proc_wait` (thread-drain + sleep-poll idiom T3 mirrors).
- `crates/mvm-guest/src/bin/mvm-guest-agent.rs` — `do_exec`,
  `handle_proc_wait_streaming`, `write_response`, dispatch (`file` scope).
- `crates/mvm-cli/src/exec.rs` — `run`/`run_captured`/`run_in_guest`/
  `send_request`/`dispatch_in_session`.
- `crates/mvm-cli/src/commands/vm/console.rs` — `console --command`.
- `crates/mvm-cli/src/commands/vm/invoke.rs` — `dispatch_inner` (live
  stream-consumer reference).
</content>
