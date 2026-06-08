# Exec `timeout_secs` Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `mvmctl exec` / `run` / `console --command` / `session run-code` / `session exec` actually honor a per-command timeout — today the value reaches the guest but the agent discards it and `stream_exec` has no deadline.

**Architecture:** Mirror the already-shipped `process_rpc` timeout idiom: spawn the child in its own process group (`process_group(0)`), compute a deadline, kill the **pgroup** with `SIGKILL` on overrun, and return a dedicated terminal `ExecEvent::TimedOut` (sibling to `ProcWaitEvent::TimedOut`). Semantics **(b)**: an *unset* `--timeout` means *no* per-command kill — the user-facing flags become `Option<u64>` (absent ⇒ `None` ⇒ unbounded), so long-running dev commands that "worked" before (because the value was ignored) are not silently killed. The overloaded `--timeout` on `exec`/`run` still feeds the signed `ExecutionPlan.exec_timeout_secs` via `args.timeout.unwrap_or(60)`, so the claim-8 admission path is byte-for-byte unchanged when the flag is unset. The host maps `TimedOut` to exit code **124** (GNU `timeout(1)` convention) for user commands, and to `Err` for the `linux_env` infrastructure leg.

**Tech Stack:** Rust, `libc` (already a `mvm-guest` dep) for `kill(-pgid, SIGKILL)`, clap derive (`Option<u64>` flags), the `dev-shell`-gated `mvm-guest` exec path.

**Spec:** `specs/notes/plan-172-exec-timeout-enforcement-design.md` (approved 2026-06-08).

**Worktree:** `/Users/auser/work/tinylabs/mvmco/mvm-exec-timeout`, branch `feat/plan-172-exec-timeout` off `main`.

**Cross-crate note:** `send_exec_streaming`, `ExecEvent`, and `RunCode` are in `mvm-guest`; widening their signatures breaks downstream callers in `mvm-backend` and `mvm-cli` until those crates are updated. Tasks are scoped one crate each (mvm-guest → mvm-backend → mvm-cli → integration) so each task ends with its own crate green; the **full** `cargo nextest run --workspace` gate runs in the final task.

**Claim 4 invariant:** `stream_exec` and the `Exec`/`RunCode` agent arms are `#[cfg(feature = "dev-shell")]`. The prod agent (`--no-default-features`) constructs no `ExecEvent` and links no `stream_exec`. Adding the `TimedOut` variant does not introduce a prod-constructed symbol. The `prod-agent-no-console` / `prod-agent-no-exec` CI greps stay green — do **not** remove the cfg gates.

---

### Task 1: mvm-guest — `ExecEvent::TimedOut` + `stream_exec` enforcement + agent dispatch

**Files:**
- Modify: `crates/mvm-guest/src/vsock.rs` (ExecEvent + is_terminal; `RunCode.timeout_secs` → `Option<u64>`; `send_exec_streaming` → `Option<u64>`; test call sites)
- Modify: `crates/mvm-guest/src/exec_stream.rs` (timeout param, pgroup, deadline, tests)
- Modify: `crates/mvm-guest/src/bin/mvm-guest-agent.rs` (`do_exec_streaming`, `do_run_code`, `Exec`/`RunCode` arms)

- [ ] **Step 1: Add the `TimedOut` variant + update `is_terminal()`**

In `crates/mvm-guest/src/vsock.rs`, the `ExecEvent` enum (currently `Stdout`/`Stderr`/`Exit`) and its `is_terminal()` — replace with:

```rust
pub enum ExecEvent {
    /// Bytes from the command's stdout, as they arrive.
    Stdout { chunk: Vec<u8> },
    /// Bytes from the command's stderr, as they arrive.
    Stderr { chunk: Vec<u8> },
    /// Command exited with this code. Terminal.
    Exit { code: i32 },
    /// `timeout_secs` elapsed; the agent killed the command's process
    /// group. Terminal. Mirrors `ProcWaitEvent::TimedOut`. The host maps
    /// this to exit code 124 (GNU `timeout(1)` convention) for user
    /// commands. Plan 173.
    TimedOut,
}

impl ExecEvent {
    /// True if this event terminates the `Exec` response stream.
    pub fn is_terminal(&self) -> bool {
        matches!(self, ExecEvent::Exit { .. } | ExecEvent::TimedOut)
    }
}
```

- [ ] **Step 2: Widen `RunCode.timeout_secs` to `Option<u64>`**

In `crates/mvm-guest/src/vsock.rs`, the `GuestRequest::RunCode` variant (currently `RunCode { code: String, timeout_secs: u64 }`):

```rust
    RunCode { code: String, timeout_secs: Option<u64> },
```

`#[serde(deny_unknown_fields)]` is already on `GuestRequest`; `Option<u64>` serializes as `null`/number and round-trips. Leave the `"run-code"` verb string and `RequestClass::DevOnly` mapping unchanged.

- [ ] **Step 3: Widen `send_exec_streaming` to `Option<u64>` (host helper)**

In `crates/mvm-guest/src/vsock.rs`, `send_exec_streaming` — change the parameter and drop the forced `Some`:

```rust
pub fn send_exec_streaming<F>(
    stream: &mut UnixStream,
    command: &str,
    stdin: Option<String>,
    timeout_secs: Option<u64>,
    on_event: F,
) -> Result<ExecEvent>
where
    F: FnMut(&ExecEvent),
{
    let _ = negotiate_protocol(stream, Vec::new())?;
    let req = GuestRequest::Exec {
        command: command.to_string(),
        stdin,
        timeout_secs,
    };
    write_frame(stream, &req)?;
    read_exec_stream(stream, on_event)
}
```

`read_exec_stream` needs **no** change — it already returns on `event.is_terminal()`, which now covers `TimedOut`.

- [ ] **Step 4: Update in-crate test call sites in `vsock.rs`**

Find every test constructing `RunCode { ... timeout_secs: <u64> }` (around lines 2798, 4866, 4920) and the `send_exec_streaming(..., 30, ...)` call (around line 5422). Wrap the literals in `Some(...)`:
- `timeout_secs: 30` → `timeout_secs: Some(30)` (in `RunCode { .. }` literals).
- `send_exec_streaming(&mut host, "echo hi", None, 30, ...)` → `... None, Some(30), ...`.

- [ ] **Step 5: Run mvm-guest lib tests to confirm the protocol change compiles**

Run: `cargo test -p mvm-guest --features dev-shell --lib exec -- --list`
Expected: lists `exec_stream::tests::*` and the vsock exec tests without a compile error. (Full run happens after Step 9.)

- [ ] **Step 6: Write the failing timeout tests in `exec_stream.rs`**

Append to the `mod tests` block in `crates/mvm-guest/src/exec_stream.rs`:

```rust
    #[test]
    fn times_out_and_returns_timedout() {
        // `sleep 5` with a 1s deadline must return TimedOut well under 5s.
        let start = std::time::Instant::now();
        let term = stream_exec("sleep 5", None, Some(1), |_| {});
        assert!(matches!(term, ExecEvent::TimedOut), "got {term:?}");
        assert!(
            start.elapsed() < Duration::from_secs(4),
            "should have been killed near the 1s deadline, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn timeout_kills_the_whole_process_group() {
        // The command backgrounds a long sleep in the SAME process group,
        // writes the grandchild PID, then blocks. On timeout we SIGKILL the
        // pgroup, so the grandchild must also be gone afterward.
        let pidfile = std::env::temp_dir().join(format!("mvm-pgkill-{}", std::process::id()));
        let pidfile_s = pidfile.to_string_lossy().into_owned();
        let cmd = format!("sleep 30 & echo $! > {pidfile_s}; wait");
        let term = stream_exec(&cmd, None, Some(1), |_| {});
        assert!(matches!(term, ExecEvent::TimedOut), "got {term:?}");
        // Give the kernel a beat to reap the SIGKILL'd group.
        std::thread::sleep(Duration::from_millis(200));
        let pid: i32 = std::fs::read_to_string(&pidfile)
            .expect("grandchild pidfile")
            .trim()
            .parse()
            .expect("pid");
        let _ = std::fs::remove_file(&pidfile);
        // kill(pid, 0) returns -1/ESRCH when the process is gone.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        assert!(!alive, "grandchild {pid} survived the pgroup kill");
    }

    #[test]
    fn no_timeout_runs_to_completion() {
        let mut events = Vec::new();
        let term = stream_exec("printf done", None, None, |e| events.push(e));
        assert!(matches!(term, ExecEvent::Exit { code: 0 }), "got {term:?}");
    }
```

- [ ] **Step 7: Run the new tests to verify they fail to compile (signature mismatch)**

Run: `cargo test -p mvm-guest --features dev-shell --lib exec_stream::tests::times_out_and_returns_timedout`
Expected: FAIL — `stream_exec` takes 3 args, called with 4 (`Some(1)`).

- [ ] **Step 8: Implement the timeout in `stream_exec`**

In `crates/mvm-guest/src/exec_stream.rs`:

Add to the imports at the top (`use std::time::Duration;` already present):

```rust
use std::time::{Duration, Instant};
use std::process::Child;
```

Add a pgroup-kill helper above `stream_exec` (mirrors `process_rpc::handle_proc_signal`'s `kill(-pgid, …)`; the child is its own group leader so `pgid == child.id()`):

```rust
/// SIGKILL the child's entire process group. The child is spawned with
/// `process_group(0)`, so it is the group leader and `pgid == child.id()`.
/// Negative pid targets the group (POSIX `kill(2)`). Best-effort.
#[cfg(unix)]
fn kill_pgroup(child: &Child) {
    let pgid = child.id() as libc::pid_t;
    unsafe {
        let _ = libc::kill(-pgid, libc::SIGKILL);
    }
}
#[cfg(not(unix))]
fn kill_pgroup(child: &Child) {
    // No pgroups off-unix; fall back to killing the child only. mvm guests
    // are always Linux, so this arm exists purely to keep host-side unit
    // tests building on non-unix CI (there are none today).
    let _ = child;
}
```

Change the `stream_exec` signature to take `timeout_secs: Option<u64>`:

```rust
pub fn stream_exec<F: FnMut(ExecEvent)>(
    command: &str,
    stdin_data: Option<&str>,
    timeout_secs: Option<u64>,
    mut emit: F,
) -> ExecEvent {
```

After the `Command::new("/bin/sh")` builder line and BEFORE `.spawn()`, add the process-group setup so the whole tree is reapable as one group:

```rust
    let mut builder = Command::new("/bin/sh");
    builder
        .arg("-c")
        .arg(command)
        .stdin(if stdin_data.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    builder.process_group(0);
    let mut child = match builder.spawn() {
        Ok(c) => c,
        Err(e) => {
            emit(ExecEvent::Stderr {
                chunk: format!("failed to spawn: {e}").into_bytes(),
            });
            return ExecEvent::Exit { code: -1 };
        }
    };
```

(This replaces the existing `let mut child = match Command::new("/bin/sh") … .spawn() { … };` block. `process_group` is `std::os::unix::process::CommandExt::process_group`; add `use std::os::unix::process::CommandExt;` under the unix cfg or unconditionally — it is unix-only, so gate the `use` with `#[cfg(unix)]`.)

Compute the deadline just before the poll loop (after `let mut sent_err = 0usize;`):

```rust
    let deadline = timeout_secs.map(|s| Instant::now() + Duration::from_secs(s));
```

Change the existing cap-kill branch from `child.kill()` to the pgroup kill:

```rust
        if capped {
            kill_pgroup(&child);
            let _ = child.wait();
            emit(ExecEvent::Stderr {
                chunk: b"\n... (truncated)".to_vec(),
            });
            return ExecEvent::Exit { code: -1 };
        }
```

Add the deadline check immediately after the cap branch and before `match child.try_wait()`:

```rust
        if deadline.is_some_and(|d| Instant::now() >= d) {
            kill_pgroup(&child);
            let _ = child.wait();
            // Same no-tail-loss discipline as the normal exit path: join the
            // drain threads so all buffered bytes are appended, then flush.
            if let Some(h) = out_handle.take() {
                let _ = h.join();
            }
            if let Some(h) = err_handle.take() {
                let _ = h.join();
            }
            let _ = drain_into(&out_buf, &mut sent_out, true, &mut emit);
            let _ = drain_into(&err_buf, &mut sent_err, false, &mut emit);
            return ExecEvent::TimedOut;
        }
```

Update the three existing tests (`streams_stdout_then_exit_zero`, `captures_stderr_and_nonzero_exit`, `pipes_stdin`, `large_final_write_is_not_truncated`) to pass `None` as the new third argument, e.g.:

```rust
        let term = stream_exec("printf hello", None, None, |e| events.push(e));
```

- [ ] **Step 9: Run the exec_stream tests to verify they pass**

Run: `cargo test -p mvm-guest --features dev-shell --lib exec_stream`
Expected: PASS — all of `streams_stdout_then_exit_zero`, `captures_stderr_and_nonzero_exit`, `pipes_stdin`, `large_final_write_is_not_truncated`, `times_out_and_returns_timedout`, `timeout_kills_the_whole_process_group`, `no_timeout_runs_to_completion`.

- [ ] **Step 10: Thread the timeout through the agent dispatch**

In `crates/mvm-guest/src/bin/mvm-guest-agent.rs`:

`do_exec_streaming` — add the param and forward it:

```rust
#[cfg(feature = "dev-shell")]
fn do_exec_streaming(
    file: &mut std::fs::File,
    command: &str,
    stdin_data: Option<&str>,
    timeout_secs: Option<u64>,
) -> GuestResponse {
    let terminal = mvm_guest::exec_stream::stream_exec(command, stdin_data, timeout_secs, |ev| {
        write_response(file, &GuestResponse::ExecEvent(ev));
    });
    GuestResponse::ExecEvent(terminal)
}
```

`do_run_code` — change `_timeout_secs: u64` to `timeout_secs: Option<u64>` and pass it to the final `do_exec_streaming` call:

```rust
#[cfg(feature = "dev-shell")]
fn do_run_code(file: &mut std::fs::File, code: &str, timeout_secs: Option<u64>) -> GuestResponse {
```

and at the end of that function:

```rust
    do_exec_streaming(file, &shell_command, None, timeout_secs)
```

The `Exec` dispatch arm — stop discarding `timeout_secs`:

```rust
        #[cfg(feature = "dev-shell")]
        GuestRequest::Exec {
            command,
            stdin,
            timeout_secs,
        } => {
            eprintln!("[audit] exec request: {:?}", command);
            do_exec_streaming(&mut file, &command, stdin.as_deref(), timeout_secs)
        }
```

The `RunCode` dispatch arm — `timeout_secs` is now `Option<u64>`, pass it straight through (the body comment block stays):

```rust
            eprintln!("[audit] run-code request");
            do_run_code(&mut file, &code, timeout_secs)
```

- [ ] **Step 11: Build the agent + run mvm-guest tests + clippy**

Run: `cargo build -p mvm-guest --features dev-shell --bin mvm-guest-agent`
Expected: builds clean.
Run: `cargo test -p mvm-guest --features dev-shell`
Expected: PASS (lib + exec tests).
Run: `cargo clippy -p mvm-guest --features dev-shell -- -D warnings`
Expected: no warnings.

- [ ] **Step 12: Commit**

```bash
git add crates/mvm-guest/src/vsock.rs crates/mvm-guest/src/exec_stream.rs crates/mvm-guest/src/bin/mvm-guest-agent.rs
git commit -m "feat(guest): enforce exec timeout_secs via pgroup kill + ExecEvent::TimedOut"
```

---

### Task 2: mvm-backend — enforce `linux_env` setup-script timeouts, map `TimedOut` to `Err`

**Files:**
- Modify: `crates/mvm-backend/src/base/linux_env.rs:185-216` (`exec_via_vsock`)

The callers (`exec_via_vsock(script, 60)` / `(script, 300)` at lines 224/239/266) pass deliberate per-operation bounds that were silently dead. Enforcing them is the intent; a hung provisioning step is a hard failure (`Err`), not a fabricated `Output`.

- [ ] **Step 1: Pass the bound through and add the `TimedOut` arm**

In `exec_via_vsock`, change the `send_exec_streaming` call's timeout argument from `timeout_secs` to `Some(timeout_secs)`:

```rust
        let terminal = mvm_guest::vsock::send_exec_streaming(
            &mut stream,
            &wrapped,
            None,
            Some(timeout_secs),
            |event| match event {
                mvm_guest::vsock::ExecEvent::Stdout { chunk } => out_buf.extend_from_slice(chunk),
                mvm_guest::vsock::ExecEvent::Stderr { chunk } => err_buf.extend_from_slice(chunk),
                _ => {}
            },
        )
        .with_context(|| format!("Failed to execute command in dev VM '{}'", self.vm_id))?;
```

Replace the terminal `match` with one that handles `TimedOut` as a hard error:

```rust
        match terminal {
            mvm_guest::vsock::ExecEvent::Exit { code } => {
                use std::os::unix::process::ExitStatusExt;
                Ok(Output {
                    status: std::process::ExitStatus::from_raw(code << 8),
                    stdout: out_buf,
                    stderr: err_buf,
                })
            }
            mvm_guest::vsock::ExecEvent::TimedOut => anyhow::bail!(
                "command timed out after {timeout_secs}s in dev VM '{}'",
                self.vm_id
            ),
            other => anyhow::bail!("unexpected terminal exec event from dev VM: {other:?}"),
        }
```

- [ ] **Step 2: Build mvm-backend + clippy**

Run: `cargo build -p mvm-backend`
Expected: builds clean (mvm-guest signature change from Task 1 now satisfied).
Run: `cargo clippy -p mvm-backend -- -D warnings`
Expected: no warnings. (Note: `cargo nextest -p mvm-backend` may SIGKILL on this macOS host via codesign — see `reference_mvm_backend_test_binary_macos_codesign_sigkill`; lean on Linux CI. A plain `cargo build`/`clippy` is sufficient here.)

- [ ] **Step 3: Commit**

```bash
git add crates/mvm-backend/src/base/linux_env.rs
git commit -m "feat(backend): enforce linux_env setup-script timeouts (TimedOut -> Err)"
```

---

### Task 3: mvm-cli — `Option<u64>` flags, `unwrap_or(60)` at signed-plan legs, `TimedOut` → 124

**Files:**
- Modify: `crates/mvm-cli/src/exec.rs` (const; `ExecRequest.timeout_secs` → `Option`; `run_in_guest` + `dispatch_in_session` terminal arms)
- Modify: `crates/mvm-cli/src/commands/vm/exec.rs` (`--timeout` → `Option<u64>` on both Args; `unwrap_or(60)` at admission/receipt/display legs)
- Modify: `crates/mvm-cli/src/commands/vm/session.rs` (`--timeout` → `Option<u64>` on the 3 Args; `dispatch_run_code` / `dispatch` `timeout_secs` → `Option`; `TimedOut` arm; test args)
- Modify: `crates/mvm-cli/src/commands/ops/mcp.rs` (`dispatch_in_session(..., Some(timeout))`)
- Modify: `crates/mvm-cli/src/commands/vm/console.rs` (`None`; `TimedOut` → 124)

This whole task is one crate; it compiles green only at the end (Step 12). Work top-down (engine first), committing in logical chunks.

- [ ] **Step 1: Add the 124 constant in the engine**

In `crates/mvm-cli/src/exec.rs`, near the top (after imports / before `ExecRequest`):

```rust
/// Exit code the CLI returns when a guest command exceeds its `--timeout`.
/// Matches GNU `timeout(1)` so scripts can branch on it.
pub const EXEC_TIMEOUT_EXIT_CODE: i32 = 124;
```

- [ ] **Step 2: Widen `ExecRequest.timeout_secs` to `Option<u64>`**

In `crates/mvm-cli/src/exec.rs`, the `ExecRequest` struct field:

```rust
    /// Timeout for the in-guest command in seconds. `None` ⇒ no per-command
    /// kill (the default for interactive/ad-hoc exec).
    pub timeout_secs: Option<u64>,
```

- [ ] **Step 3: `run_in_guest` — pass the `Option` + add the `TimedOut` arm**

In `crates/mvm-cli/src/exec.rs`, `run_in_guest` already passes `req.timeout_secs` to `send_exec_streaming` (now type-compatible). Replace its terminal `match` (the `let exit_code = match terminal { … }` near line 791):

```rust
    let exit_code = match terminal {
        mvm_guest::vsock::ExecEvent::Exit { code } => code,
        mvm_guest::vsock::ExecEvent::TimedOut => {
            let suffix = req
                .timeout_secs
                .map(|s| format!(" after {s}s"))
                .unwrap_or_default();
            eprintln!("error: command timed out{suffix}");
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };
```

- [ ] **Step 4: `dispatch_in_session` — `Option` param + `TimedOut` → 124 in `ExecOutput`**

In `crates/mvm-cli/src/exec.rs`, change the signature:

```rust
pub fn dispatch_in_session(
    vm: &SessionVm,
    code: String,
    timeout_secs: Option<u64>,
) -> Result<ExecOutput> {
```

The `ExecRequest { … timeout_secs }` literal inside it now type-checks (field is `Option`). Replace its terminal `match` (the `let exit_code = match terminal { … }`):

```rust
    let exit_code = match terminal {
        mvm_guest::vsock::ExecEvent::Exit { code } => code,
        mvm_guest::vsock::ExecEvent::TimedOut => {
            let suffix = timeout_secs
                .map(|s| format!(" after {s}s"))
                .unwrap_or_default();
            err.extend_from_slice(format!("error: command timed out{suffix}\n").as_bytes());
            EXEC_TIMEOUT_EXIT_CODE
        }
        other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
    };
```

- [ ] **Step 5: Commit the engine changes**

```bash
git add crates/mvm-cli/src/exec.rs
git commit -m "feat(cli): exec engine carries Option timeout, maps TimedOut to 124"
```

- [ ] **Step 6: `commands/vm/exec.rs` — make both `--timeout` flags `Option<u64>`**

In `crates/mvm-cli/src/commands/vm/exec.rs`, both Args structs (around lines 47-48 and 108-109) — change:

```rust
    /// Per-command timeout in seconds. Unset ⇒ no per-command kill.
    #[arg(long)]
    pub timeout: Option<u64>,
```

Update the passthrough at line ~214 — `timeout: self.timeout` stays as-is (both fields are now `Option<u64>`).

- [ ] **Step 7: `commands/vm/exec.rs` — `unwrap_or(60)` at the non-ad-hoc legs**

The ad-hoc `ExecRequest` build (around line 507) carries the raw `Option`:

```rust
        timeout_secs: args.timeout,
```

(no change needed — `ExecRequest.timeout_secs` is now `Option<u64>`.)

The signed-plan / admission / receipt / display legs keep the existing default-60 behavior — apply `.unwrap_or(60)`:
- Line ~457: `emit_oci_run_admission(&cached, args.cpus, u64::from(memory_mib), args.timeout.unwrap_or(60))`
- Line ~748 (preflight resources display): `timeout_secs: args.timeout.unwrap_or(60),`
- Line ~860 (receipt input build): `timeout_secs: args.timeout.unwrap_or(60),`

The function at line ~515 already takes `timeout_secs: u64` and feeds `exec_timeout_secs` / `SynthesisInput` — its callers pass `args.timeout`; change those call sites to `args.timeout.unwrap_or(60)`. (Search the file for the function's invocation; it is the one building the `SynthesisInput` with `exec_timeout_secs`.) Do **not** change that function's `u64` param.

The test literal at line ~1016 (`timeout: 60`) → `timeout: Some(60)`.

- [ ] **Step 8: Commit the exec command changes**

```bash
git add crates/mvm-cli/src/commands/vm/exec.rs
git commit -m "feat(cli): exec/run --timeout is Option; signed-plan legs default 60"
```

- [ ] **Step 9: `commands/vm/session.rs` — `Option` flags, dispatch params, `TimedOut` arm**

In `crates/mvm-cli/src/commands/vm/session.rs`:

The three Args structs with `#[arg(long, default_value = "30")] pub timeout: u64` (lines ~147, ~161, ~174) — change each to:

```rust
    /// Wall-clock timeout for the call, in seconds. Unset ⇒ no kill.
    #[arg(long)]
    pub timeout: Option<u64>,
```

`dispatch_run_code` (line ~742) — change `timeout_secs: u64` to `timeout_secs: Option<u64>`. The `GuestRequest::RunCode { code, timeout_secs }` literal at line ~765 now type-checks (`RunCode.timeout_secs` is `Option`). Replace its terminal `match` (the `let exit_code = match terminal { … }` near line ~787):

```rust
    let exit_code = match terminal {
        mvm_guest::vsock::ExecEvent::Exit { code } => code,
        mvm_guest::vsock::ExecEvent::TimedOut => {
            let suffix = timeout_secs
                .map(|s| format!(" after {s}s"))
                .unwrap_or_default();
            eprintln!("error: command timed out{suffix}");
            crate::exec::EXEC_TIMEOUT_EXIT_CODE
        }
        other => bail!("unexpected terminal exec event: {other:?}"),
    };
```

The `session exec` dispatch helper (the `cmd` around line 830 that takes `timeout_secs: u64` and calls `crate::exec::dispatch_in_session`) — change its `timeout_secs` param to `Option<u64>` (it forwards directly).

Trace `cmd_exec` (line 683) and `cmd_run_code` (line 712): they pass `args.timeout` into the dispatch helpers — now `Option<u64>`, so they forward unchanged.

The two test arg literals (line ~1271 `ExecArgs { … }` and ~1344 `RunCodeArgs { … }`) — set `timeout: None` (or `Some(30)` if a test asserts a specific value; default `None`).

- [ ] **Step 10: `commands/ops/mcp.rs` — pass `Some(clamped)`**

In `crates/mvm-cli/src/commands/ops/mcp.rs`, the `dispatch_in_session(&vm, code.to_string(), timeout)` call (line ~430) — MCP always has a clamped, meaningful timeout, so enforce it:

```rust
        crate::exec::dispatch_in_session(&vm, code.to_string(), Some(timeout))
```

The `run_cold` ad-hoc `ExecRequest` build (around line 409, `timeout_secs: timeout`) — wrap as `Some(timeout)`:

```rust
            timeout_secs: Some(timeout),
```

(Leave `clamp_timeout` and the `timeout: u64` params unchanged — MCP's contract is a bounded value, not optional.)

- [ ] **Step 11: `commands/vm/console.rs` — `None` + `TimedOut` → 124**

In `crates/mvm-cli/src/commands/vm/console.rs`:

The audit-emit `GuestRequest::Exec { … timeout_secs: Some(30) }` (line ~110) → `timeout_secs: None`.

The `send_exec_streaming(&mut stream, cmd, None, 30, …)` call (line ~115) → `… None, None, …`.

The terminal `match` (line ~138) — add the `TimedOut` arm:

```rust
        match terminal {
            mvm_guest::vsock::ExecEvent::Exit { code } => {
                if code != 0 {
                    std::process::exit(code);
                }
                Ok(())
            }
            mvm_guest::vsock::ExecEvent::TimedOut => {
                eprintln!("error: command timed out");
                std::process::exit(crate::exec::EXEC_TIMEOUT_EXIT_CODE);
            }
            other => anyhow::bail!("unexpected terminal exec event: {other:?}"),
        }
```

- [ ] **Step 12: Build the whole crate, clippy, fmt**

Run: `cargo build -p mvm-cli`
Expected: builds clean (all `send_exec_streaming` / `ExecEvent` / `RunCode` / `dispatch_in_session` call sites now consistent).
Run: `cargo clippy -p mvm-cli -- -D warnings`
Expected: no warnings.

- [ ] **Step 13: Commit the remaining CLI changes**

```bash
git add crates/mvm-cli/src/commands/vm/session.rs crates/mvm-cli/src/commands/ops/mcp.rs crates/mvm-cli/src/commands/vm/console.rs
git commit -m "feat(cli): session/mcp/console honor Option timeout, map TimedOut to 124"
```

---

### Task 4: Integration — CLI parse test, full gate, docs, live verification

**Files:**
- Modify: `crates/mvm-cli/tests/cli.rs` (parse test for `--timeout` present vs absent)
- Modify: `specs/REFACTOR-STATUS.md` (tick the deferred item)
- Modify: `specs/plans/172-plan-159-wse-streamed-exec.md` (strike the deferred "enforce exec timeout_secs" follow-up)

- [ ] **Step 1: Write a CLI parse test asserting `--timeout` is optional and parses**

Add to `crates/mvm-cli/tests/cli.rs` (follow the existing `Cli::try_parse_from` style in that file — match the exact command path for `exec`):

```rust
#[test]
fn exec_timeout_defaults_to_none_and_parses_when_set() {
    use clap::Parser;
    // Unset → None (no per-command kill).
    let cli = Cli::try_parse_from(["mvmctl", "exec", "myvm", "--", "echo", "hi"])
        .expect("parse without --timeout");
    // Set → Some(N).
    let cli2 = Cli::try_parse_from(["mvmctl", "exec", "myvm", "--timeout", "5", "--", "echo", "hi"])
        .expect("parse with --timeout");
    // Reach the timeout field via the parsed command; assert None vs Some(5).
    // (Adjust the match arms to this repo's Commands enum shape — see the
    // sibling exec parse tests already in this file.)
    let _ = (cli, cli2);
}
```

Note for the implementer: this file already has exec-parsing tests — copy their exact enum-destructuring pattern to read `args.timeout` and assert `None` then `Some(5)`. Do not invent a new harness.

- [ ] **Step 2: Run the parse test**

Run: `cargo test -p mvm-cli --test cli exec_timeout_defaults_to_none_and_parses_when_set`
Expected: PASS.

- [ ] **Step 3: Full workspace gate**

Run: `cargo fmt --all -- --check` (CI uses nightly rustfmt: `rustup run nightly cargo fmt --all -- --check`)
Expected: clean.
Run: `cargo clippy --workspace -- -D warnings`
Expected: no warnings.
Run: `cargo nextest run --workspace -E 'not package(mvm-backend)'` (mvm-backend test bins SIGKILL on this macOS host — Linux CI covers them)
Expected: PASS.
Run: `cargo test --workspace --doc`
Expected: PASS.

- [ ] **Step 4: Commit the test**

```bash
git add crates/mvm-cli/tests/cli.rs
git commit -m "test(cli): exec --timeout is optional and parses"
```

- [ ] **Step 5: Live verification on the local VZ/libkrun host**

Boot a long-lived dev guest, then (isolate with `MVM_CACHE_DIR`/`MVM_DATA_DIR` per `project_dev_host_runs_builder_via_vz`):
- `mvmctl console <vm> --command "sleep 30"` (no `--timeout`) → runs to completion (unbounded). NOTE: console has no `--timeout` flag; the unbounded path is the assertion. For an armed test use `session run-code`/`exec` with `--timeout`.
- `mvmctl session exec <id> --timeout 2 -- sleep 30` → exits **124** within ~2s with `command timed out after 2s` on stderr.
- `mvmctl session exec <id> -- sleep 2` (no `--timeout`) → completes normally, exit 0.

Record the observed exit codes + timing. If a microVM backend isn't readily bootable, the `exec_stream` unit tests (Task 1, Step 9) are the authoritative functional proof; note that in the PR.

- [ ] **Step 6: Update REFACTOR-STATUS + the parent plan's deferred list**

In `specs/REFACTOR-STATUS.md`, under the Plan 159 row, strike "enforce exec `timeout_secs`" from the open/deferred list (it's now shipped via Plan 173) and bump the "Last updated" date to 2026-06-08.

In `specs/plans/172-plan-159-wse-streamed-exec.md`, find the deferred follow-up bullet for enforcing exec `timeout_secs` and mark it `- [x]` with a pointer to `specs/plans/173-exec-timeout-enforcement.md`.

- [ ] **Step 7: Commit the docs**

```bash
git add specs/REFACTOR-STATUS.md specs/plans/172-plan-159-wse-streamed-exec.md
git commit -m "docs(plan-173): tick exec-timeout deferred item in rollup + plan 172"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** §1 ExecEvent::TimedOut → T1.S1; §2 guest enforcement (pgroup/deadline) → T1.S6-9; §3 dispatch threading (Exec + RunCode) → T1.S10; §4 Option pass-through + per-caller table → T1.S3 (send_exec_streaming), T2 (linux_env Some + Err), T3 (exec/run/session Option, mcp Some, console None); §5 terminal mapping (124 / Err) → T3.S3/S4/S9/S11 + T2.S1; testing → T1.S6-9, T4.S1-3; live verify → T4.S5; claim-4 invariant → header note + cfg gates preserved.
- **Type consistency:** `timeout_secs: Option<u64>` is consistent across `ExecEvent`-adjacent `GuestRequest::{Exec,RunCode}`, `send_exec_streaming`, `stream_exec`, `do_exec_streaming`, `do_run_code`, `ExecRequest`, `dispatch_in_session`, `dispatch_run_code`. `EXEC_TIMEOUT_EXIT_CODE` is defined once in `crate::exec` and referenced (not redefined) from session/console. The signed-plan/admission/receipt legs keep `u64` and read `.unwrap_or(60)`.
- **Placeholder scan:** every code step shows real code; the one "match this file's existing pattern" note (T4.S1) points at concrete sibling tests rather than leaving a body blank, because the `Commands` enum destructuring is repo-specific and copying the wrong shape would be worse than directing the implementer to the established pattern.
