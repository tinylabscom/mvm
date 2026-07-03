# Vz Deprecation — Phase 1: auto-detect stdin (drop `--stdin`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the `machine run --stdin` flag and make `mvmctl machine run` accept piped/redirected stdin the *nix way — when mvmctl's own stdin is not a TTY, its bytes are the workload's stdin.

**Architecture:** The guest protocol already carries stdin in both run verbs (`GuestRequest::Exec { stdin }` dev path, `GuestRequest::RunEntrypoint { stdin }` prod path — `crates/mvm-guest/src/vsock.rs`). This phase is host/CLI-side only: read non-TTY stdin once (buffered, 1 MiB cap), and route the bytes into whichever verb the run resolves to. No guest-agent or wire-protocol change.

**Tech Stack:** Rust, clap, the workspace's `cargo nextest` test harness.

**Design source:** `specs/notes/2026-07-02-vz-deprecation-design.md` (§"Companion: drop `--stdin`, auto-detect non-TTY stdin"). This is Phase 1 of that spec.

## Global Constraints

- No backwards compatibility: hard-remove the `--stdin` flag; no alias, no deprecation shim (repo rule — first version, nothing in production).
- `#[allow(clippy::too_many_arguments)]` is banned in hand-written code. If a fn trips it, introduce a params struct.
- No plan/PR/ADR citations in code comments (`xtask check-no-spec-refs-in-comments` gate). Keep the reasoning, drop the citation.
- Stdin payload is buffered and capped at **1 MiB** in v1 (the runner's existing contract); over-cap fails closed. Unbounded/live streaming stdin is explicitly out of scope.
- `cargo fmt --all -- --check`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings` all green before done.
- Scope is `machine run` only. `invoke`/`proc`/`session` have their own separate `--stdin`/stdin surfaces (`crates/mvm-cli/src/commands/vm/invoke.rs:340` `read_stdin_payload`); they are NOT touched here.

---

## File Structure

- `crates/mvm-cli/src/commands/vm/invoke.rs` — home of the existing host stdin reader `read_stdin_payload`. Add the TTY-aware capped reader `read_auto_stdin` next to it (one responsibility: host-side stdin acquisition).
- `crates/mvm-cli/src/commands/vm/exec.rs` — `RunArgs` / `Args` (transient/inline-argv run args). Add a `stdin: Vec<u8>` field so the transient path can carry a payload it previously dropped.
- `crates/mvm/src/vm/exec_builder.rs` — where the host builds the `Exec` / `RunEntrypoint` frames. Inject the stdin bytes here.
- `crates/mvm-cli/src/commands/machine/mod.rs` — `MachineRunArgs` (the `--stdin` clap flag + the entrypoint action). Delete the flag; auto-read at dispatch.
- `crates/mvm-cli/tests/cli.rs` — CLI parse/help assertions (the flag is gone).

---

## Task 1: Host-side TTY-aware capped stdin reader

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/invoke.rs` (add `read_auto_stdin` + `AutoStdinError`, near `read_stdin_payload` at line 340)
- Test: same file, `#[cfg(test)]` module

**Interfaces:**
- Produces: `pub(in crate::commands) fn read_auto_stdin(is_tty: bool) -> Result<Vec<u8>>` — public entry used by later tasks. Internally delegates to a testable core `fn read_auto_stdin_from<R: std::io::Read>(reader: R, is_tty: bool, cap: usize) -> Result<Vec<u8>, AutoStdinError>`.
- Consumes: `MAX_STDIN_BYTES` — reuse the runner's 1 MiB constant if `mvm_guest` re-exports it; otherwise define `const MAX_STDIN_BYTES: usize = 1024 * 1024;` locally with a comment that it mirrors the runner cap.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod auto_stdin_tests {
    use super::{read_auto_stdin_from, AutoStdinError};
    use std::io::Cursor;

    #[test]
    fn tty_stdin_yields_empty_payload() {
        // A terminal on stdin is interactive, not input: never block reading it.
        let got = read_auto_stdin_from(Cursor::new(b"ignored" as &[u8]), true, 1024).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn piped_stdin_under_cap_is_read_whole() {
        let got = read_auto_stdin_from(Cursor::new(b"STDIN-RT-42" as &[u8]), false, 1024).unwrap();
        assert_eq!(got, b"STDIN-RT-42");
    }

    #[test]
    fn piped_stdin_over_cap_fails_closed() {
        let payload = vec![b'x'; 2048];
        let err = read_auto_stdin_from(Cursor::new(&payload[..]), false, 1024).unwrap_err();
        assert!(matches!(err, AutoStdinError::TooLarge { cap: 1024 }));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli auto_stdin_tests`
Expected: FAIL — `read_auto_stdin_from` / `AutoStdinError` not found.

- [ ] **Step 3: Write minimal implementation**

```rust
/// Host-side cap on a buffered stdin payload. Mirrors the guest runner's v1
/// inbound cap; over-cap fails closed rather than silently truncating.
const MAX_STDIN_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
pub(in crate::commands) enum AutoStdinError {
    TooLarge { cap: usize },
    Io(std::io::Error),
}

impl std::fmt::Display for AutoStdinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { cap } => {
                write!(f, "stdin payload exceeds the {cap}-byte limit")
            }
            Self::Io(e) => write!(f, "reading stdin: {e}"),
        }
    }
}
impl std::error::Error for AutoStdinError {}

/// Read one buffered stdin payload, capped. A TTY on stdin is interactive input
/// for the terminal, not a workload payload, so it yields empty and never blocks.
fn read_auto_stdin_from<R: std::io::Read>(
    mut reader: R,
    is_tty: bool,
    cap: usize,
) -> Result<Vec<u8>, AutoStdinError> {
    if is_tty {
        return Ok(Vec::new());
    }
    // Read cap+1 so an exactly-cap payload passes and the first over-cap byte trips.
    let mut buf = Vec::new();
    reader
        .by_ref()
        .take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(AutoStdinError::Io)?;
    if buf.len() > cap {
        return Err(AutoStdinError::TooLarge { cap });
    }
    Ok(buf)
}

/// Public entry: acquire the caller's stdin payload from the real stdin fd.
pub(in crate::commands) fn read_auto_stdin(is_tty: bool) -> anyhow::Result<Vec<u8>> {
    read_auto_stdin_from(std::io::stdin().lock(), is_tty, MAX_STDIN_BYTES)
        .map_err(|e| anyhow::anyhow!(e))
}
```

Add `use std::io::Read;` to the file's imports if not already present (needed for `read_to_end` / `by_ref`).

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-cli auto_stdin_tests`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/invoke.rs
git commit -m "feat(cli): host-side TTY-aware capped stdin reader (read_auto_stdin)"
```

---

## Task 2: Carry stdin through the transient/inline-argv path into the `Exec` frame

**Files:**
- Modify: `crates/mvm-cli/src/commands/vm/exec.rs` (`RunArgs` struct ~line 94; `into_exec_args` ~line 250; `Args` struct — the exec-args target)
- Modify: `crates/mvm/src/vm/exec_builder.rs` (set `Exec.stdin` from carried bytes)
- Test: `crates/mvm/src/vm/exec_builder.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `read_auto_stdin` (Task 1).
- Produces: `Args.stdin: Vec<u8>` and `RunArgs.stdin: Vec<u8>`; the `ExecBuilder` sends `GuestRequest::Exec { stdin: Some(<utf8>), .. }` when the payload is non-empty, else `stdin: None`.

- [ ] **Step 1: Write the failing test**

In `crates/mvm/src/vm/exec_builder.rs` test module (adapt to the builder's actual constructor — inspect the existing `#[cfg(test)]` there for the pattern):

```rust
#[test]
fn exec_frame_carries_stdin_payload() {
    // Build the Exec request the transient inline-argv path emits, and assert
    // the stdin bytes are threaded into the GuestRequest::Exec.stdin field.
    let req = build_exec_request_for_test(vec!["/bin/cat".into()], b"STDIN-RT-42".to_vec());
    match req {
        mvm_guest::vsock::GuestRequest::Exec { stdin, .. } => {
            assert_eq!(stdin.as_deref(), Some("STDIN-RT-42"));
        }
        other => panic!("expected Exec, got {other:?}"),
    }
}

#[test]
fn exec_frame_empty_stdin_is_none() {
    let req = build_exec_request_for_test(vec!["/bin/true".into()], Vec::new());
    match req {
        mvm_guest::vsock::GuestRequest::Exec { stdin, .. } => assert_eq!(stdin, None),
        other => panic!("expected Exec, got {other:?}"),
    }
}
```

If the builder has no seam to construct the frame in a test, add a small private helper `fn exec_request(argv: Vec<String>, stdin: Vec<u8>) -> GuestRequest` that both the builder and the test call (DRY), and have the test target it via `build_exec_request_for_test`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm exec_frame_carries_stdin_payload exec_frame_empty_stdin_is_none`
Expected: FAIL — helper/field not wired.

- [ ] **Step 3: Write minimal implementation**

In `exec_builder.rs`, where the `Exec` frame is constructed, source its `stdin` from the carried bytes (empty ⇒ `None`, non-empty ⇒ `Some(String::from_utf8_lossy(&bytes).into_owned())`):

```rust
// stdin: empty payload ⇒ no stdin (None); bytes ⇒ Some. Exec's stdin is a
// String (utf8) today; lossy-decode keeps the dev debug path simple.
let stdin = if stdin_bytes.is_empty() {
    None
} else {
    Some(String::from_utf8_lossy(&stdin_bytes).into_owned())
};
let request = GuestRequest::Exec { argv, stdin, /* ..existing fields.. */ };
```

In `exec.rs`: add `pub stdin: Vec<u8>` to `RunArgs` and to `Args`, and pass it through `into_exec_args`:

```rust
// RunArgs { .. , stdin: Vec<u8> }   // add field
// Args    { .. , stdin: Vec<u8> }   // add field
fn into_exec_args(self) -> Args {
    Args {
        // ..existing fields..
        argv: self.argv,
        stdin: self.stdin,
    }
}
```

Populate `RunArgs.stdin` at the point the transient path is built in `machine/mod.rs` (Task 4 wires the actual `read_auto_stdin` call there); for now default it to `Vec::new()` at all `RunArgs`/`Args` construction sites so the workspace compiles.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm exec_frame_carries_stdin_payload exec_frame_empty_stdin_is_none`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/vm/exec.rs crates/mvm/src/vm/exec_builder.rs
git commit -m "feat(run): carry stdin bytes into the transient Exec frame"
```

---

## Task 3: Route auto-stdin at `machine run` dispatch (both verbs) + delete the flag

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` — delete the `--stdin` field (~line 255-258); auto-read at dispatch; feed `RunArgs.stdin` (transient) and `RunEntrypoint`'s payload (entrypoint action ~line 2337/2361); fix construction sites (`boot_persistent_by_name` ~line 2485 sets `stdin: None`).
- Test: `crates/mvm-cli/tests/cli.rs`

**Interfaces:**
- Consumes: `read_auto_stdin` (Task 1), `RunArgs.stdin` (Task 2).

- [ ] **Step 1: Write the failing test**

In `crates/mvm-cli/tests/cli.rs`:

```rust
#[test]
fn machine_run_rejects_removed_stdin_flag() {
    // The --stdin flag is gone; piped stdin is auto-detected instead.
    let mut cmd = assert_cmd::Command::cargo_bin("mvmctl").unwrap();
    let out = cmd.args(["machine", "run", "--image", "alpine", "--stdin", "-", "--", "/bin/cat"]).output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unexpected argument") || stderr.contains("--stdin"),
        "expected an unknown-flag error, got: {stderr}");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p mvm-cli machine_run_rejects_removed_stdin_flag`
Expected: FAIL — `--stdin` still parses (currently accepted, silently ignored).

- [ ] **Step 3: Write minimal implementation**

Delete the flag field in `MachineRunArgs`:

```rust
// DELETE these lines (the --stdin flag + its doc comment):
//   /// Entrypoint stdin payload: a file path, or `-` for mvmctl's own stdin.
//   /// Omit for the no-argument call. Requires `--entrypoint`.
//   #[arg(long, value_name = "PATH", requires = "entrypoint")]
//   pub stdin: Option<String>,
```

At the transient dispatch (`run_dispatch` → the `MachineRunMode::Transient` / `InteractiveTransient` arms), set `run_args.stdin`:

```rust
use std::io::IsTerminal as _;
let stdin_bytes = crate::commands::vm::invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
// ... where run_args is built:
run_args.stdin = stdin_bytes;
```

In `run_entrypoint_action` (~line 2337), replace the old flag read (`args.stdin` at line 2361) with the auto-read feeding `RunEntrypoint`'s payload:

```rust
use std::io::IsTerminal as _;
let stdin = crate::commands::vm::invoke::read_auto_stdin(std::io::stdin().is_terminal())?;
// hand `stdin` (Vec<u8>) to the entrypoint call in place of the old
// read_stdin_payload(args.stdin.as_deref()) result.
```

Remove every remaining reference to the deleted field: the `stdin: args.stdin.clone()` at ~line 2361 and `stdin: None` at ~line 2485 (`boot_persistent_by_name`) — delete those struct-init lines.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo nextest run -p mvm-cli machine_run_rejects_removed_stdin_flag`
Expected: PASS. Then `cargo build --bin mvmctl` to confirm no dangling `stdin` references.

- [ ] **Step 5: Commit**

```bash
git add crates/mvm-cli/src/commands/machine/mod.rs crates/mvm-cli/tests/cli.rs
git commit -m "feat(run): auto-detect non-TTY stdin; remove the --stdin flag"
```

---

## Task 4: Full-suite green + help-text snapshot

**Files:**
- Modify: `crates/mvm-cli/tests/cli.rs` (help assertion if one pins `machine run --help` output)

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn machine_run_help_has_no_stdin_flag() {
    let mut cmd = assert_cmd::Command::cargo_bin("mvmctl").unwrap();
    let out = cmd.args(["machine", "run", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(!help.contains("--stdin"), "help still advertises --stdin:\n{help}");
}
```

- [ ] **Step 2: Run test to verify it fails, then passes**

Run: `cargo nextest run -p mvm-cli machine_run_help_has_no_stdin_flag`
Expected: PASS if Task 3 landed cleanly (the flag is gone). If a pre-existing snapshot test pins the old help, update the snapshot in this step.

- [ ] **Step 3: Run the full gate**

Run:
```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo nextest run --workspace
cargo test --workspace --doc
```
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "test(cli): assert machine run help drops --stdin; full-suite green"
```

---

## Task 5: Live acceptance — channel-1 inbound proof (manual, not CI)

This is the Step-0 inbound proof from the design, now idiomatic. It boots a VM, so it is a documented manual acceptance step, not a CI test.

- [ ] **Step 1: Build fresh bins co-located**

Run: `cargo build -p mvmctl -p mvm-vm-host --bin mvmctl --bin mvm-hvf-supervisor`

- [ ] **Step 2: Run the round-trip**

Run:
```bash
printf 'STDIN-RT-42' | ./target/debug/mvmctl machine run --image alpine --hypervisor inhouse --json -- /bin/cat
```
Expected: JSON `outcome.stdout_bytes == 11` and `outcome.stdout_sha256 == 81fce04b8b9ba4c6d54dfd19eea070fbaeef1d94120c9d403e6f45c916600cb3` (`sha256("STDIN-RT-42")`). This proves host→guest stdin delivery over the in-house `agent.sock` end-to-end.

- [ ] **Step 3: Record the result** in `specs/notes/2026-07-02-vz-deprecation-design.md` (flip the Step-0 "channel-1 inbound" bullet from "NOT YET PROVEN" to PROVEN with the hash), and commit.

---

## Roadmap: subsequent plans (not in this document)

This spec decomposes into three shippable plans; this is Phase 1. The next two are authored separately because Phase 2's console slice depends on an unresolved spike:

- **Plan 221 — Phase 0 spike + Phase 2 (flip + wire).** First task: spike whether the in-house `vmm/vsock.rs` bridge can pre-open guest console data ports on demand or needs them fixed at boot. Then: flip `AnyBackend::auto_select` (macOS-26 → in-house) and `builder_backend_select::auto_detect_default_for` (→ in-house builder); add the dev-gated `dev_console` pre-open + `DevConsoleTransport` (rename of `VzTransport`) + the `pick_console_transport` in-house probe (extend the two claim-15 boundary tests); collapse `hvf` → the runner and delete `HvfBackend::start`'s duplicate. Keep Vz reachable via explicit `--hypervisor vz` / `MVM_BUILDER_BACKEND=vz`.
- **Plan 222 — Phase 3 (delete Vz).** Remove `vz.rs`, `vz_control.rs`, the (renamed) transport's Vz naming, `mvm-vz-supervisor` (Rust bin + Swift), `is_vz_default_tier`, `vz_builder.rs` / `BuilderBackendChoice::Vz`, and Vz cases across `catalog` / `console` / `for_started_vm` / doctor. Gated on Plan 221 proven live AND mvmd confirming its `mvmctl::runtime::*` consumption still builds.
