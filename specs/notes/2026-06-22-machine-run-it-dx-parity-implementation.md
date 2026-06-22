# `machine run -it` DX Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `mvmctl machine run --image <img> -it` boot quietly and drop into a shell with working job control, matching the `docker run -it` experience.

**Architecture:** Three independent changes, each its own commit. (1) The guest PTY child claims its slave as a controlling terminal so the shell enables job control. (2) The boot-time `started machine <id>` banner is suppressed when an interactive shell attach follows. (3) The Vz supervisor's ad-hoc `codesign` call stops leaking its stdout/stderr on success. Design: `specs/notes/2026-06-22-machine-run-it-dx-parity-design.md`.

**Tech Stack:** Rust, raw POSIX FFI (`ioctl`/`setsid`), clap derive, `libc` (dev), `cargo nextest`.

## Global Constraints

- Comments must not reference plans, PRs, ADRs, or sprint docs (CI lint `check-no-spec-refs-in-comments`). Keep the reasoning, drop the citation.
- `#[allow(clippy::too_many_arguments)]` is banned in hand-written code.
- Prose/comments terse, expert-level — WHY not WHAT, no decorative bold.
- Commit messages: no `Co-Authored-By: Claude` trailer; attribute to the repo author.
- Final gates (run before declaring done): `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo nextest run --workspace`, `cargo test --workspace --doc`, `cargo build --all-targets`, and `cargo run -p xtask -- check-no-spec-refs-in-comments` (or `just lint`).
- Does NOT edit the in-flight branches `fix/machine-run-it-fast-teardown` (owns the `Stopping transient machine` line — leave it) or `fix/machine-run-it-console-attach`.

---

### Task 1: Job control — claim the PTY slave as controlling terminal

The guest shell prints `can't access tty; job control turned off` because the
forked child calls `setsid()` (new session, no controlling tty) and never claims
the PTY slave via `TIOCSCTTY`. Add that ioctl. This is the only functional bug.

**Files:**
- Modify: `crates/mvm-guest/src/console.rs` (FFI const block ~line 83-87; child branch ~line 189-212; add helper near `resize_pty` ~line 244; test module at line 538)

**Interfaces:**
- Produces: `unsafe fn set_controlling_tty(slave_fd: i32)` — private to `console.rs`; called in the post-`fork` child after `setsid()`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `crates/mvm-guest/src/console.rs` (after `test_is_active_default`, before the closing `}` at line 626):

```rust
    // Linux-only: TIOCSCTTY + /dev/tty controlling-terminal semantics are
    // Linux-specific. macOS dev hosts skip this; the Linux CI lane runs it.
    #[cfg(target_os = "linux")]
    #[test]
    fn child_acquires_controlling_tty() {
        let ws = Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut master_fd: i32 = -1;
        let mut slave_fd: i32 = -1;
        // SAFETY: out-params are live i32s; name/termp NULL = defaults.
        let rc = unsafe {
            openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                &ws,
            )
        };
        assert_eq!(rc, 0, "openpty failed");

        // SAFETY: fork has no preconditions; returns 0 in child.
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            // Child: become a session leader, claim the slave as our
            // controlling terminal, then prove it by opening /dev/tty
            // (only a process WITH a controlling tty can). Async-signal-safe
            // calls only: setsid/ioctl/open/_exit.
            // SAFETY: slave_fd is a valid PTY slave; we are post-fork.
            unsafe {
                setsid();
                set_controlling_tty(slave_fd);
                let fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR);
                libc::_exit(if fd >= 0 { 0 } else { 1 });
            }
        }

        // SAFETY: slave_fd valid; the child holds its own copy.
        unsafe {
            close(slave_fd);
        }
        let mut status: i32 = 0;
        // SAFETY: pid is the just-forked child; status is a live i32.
        unsafe {
            waitpid(pid, &mut status, 0);
            close(master_fd);
        }
        assert!(libc::WIFEXITED(status), "child did not exit normally");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child could not open /dev/tty — no controlling terminal acquired"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails (compile error — symbol absent)**

Run: `cargo test -p mvm-guest --lib console::tests::child_acquires_controlling_tty 2>&1 | tail -20`
Expected: FAIL — `cannot find function set_controlling_tty in this scope`.

- [ ] **Step 3: Add the const, the helper, and wire the call**

In `crates/mvm-guest/src/console.rs`, after the `TIOCSWINSZ` const block (line 87) add:

```rust
/// ioctl request to set the controlling terminal.
#[cfg(target_os = "linux")]
const TIOCSCTTY: u64 = 0x540E;
#[cfg(not(target_os = "linux"))]
const TIOCSCTTY: u64 = 0x2000_7461;
```

Add the helper immediately before `resize_pty` (line 244):

```rust
/// Make `slave_fd` the controlling terminal of the calling session, so an
/// interactive shell can do job control (Ctrl-Z/fg/bg, Ctrl-C process-group
/// signaling). `setsid()` alone leaves the new session leader with no
/// controlling tty.
///
/// # Safety
/// Must run in the forked child after `setsid()`: `slave_fd` must be a valid
/// open PTY slave and the caller a fresh session leader with no controlling
/// terminal yet. Async-signal-safe (a single `ioctl`).
unsafe fn set_controlling_tty(slave_fd: i32) {
    // SAFETY: TIOCSCTTY takes an int arg; 0 = do not steal the tty from an
    // existing session. `slave_fd` is a live PTY slave fd.
    unsafe {
        ioctl(slave_fd, TIOCSCTTY, 0i32);
    }
}
```

In the child branch, insert the call right after `setsid();` (line 191), before the `dup2` calls:

```rust
            close(master_fd);
            setsid();
            set_controlling_tty(slave_fd);
            // Redirect stdin/stdout/stderr to the PTY slave.
            dup2(slave_fd, 0);
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p mvm-guest --lib console::tests::child_acquires_controlling_tty 2>&1 | tail -20`
Expected: PASS (1 passed).

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all
cargo clippy -p mvm-guest --all-targets -- -D warnings
git add crates/mvm-guest/src/console.rs
git commit -m "fix(guest): claim PTY slave as controlling tty so -it shell has job control"
```

---

### Task 2: Suppress the boot banner in interactive mode

`start_machine` prints `started machine <name>` (`mod.rs:1546`), reached by the
interactive path via `run_interactive` → `persist_and_boot_machine`. Add a
non-CLI `quiet` flag to `MachineStartArgs`, set it on the interactive call, and
skip the banner when it is set. Detached / `--json` / standalone `machine start`
keep printing.

**Files:**
- Modify: `crates/mvm-cli/src/commands/machine/mod.rs` (struct line 580-593; print branch line 1542-1547; construction sites line 1824-1829 and 1903-1908; test module at line 2006)

**Interfaces:**
- Consumes: nothing new.
- Produces: `MachineStartArgs { name, receipt, json, dry_run, quiet }` — `quiet: bool` is `#[arg(skip)]` (not a CLI flag, defaults `false`).

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `crates/mvm-cli/src/commands/machine/mod.rs` (alongside `list_inspect_and_remove_parse`, using the existing `parse` helper):

```rust
    #[test]
    fn start_quiet_is_internal_only_and_defaults_off() {
        // `quiet` is not a user-facing flag — the standalone `machine start`
        // and the detached path must keep printing the boot banner.
        match parse(&["start", "--name", "web"]).expect("parse") {
            MachineAction::Start(args) => assert!(!args.quiet),
            other => panic!("expected start action, got {other:?}"),
        }
        assert!(
            parse(&["start", "--name", "web", "--quiet"]).is_err(),
            "--quiet must not be exposed as a CLI flag"
        );
    }
```

- [ ] **Step 2: Run the test to verify it fails (compile error — field absent)**

Run: `cargo test -p mvm-cli --lib commands::machine::tests::start_quiet_is_internal_only_and_defaults_off 2>&1 | tail -20`
Expected: FAIL — `no field quiet on type MachineStartArgs`.

- [ ] **Step 3: Add the field, set it on the interactive call, gate the banner**

In the `MachineStartArgs` struct (after the `dry_run` field at line 592):

```rust
    /// Validate and explain the effective start without booting a VM.
    #[arg(long)]
    pub dry_run: bool,
    /// Suppress the human `started machine <name>` banner — set internally
    /// when an interactive shell attach follows. Not a CLI flag.
    #[arg(skip)]
    pub quiet: bool,
```

In `run_persistent` (the construction at line 1824-1829), keep the banner — add `quiet: false`:

```rust
        MachineStartArgs {
            name: name.clone(),
            receipt: args.receipt.clone(),
            json: args.json,
            dry_run: false,
            quiet: false,
        },
```

In `run_interactive` (the construction at line 1903-1908), suppress it — add `quiet: true`:

```rust
        MachineStartArgs {
            name: name.clone(),
            receipt: None,
            json: false,
            dry_run: false,
            quiet: true,
        },
```

Change the print branch at line 1542-1547 to skip the banner when quiet:

```rust
    if args.json {
        let summary = MachineStartJsonSummary::from_parts(receipt_input, outcome, args.receipt);
        println!("{}", serde_json::to_string_pretty(&summary)?);
    } else if !args.quiet {
        println!("started machine {}", spec.name);
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p mvm-cli --lib commands::machine::tests::start_quiet_is_internal_only_and_defaults_off 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Lint and commit**

```bash
cargo fmt --all
cargo clippy -p mvm-cli --all-targets -- -D warnings
git add crates/mvm-cli/src/commands/machine/mod.rs
git commit -m "fix(cli): suppress 'started machine' banner when machine run -it attaches a shell"
```

---

### Task 3: Stop the Vz supervisor leaking codesign output

`ensure_self_signed` runs `codesign` with `.status()`, so codesign's
`replacing existing signature` line is inherited and printed on (effectively)
every debug-build run. Capture with `.output()` and surface stderr only on
failure — mirroring `crates/mvm-backend/src/codesign.rs`.

This function execs `codesign` and then re-execs the process; it is macOS-cfg'd
and not isolable for a unit test. Verification is the macOS build gate plus a
manual interactive run. No fabricated test.

**Files:**
- Modify: `crates/mvm-vm-host/src/bin/mvm-vz-supervisor.rs:106-116`

- [ ] **Step 1: Replace `.status()` with captured `.output()`**

Replace lines 106-116 (the `let signed = Command::new("codesign")…` block through its `if !signed { … return; }`) with:

```rust
        let output = Command::new("codesign")
            .args(["--sign", "-", "--force", "--entitlements"])
            .arg(&ent)
            .arg(&exe)
            .output();
        let signed = output.as_ref().map(|o| o.status.success()).unwrap_or(false);
        if !signed {
            eprintln!("mvm-vz-supervisor: ad-hoc codesign failed; VM start may be rejected");
            // On success codesign's "replacing existing signature" line is
            // discarded; on failure its stderr is the actionable detail.
            if let Ok(o) = &output {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stderr = stderr.trim_end();
                if !stderr.is_empty() {
                    eprintln!("{stderr}");
                }
            }
            return;
        }
```

- [ ] **Step 2: Verify it builds (macOS)**

Run: `cargo build -p mvm-vm-host --bin mvm-vz-supervisor 2>&1 | tail -10`
Expected: builds clean, no warnings.

- [ ] **Step 3: Manual verification (macOS, interactive)**

Run: `cargo run -- machine run --image alpine -it`
Expected: the `…/mvm-vz-supervisor: replacing existing signature` line is gone; you reach the Alpine shell with no `can't access tty` warning (Task 1) and no `started machine <id>` banner (Task 2).

- [ ] **Step 4: Lint and commit**

```bash
cargo fmt --all
cargo clippy -p mvm-vm-host --all-targets -- -D warnings
git add crates/mvm-vm-host/src/bin/mvm-vz-supervisor.rs
git commit -m "fix(vm-host): capture codesign output in vz supervisor instead of leaking it to the terminal"
```

---

### Task 4: Full-workspace gates

- [ ] **Step 1: Run the complete gate set**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo test --workspace --doc
cargo build --all-targets
cargo run -p xtask -- check-no-spec-refs-in-comments
```

Expected: all green. (`just lint` + `just test` wrap most of these.)

- [ ] **Step 2: Confirm the three commits are present and the branch is clean**

```bash
git log --oneline origin/main..HEAD
git status --short
```

Expected: three `fix(...)` commits on `feat/machine-run-it-dx-parity`, clean tree.

---

## Self-review

- **Spec coverage:** A1 → Task 3; A2 → Task 2; A3 → Task 1. All three Plan A items covered. Plan B is explicitly deferred in the design doc — no tasks here, by design.
- **Type consistency:** `set_controlling_tty(slave_fd: i32)` used identically in the helper, the child call, and the test. `MachineStartArgs.quiet: bool` added to the struct and both construction sites and read in the print branch.
- **In-flight composition:** Task 2 touches only the boot-banner emit in `start_machine`; the `Stopping transient machine` teardown line owned by `fix/machine-run-it-fast-teardown` is untouched. Tasks 1 and 3 touch files no in-flight branch edits.
- **No placeholders:** every code step carries complete code; Task 3 honestly omits a unit test (exec wrapper) and substitutes a build + manual gate.
