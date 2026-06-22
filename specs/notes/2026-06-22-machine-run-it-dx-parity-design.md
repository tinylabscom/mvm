# `machine run -it` DX: docker-parity interactive sessions

Status: design approved, ready for implementation plan
Date: 2026-06-22

## Problem

`mvmctl machine run --image alpine -it` drops into an Alpine shell, but the
transcript around it is noisy and the shell itself is degraded:

```
/Users/.../target/debug/mvm-vz-supervisor: replacing existing signature
started machine i-2744c62f
/bin/sh: can't access tty; job control turned off
~ #
```

Three defects, two cosmetic and one functional:

1. `codesign` self-signing output leaks to the terminal on (effectively) every
   debug-build invocation.
2. A `started machine <id>` lifecycle banner prints in front of the prompt —
   `docker run -it` does not announce the container before the shell.
3. The guest shell reports `can't access tty; job control turned off`: it has no
   controlling terminal, so Ctrl-Z / `fg` / `bg` / Ctrl-C process-group signaling
   misbehaves. This is a real PTY-wiring bug, not cosmetics.

The interactive path already reuses the polished console relay
(`crates/mvm-cli/src/commands/vm/console.rs` → `console::run`): raw mode,
SIGWINCH, and `ConsoleResize` over the control RPC (guest agent port) are
already wired for `-it`. Terminal resize is therefore not in scope — it works.

## Scope: Plan A (this spec) — docker-parity

Goal: `machine run -it` boots quietly, drops straight into a shell with working
job control and resize, and exits cleanly. Three independent changes.

### A1 — Silence codesign self-signing noise

`crates/mvm-vm-host/src/bin/mvm-vz-supervisor.rs` `ensure_self_signed()` shells
out to `codesign` with `.status()`, so codesign's own
`replacing existing signature` line (stderr) is inherited by the parent and
printed. The binary is re-signed whenever it lacks the virtualization
entitlement, which a re-linked debug build trips on nearly every run.

Fix: capture with `.output()` and surface captured stderr only on failure.
This mirrors the already-correct path in
`crates/mvm-backend/src/codesign.rs` (uses `.output()`). No behavior change on
the signed-release path; pure output hygiene.

### A2 — Suppress the boot banner in interactive mode

`start_machine()` prints `started machine {name}`
(`crates/mvm-cli/src/commands/machine/mod.rs`, the non-`--json` arm). The
interactive transient/persistent path reaches it via
`run_interactive` → `persist_and_boot_machine` → `start_machine`.

Fix: add a `quiet: bool` field to `MachineStartArgs`; set it `true` from
`run_interactive`'s `persist_and_boot_machine` call so the human banner is
suppressed when a shell attach follows. Detached (`-d` / `--name` without a
TTY), transient-with-command, and every `--json` path are unchanged — the
machine ID still prints where a caller needs it to reattach or script.

Out of scope for A2: the `Stopping transient machine {name}.` teardown line in
`run_interactive`. That line is owned by the in-flight
`fix/machine-run-it-fast-teardown` branch, which added it deliberately as
feedback that a Ctrl+D SIGKILL teardown completed (the alternative reads as a
hang). We keep it. A2 touches only the boot-banner emit, not the teardown
region that branch edits, so the two compose without collision.

### A3 — Establish the controlling terminal (job control)

`crates/mvm-guest/src/console.rs` `open_session()` forks a child that calls
`setsid()` then `execve("/bin/sh", ["-i"])`, dup'ing the PTY slave onto
fds 0/1/2. `setsid()` makes the child a session leader but leaves it with no
controlling terminal, so the interactive shell prints
`can't access tty; job control turned off` and cannot drive job control.

Fix: after `setsid()` and before the dups, `ioctl(slave_fd, TIOCSCTTY, 0)` to
claim the PTY slave as the session's controlling terminal.

Test: guest-side console regression test asserting the session establishes a
controlling tty for the child (e.g. the child's `tcgetpgrp(slave)` /
`/proc/<pid>/stat` tty_nr is the PTY, or equivalently that the `setsid` leader
acquires the slave as controlling tty). The test must fail without the
`TIOCSCTTY` call and pass with it.

## In-flight work this composes with (do not edit those branches)

- `fix/machine-run-it-console-attach` — pre-opens console data ports so `-it`
  can attach (backends + `mvm-guest/vsock.rs`). Enabling plumbing; orthogonal.
- `fix/machine-run-it-fast-teardown` — fast SIGKILL teardown; owns the
  `Stopping transient machine` line A2 deliberately leaves alone.
- `fix/typed-builder-progress-visible` — merged as #1273 (build-progress
  streaming); already on main.

A1 and A3 touch files none of these branches edit. A2 touches only the
boot-banner emit in `start_machine`.

## Deferred follow-ups (Plan B)

mvm-native niceties beyond docker parity, recorded here, not built in Plan A:

- [ ] Boot feedback: a spinner/status while the microVM boots (not instant like
      a container), cleared on shell entry — replaces "stare at nothing, then a
      prompt".
- [ ] Detach sequence: a Ctrl-P Ctrl-Q equivalent that leaves a persistent
      `-it` session running without killing it.
- [ ] Reattach hint: on persistent `-it` exit, print
      `reattach: mvmctl machine console {name}`.
- [ ] Exit-status passthrough: propagate the guest shell's exit code as
      `mvmctl`'s process exit code (docker-style).
