# `machine run` says what it is waiting on

A first `mvmctl machine run --image rust -it -- /bin/bash` from a source
checkout could sit on a blank terminal for minutes. That happened while it
built the Stage 0 builder image, compiled the workload kernel and the guest
runtime, pulled the image, or queued behind another session's lock. Every one
of those waits now has a live status line on stderr, at the default verbosity.
The plan is `specs/plans/2026-09-24-machine-run-never-silent.md`.

## What the terminal shows now

- **One live line on a TTY.** It shows a spinner, the phase, the elapsed time,
  and a detail such as bytes pulled, advisories fetched, or `building
  linux-6.12 (3/42) · fetched 118/118 paths`.
- **Scrollback lines only for slow phases.** A phase still running after two
  seconds leaves `[mvm] <phase>…` in the scrollback, then `[mvm] <phase> — done
  in 4m12s` when it ends. A cached kernel or a reused image passes through in
  milliseconds and prints nothing.
- **No live line off a TTY.** An announced phase prints a heartbeat line every
  15 s instead.
- **stdout is untouched.** It still carries only results and JSON.
- **The in-guest nix build is visible on HVF.** `BuilderRunner` already tailed
  the builder console to notice a halted guest. It now also condenses the
  lines it reads into the status detail, and echoes them raw at `-v`. Until
  now, `-v` switched off the Stage 0 spinner on the assumption that the log was
  streaming, which only libkrun did. On HVF, `-v` meant total silence.

## Lock waits

`acquire_lock_waiting` in `mvm-build` generalizes the store-image lock's
existing queue-and-report loop. Every waiter uses it: the builder store,
volumes, the three Stage 0 locks, and the guest-runtime and runtime-overlay
build locks.

- **It names the holder.** The status line reads `waiting for <what> — held by
  pid N (`cmd`) since HH:MM:SS`.
- **It waits instead of failing.** The Stage 0 locks used to fail at once with
  "delete the lock file and retry". That advice was always wrong for an
  `flock` lock: the kernel releases the lock when its holder exits, so a
  crashed holder is reclaimed on the next poll.
- **The builder bootstrap re-checks its cache after the wait.** The session it
  waited on has usually just built the same image.

## Verification

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `RUSTFLAGS="-D warnings" just check-gated`
- `cargo nextest run --workspace`
- `cargo test --workspace --doc`
- The xtask gates the CI lint job runs.

New tests cover:

- TTY and plain rendering, the deferred announcement, the width cap, and
  nesting.
- nix log parsing and the condensed summary.
- Console-line condensing and raw echo.
- The lock paths:
  - the waiting line names a live holder;
  - a stale owner record is ignored;
  - a Stage 0 waiter proceeds once the holder releases;
  - an integration test kills a separate holder process and checks the waiter
    reclaims the lock.
- Byte progress through the hermetic registry.
- OSV advisory progress.

Not verified: a live cold run on macOS 26 HVF. The change was not booted
against a real Stage 0 build or a concurrent `machine build`. That check is the
plan's last open item.
