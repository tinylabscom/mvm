# Plan 305 WS4 — seccomp-audit now follows clones and threads

WS4 (confine the four unconfined signer/broker roles) was blocked on the
tracer: `mvmctl seccomp-audit` observed only the main thread, and all four
roles build a multi-threaded tokio runtime, so any allowlist derived from it
was incomplete by construction. The failure mode is SIGSYS under load, after
the filter is already installed.

## What was actually wrong

Two defects, and the second is the dangerous one.

1. The tracer set neither `PTRACE_O_TRACECLONE`, `PTRACE_O_TRACEFORK` nor
   `PTRACE_O_TRACEVFORK`, and its `waitpid` named `main_pid` without `__WALL` —
   so cloned threads were invisible twice over.

2. Syscall entry/exit state was a single `bool` for the whole session. Entry
   and exit are separate stops and siblings interleave them freely, so a shared
   flag pairs one thread's entry with another's exit and records the wrong half.

Adding the ptrace options alone would have started delivering thread data
through the broken state machine — a plausible but wrong allowlist, which is
worse than the honest "main process only" limitation it replaced.

## Delivered

- Follow clone/fork/vfork; wait on any tracee with `__WALL`.
- Per-tracee entry/exit state (`HashMap<Pid, bool>`).
- Handle the clone-event/SIGSTOP race: whichever arrives first registers the
  tracee, the other is a no-op.
- A new tracee's birth `SIGSTOP` is an attachment artefact and is not forwarded;
  a known tracee's `SIGSTOP` still is. That decision is extracted as
  `is_new_tracee_birth_stop` and witnessed by three tests.
- Only the main process dying by signal fails the audit; a worker thread killed
  by design does not.
- Module docs corrected — they advertised the limitation this removes.

## Validation

`cargo nextest run -p mvm-cli -E 'test(traceclone)'` — 3 passed. The helper
takes a raw signal number rather than `nix`'s `Signal` so it is testable on
macOS, where `nix` is not linked.

`cargo zigbuild --target aarch64-unknown-linux-gnu -p mvm-cli --lib` — clean,
no warnings. The tracer itself is `#[cfg(target_os = "linux")]` and cannot be
exercised on this host.

## Still open in WS4

Deriving the four allowlists needs a live Linux box and a running instance of
each role; confining them is one PR per role afterwards. This change unblocks
that work rather than performing it.
