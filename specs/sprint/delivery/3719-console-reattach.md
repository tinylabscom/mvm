# Console reattach (PS-09, part of #3719)

`mvmctl machine console` used to end the shell whenever its client went away:
the guest agent's relay SIGTERMed the foreground job and the shell on EOF, so
a console could not be left and picked up again. Sessions now outlive their
client.

## Guest agent

- `crates/mvm-agentd/src/console/registry.rs` is a pure state machine for the
  one console session a VM carries: pending attach, live client, detached,
  busy, take-over, exited. Every transition runs under one mutex, and the exit
  code is recorded before the client is hung up, so a host that sees its data
  stream end can always ask how the session finished.
- `crates/mvm-agentd/src/console/scrollback.rs` holds the last
  `SCROLLBACK_CAP_BYTES` (1 MiB, const-asserted to stay within 1–8 MiB) of
  output. A wrapped replay starts at the first newline within 4 KiB so it does
  not open mid-escape-sequence.
- The output pump runs for the session's whole life, attached or not. A client
  that cannot take output within 5 s is detached rather than allowed to stall
  the shell. The pump also polls the shell's exit, so a background job holding
  the terminal open no longer keeps a finished session alive.
- Each attach allocates a fresh data port and binds its listener before the
  control reply is sent. The host-CID peer check is unchanged, and an accept
  that never arrives lapses after 30 s.
- The shell's exit status goes through `child_wait::try_wait_pid`, a raw-pid
  sibling of `try_wait`. Before this change, a console shell's status could be
  swallowed by the PID 1 orphan reaper.
- Optional detach timeout: a session left with no client for that long is hung
  up.

## Protocol

New requests: `ConsoleAttach { session_id, cols, rows, take_over }`,
`ConsoleDetach`, `ConsoleList`. New responses: `ConsoleAttached`,
`ConsoleBusy`, `ConsoleDetached`, `ConsoleSessions { ConsoleSessionInfo }`.
`ConsoleOpen` gains `detach_timeout_secs`; `ConsoleClose` now means terminate:
it hangs the shell up, escalates to SIGKILL, and returns the exit code. Every
new verb is `DevOnly`, a control-plane verb, and does not spawn a workload
process. A sealed VM therefore refuses them through the same profile and
grant gates as `ConsoleOpen`, and the agent's `access.console` policy check is
shared by all of them. All types use `deny_unknown_fields`. The session
listing reports argv\[0\] only. Schema and SDK stubs were regenerated, and the
`fuzz_guest_request` corpus has new seeds.

## CLI

- `machine console <vm>` (alias `machine attach`) attaches to the running
  session, replaying its scrollback, or starts one. A console with its own
  argv or environment (`machine exec -t -- cmd`, `machine run -it -- cmd`)
  still gets a dedicated session, and it is refused while the shared shell
  runs.
- Escapes: `~d` detaches and `~.` ends the session. `--help` states both.
- `--list`, `--force` (take over from the attached client), and
  `--detach-timeout <SECONDS>`. `--force` used to be a no-op; it now has this
  meaning, and `machine shell --force` passes it through.
- `machine detach <vm>` disconnects whoever is attached.
- Audit uses the existing mechanisms: `ConsoleSessionStart` carries
  `attach=open|reattach|take-over`, `ConsoleSessionEnd` carries
  `outcome=exited|terminated|detached|displaced|detached-remotely`, and every
  console request emits the inbound vsock RPC record.

**Why `--force` is safe.** It requires the same authorization as a plain
attach. It changes no privilege and leaves the shell and its state alone. Its
only effect is to hang up another client of the same host principal. The
displaced client sees its stream end and queries the session. It finds the
session running and reports that it was displaced. It does not send
`ConsoleClose`, so it cannot kill the shell out from under its successor.

## Also landed

- The lifecycle surface is `ps` (existing alias of `ls`), `attach`, `detach`,
  `logs -f`, `stop`, and `inspect`. `inspect` still covers persistent machine
  specs only.

## Still open

- Detached start does not yet fail closed when the machine or its control
  socket fails to come up.
- Healthchecks and session timeouts are not enforced, and there is no
  documented restart policy.

## Tests

- Scrollback: wraparound, cap, a single oversized write, and line-aligned
  replay.
- Registry: first-attach replay, busy, pending-attach busy, detach and
  reattach with a fresh port, lost connection, stalled client, take-over,
  superseded connection, exit before hang-up, attach after exit,
  open-while-running, unknown session, and the detach timeout.
- Console: terminate semantics against a stand-in pump, and a Linux-only
  end-to-end PTY test covering the pump, exit code, and replay.
- `child_wait`: raw-pid recovery from the reaper.
- Wire: round trip and unknown-field rejection for every new request and
  response, plus response contracts.
- CLI: escape filter (`~d`, `~.`), guest-close classification, and help and
  parse tests in `tests/cli.rs`. `tests/audit_total_coverage.rs` classifies
  `machine detach`.

## Live verification

These runs used a debug `just embed` build, the macOS 26 Apple Silicon HVF
backend, and `machine run --image alpine --name cr-live --profile dev -d`. A
Python pty harness drove the console.

- **Open and detach.** `echo FIRST-42` ran. A background job was started to
  print later, then `~d` detached with exit 0. `--list` reported
  `detached 18s, 127 B`.
- **Reattach.** The replay showed `FIRST-42` and `WHILE-DETACHED-25`, which
  was printed while nobody was attached. The shell's job table survived, and
  it reported `[1]+ Done`.
- **Busy and take-over.** A second attach while one was live was refused and
  named `--force` and `machine detach`. `--force` took the session over, and
  the displaced client printed that it was disconnected and exited 0 without
  ending the shell. `machine detach` did the same from another process, and
  said so when nobody was attached.
- **End with `~.`.** The session was listed as `exited (129)` (SIGHUP). The
  next `machine console` opened session 2, and `exit` there recorded
  `exited (0)`.
- **Window size.** `stty size` read `30 100` when the session was opened at
  100x30 and `50 132` after reattaching at 132x50.
- **Killed client.** SIGKILL of the client left the session `detached`.
- **Dedicated session.** `machine exec -t -- echo hi` was refused while the
  shared shell ran ("console session 3 is already running").
- **Detach timeout.** With `--detach-timeout 3`, the session went from
  `detached 0s, ends at 3s` to `exited (129)` within 5 s.
- **Grant gate.** The same VM booted without `--profile dev` (restricted
  ProdSafe grant) refused `console-list` with "verb console-list not
  authorized by the session's verb grant".
- **Audit log.** `~/.mvm/state/log/audit.jsonl` carried `verb=console-list`,
  `console-attach`, `console-open`, and `console-close` inbound records, along
  with `console_session_start` (`attach=open|reattach`) and
  `console_session_end` (`outcome=detached|terminated`).

Separately, on the Linux KVM box, the full `mvm-agentd` suite passed (857 lib
tests), including the Linux-only PTY end-to-end test.

The first boot failed with `VerbNotAuthorized { activate-environment }`. That
failure predates this change and is unrelated to it. The run's verb grant was
minted before a 446 s cold build of the guest runtime and had expired
(`verb grant expired` in the guest console) by the time the guest checked it.
With the runtime cached, a re-run booted normally.
