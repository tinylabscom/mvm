# HVF supervisor inherited the caller's stderr, hanging every captured-output caller

Backing: shipped-source
Validation: check-claim-catalog

## Status

Fixed. Found by the end-to-end launch suite
(`features/suites/s31_launch_e2e/`) on 2026-08-26, on macOS 26 / Apple Silicon
with the HVF backend. Tracked as #2885.

This is **not** the launch regression fixed in #2884. That one — a cold
universal-initramfs cache silently producing a guest with no runtime overlay —
had masked this defect completely: before it, no guest booted at all on this
host, so nothing ever reached the persistent path's post-boot steps.

## What the first diagnosis got wrong

The issue was originally filed as "`machine start` hangs and `machine exec`
returns `os error 5`". Both halves were wrong, and the correction is recorded
here rather than edited away.

`machine start` returns in 0.4s and `machine exec` works. What made `start` look
like it hung was the *shell pipeline* it was being observed through. The
`os error 5` was a separate artifact: that machine had been left half-started by
a debug-built supervisor that was SIGKILLed, and it does not reproduce on a
cleanly started machine.

## The actual defect

`mvmctl machine start` spawns the detached `mvm-hvf-supervisor` with
`stderr(Stdio::inherit())`. The supervisor owns its guest for the VM's whole
life, so it held the **spawning process's stderr file descriptor** for that
whole life. `mvmctl` exits 0 promptly, but any caller that captures stderr
through a pipe and reads to EOF never sees EOF.

```
mvmctl machine start X > file 2>&1     # 0.426s, exits 0
mvmctl machine start X 2>&1 | cat      # never terminates
```

Reached by:

- `Command::output()` — the BDD steps.
- `subprocess.run(argv, capture_output=True)` — the Python SDK's live
  transport, at every call site, so `mvmctl run --mode live` inherited it.
- any `2>&1 | ...` shell pipeline.

Invisible interactively at a TTY, because there is no pipe to hold open. Only
automation sees it.

## Fix

libkrun already routed supervisor stderr to a per-VM log file; the two HVF
sites were never converted. The routing is now one shared helper,
`mvm_vmm::host::console_capture::supervisor_stderr`, used by all three
(`hvf.rs`, `hvf_restore.rs`, `libkrun.rs`), so they cannot drift again. It
falls back to `inherit` only when the state dir cannot be written — a boot
that is already failing, where losing the diagnostics would be worse.

## A second defect behind the first

With the stderr leak fixed, the persistent lifecycle went green and the
SDK live-mode scenario failed differently:

```
`mvmctl machine run --up-json` stdout is not valid JSON: Expecting value
```

`machine run -d --up-json` printed the human `started machine <name>` banner to
**stdout**, ahead of the JSON envelope, so the SDK's `json.loads(stdout)` died
on line 1 column 1. `machine start` already withheld the banner under `--json`;
the `run` path hardcoded `quiet: false`.

`machine_run_up_json_guards_stdout` existed the whole time and passed the whole
time — it asserts `emits_machine_readable_stdout()`, a parse-level flag, which
says stdout is *reserved* and nothing about whether anything else writes to it.
The construction of the start arguments is now a named function
(`start_args_for_run`) so the wiring is pinned, not just the decision: a mapping
that stopped consulting `banner_suppressed` would otherwise leave a
`banner_suppressed`-only test green.

## Witnesses

- `supervisor_stderr_creates_the_log_inside_the_state_dir`
- `supervisor_stderr_truncates_a_previous_boots_log`
- `supervisor_stderr_falls_back_when_the_state_dir_is_absent`
- `s31_launch_e2e/cli_launch_modes.feature` — "the documented persistent machine
  lifecycle operates one guest". The behavioural witness: its steps drive
  `mvmctl` through `Command::output()`, so it cannot terminate while the
  supervisor holds that pipe.
- `s31_launch_e2e/sdk_and_library_modes.feature` — "a runtime-SDK script boots a
  real guest in live mode". Same, through the SDK's capture transport, and the
  witness for the `--up-json` stdout pollution above.
- `machine_run_up_json_withholds_the_started_banner` — pins both the decision
  and the wiring; verified red against a `quiet: false` mutation.
- `machine_run_without_up_json_keeps_the_started_banner` — an interactive `-d`
  run still says the machine started.

The persistent-lifecycle scenario was `@wip` while this was open and is now
un-tagged. The SDK live-mode scenario stays `@wip`, re-attributed: both blockers
named here are fixed and it now boots a real guest, but it then fails on the
first guest-RPC verb it issues. Every `fs` and `proc` verb answers "Unexpected
response to ... verb" on a build predating this work — a host/agent wire drift
tracked as #2887, in a different subsystem. Un-tag it there, not here.

## A signing trap worth knowing

Verifying this cost a wrong turn worth recording. `cargo build` re-links the
per-VM supervisor whenever its dependency graph changes and does **not**
re-sign it; `mvm-hvf-supervisor` has no `ensure_signed()` of its own (the
libkrun one does). macOS then SIGKILLs the unentitled binary, and the only
symptom is:

```
hvf supervisor exited before writing its PID file (status: signal: 9 (SIGKILL))
```

which names neither the signature nor the rebuild that dropped it. It reads
exactly like a boot regression. `mvmctl env sign` fixes it, and
`scripts/e2e-launch-modes.sh` now runs that after every build so the suite
cannot fail this way again.
