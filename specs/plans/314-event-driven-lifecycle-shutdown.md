# Plan 314 — Event-driven process lifecycle and shutdown

**Status:** COMPLETE — event-driven process observation, cross-backend adoption, live profiling, leak checks, and repository-wide verification are green

**Last updated:** 2026-08-11

**Resume point:** Complete; open a new measured plan for any further lifecycle optimization

This plan makes process lifecycle waits event-driven where the host owns a
reliable operating-system event, while retaining bounded polling for recovery,
unsupported platforms, and reconciliation. It begins with transient HVF
teardown because the measured `machine run` sample spends 123.0 ms in
`stop_transient` and only 0.6 ms removing state.

The plan deliberately does not convert the entire repository to one async
runtime. Event-driven I/O, process watches, and lifecycle notifications are
the right tools for owned live resources; deadlines, TTLs, leases, retries,
and crash recovery still need timers or reconciliation.

## Current evidence

The representative cached Apple Silicon/HVF run is:

| Phase | Observed |
|---|---:|
| Full one-shot launch | 332.6 ms |
| Authenticated dispatch window | 90.1 ms |
| `stop_transient` | 123.0 ms |
| State removal | 0.6 ms |

Implementation verification now includes nine Linux pidfd/fallback tests,
including live exit, already-exited, timeout, fallback, final verification,
and deterministic `ENOSYS`, `EINVAL`, `ESRCH`, and `EPERM` classification.
The Firecracker driver suite passes 34 tests, and the lifecycle benchmark's
seven harness/configuration tests pass. `cargo check --workspace`,
`cargo fmt --all -- --check`, and Linux
`cargo clippy --workspace --all-targets -- -D warnings` pass with Rust 1.96.
The legacy HVF, libkrun, and QEMU PID probes route through
`mvm-vmm::host::process_liveness::pid_is_alive`.

The final `cargo test --workspace` run passes, including all unit, integration,
CLI, xtask, and documentation tests. Verification also repaired three
load-sensitive test-harness defects exposed by full parallel execution: the
audit dedup test now injects one fixed observation time; the eBPF telemetry
test uses the shared restoring environment guard; and the UDS descriptor test
derives its listener and client paths from one explicit temporary home rather
than mutable process-global state. These changes do not alter production
lifecycle behavior.

The live HVF lifecycle benchmark also passes 1,000/1,000 cycles. It reports
start p50/p95/p99 of 10.18/25.77/53.91 ms and stop p50/p95/p99 of
703.48/1,151.28/1,865.07 ms, with zero force-kill escalations. The stop tail
is now proven to be supervisor PID disappearance rather than observer setup,
endpoint reaping, console cleanup, or fallback SIGKILL handling.

The live Firecracker lifecycle benchmark passes 100/100 serial KVM cycles on
x86_64 Linux with Firecracker 1.14.1, one vCPU, 256 MiB, and an isolated
rootfs-only agent image. Start p50/p95/p99/max was
1,078.24/1,186.82/1,227.48/1,715.35 ms. Stop p50/p95/p99/max was
79.44/116.66/295.95/327.58 ms; driver kill accounted for
75.49/114.61/293.88/325.48 ms of those percentiles. The first repetition run
exposed a transient Firecracker CONNECT-handshake `EPIPE`; classifying
`BrokenPipe` with the connector's existing bounded transient retries fixed the
race without weakening malformed-ack refusal or stop-time flush fail-closed
behavior. The successful rerun left zero live Firecracker processes and zero
PID markers.

A 25-cycle native HVF profile separates the supervisor from the host process
observer. Stop p50/p95/p99 was 61.74/103.08/230.38 ms. From watchdog stop
observation through vCPU run-loop return was 48.44/63.99/160.98 ms and is the
dominant internal span. Watchdog join was at most 0.02 ms; host-I/O join p50 was
0.06 ms (4.56 ms max); vCPU destruction p50 was 0.03 ms; VM destruction p50
was 0.21 ms; console persistence p50 was 0.18 ms. The watchdog checks the stop
flag every 5 ms, so replacing that timer could save no more than 5 ms and would
not address the measured vCPU-exit cost. No lifecycle control channel is
justified: the existing signal reaches the watchdog, and the remaining dominant
span is inside vCPU exit rather than request coordination.

Live Linux KVM coverage now includes 25 serial libkrun cycles and 25 serial
QEMU cycles. Libkrun stop p50/p95/p99 was 44.28/168.18/222.92 ms; QEMU was
28.09/36.97/38.82 ms. The run exposed two harness/runtime issues that are now
covered: benchmark VM names are capped so backend Unix-socket paths fit, and
QEMU resolves its detached bridge through the shared auxiliary-binary resolver
instead of assuming `current_exe()` is `mvmctl`. A five-cycle post-fix rerun of
both backends left zero VMM/supervisor/bridge processes, zero PID markers, and
zero Unix sockets. Cleanup derives allow-listed libkrun paths and accepts QEMU
paths only when they exactly match the repository-derived state-dir/port path;
a persisted bridge spec cannot redirect deletion.

Additional Linux coverage: `cargo zigbuild -p mvm-vmm --target
aarch64-unknown-linux-gnu` passes with the pinned Rust 1.96 compiler, and the
native x86_64 Firecracker host validates the Linux-gated pidfd implementation,
the full all-target clippy surface, and real KVM shutdown behavior.

The current HVF stop path:

1. Reaps optional per-VM endpoints and host-agent registration.
2. Reads `hvf.pid`.
3. Arms the platform process-exit observer before sending `SIGTERM`.
4. Waits for the exit event, falling back to bounded adaptive polling when the
   observer is unavailable or cannot verify liveness.
5. Sends `SIGKILL` after the grace deadline and fails closed if exit still
   cannot be proven.
6. Removes the PID marker only after proof of exit and, later, the transient
   state directory.

The supervisor already has a signal-driven guest stop: `SIGTERM` sets an atomic
flag, a watchdog wakes the HVF vCPU, and the supervisor persists console and
workload-exit state before removing its PID file and exiting. The avoidable
polling boundary is the backend waiting for that process to exit after the
backend has dropped the original `Child` handle.

The authorized native macOS HVF benchmark completed 1,000/1,000 serial
start/stop cycles with the current cached Alpine rootfs and ARM64 kernel. The
run used the Rust test profile, one vCPU, 256 MiB, and concurrency 1 on
macOS 26.5.2 / arm64 (Darwin 25.5.0, Apple Silicon). Start was p50 10.18 ms,
p95 25.77 ms, p99 53.91 ms, max 139.81 ms. Stop was p50 703.48 ms,
p95 1,151.28 ms, p99 1,865.07 ms, max 2,922.56 ms. The stop tail was entirely
`pid_disappearance`; endpoint reaping and state cleanup were below 0.62 ms and
3.29 ms at max respectively. All 1,000 stops used the event path and recorded
zero SIGKILL escalations. A one-cycle comparison before the macOS zombie-aware
liveness fix measured 2,229.28 ms stop; after the fix it measured 8.42 ms.

## Goals

- [x] Make transient HVF shutdown wait on an OS exit event rather than a
      repeated `kill(pid, 0)` probe.
- [x] Preserve SIGTERM → bounded deadline → SIGKILL escalation and fail-closed
      behavior when the event cannot be observed.
- [x] Preserve PID/process identity checks so PID reuse cannot signal or clean
      up an unrelated process.
- [x] Expose shutdown sub-timings in the normal launch diagnostic and benchmark
      sample before optimizing the wrong span.
- [x] Define one reusable process-lifecycle seam that Firecracker, libkrun, and
      QEMU can adopt where their process ownership and platform permit it.
- [x] Keep durable state, signed audit records, and security gates independent
      of best-effort live event delivery.
- [x] Keep all lifecycle changes covered by unit, integration, and live HVF
      tests appropriate to the code path.

## Non-goals

- [x] Do not rewrite all synchronous orchestration into Tokio.
- [x] Do not replace TTLs, lease expiry, health intervals, retry deadlines, or
      orphan reconciliation with event subscriptions.
- [x] Do not use the in-process host event bus as the correctness signal for
      process termination; it is best-effort and has no cross-process replay.
- [x] Do not return from `machine run` before ownership-safe cleanup unless a
      later design explicitly transfers that cleanup to a resident lifecycle
      owner.
- [x] Do not weaken the current cleanup of substitution endpoints, netd,
      host-agent registrations, consoles, or audit state.

## Design decision

Use a layered lifecycle wait:

```text
                      ┌─ direct child waitpid, when ownership is retained
arm identity + watcher ├─ macOS kqueue EVFILT_PROC / NOTE_EXIT
                      ├─ Linux pidfd + poll/epoll
                      └─ bounded adaptive polling fallback
                                │
send SIGTERM ────────────────────┘
                                │
                  exit event or bounded timeout
                       │                    │
              verify final state      SIGKILL escalation
                       │                    │
                 remove state       fail closed if still alive
```

The event is an observation of process termination, not a substitute for
verification. A successful stop requires all of the following:

1. The watched process identity is the process recorded for this VM.
2. The supervisor has exited, or the force-kill path has proved it exited.
3. The supervisor-owned finalization ordering has completed: console and
   workload-exit output precede PID-marker removal.
4. Only then may transient state be removed.

### Process watcher seam

Extend the existing host process-liveness area rather than scattering platform
branches through each backend:

```text
crates/mvm-vmm/src/host/process_liveness.rs
    process identity and cheap liveness primitives

crates/mvm-vmm/src/host/process_exit.rs
    arm-and-wait process-exit observer
    macOS kqueue implementation
    Linux pidfd implementation
    bounded fallback implementation
```

The observer must support:

- arming before signal delivery;
- an already-exited process;
- a deadline and explicit timeout result;
- unsupported/permission failure without silently claiming success;
- a final identity/liveness verification;
- deterministic test injection without spawning a VM.

The macOS implementation should reuse the already-tested `kqueue`/
`EVFILT_PROC`/`NOTE_EXIT` pattern in `crates/mvm-hostd/src/parent_death.rs`.
The Linux implementation should use `pidfd_open` where available and report
unsupported kernels cleanly. The fallback remains adaptive polling and is a
recovery mechanism, not the preferred hot path.

### HVF integration

Replace the direct wait in `terminate_pid_timed` with the shared observer.
Keep the existing ordering of endpoint reaping and host-agent deregistration,
but arm the process watcher before sending SIGTERM. On timeout, send SIGKILL,
wait through the same observer when possible, and preserve the PID marker when
the process cannot be proven dead.

For transient launches, retain the supervisor child handle when that can be
done without changing the persistent attach model. A separately attached
`machine stop` must continue to work using the PID marker plus the shared
platform watcher.

### Optional lifecycle control channel

Do not add a new control socket in the first implementation unless process-exit
events cannot explain the measured wait. If richer coordination is later
needed, add a private per-VM Unix socket with:

```text
StopRequested(request_id)
StopAccepted(request_id)
Stopped(request_id, final_status)
```

The socket would coordinate draining and report a reason, but process exit and
final-state verification would remain the authoritative completion boundary.
The existing host `EventBus` would remain an observer/UX mechanism only.

### Cross-backend audit snapshot

The first code audit finds three distinct adoption shapes:

| Backend/path | Current wait | Next safe seam |
|---|---|---|
| HVF supervisor | Shared observer with bounded fallback | Measure the live path before changing the supervisor's internal watchdog. |
| Firecracker driver | Injected `SIGTERM`/grace/`SIGKILL` decision helper; real liveness probe is backend-specific | Add an observer-backed probe behind the existing injected decision seam on Linux. |
| libkrun driver and legacy stop | Shared observer with bounded fallback; PID marker is retained when forced exit is unverified | Add backend-specific live coverage and measure the new path. |
| QEMU driver and legacy stop | Shared observer with bounded fallback; bridge cleanup remains separate and ordered | Add backend-specific live coverage and measure the new path. |
| Host sidecars and readiness | File/socket polling plus best-effort signal cleanup | Audit separately; these waits do not share the supervisor's process-identity boundary. |

This keeps backend adoption incremental: the process watcher is reusable, but
the control-plane response, bridge ownership, and sidecar cleanup rules remain
backend-specific.

## Event-driven scope audit

| Area | Decision | Rationale |
|---|---|---|
| Supervisor process exit | Event-driven | OS provides a precise lifecycle event. |
| HVF vCPU wake on stop | Event-driven follow-up | The current signal flag is already correct; the watchdog’s 5 ms check is a small secondary wait. |
| Host vsock and UDS I/O | Keep event-driven | `mio` already drives this path. |
| Guest workload exit file | Add notification only if profiling shows it matters | File polling is a compatibility surface; a socket/pipe can be an optimization, not the source of truth. |
| Boot PID/readiness markers | Event-driven handshake candidate | Replace foreground polling only after the stop watcher is measured. |
| Firecracker API/process shutdown | Backend-specific adoption | Prefer the VMM’s control response plus process watcher; retain escalation. |
| libkrun/QEMU shutdown | Backend-specific adoption | Their process ownership and signal behavior differ. |
| TTLs, leases, health checks | Keep timer-driven | Time itself is the condition. |
| Crash/orphan reconciliation | Keep reconciler polling | Events are unavailable precisely when the owner crashed. |
| Audit and durable state | Keep synchronous/durable | Live notifications cannot replace security evidence. |
| Host lifecycle event bus | Keep as best-effort observer | It is in-process, lossy, and not a termination proof. |

### Foreground wait inventory

| Foreground boundary | Representative implementation | Class | Decision and evidence |
|---|---|---|---|
| VMM/supervisor process exit | `mvm-vmm::host::process_exit`; HVF, Firecracker, libkrun, QEMU stop paths | Owned live event | Event-driven observer, bounded fallback, final liveness verification. This is the measured conversion delivered by this plan. |
| HVF stop wake | `mvm-runtime::backends::hvf::kernel_boot` watchdog | Timer plus owned wake | Retain the 5 ms watchdog. Its maximum flag-observation delay is smaller than the measured 48.44 ms vCPU-exit p50, and it also provides timeout/pause/host-I/O heartbeat duties. |
| HVF/libkrun supervisor launch markers | Driver PID-file and socket waits | External child readiness | Retain bounded adaptive polling. Positive readiness is represented by a cross-process marker/socket, while the retained child handle already provides an event for premature failure. HVF start p50 is 9.08 ms and libkrun start is guest-boot dominated at 904.95 ms. |
| QEMU daemon PID marker | `-daemonize` plus defensive PID-file wait | Recovery fallback | Retain bounded polling. QEMU documents that `-daemonize` returns after the PID file; the loop protects slow/error cases and is not the normal readiness barrier. |
| Firecracker/guest-agent readiness | Authenticated RPC connect/probe with bounded backoff | External state transition | Retain retries. Guest boot and authenticated service readiness are not host-owned wait handles; successful RPC is the security boundary. |
| Workload exit | Backend vsock listener persists `workload.exit`; `host::workload_wait` reads it | Event capture plus durable reconciliation | Keep the blocking socket capture event-driven and the bounded file check attach-safe. A waiter may be reattached in another process, so an in-memory notification cannot replace the durable marker. |
| netd readiness | Child stdout readiness frame in `host::netd_spawn` | Owned live event | Already event-driven; no conversion needed. |
| Broker, audit signer, host-agent, virtiofsd readiness | UDS/control RPC or socket marker with child failure checks and deadline | External process readiness | Keep bounded connect/retry. The successful authenticated/control operation is authoritative; socket existence alone is not. |
| HVF pause/resume marker | `legacy::hvf::wait_for_pause_state` | Owned state transition with durable marker | Retain the 10 ms bounded compatibility wait. No foreground latency regression is measured, and the marker supports attached controllers. |
| HVF snapshot handoff | Request file plus RAM/frame publication check | Owned state transition with durable artifacts | Retain bounded backoff until snapshot profiling shows a material cost. Artifact existence and later verification remain the correctness boundary. |
| QEMU bridge VM watch | Bridge re-reads the QEMU PID marker every 100 ms | Crash/orphan reconciliation | Retain reconciliation. Normal stop explicitly signals the bridge; the loop exists for VM crash and owner-loss cleanup. |
| CLI `wait`, log follow, leases, health, retry backoff | User interval/deadline loops | Timer | Retain timer-driven behavior because elapsed time or user-selected cadence is the condition. |

The repository rule implementing this classification is in `AGENTS.md` under
“Waiting Model: Events, Timers, and Reconciliation.” No additional owned
foreground poll had both a trustworthy event boundary and a measured latency or
CPU regression, so Phase 5 deliberately makes no mechanical async conversion.

## Implementation checklist

### Phase 0 — Instrument the current stop path

- [x] **0.1** Thread the existing backend stop detail (`supervisor_signal`,
      `pid_disappearance`, `force_kill_wait`, and `state_cleanup`) through the
      launch timing path without changing stop behavior. Target:
      `crates/mvm-runtime/src/backend.rs`,
      `crates/mvm-backends/src/driver/hvf.rs`,
      `crates/mvm-cli/src/commands/vm/phase_timing.rs`, and
      `crates/mvm-cli/src/commands/vm/launch_sample.rs`.
- [x] **0.2** Extend the human timing line and JSON sample with explicit stop
      sub-spans while preserving schema-version rejection for incompatible
      consumers.
- [x] **0.3** Add a 1,000-cycle HVF measurement that reports p50/p95/p99 for
      every stop sub-span and records whether SIGKILL escalation occurred.
      Reuse `tests/microvm_lifecycle_bench.rs`; do not add a second benchmark
      harness.
- [x] **0.4** Record the baseline in this plan and update the owning fast-launch
      performance documentation with the measured image, backend, host, and
      build profile.

### Phase 1 — Shared process-exit observer

- [x] **1.1** Add the typed observer API under
      `crates/mvm-vmm/src/host/process_exit.rs`, including explicit outcomes for
      exited, timed out, unsupported, and failed verification.
- [x] **1.2** Implement and unit-test macOS `kqueue` process exit watching,
      including registration races where the process exits before `kevent`.
- [x] **1.3** Implement and unit-test Linux `pidfd` watching, including kernels
      without `pidfd_open` and permission failures.
- [x] **1.4** Implement the bounded adaptive-poll fallback and prove that it
      never reports success without a final liveness/identity check.
- [x] **1.5** Add tests for already-dead processes, timeout, PID reuse defense,
      forced-kill escalation, watcher setup failure, and cleanup ordering.
- [x] **1.6** Route the legacy HVF, libkrun, and QEMU backend liveness helpers
      through the shared permission-aware PID probe, removing duplicate
      `kill(pid, 0)` implementations without changing semantics.

### Phase 2 — HVF event-driven stop

- [x] **2.1** Arm the observer before SIGTERM in the HVF stop path.
- [x] **2.2** Wait on the observer instead of polling `kill(pid, 0)` on the
      normal path; retain bounded polling only as fallback.
- [x] **2.3** Preserve SIGKILL escalation and fail closed when the supervisor
      cannot be proven dead.
- [x] **2.4** Keep final console/workload-exit persistence ahead of PID-marker
      removal and transient state deletion.
- [x] **2.5** Add an integration test that runs a real short-lived HVF
      supervisor, requests stop, observes the exit event, and verifies state
      cleanup.
- [x] **2.6** Re-run the lifecycle benchmark and compare stop p50/p95/p99 and
      full `machine run` wall time against Phase 0.

### Phase 3 — Supervisor wakeup and lifecycle handshakes

- [x] **3.1** Profile the supervisor’s internal stop path separately from the
      host’s process-exit wait; identify watchdog wake, vCPU exit, I/O-thread
      join, console flush, and final file writes.
- [x] **3.2** If the internal 5 ms stop watchdog is measurable, replace its
      periodic flag check with an OS wake mechanism that is safe from a signal
      handler, such as a self-pipe or platform event source, while retaining a
      timeout watchdog. The condition was not met: the timer contributes at
      most 5 ms while watchdog-to-vCPU-exit is 48.44 ms p50, so it remains.
- [x] **3.3** Add a private per-VM lifecycle control channel only if Phase 3.1
      shows that shutdown coordination, rather than process observation, is the
      dominant cost. The condition was not met; vCPU exit is dominant and no
      channel was added.
- [x] **3.4** Add protocol tests for idempotent stop, duplicate request IDs,
      disconnect during shutdown, and a supervisor that ignores the request.
      Not applicable because Phase 3.3 added no protocol; the existing signal,
      timeout, ignored-stop escalation, and idempotent-stop paths remain covered.

### Phase 4 — Cross-backend adoption

- [x] **4.1** Apply the shared process watcher to Firecracker while preserving
      its control-API shutdown and root-owned signal path; retain the existing
      `/proc` liveness and sudo-signal fallback when the observer cannot arm.
- [x] **4.2** Apply the shared process watcher to libkrun without weakening its
      existing SIGTERM/SIGKILL behavior.
- [x] **4.3** Apply the shared process watcher to QEMU only where its process
      ownership and bridge teardown can provide a trustworthy exit event.
- [x] **4.4** Add backend-specific live tests and keep unsupported combinations
      on the bounded fallback.
- [x] **4.5** Update the backend capability and performance reports with the
      new stop-wait evidence.

### Phase 5 — Broader event-driven audit

- [x] **5.1** Inventory remaining foreground polls in boot confirmation,
      readiness, workload-exit capture, service spawn, pause/resume, and
      snapshot handoff.
- [x] **5.2** For each poll, record whether it waits for an owned event, a timer,
      an external state transition, or crash recovery; do not replace timer or
      reconciliation polls mechanically.
- [x] **5.3** Convert only the owned live-resource waits with a measurable
      latency or CPU benefit, using the same event/fallback/verification model.
- [x] **5.4** Add a repository design rule documenting when event-driven,
      timer-driven, and reconciliation-driven waiting is required.

## Verification gates

- [x] Unit tests for every watcher outcome and platform race.
- [x] Positive and negative tests for signal delivery, forced kill, PID reuse,
      stale PID markers, and cleanup refusal.
- [x] Live HVF integration test on Apple Silicon.
- [x] Linux builder tests for pidfd and fallback behavior.
- [x] `cargo fmt --check`.
- [x] `cargo test --workspace`.
- [x] `cargo check --workspace`.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` in the builder VM.
- [x] Update `specs/SPRINT.md` and `specs/REFACTOR-STATUS.md` when an
      implementation phase lands, not merely when this design is created.

## Post-completion builder regression

- [x] Diagnose the HVF builder's missing-result failure as an oversized work
      disk: the raw source checkout included host `target/` output and expanded
      to a 55.7 GB guest input for a roughly 40 MB staged flake.
- [x] Move filtered work staging into the shared builder runtime and route both
      libkrun and HVF input preparation through that seam.
- [x] Exercise the actual HVF ext4 packing boundary and prove `work/flake.nix`
      is retained while `work/target` is excluded.
- [x] Run the authorized live sleeper command from the fix worktree: its HVF
      input disk is 57.1 MiB instead of 55.7 GB, and the guest writes a builder
      result with exit code zero. The later workload boot reaches a separate
      guest-agent readiness timeout rather than the original missing-result
      failure.

## Resume instructions

Plan 314 is complete. Implementation, the complete workspace suite, macOS and
Linux all-target clippy, 1,000-cycle HVF, 100-cycle Firecracker, 25-cycle
supervisor profiling, 25-cycle libkrun/QEMU, and post-cleanup leak audits are
green. Further work should begin from a new profile and preserve the event /
timer / reconciliation classification recorded here and in `AGENTS.md`.
