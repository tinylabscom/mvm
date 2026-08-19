# FlowMux session readiness without a launch race

Backing: shipped-source
Validation: check-sprint-append

**Status:** COMPLETE
**Date:** 2026-08-18
**Branch:** `fix/flowmux-session-readiness`

## Problem

`machine run --allow-host …` waits for the guest agent, then samples the
endpoint's `substitution.session` marker once. Guest-agent readiness and the
guest's FlowMux authentication are independent. When the first wins by even a
few milliseconds, a healthy endpoint is falsely diagnosed as a guest that did
not find its identity drive.

Adding a sleep would spend the full delay on every launch and still race on a
loaded host. The fix needs an owned event, a bounded failure deadline, and the
existing marker as durable verification.

## Invariants

- The endpoint binds its host-local readiness socket before its process-ready
  handshake, so launch never races the listener.
- Only a successfully authenticated FlowMux session signals readiness.
- The durable session marker is written before the event and verified after
  wakeup; the socket is a wakeup, not a source of truth.
- Linux confinement grants the endpoint write access only to the configured
  marker's per-VM parent directory, and only when session readiness is enabled.
- Already-authenticated sessions take the marker fast path with no socket wait.
- Endpoint exit, malformed signals, missing durable evidence, and timeout all
  fail closed.
- Healthy launch latency gains no fixed sleep or polling interval.

## Work

- [x] Add red tests for delayed authentication, already-recorded readiness,
      endpoint exit, and bounded timeout.
- [x] Add the per-VM authenticated-session readiness socket to endpoint config
      and bind it before the endpoint handshake.
- [x] Signal the event only after FlowMux authentication and marker creation.
- [x] Replace the CLI's one-shot marker sample with an event wait followed by
      durable marker verification.
- [x] Add real endpoint subprocess coverage and a hermetic BDD scenario for the
      delayed-authentication ordering.
- [x] Preserve Linux self-confinement while permitting the authenticated
      session marker to be created and verified.
- [x] Pass workspace tests, check, formatting, host Clippy, gated Linux checks,
      and product invariant gates.
- [x] Record delivery and update the FlowMux refactor rollup.

## Acceptance

- `machine run --image alpine --allow-host github.com -- …` no longer emits a
  false “no guest ever authenticated” error when authentication follows guest
  agent readiness.
- A healthy event path remains compatible with the sub-200 ms warm-launch
  target; only a broken guest can consume the five-second failure deadline.
- No network grant is widened and no unauthenticated guest can satisfy launch
  readiness.
