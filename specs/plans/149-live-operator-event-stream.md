# Plan 149 — `mvmctl watch`: unified live operator event stream

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

> **Spec number:** 149 is the next free integer after 148 at authoring time (145
> app-deps-completion on `main`, 146 cloud-hypervisor-tier1-parity, 147
> portable-runnable-artifacts, 148 fork-fanout). `xtask check-spec-numbers` is a Lint
> gate — re-confirm 149 against open PRs + `main` before merge and renumber if taken.

## Context

A comparable open-source Apple-Silicon microVM sandbox ships a live monitor as headline
DX: an operator watches every network request / file write / admission event as it
happens. We already emit all of that — we just have no single command that streams it.
Today an operator must run `mvmctl audit tail --chain -f` (chain-signed plan/secret/
lifecycle events, 500ms file poll) *and separately* `nc -U ~/.mvm/audit/gateway-<vm>.sock`
(live NDJSON network-flow events) per VM, with no filter and no merge. This plan adds one
read-only consumer — `mvmctl watch` — that merges both sources into a single, filterable,
real-time stream.

This is operator-facing **live forensics**, deliberately distinct from two neighbours that
already have owners: Plan 127 Phase D's developer `tracing` spans (RUST_LOG, host-path
debugging) and Plan 127 Phase A's metering/billing samples. It adds no new trust surface —
the chain-signed JSONL remains the lossless source of truth; `watch` is convenience over
data already written. It also makes the claim-10 egress posture *observable*: an operator
can watch allow/deny flow decisions (Plan 142) live.

## Architecture (everything this consumes already exists)

- **Flow events (live):** broadcast as NDJSON `FlowEventWire` over
  `~/.mvm/audit/gateway-<vm>.sock`, bounded 256-event queue, mode 0700
  (`crates/mvm-supervisor/src/gateway_audit.rs` — `GatewayAuditSink` + accept loop;
  wire shape in `gateway_bridge.rs`: `{kind: flow_opened|flow_closed, flow_id, direction,
  reason}`). Producers were activated by Plan 102 W6.A + Plan 112.
- **Chain events (file):** `SignedEnvelope`-wrapped `AuditEntry` lines in
  `~/.mvm/audit/<tenant>.jsonl` (`crates/mvm-supervisor/src/audit_file.rs`); categories via
  `Recorder` / `EventCategory` (plan, flow, secret, lifecycle, policy, key, host, audit,
  workload-audit) in `audit_recorder.rs`.
- **Existing consumption to reuse, not duplicate:** the follow-poll loop and
  `print_chain_line` formatter in `crates/mvm-cli/src/commands/ops/audit.rs`
  (`mvmctl audit tail --chain -f` — seek-to-last-position, 500ms poll).
- **Socket path derivation:** `compute_audit_substrate(vm_name, tenant_id)` in
  `crates/mvm-backend/src/audit_substrate.rs` returns the per-VM gateway socket path(s).
- **CLI registration:** `Commands` enum + module dispatch in
  `crates/mvm-cli/src/commands/mod.rs`; subcommand modules under `commands/`.

## Tech Stack

Rust (`mvm-cli`); existing tokio current-thread bridges; NDJSON; the existing Ed25519
chain reader (`verify`-compatible). No new third-party crates. Arg-parse coverage in
`tests/cli.rs`.

## Sequencing

Independent of the Plan 120 core-demo line (it consumes data, it does not touch the launch
path). Soft prereq: the Plan 102/112 gateway producers are landed (they are). Complements —
does not block — Plan 127 (metering/tracing) and Plan 142 (egress no-bypass). Can land any
time after 120 is green.

## Out of scope / deferred

- Snapshot/restore/fan-out and their wake events — owned by Plans 139/140/148/123. `watch`
  will *display* `vm.snapshot_saved`/`vm.snapshot_restored` chain entries when they appear,
  but adds nothing to that machinery.
- Metering/billing samples and the boot-latency bench — Plan 127 Phases A/B.
- Developer `tracing` spans — Plan 127 Phase D.
- A GUI/desktop view — `mvmctl watch --json` is the substrate a future UI would consume; no
  UI here.

---

## Task 1: factor the chain follow-reader into a reusable helper

The 500ms seek-and-poll loop currently lives inside `audit tail`. Lift it so `watch` and
`tail` share one implementation rather than copy-pasting the follow semantics.

**Files:** `crates/mvm-cli/src/commands/ops/audit.rs`.

- [ ] **Step 1:** Failing test — a helper `follow_chain(path, from_position, on_line)`
      yields each new `SignedEnvelope` line appended after `from_position`, surviving file
      growth across polls; `audit tail --chain -f` still behaves identically (regression).
- [ ] **Step 2:** Extract the loop; repoint `audit tail` at it. Commit.

## Task 2: a gateway flow-socket reader

- [ ] **Step 1:** Failing test — given a temp unix socket emitting NDJSON `FlowEventWire`
      lines, a `follow_flows(socket_path, on_event)` reader yields each event; a
      not-yet-existing socket is tolerated and connected once it appears; a closed socket
      reconnects without killing the stream.
- [ ] **Step 2:** Implement the reader; resolve socket paths via
      `compute_audit_substrate` for each `--vm` (or every VM under the tenant when `--vm`
      is omitted). Commit.

## Task 3: the `mvmctl watch` command — merge, filter, render

**Files:** new `crates/mvm-cli/src/commands/vm/watch.rs`; register in
`crates/mvm-cli/src/commands/mod.rs` (`Commands::Watch` + dispatch + module export).

- [ ] **Step 1:** `pub struct Args` (clap): `--tenant <id>` (default `local`),
      `--vm <name>` (repeatable, optional), `--categories plan,flow,secret,lifecycle,...`
      (comma list, default all), `--json` (raw NDJSON vs. one-line human), `--since
      <rfc3339>` (optional backfill from the chain file). Default behaviour streams until
      Ctrl-C. Arg-parse test in `tests/cli.rs`.
- [ ] **Step 2:** Merge Task 1 (chain) + Task 2 (flows) into one ordered stream by
      `entry.timestamp` / flow arrival; apply `--categories` and `--vm` filters before
      output. Human render reuses `print_chain_line` for chain events and a flow one-liner
      (e.g. `2026-06-03T14:23:45Z  flow_opened  egress  vm=web flow=<id>`); `--json` emits
      the unwrapped `AuditEntry` / `FlowEventWire`, one record per line.
- [ ] **Step 3:** Backpressure / honesty — rely on the existing bounded 256-event gateway
      broadcast (drop-oldest); the file source is decoupled by polling. Document in
      `--help` and the user docs that `watch` is lossy under flood and the JSONL chain is
      the lossless record. Never block the signer.

## Task 4: surface egress/secret decisions in the filter

- [ ] **Step 1:** Confirm where Plan 142 flow allow/deny decisions and Plan 129
      egress secret-substitution events land (category `flow.*` vs `secret.*`) so
      `--categories flow,secret` shows them live. If any are emitted only structurally with
      no live path, record the gap as a deferred follow-up here — do not fake a live event.
- [ ] **Step 2:** Integration test — emit two chain lines (`plan.admitted`, `secret.get`)
      plus one `FlowEventWire` onto a temp gateway socket; run the merge with a bounded
      deadline; assert all three appear in timestamp order, that `--categories plan` filters
      the flow + secret out, and that `--json` round-trips each record.

## Acceptance (this plan is done when)

- [ ] `mvmctl watch --tenant local` streams plan, secret, lifecycle, snapshot, and network-
      flow events for a running workload in one merged stream; `--json`, `--categories`,
      `--vm`, and `--since` work; Ctrl-C exits clean.
- [ ] `audit tail --chain -f` is unchanged, now sharing the lifted follow helper (Task 1).
- [ ] Egress allow/deny + secret-substitution events are watchable via `--categories
      flow,secret`, or the gap is recorded as a deferred follow-up.
- [ ] Docs note `watch` is a lossy convenience; the chain-signed JSONL stays the source of
      truth; `verify_audit_chain` is unaffected.
- [ ] `cargo fmt --all -- --check` (nightly), `cargo test --workspace`, `cargo clippy
      --workspace -- -D warnings` green; no new dependency.

## Self-review

- **Reuses, does not rebuild:** consumes the Plan 102/112 gateway broadcast and the
  existing chain file + follow loop; the only new code is one reader, one merge, one command.
- **No new trust surface:** read-only over already-written data; the lossless chain is
  untouched; backpressure cannot stall the signer.
- **No overlap with neighbours:** snapshot/restore is 139/140/148; metering + boot-bench +
  dev tracing are 127; egress *enforcement* is 142 — this plan only makes their events
  *watchable* live.
- **Honesty:** `watch` is documented lossy-under-flood; egress/secret live-ness is verified,
  not assumed (Task 4 Step 1), with any gap deferred rather than faked.
