# Plan 201 — `WarmLease` borrow-handle + batched guest exec

## Status — PROPOSED (2026-06-15)

DX-ergonomics layer over the existing warm-pool (Plan 118) and agent-RPC
(Plan 169) substrate. No new backend, no new transport, no change to the
admission/audit path. Everything except the end-to-end example lands and
tests on the mock backend + mock guest agent (no live boot required).

## Context

Two ergonomics are missing from the current surface, and both are pure
caller-convenience over machinery we already have:

1. **No RAII claim/release.** A caller that wants a warm VM today wires up
   `SupervisorStandbyPool::select_idle_compatible` → `mark_claimed` →
   `VmBackend::claim_standby` → `remove`, then separately resolves a
   `VsockTransport` via `vsock_transport::for_vm`, and is responsible for
   stopping the VM and replenishing the pool on every exit path. Nothing
   ties claim → use → release into one owned handle.

2. **No batched guest exec.** `send_exec_streaming`, `send_run_entrypoint`,
   and `send_fs_request_on` (`crates/mvm-guest/src/vsock.rs`) are discrete
   calls, each typically over a fresh stream. A verification loop that
   stages a file then compiles then runs pays three reconnects and three
   round-trips for what is logically one batch.

The substrate already exists:

- `VmBackend` (`crates/mvm-core/src/protocol/vm_backend.rs`):
  `supports_standby_pool`, `spawn_standby(&StandbySpec) -> StandbyHandle`,
  `claim_standby(&StandbyHandle, &StandbyClaim) -> VmId`. `claim_standby`
  re-verifies the signed `ExecutionPlan` before boot — claim 8 is enforced
  here and this plan does not touch it.
- `SupervisorStandbyPool` (`crates/mvm-backend/src/standby_pool.rs`):
  disk-backed registry with `select_idle_compatible(&StandbyCompat)`,
  `mark_claimed`, `remove`, `idle_count_compatible`, `reap_stale`.
- `VsockTransport::for_vm(name)` (`crates/mvm/src/vsock_transport.rs`):
  backend-probed connected guest channel.
- `GuestRequest::{Exec, RunEntrypoint, FsWrite, FsRead}` + the `send_*_on`
  helpers (`crates/mvm-guest/src/vsock.rs`).

## Design

### `WarmLease` — an exclusively-held warm VM

```text
WarmLease::acquire(backend, &AcquireSpec) -> WarmLease
  1. pool.select_idle_compatible(&spec.want)        // existing match key
  2. pool.mark_claimed(id)                           // guards double-claim
  3. backend.claim_standby(handle, &spec.claim)      // re-verifies signed plan
  4. pool.remove(id)                                 // it is a booted VM now
  5. replenish-to-target in the background
  miss -> cold-boot fallback, on_release = Stop
```

The handle owns `Arc<dyn VmBackend>` + `VmId` + the resolved VM name + pool
root, and exposes `id()`, `transport()` (delegates to
`vsock_transport::for_vm`), `exec()` (the builder below), and a consuming
`release()` that surfaces errors. `Drop` is the best-effort, non-blocking,
non-panicking equivalent: `backend.stop(id)` then trigger replenish.

**Deliberate divergence from the prior-art borrow-pool model.** Prior art
*returns the same VM* to the pool on drop. We do not: release = **stop +
replenish a fresh standby**, never reuse a mutated booted VM. This is the
security-correct shape of the same ergonomic — it avoids cross-run state
bleed (claim 1 / one-guest-one-workload) and matches the Vz saved-state
reality (standbys are `pid=0` snapshots; a booted VM cannot be "returned",
only discarded and re-restored). There is no single `Vm` value to
`Deref` to — mvm's model is *backend + `VmId` + transport* — so `WarmLease`
bundles those three and exposes `.transport()` / `.exec()` rather than
`Deref<Target = Vm>`.

```rust
pub struct AcquireSpec {
    pub want: StandbyCompat,   // kernel + fixed resources + image
    pub claim: StandbyClaim,   // admitted signed plan + rootfs + audit substrate
}

pub struct WarmLease { /* Arc<dyn VmBackend>, VmId, name, pool_root, ReleasePolicy */ }

impl WarmLease {
    pub fn acquire(backend: Arc<dyn VmBackend>, spec: &AcquireSpec) -> Result<Self>;
    pub fn id(&self) -> &VmId;
    pub fn transport(&self) -> Result<Box<dyn VsockTransport>>;
    pub fn exec(&self) -> ExecBuilder<'_>;
    pub fn release(self) -> Result<()>;
}
```

Location: `crates/mvm/src/vm/lease.rs`, re-exported through the facade so it
is reachable as an embedded-library surface, not only from the CLI.

### `ExecBuilder` — batch staging + run

Two tiers; the first needs no guest change, the second is opt-in.

**Tier 1 — connection reuse (no guest change).** The builder takes one
stream from the transport and pipelines the existing `FsWrite` staging
frames then the `Exec` / `RunEntrypoint` frame on that *same* stream
instead of reconnecting per call. Wall-clock duration captured host-side.

**Tier 2 — `GuestRequest::ExecBatch { stages }` (opt-in).** The agent runs
`stages` (`StageFile` | `Run { argv, env, cwd }`) sequentially in-guest and
returns `Vec<ExecOutcome>` with agent-measured duration and peak RSS
(`getrusage(RUSAGE_CHILDREN)`). One round-trip — the full analog of
stage → run → chain.

```rust
lease.exec()
    .stage_file("/tmp/main.rs", source_bytes)
    .argv(["rustc", "/tmp/main.rs", "-o", "/tmp/m"])
    .chain(["/tmp/m"])
    .timeout(Duration::from_secs(30))
    .output()?;   // ExecOutcome { status, stdout, stderr, duration, peak_rss_kib }
```

`ExecOutcome` gains `duration` and `peak_rss_kib: Option<u64>` — cheap, and
useful on the prod `RunEntrypoint` path too.

**Security gating.** The argv form (`Exec` / `ExecBatch`) stays
`dev-shell`-gated exactly like today's `Exec` handler (claims 4 and 15). The
builder offers a `.run_entrypoint(stdin)` terminal that routes through the
prod `RunEntrypoint` path (no argv, no shell) so prod verification loops use
the same builder surface without linking the dev-only handler. The new
`ExecBatch` frame joins the fuzzed `GuestRequest` surface (claim 5).

## Workstreams

- [x] **WS-A — `WarmLease` + acquire/release/Drop.** Landed at
  `crates/mvm/src/vm/lease.rs`: `AcquireSpec`, `WarmLease` (`acquire` =
  `select_idle_compatible` → `mark_claimed` → `claim_standby` → `remove` on a
  hit, cold-boot fallback on a miss; `id()` / `transport()` /
  `release()` / `Drop`). Replenish is an **injected `ReplenishFn`** so `mvm`
  doesn't depend upward on the CLI's `pool warm` machinery; release/Drop of a
  claimed lease stops + replenishes, a cold-boot lease only stops. `MockBackend`
  gained opt-in standby support (`with_standby`) + a `with_failing_stop` knob.
  Tests (mock backend, no live boot, 4): claim → release stops + replenishes;
  cold-boot fallback on an empty pool does **not** replenish; drop of a claimed
  lease stops + replenishes; `release()` surfaces a stop error `Drop` swallows.
- [x] **WS-B — `ExecBuilder` Tier 1.** Landed at `crates/mvm/src/vm/exec_builder.rs`:
  `WarmLease::exec()` → `ExecBuilder` (`stage_file`/`argv`/`chain`/`timeout`/
  `output()`/`run_entrypoint()`). Connection-reuse — one stream pipelines the
  `FsWrite` staging frames (`call_unary`) then the `Exec`/`RunEntrypoint`
  frame(s) (`call_streaming`), reusing the `mvm-guest` host plumbing (no upward
  dep on the CLI exec driver). Argv is shell-quoted. Tests against
  `mock_guest_agent` (gained `Exec`/`RunEntrypoint` single-terminal handlers):
  stage→exec on one stream, multi-file stage, run_entrypoint, shell-join quoting.
- [x] **WS-C — `ExecOutcome` enrichment.** `ExecOutcome { status, stdout,
  stderr, duration, peak_rss_kib }` — `duration` is host-measured (Tier 1);
  `peak_rss_kib` is `None` on Tier 1 (agent-measured `getrusage` arrives with
  the Tier-2 `ExecBatch` path in WS-D).
- [x] **WS-D — `GuestRequest::ExecBatch` Tier 2.** Landed. New `ExecBatch
  { stages, commands, timeout_secs }` request + `ExecBatchResult { outcomes }`
  response carrying agent-measured `ExecOutcomeWire { status, stdout, stderr,
  duration_ms, peak_rss_kib }` (`deny_unknown_fields` on `StageFile` +
  `ExecOutcomeWire`). One round-trip, unary contract. The in-guest runner
  (`do_exec_batch` in `mvm-guest-agent`) stages files then runs each argv
  buffered via `exec_stream::stream_exec`, stops at the first non-zero exit, and
  fills `peak_rss_kib` from `getrusage(RUSAGE_CHILDREN)` — `dev-shell`-gated, so
  the prod agent ships the not-feature `Error` arm (verified: prod no-default
  build + `check-prod-agent-no-exec`/`-console` still green). The
  `fuzz_guest_request` target is `serde_json::from_slice::<GuestRequest>`, so it
  covers `ExecBatch` automatically. Host `ExecBuilder::batch()` sends it and
  maps `ExecBatchResult` → `Vec<ExecOutcome>`; `mock_guest_agent` answers one
  zero-exit outcome per command. Tests: 3 vsock (request roundtrip + verb/
  class/contract, result roundtrip + variant, `deny_unknown_fields`) + 1
  host-side batch round-trip against the mock.
- [x] **WS-E — facade + example.** Re-export DONE — `mvm` now re-exports
  `WarmLease`/`AcquireSpec`/`ExecBuilder`/`ExecOutcome` at the crate root
  (`crates/mvm/src/lib.rs`), reachable via the `mvmctl::runtime` facade.
  **Example DONE** — `crates/mvm-cli/examples/verification_loop.rs` shows the
  canonical flow (acquire → `exec().stage_file().argv().chain().output()` →
  `release`/Drop) with no explicit pool/transport/stop/replenish in the caller
  body; runs on the mock backend (the guest-exec step degrades cleanly without a
  live agent) and is gated by `cargo build --example`.

## Success criteria

- [x] A caller acquires a warm VM, runs a staged compile-and-run batch, and
  drops the handle — with no explicit pool, transport, stop, or replenish
  calls in caller code. **Demonstrated** by `verification_loop.rs` (caller-body
  shape) + the WS-A/B lease/exec unit tests; a real-VM run of the example is
  live-gated.
- [ ] Release never reuses a dirty VM; a dropped lease leaves the pool at
  target idle count for its compat key.
- [ ] The argv exec surface is absent from a production agent build
  (existing `prod-agent-no-console` / no-`do_exec` lanes stay green with the
  new `ExecBatch` handler `dev-shell`-gated).
- [ ] `cargo fmt --all --check`, `cargo nextest run --workspace`,
  `cargo test --workspace --doc`, `cargo clippy --workspace -- -D warnings`
  all clean.

## Deferred follow-ups

- [ ] `WarmLease` async variant behind the existing optional `tokio`
  feature (only if a real async consumer appears — YAGNI until then).
- [ ] Streaming `ExecBuilder::spawn()` for long-running / interactive
  processes (builds on the console PTY transport; out of scope for the
  batch surface).
