# Plan 199 — `WarmLease` borrow-handle + batched guest exec

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

- [ ] **WS-A — `WarmLease` + acquire/release/Drop.** `AcquireSpec`,
  `ReleasePolicy`, background replenish-to-target. Tests (mock backend, no
  live boot): claim → use → drop stops and replenishes; cold-boot fallback
  on an empty pool; double-claim guard via `mark_claimed`; `release()`
  surfaces a stop error that `Drop` would swallow.
- [ ] **WS-B — `ExecBuilder` Tier 1.** Connection-reuse pipelining over
  `VsockTransport`. Tests against `mvm-backend`'s `mock_guest_agent`:
  staged files land before the command runs; one stream serves the batch.
- [ ] **WS-C — `ExecOutcome` enrichment.** Add `duration` + `peak_rss_kib`;
  populate host-side (Tier 1) and agent-side (`getrusage`, Tier 2). Serde
  roundtrip + default-value tests.
- [ ] **WS-D — `GuestRequest::ExecBatch` Tier 2.** New frame + in-guest
  sequential runner, `dev-shell`-gated. Extend the `GuestRequest` fuzz
  target. `#[serde(deny_unknown_fields)]` on the new stage types.
- [ ] **WS-E — facade + example.** Re-export `WarmLease` / `ExecBuilder`;
  add `crates/mvm-cli/examples/verification_loop.rs` proving
  `WarmLease` + batched exec end-to-end (the embedded-library tier we do
  not currently demonstrate).

## Success criteria

- [ ] A caller acquires a warm VM, runs a staged compile-and-run batch, and
  drops the handle — with no explicit pool, transport, stop, or replenish
  calls in caller code.
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
