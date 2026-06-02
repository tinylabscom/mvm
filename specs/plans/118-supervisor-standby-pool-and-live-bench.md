# Plan 118 — supervisor standby pool + live launch bench (design)

**Status:** design drafted 2026-05-29 (renumbered from the Plan 93 PR-10 draft). Child of
[`93-fast-secure-dev-path-followups.md`](93-fast-secure-dev-path-followups.md)
(Phase 2 Lever 0 + Lever 3) and Sprint 59
(`worktree-plan-93-fast-secure-dev-path`). Sequenced **A → B**:
A (live bench probe) lands first so B (the pool) is provable.

**Scope:** two PRs.

- **PR-10a — live `bench microvm-launch` probe** (Phase 2 Lever 0
  follow-up). Replaces the `LibkrunProbe::measure_once` stub with a
  real boot-measure-teardown cycle through signed-plan admission.
- **PR-10b — host-side supervisor standby pool** (Phase 2 Lever 3).
  `--warm-pool-size N` (default 0) trades RAM for cold-start latency
  by pre-spawning `mvm-libkrun-supervisor` processes that block
  *before* guest boot until an admitted plan is attached.

**Backend scope:** libkrun only in v1 (matches the bench harness and
the plan). Vz / Firecracker / Apple-Container pools are a tracked
follow-up.

**Non-goals:** no `--prod` admission-policy changes (lives in mvmd);
no fleet-level pre-warming (mvmd's instance layer, designed in the
mvmd repo); no new persistent host daemon; no backcompat shims.

---

## Why this is the next Plan 93 item

Everything earlier in the Sprint 59 chain is shipped (PR-1/2/3,
PR-9) or superseded by ADR-064 (PR-4..8). PR-10 is the last
unblocked chain item. It depends on nothing gated: the bench
substrate already exists (PR-1), libkrun boots end-to-end on the
target host (verified 2026-05-29 via `libkrun-smoke` against
`~/.mvm/dev/current`), and the short-lived signed-credential
machinery the pool rides is already enforced in the supervisor
(`mvm-supervisor/src/supervisor.rs:317`, "G4: time-window +
nonce-replay").

---

## Part A — live `bench microvm-launch` probe (PR-10a)

### Goal

`crates/mvm-cli/src/commands/ops/bench.rs::LibkrunProbe::measure_once`
currently `bail!`s. Wire it to boot a real libkrun guest through the
claim-8 admission path, time the four host spans, read the guest
`BootTimingReport` for cross-check, tear down, and return an
`IterationTiming`. The pure substrate (stats, schema, regression
gate, orchestration loop) is unchanged and already unit-tested via
`MockProbe`.

### What it boots — no artifact flags

The probe boots the **canonical default runtime image**, resolved by
the *same* `ensure_default_microvm_image()`
(`crates/mvm-cli/src/commands/env/apple_container.rs:4220`) that
`mvmctl up` uses (`up.rs:1522`). On the target host this image is
already cached at `~/.cache/mvm/default-microvm/` (≈95 MiB rootfs +
15 MiB kernel).

**No `--kernel`/`--rootfs` override flags.** They were considered and
rejected: their only use would be pointing at the *dev-shell* rootfs
(`~/.mvm/dev/current`, ≈780 MiB), which is the wrong artifact (the
bench measures *runtime* launch), and arbitrary-rootfs inputs would
undermine the `HostDescriptor`-based regression-comparability gate.
The bench is a measurement tool, not a debug tool; it pins to one
canonical target. (`libkrun-smoke` keeps its override flags — it *is*
the debug tool.)

### Span mapping

| `IterationTiming` field | Measured span |
|---|---|
| `start_to_pid_ms` | `LibkrunBackend::start` entry → `libkrun.pid` appears |
| `pid_to_connect_ms` | pid present → first successful vsock connect |
| `handshake_ms` | connect → authenticated/negotiated (PR-9 wait path) |
| `total_ready_ms` | `start` entry → guest `control plane ready` |

`total_ready_ms` is the headline and the regression-gated metric.
Guest-monotonic milestones from `BootTimingReport` are recorded for
cross-check but **not** folded into the host-clock spans (mixing
clock domains double-counts — already noted in `bench.rs`).

### Admission — no bypass

Every iteration synthesizes → signs → admits a plan via
`admit_plan_for_boot` → `admit_for_run`
(`crates/mvm-cli/src/commands/vm/up.rs`), then boots. The harness must
never benchmark a config that can't ship; the module docs already
mandate this.

### Teardown

Each iteration ends with `LibkrunBackend::stop` (SIGTERM the
supervisor) + removal of the per-VM state dir, so iteration N+1 is a
true cold start. Warmup iterations (default 2) absorb first-run
dylib-load / codesign re-exec cost.

### Testing (PR-10a)

- Pure substrate: unchanged, already covered.
- **Live integration test** gated behind a `libkrun-live` feature (or
  `MVM_LIBKRUN_LIVE=1`) so it runs only where libkrun boots. Asserts
  a single `measure_once` returns finite, ordered spans
  (`start_to_pid <= total_ready`, all `> 0`).
- **CI caveat (honest):** GitHub's hosted macOS runners generally do
  **not** expose Hypervisor.framework nested virt for a libkrun
  guest, so the live test + the committed baseline realistically run
  **only on a dev host or a self-hosted macOS runner**, not stock CI.
  The pure substrate stays CI-gated; the *live* lane is
  host/self-hosted-gated. The plan does not claim stock-CI
  regression-gating it cannot deliver.
- Commit the first real run as the baseline JSON
  (`microvm-launch-latest.json`) so PR-10b has a regression baseline.

---

## Part B — supervisor standby pool (PR-10b)

### Naming

`mvm-core/src/pool.rs` is already mvmd's **tenant/instance pool**;
the guest agent already has a **`WorkerPool`** (in-guest pre-forked
entrypoint workers, the SDK `WarmProcess` model). To avoid a
three-way "pool" collision, the host-side concept is named
**`SupervisorStandbyPool`** / **`PrelaunchedSupervisor`** in code and
types. The user-facing flag stays `--warm-pool-size` (the string the
plan fixed) and the config field is `warm_pool_size`.

### Mechanism — why a "warm VM" can't exist under libkrun

`krun_start_enter` boots-and-`exit()`s the calling process (one
supervisor per VM; see `reference_libkrun_gotchas`). So a standby
**cannot** be a booted VM awaiting a rootfs. A **prelaunched
supervisor** is instead a spawned `mvm-libkrun-supervisor` that:

1. does all *workload-independent* expensive setup — codesign
   re-exec (`ensure_signed`), dylib load, `KrunContext` creation,
   kernel-image load;
2. then **blocks on a control UDS, holding no rootfs and no plan**,
   *before* `start_enter`.

When an admitted plan arrives, the host sends one **attach** message;
the supervisor validates it, configures the remaining krun fields
(rootfs, plan, bundle, tenant, audit paths), and only *then* calls
`start_enter`.

### SupervisorConfig split

Today the supervisor reads one `SupervisorConfig` from stdin
(`mvm-libkrun/src/lib.rs:1223`). PR-10b splits it:

- **`SupervisorBaseConfig`** — read from **stdin at spawn**;
  workload-independent: kernel path, vsock wiring, control-UDS path,
  per-supervisor binding nonce. Drives `KrunContext` creation.
- **`SupervisorAttachConfig`** — read from the **control UDS at
  claim**; workload-specific: `plan_json`, `bundle_json`,
  `rootfs_path`, `tenant_id`, audit paths, the echoed binding nonce.
  This is the workload subset of today's `SupervisorConfig`.

Both `#[serde(deny_unknown_fields)]`. The **attach** struct is the
only attacker-reachable-post-spawn surface and gets the new fuzz
target (below). The non-pool path (`mvmctl dev` Stage 0 builder,
session VMs) is unchanged — it still sends a whole `SupervisorConfig`
on stdin and never opens a control UDS.

### Pool ownership — B-ii (detached, state-dir tracked)

Considered two shapes:

- **B-i — daemon-owned children.** Control channel could be an
  inherited `socketpair` fd (no on-disk socket, smallest surface),
  but introduces a *persistent hypervisor-entitled daemon* — a new
  always-on privileged target.
- **B-ii — detached, tracked by state dir** (chosen). Prelaunched
  supervisors are spawned detached, recorded under
  `~/.mvm/pool/<id>/` (control UDS + pid), and any launch can claim
  an idle one. No new daemon; reuses the existing pid-file/state-dir
  + reaper model (`mvmctl cache prune`, Stage 0 reaper precedent).

**B-ii security tradeoff and why it is sound.** B-ii's control UDS is
an on-disk, connectable endpoint, so any **same-uid** process can
reach it (other users / a malicious host are already out of scope per
ADR-002), and a detached supervisor is an idle entitled process until
reaped — a larger, longer-lived surface than B-i. This is acceptable
**only because** of the load-bearing invariant that makes the channel
*not* an admission bypass:

> The supervisor **independently re-verifies the signed
> `ExecutionPlan`** (Ed25519 signature + G4 time window + nonce)
> before `start_enter` — the same check `run_with_bridge` /
> `mvm-supervisor` already perform. The host admits; the supervisor
> verifies *again*. An attacker with same-uid UDS write access cannot
> boot a forged or unsigned workload without the host plan-signing
> key (the claim-8 key — no new key is introduced).

That reduces B-ii's residual risk to three items, each with a
required mitigation that is part of PR-10b's core (not optional):

1. **Replay** (capture an attach, replay to another idle standby) →
   the **per-supervisor binding nonce is the primary defense here,
   not defense-in-depth.** Each standby is a *fresh process* with a
   *fresh* nonce ledger, so the plan's own nonce-replay store does
   **not** stop a captured attach being redirected to a *different*
   idle standby (the second standby's ledger has never seen the
   nonce). What stops it: the base-config binding nonce (unique per
   standby, spawned-in) must be echoed in the attach, so an attach
   minted for standby A is rejected by standby B. Combined with
   **one-shot attach** (a standby accepts exactly one attach, then
   boots or dies — no reject-and-wait loop) and the plan's own G4
   time window, cross-standby replay is closed. (The plan nonce-replay
   store still guards single-standby replay and the non-pool path.)
2. **DoS / pool exhaustion** → bounded pool size + per-connection
   attach timeout; abandoned connects do not wedge a slot.
3. **Idle entitled-process exposure** → reaper TTL + liveness,
   wired into `cache prune`; never leave orphaned entitled processes.

Channel hardening: control UDS mode `0700`, parent dir `0700`
(matches the W1.2 vsock-proxy-socket posture); the per-supervisor
binding nonce also appears in the socket path so same-uid discovery
is non-trivial even within a `0700` dir (defense in depth).

### Short-lived credentials — the pool rides existing, enforced infra

A standby's attach is gated by the **signed plan itself**, which is
already a short-lived credential: per-plan nonce (`plan.rs:133`) +
G4 time-window + nonce-replay, **enforced in the supervisor today**
(`mvm-supervisor/src/supervisor.rs:317`; rejects with
`plan.rejected.nonce_replay`, tests at `supervisor.rs:1566/1649`).
The pooled supervisor runs the **same gate** before `start_enter`, so
the warm pool inherits short-lived/single-use semantics on the
already-enforced path — it does not weaken the "every workload boots
from a short-lived, signed, replay-protected credential" posture, it
*runs that gate*.

The attach therefore carries the **full signed `ExecutionPlan`
bytes** (Opt-1), not a bespoke token (Opt-2). Opt-1 adds **no new key
material**, keeps the supervisor self-verifying, and makes the attach
schema a natural subset of `SupervisorConfig`. Opt-2's only win is a
smaller message, at the cost of a new token-signing key + a weaker
"trust the host attestation" model — rejected.

If attach validity must later be **decoupled** from plan validity
(shorter than the plan's window), the broker's `host.secrets.v1`
destination-bound/time-bound signed-credential machinery (claim 13 /
ADR-049, `mvm-core/src/protocol/{broker,host_signer}.rs`) is the
established pattern to reuse — no corner is painted.

### mvm / mvmd boundary — what is actually reachable today

**Verified against `../mvmd` (2026-05-29).** mvmd is the orchestrator,
but its runtime launches microvms via **Firecracker + jailer,
directly, on Linux/KVM** (`crates/mvmd-runtime/src/security/jailer.rs`
shells out to `/usr/bin/jailer --exec-file $(which firecracker)`;
instances track `firecracker_pid`). mvmd **never references libkrun,
`VmBackend`, or `VmStartConfig`** — it consumes mvm only through the
`mvmctl::core` / `mvmctl::guest` / `mvmctl::runtime` *facade* (types,
vsock, shell), not the launch seam. mvmd is also a *future, not
well-defined* endeavor.

Consequences for the warm pool:

- The v1 libkrun standby pool is **not reachable from mvmd today**,
  and adding a field to `VmStartConfig` does not change that — mvmd
  doesn't go through that path. The libkrun pool's v1 beneficiary is
  **local macOS `mvmctl up` / dev-loop latency**, which is a real
  Phase 2 target, but it is *not* the fleet.
- mvmd's real benefit (it launches at fleet scale — where warm pools
  pay off most) requires a **Firecracker standby pool**, already a
  deferred follow-up. v1 stays libkrun because libkrun is the only
  backend that **boots and is bench-verifiable on the dev host**
  (Firecracker needs `/dev/kvm`; it cannot be live-tested on macOS),
  and because the risky, load-bearing part of the design is
  backend-agnostic (see "Designed for the Firecracker port" below).

So the seam is positioned, not delivered:

- `warm_pool_size: u32` (default 0) is a new field on the
  backend-agnostic **`VmStartConfig`**
  (`mvm-core/src/protocol/vm_backend.rs:30`, alongside `tenant_id` /
  `plan_json` / `bundle_json`) **specifically so a future Firecracker
  standby reads the same field** — not because mvmd reads it today.
  `--warm-pool-size` is a thin CLI wrapper onto it.
- **Replenish-on-use** is the no-daemon maintainer: each launch tops
  the pool back to target after claiming a standby. A library-level
  "ensure pool at target" entry point is provided for a future
  orchestrator to drive sizing.
- **mvm owns the mechanism + replenish; sizing policy is
  orchestration territory** (`feedback_prod_gate_lives_in_mvmd`).
  Real mvmd reach is **gated on the Firecracker standby follow-up**,
  tracked in Plan 93 `§deferred follow-ups` (and the mvmd repo when
  it firms up). This PR ships no cross-repo wiring.

### Designed for the Firecracker port

The follow-up that actually serves mvmd is a Firecracker standby
pool. To keep that port mechanical, PR-10b separates backend-agnostic
from libkrun-specific pieces:

- **Backend-agnostic (reused verbatim by Firecracker):** the
  `warm_pool_size` config field, the `SupervisorAttachConfig` schema
  + `deny_unknown_fields`, the security gate (supervisor re-verifies
  signed plan + G4 window + nonce + binding nonce, one-shot),
  replenish-on-use, the `~/.mvm/pool/<id>/` state-dir + reaper +
  `cache prune` integration, and the bench-measured span model.
- **libkrun-specific (re-implemented per backend):** the "build
  `KrunContext` (kernel load) then block before `start_enter`"
  blocking primitive. The Firecracker equivalent is "pre-spawn
  firecracker/jailer up to the boot API call, block, then issue
  `InstanceStart` on attach" — a different blocking point, same
  protocol around it.

### Default-off

`warm_pool_size = 0` ⇒ feature entirely off: no standbys spawned, no
idle RAM, no behavior change, no control UDS. Safe to land dark and
measure opt-in via PR-10a's bench.

### Testing (PR-10b)

- **`deny_unknown_fields`** rejection tests on both
  `SupervisorBaseConfig` and `SupervisorAttachConfig`.
- **New fuzz target** `crates/mvm-libkrun/fuzz/fuzz_targets/fuzz_attach_message.rs`
  (alongside `fuzz_supervisor_config.rs`) over the attach parser.
- **Security negative paths:** attach with (a) unsigned/forged plan →
  refused; (b) expired plan (G4 window) → refused; (c) replayed nonce
  → refused; (d) wrong binding nonce (attach meant for another
  standby) → refused; (e) second attach to a one-shot standby →
  refused. No path reaches `start_enter`.
- **Pool lifecycle:** claim picks an idle standby; replenish restores
  target; reaper removes a stale/dead standby and its state dir;
  `warm_pool_size = 0` spawns nothing and opens no UDS.
- **Bench delta:** PR-10a's harness shows the `start_to_pid_ms`
  collapse and the `total_ready_ms` partial improvement with a warm
  pool vs without, on the target host.
- `cargo test --workspace` green; `cargo clippy --workspace
  --all-targets -- -D warnings` clean; `cargo fmt --all -- --check`.

---

## Honest scope note

The pool hides process-spawn + codesign + dylib-load +
context-setup + kernel-image-load. It does **not** hide guest kernel
boot (that cannot begin until the rootfs is attached
post-admission). So this is a *partial* cold-start win — PR-10a's
per-span breakdown quantifies exactly which spans collapse. The
sub-200 ms headline itself remains gated on Plan 92/95's slim kernel
(per Sprint 59 success criteria); PR-10 delivers a measurable
process-spawn delta, not the headline number.

## Ship checklists

### PR-10a — live bench probe

- [x] `LibkrunProbe::measure_once` boots `ensure_default_microvm_image()`
      through `admit_probe_plan` → `admit_for_run`, times four
      spans, tears down. No artifact flags. (`bench_probe::boot_measure_once`.)
- [ ] `BootTimingReport` recorded for cross-check (not folded into
      host spans). **Deferred:** v1 reads readiness via the atomic
      `vsock::ping` (Pong), not the `ReadinessReport.boot_millis`
      report; the guest-monotonic cross-check is a tracked follow-up.
- [x] `libkrun-live`-gated integration test asserts finite, ordered
      spans. Validated on the dev host through `backend.start` (see
      baseline note).
- [ ] First real run committed as baseline JSON. **Blocked:** the
      cached `default-microvm` image on the dev host is stale
      (predates the W1.4b runtime-overlay / `mvm-meta.json` sidecar),
      so `backend.start` correctly refuses it — the probe path is
      validated end-to-end, but the committed baseline needs a
      freshly-built `default-microvm` image.
- [x] `HostDescriptor` populated (kernel sha256 + runtime cmdline) so
      the regression gate is meaningful. (`libkrun_version` left
      `None` — no accessor today.)

### PR-10b — supervisor standby pool

- [ ] `warm_pool_size: u32` on `VmStartConfig`; `--warm-pool-size`
      CLI wrapper; library "ensure pool at target" entry point.
- [ ] `SupervisorBaseConfig` (stdin) / `SupervisorAttachConfig`
      (control UDS) split; both `deny_unknown_fields`.
- [ ] Prelaunched supervisor: setup → block before `start_enter` →
      attach → verify (signature + G4 + nonce + binding nonce) →
      `start_enter`. One-shot.
- [ ] `SupervisorStandbyPool` under `~/.mvm/pool/<id>/`; control UDS
      `0700` + binding-nonce in path; replenish-on-use; reaper +
      `cache prune` integration.
- [ ] `fuzz_attach_message.rs` fuzz target.
- [ ] Security negative-path tests (a)–(e) above; none reach
      `start_enter`.
- [ ] Bench delta demonstrated via PR-10a harness.
- [ ] `warm_pool_size = 0` default-off verified (no standbys, no UDS).

### Deferred follow-ups (tracked in Plan 93 §deferred follow-ups)

- [ ] **Firecracker standby pool — the mvmd-facing deliverable.**
      mvmd launches Firecracker/jailer on Linux and does not consume
      the libkrun seam; the Firecracker standby (pre-spawn to the
      boot API call, block, `InstanceStart` on attach) reuses v1's
      backend-agnostic attach schema + `warm_pool_size` + security
      gate. This, not the libkrun v1, is what makes warm pools
      reachable from the orchestrator.
- [ ] mvmd sizing hookup: once a Firecracker standby exists, mvmd
      sets `warm_pool_size` per host + fleet-level instance
      pre-warming — designed in the mvmd repo when it firms up.
- [ ] Vz / Apple-Container standby pools (different process models).
- [ ] Optional decoupled attach credential via `host.secrets.v1`
      pattern, if attach validity must be shorter than plan validity.

## Success criteria

- [ ] `mvmctl bench microvm-launch` produces a real versioned JSON
      report on the target host and regression-gates against a
      committed baseline.
- [ ] With `--warm-pool-size N > 0`, the bench shows a measured
      `start_to_pid_ms` collapse vs `N = 0`.
- [ ] No security regression: a standby never reaches `start_enter`
      without a valid signed + in-window + non-replayed + correctly
      bound plan; fuzz + negative-path tests cover it; `cargo test
      --workspace` green; clippy clean.
- [ ] `warm_pool_size` is settable from the backend-agnostic
      `mvm-core` launch-config seam (not only the CLI), positioned so
      the deferred Firecracker standby — the actual mvmd-facing
      path — reads the same field unchanged.
