# Plan 118 — supervisor standby pool + live launch bench (design)

**Status:** design drafted 2026-05-29 (renumbered from the Plan 93 PR-10 draft). Child of
[`93-fast-secure-dev-path-followups.md`](93-fast-secure-dev-path-followups.md)
(Phase 2 Lever 0 + Lever 3) and Sprint 59
(`worktree-plan-93-fast-secure-dev-path`). Sequenced **A → B → C**:
A (live bench probe) lands first so B (the pool) is provable; C
(density + concurrency bench, added 2026-06-16) extends A's probe
substrate to measure the two axes the warm pools exist to move.

**Scope:** three workstreams.

- **PR-10a — live `bench microvm-launch` probe** (Phase 2 Lever 0
  follow-up). Replaces the `LibkrunProbe::measure_once` stub with a
  real boot-measure-teardown cycle through signed-plan admission.
- **PR-10b — host-side supervisor standby pool** (Phase 2 Lever 3).
  `--warm-pool-size N` (default 0) trades RAM for cold-start latency
  by pre-spawning `mvm-libkrun-supervisor` processes that block
  *before* guest boot until an admitted plan is attached.
- **PR-10c — density + concurrent-launch distribution bench**
  (added 2026-06-16). Extends A's probe to two new metrics —
  per-instance host footprint (density) and launch-latency P50/P95/P99
  under concurrency — so the pool's payoff is provable and our own
  footprint/latency posture rests on committed numbers, not assertion.
  Read-only measurement; no new attack surface (see Part C).

**Backend scope:** libkrun v1, Vz saved-standby, and Linux/KVM
Firecracker standby are implemented. Apple-Container pools remain a
tracked follow-up.

**Non-goals:** no `--prod` admission-policy changes (lives in mvmd);
no fleet-level pre-warming (mvmd's instance layer, designed in the
mvmd repo); no new persistent host daemon; no backcompat shims.

**Follow-up status — 2026-06-20:** the x86_64/libkrun live lane now
threads kernel format into `KrunContext`, extracts/reuses the sibling
ELF `vmlinux` for x86_64 libkrun starts, and forwards the root
`libkrun-live` / `libkrun-sys` feature flags so the root `mvmctl`
binary can run the gated live bench. Remote proof on the KVM host:
raw bzImage and ELF-as-raw both reproduced libkrun's `Kernel doesn't
fit in RAM` panic; ELF with `KernelFormat::Elf` loaded the kernel and
reached libkrun device initialization. Remaining blocker for committed
baselines: the default image still never exposes the guest-agent vsock
socket (`vsock-5252.sock`) on that host, and `console.log` stays empty.
So the kernel-loader issue is fixed, but libkrun guest-agent-ready
baseline proof remains open. Firecracker now has committed live
baseline artifacts under `specs/perf/plan-118/` using an explicit
`readiness_boundary = "firecracker-pid"` because the current Linux
proof image boots but does not expose the guest-agent ping endpoint.

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

So the backend seam is delivered, but orchestrator sizing is not:

- `warm_pool_size: u32` (default 0) is a new field on the
  backend-agnostic **`VmStartConfig`**
  (`mvm-core/src/protocol/vm_backend.rs:30`, alongside `tenant_id` /
  `plan_json` / `bundle_json`) and is consumed by libkrun, Vz, and
  Firecracker standby claims. mvmd still does not set it today.
  `--warm-pool-size` is a thin CLI wrapper onto it.
- **Replenish-on-use** is the no-daemon maintainer: each launch tops
  the pool back to target after claiming a standby. A library-level
  "ensure pool at target" entry point is provided for a future
  orchestrator to drive sizing.
- **mvm owns the mechanism + replenish; sizing policy is
  orchestration territory** (`feedback_prod_gate_lives_in_mvmd`).
  Real mvmd reach is now gated on mvmd sizing/wiring, tracked in Plan
  93 `§deferred follow-ups` and the mvmd repo when it firms up. This
  PR ships no cross-repo wiring.

### Firecracker port

The follow-up that actually serves mvmd is now implemented as a
Firecracker standby pool. PR-10b separated backend-agnostic from
libkrun-specific pieces, and the Firecracker port reuses that split:

- **Backend-agnostic (reused verbatim by Firecracker):** the
  `warm_pool_size` config field, the `SupervisorAttachConfig` schema
  + `deny_unknown_fields`, the security gate (supervisor re-verifies
  signed plan + G4 window + nonce + binding nonce, one-shot),
  replenish-on-use, the `~/.mvm/pool/<id>/` state-dir + reaper +
  `cache prune` integration, and the bench-measured span model.
- **Backend-specific (re-implemented per backend):** the "build
  `KrunContext` (kernel load) then block before `start_enter`"
  blocking primitive for libkrun. Firecracker reserves the normal
  slot, pre-spawns `firecracker` with its API socket, then claim
  configures the selected launch shape and issues `InstanceStart` —
  a different blocking point, same pool protocol around it.

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
- [x] `BootTimingReport` recorded for cross-check (not folded into
      host spans). Guest-agent-ready probes now persist
      `ReadinessReport.boot_millis` as
      `bench/boot-timing-<vm>.json`; Firecracker PID-boundary proof
      reports remain explicitly separate because the current Linux
      proof image lacks guest-agent ping.
- [x] `libkrun-live`-gated integration test asserts finite, ordered
      spans. Validated on the dev host through `backend.start` (see
      baseline note).
- [x] First Firecracker real run committed as baseline JSON:
      `specs/perf/plan-118/microvm-launch-firecracker.json`
      (`readiness_boundary = "firecracker-pid"`, P50
      `total_ready_ms = 1899.851577`). **libkrun caveat:** the cached
      default image on the dev/KVM host still does not expose
      `vsock-5252.sock`, so the guest-agent-ready libkrun baseline
      remains blocked until that image is rebuilt.
- [x] `HostDescriptor` populated (kernel sha256 + runtime cmdline) so
      the regression gate is meaningful. (`libkrun_version` left
      `None` — no accessor today.)

### PR-10b — supervisor standby pool

> **1a landed** (the supervisor *primitive*) in PR #748
> (`feat/plan-118-ws1-layer1a`) — config split, prelaunched flow with the
> mandatory attach-time plan re-verify, fuzz target, and the (a)–(e) rejection
> ladder. The boxes below tagged **(1a)** are done; the rest are **1b** (the
> pool + `up` integration + bench delta). See
> `specs/notes/plan-118-ws1-layer1a-implementation-plan.md`.

- [x] `warm_pool_size: u32` on `VmStartConfig`; `--warm-pool-size`
      CLI wrapper; library "ensure pool at target" entry point.
- [x] **(1a)** `SupervisorBaseConfig` (stdin) / `SupervisorAttachConfig`
      (control UDS) split; both `deny_unknown_fields`;
      `SupervisorConfig::from_base_and_attach` merge.
- [x] **(1a)** Prelaunched supervisor: setup → block before `start_enter` →
      attach → verify (signature + G4 + nonce + binding nonce) →
      `start_enter`. One-shot. The attach-time **plan re-verify** (absent on the
      cold path, which extract-only under ADR-002) is the security crux —
      `mvm_vm_host::prelaunch::verify_and_merge_attach`.
- [x] `SupervisorStandbyPool` under `~/.mvm/pool/<id>/`; control UDS
      `0700` + binding-nonce in path; replenish-on-use; reaper +
      `cache prune` integration. *(1a binds the UDS `0700`/nonce-in-path; the
      pool that owns its lifecycle is 1b.)*
- [x] **(1a)** `fuzz_attach_message.rs` fuzz target.
- [x] **(1a)** Security negative-path tests (a)–(e) above; none reach
      `start_enter` (pure `verify_and_merge_attach` unit ladder) + a
      `libkrun-live` process-level refusal integration.
- [x] Bench delta demonstrated via PR-10a harness. Firecracker
      `--warm-pool-size 1` produced
      `specs/perf/plan-118/microvm-launch-firecracker-warm-pool.json`
      with P50 `total_ready_ms = 803.596724`, versus the gated cold
      run P50 `1590.731061` (`49.48%` faster).
- [x] `warm_pool_size = 0` default-off verified (no standbys, no UDS).

### Deferred follow-ups (tracked in Plan 93 §deferred follow-ups)

- [x] **Firecracker standby pool — the mvmd-facing deliverable.**
      Firecracker now implements `supports_standby_pool()`,
      `spawn_standby`, and `claim_standby`: warm spawns reserve the
      normal Firecracker slot and prestart the daemon; claim reuses
      that slot, configures the admitted launch shape, then issues
      `InstanceStart`. Live proof on the Firecracker host
      (`rvproxy-firecracker`, 2026-06-20): `pool warm 1` produced a
      live idle standby, `up --detach --warm-pool-size 1 --hypervisor
      firecracker --up-json` consumed the standby
      (`vm_id=standby-6a263a7a4233599a`), and replenish restored the
      pool to one fresh idle standby.
- [x] mvmd sizing hookup: companion mvmd worktree
      `feat/plan-118-sizing` reconciles `desired_counts.warm` into
      fleet-level warm Firecracker instances. mvmd does not currently
      launch via mvm `VmStartConfig`, so the real reachable hook is
      desired-instance pre-warming rather than setting
      `warm_pool_size` on mvm's direct backend config.
- [x] Vz saved-standby pool: per-image spawn (capture_vm_full) + claim (clone + restore), `image_sha256` compat key, pid=0 sentinel, TTL-only reap, `--rootfs` CLI flag, doctor reports `vz=true`.
- [x] Optional decoupled attach credential via `host.secrets.v1`
      pattern descoped for Plan 118. The current attach is already
      bounded by the signed plan's G4 validity window, per-plan nonce,
      per-standby binding nonce, and one-shot attach semantics; a
      shorter secondary credential would be defense-in-depth, not a
      required Plan 118 correctness or security gate.

## Part C — density + concurrent-launch distribution bench (PR-10c)

### Why now — prior art exposed a measurement gap

A production agent-sandbox runtime (KVM microVMs, Rust /
Cloud-Hypervisor lineage, open-sourced June 2026) published headline
numbers we currently cannot answer in kind: per-instance host
overhead "<5 MB", "2000+ sandboxes on one 96-vCPU host", and
concurrent-launch latency P95/P99 at 50–100 concurrency. Part A's
probe measures one **serial** launch's **latency** only — it
quantifies neither steady-state **footprint** (density) nor the
launch-latency **distribution under concurrency**. Those are exactly
the two axes those claims flex, and the two axes Part B's libkrun
standby pool and the landed Vz saved-standby pool exist to improve.
Part C closes the gap so the warm-pool work is provable in the same
terms and our footprint/latency posture rests on committed numbers.

This is the only idea from that survey worth building here: the other
candidates fail the "no new blast radius" bar (an eBPF egress enforcer
— new privileged in-kernel code, Linux-only, redundant with our
nftables default-deny) or live in mvmd (E2B API compatibility). An
OpenResty/Lua egress gateway was explicitly rejected: the egress
gateway holds the raw secrets (claim 13) and the name-constrained CA
key, so moving that logic into nginx+LuaJIT would enlarge the highest-
value TCB with a large C/JIT surface that cannot be `zeroize`d, cannot
share the typed `PlanFlowPolicy` lowering, and is not covered by
`cargo deny`/fuzz — and it reverses ADR-082 (the in-house Rust
gateway). Part C, by contrast, adds **zero** attack surface.

### No new blast radius — by construction

Part C is read-only measurement. Every benched boot still goes through
the **same claim-8 admission** Part A uses (`admit_probe_plan` →
`admit_for_run`) — no bypass, no shared plan, a distinct signed plan
and nonce per instance. It introduces no new key, no daemon, no
on-disk control socket. It is sampling + a wider orchestration loop
around the existing backend probes; nothing privileged is added.

### Two new metrics, one substrate

Reuse Part A verbatim: `bench_probe::boot_measure_once`,
`BootMarks`/`IterationTiming`, `admit_probe_plan`,
`resolve_probe_image`, `HostDescriptor`, the versioned-JSON +
regression-gate machinery, and the `libkrun-live` gate. Part C adds
two report shapes beside the existing single-launch report.

**1. Density — `mvmctl bench microvm-density --count K --max-count M`.**
Boot K instances of the canonical `default-microvm` image, each via
its own admitted plan, hold them live, sample host-side footprint,
tear all down. The headline is **per-instance host overhead = the
VMM/supervisor process footprint** (not guest-allocated guest RAM);
report aggregate and per-instance. Ramp K until a boot fails or a
host-memory watermark trips, report max-K and the limiting resource,
bounded by `--max-count` so the bench can never OOM the host.

The footprint accessor is **platform-split** (confirm-before-write):
Linux/Firecracker reads PSS from `/proc/<pid>/smaps_rollup` (shared
dylib/kernel pages counted once); macOS/libkrun reads `phys_footprint`
via `proc_pid_rusage` (no `/proc`; `ps -o rss` over-counts shared
pages and is a fallback only). The pid set is the per-VM supervisor
pids at `mvm_backend::libkrun::vm_state_dir(name)/libkrun.pid`.

**2. Concurrency — `mvmctl bench microvm-launch --concurrency N`.**
Launch N instances concurrently (each its own admitted plan, unique
nonce, unique name), record every instance's `total_ready_ms`, report
P50/P95/P99 plus the existing per-span breakdown at that concurrency.
Because `krun_start_enter` boots-and-`exit()`s its caller (one
supervisor per VM — `reference_libkrun_gotchas`), N concurrent
launches are N independent `boot_measure_once` contexts driven from N
threads; confirm `LibkrunBackend::start` is reentrant for distinct VM
names + state dirs before writing, and serialize only the shared
codesign re-exec if it is not.

### Backend coverage — honest, staged

libkrun first: the only backend that boots and is bench-verifiable on
the dev host (Firecracker needs `/dev/kvm`, untestable on macOS — same
constraint as Part A). Vz second: the Vz saved-standby pool already
landed (Deferred follow-ups), so a Vz density/concurrency lane is the
natural way to prove that pool's payoff. Firecracker last, gated on a
KVM host, where the density number is most load-bearing (it is the
fleet/mvmd backend). `HostDescriptor.hypervisor` already namespaces
baselines per backend, so the three lanes never cross-compare.

### Dependency — inherits Part A's prerequisite

Part C cannot commit a baseline until the blocker Part A hit is
cleared: the cached `default-microvm` image on the dev host is stale
(pre-`mvm-meta.json` sidecar) and `backend.start` correctly refuses
it. A freshly-built `default-microvm` image unblocks both. Until then
Part C's **pure substrate** (percentile math, per-instance-footprint
derivation, report schema) lands and is unit-tested VM-free; the live
lanes are validated on a dev host once the image is rebuilt.

### Testing (PR-10c)

- **Pure substrate:** P50/P95/P99 over a sample vector and the
  per-instance-footprint derivation are pure functions, unit-tested
  without a VM (mirror Part A's `BootMarks::to_timing` tests).
- **Footprint accessor:** unit-test the parse of a captured
  `smaps_rollup` fixture (Linux) and a `proc_pid_rusage` shim (macOS);
  the live read is `libkrun-live`-gated.
- **`libkrun-live` integration:** `--count 4` density + `--concurrency
  4` launch each return finite, ordered, non-negative numbers and tear
  **all** instances down — assert the per-VM state dirs are empty
  after (no leaked supervisors).
- **Admission preserved:** assert each concurrent/density boot carries
  a **distinct** admitted plan (distinct nonce); no shared-plan bypass.
- **Caps:** `--max-count` / `--max-concurrency` refuse to exceed the
  host watermark.
- `cargo test --workspace` green (live lanes gated off); clippy clean;
  `cargo fmt --all -- --check`.

### Ship checklist (PR-10c)

- [x] Density report shape + percentile/footprint pure helpers,
      unit-tested VM-free. **First PR-10c substrate slice landed:** added
      `DensityReport`, `InstanceFootprint`, `DensityStats`, and
      `LaunchDistributionReport` plus pure summary/build helpers and unit tests
      for per-instance footprint derivation and concurrent P50/P95/P99 launch
      distribution. Live wiring remains below.
- [x] Platform-split footprint accessor (Linux PSS `smaps_rollup` /
      macOS `phys_footprint`), fixture-tested. Linux parses
      `/proc/<pid>/smaps_rollup` `Pss:`; macOS reads
      `proc_pid_rusage(RUSAGE_INFO_V4).ri_phys_footprint`; unsupported
      hosts fail closed.
- [x] `mvmctl bench microvm-density --count K --max-count M` wired
      through `admit_probe_plan` (no bypass); `libkrun-live`-gated
      live read. Stock binaries fail honestly before booting; live
      builds hold admitted VMs behind an RAII guard and sample their
      supervisor PID footprints.
- [x] `mvmctl bench microvm-launch --concurrency N` distribution
      (P50/P95/P99) reusing `boot_measure_once`. Each worker gets a
      distinct probe/VM name, so every boot synthesizes its own
      admitted plan and nonce.
- [x] Firecracker `HostDescriptor`-namespaced launch/density baselines
      committed under `specs/perf/plan-118/`: single launch,
      concurrency-2 launch distribution, and density count-2 PSS. The
      host descriptor includes `readiness_boundary = "firecracker-pid"`
      so these numbers cannot cross-compare against guest-agent-ready
      libkrun/Vz baselines.
- [x] No-leak teardown assertion; `--max-*` caps; admission-
      distinctness test. `--max-count` and `--max-concurrency` cap
      checks are unit-tested; `admit_probe_plan_generates_distinct_nonces_per_boot`
      proves each probe boot gets a distinct plan nonce; Firecracker
      launch/density paths now assert the named VM is absent from the
      backend list after RAII teardown; and remote proof checked no
      named `mvm-bench-fc*` / `mvm-density-fc*` processes remained
      after the reports.
- [x] Vz density/concurrency lane (pairs with the landed Vz
      saved-standby pool). `bench microvm-launch --hypervisor vz`,
      `bench microvm-launch --hypervisor vz --concurrency N`, and
      `bench microvm-density --hypervisor vz` now use the same
      admitted-plan probe flow, macOS `phys_footprint` density
      accessor, guest-agent readiness boundary, BootTiming sidecar,
      and no-leak teardown assertion. Live Vz artifact capture remains
      host-gated; the harness lane is compiled/tested in `mvm-cli`.
- [x] Tick `specs/SPRINT.md` + `specs/REFACTOR-STATUS.md` in the same
      change when it lands.

## Success criteria

- [x] Firecracker `mvmctl bench microvm-launch` produces a real versioned JSON
      report on the target host and regression-gates against a
      committed baseline.
- [x] With `--warm-pool-size N > 0`, the bench shows a measured
      `start_to_pid_ms` collapse vs `N = 0`.
- [x] No security regression: a standby never reaches `start_enter`
      without a valid signed + in-window + non-replayed + correctly
      bound plan; fuzz + negative-path tests cover it; `cargo test
      --workspace` green; clippy clean. Closeout evidence
      (2026-06-20): `MVM_DATA_DIR=/tmp/mvm-plan-118-data
      CARGO_TARGET_DIR=/tmp/mvm-plan-118-target cargo test
      --workspace --no-fail-fast` passed; `MVM_DATA_DIR=/tmp/mvm-plan-118-data
      CARGO_TARGET_DIR=/tmp/mvm-plan-118-target cargo clippy
      --workspace --all-targets -- -D warnings` passed; `cargo fmt
      --all -- --check` passed.
- [x] `warm_pool_size` is settable from the backend-agnostic
      `mvm-core` launch-config seam (not only the CLI), and libkrun,
      Vz, and Firecracker all consume that same field unchanged.
- [x] Firecracker `mvmctl bench microvm-density` and `bench
      microvm-launch --concurrency N` produce `HostDescriptor`-
      namespaced baselines for per-instance host footprint and
      P50/P95/P99 launch latency, with every boot still going through
      claim-8 admission (no bypass, no new
      privileged surface).
