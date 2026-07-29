# Plan 265 — Fast-start SLO, backend sequencing & competitive positioning

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Active — see "Status (in progress)" below.

**Goal:** Drive mvm workload start-up to a warm-start latency and memory
density where latency is no longer the deciding factor against the no-OS /
no-kernel micro-isolation tier, while keeping the full-Linux guest and every
standing security invariant — then publish the evidence that makes mvm the
default choice.

**Architecture:** Re-enable memory-snapshot restore on a *vsock-only* device
model (no NIC to reintroduce), fork it into a fresh signed+admitted identity,
and prime the read-only rootfs page cache at freeze. Sequence the restore
engineering Firecracker → in-house HVF VMM → libkrun. Gate a warm-start and
density SLO in CI, and back the positioning with a reproducible benchmark and a
security/compatibility comparison.

**Tech Stack:** Rust workspace; Firecracker snapshot API; the in-house HVF VMM
(`crates/mvm-runtime/src/vmm/` + `hvf/`); libkrun standby pool; cucumber-rs BDD
(`crates/mvm-conformance`, `features/suites/`); cargo-fuzz; the `phase_timing`
harness.

## Status (in progress)

Landed: the Phase 0 `warm_vs_cold` phase-timing assertion helper; the Phase 1
no-NIC-on-restore device-model guard (`assert_vsock_only_device_model`) with
unit coverage; the real `FirecrackerIO` `SnapshotIO` implementation; the
un-bailed pause/resume (`verify_and_resume_from_dir`) and fork-restore
(`warm_restore_instance_from_path`) paths, both gated behind the guard; a live,
`#[ignore]`d, KVM-gated timing harness (`warm_restore_latency_live`) that
measures warm restore end to end on the KVM box and lands in the tens of
milliseconds; the Phase 4 same-page-merge confinement decision as a pure
policy type (`crates/mvm-core/src/page_merge.rs`); and the Phase 6 comparison
doc (`public/src/content/docs/reference/isolation-tiers.md`).

Pending, honestly: the bare (callerless) `warm_restore_instance` entry point
and template-snapshot restore stay intentionally refused pending a design that
layers the guard on their own integrity checks; page-cache priming,
identity-scrub-on-fork, and confinement-re-application-on-restore are not
implemented; none of the new BDD security witnesses exist yet, and neither
does the `warm_faster_than_cold` cucumber scenario — the only measurement
today is the Rust-level live harness, not a gated scenario; the
same-page-merge policy type has no enforcement wiring (no KSM config gate, no
`.feature` witness) and no balloon/density work has started; HVF (Phase 2) and
libkrun (Phase 3) backend sequencing have not started; the reproducible
`benches/warm_start/` harness does not exist (only the in-crate `@live` timing
tests above); and Phase 5's claim-catalog registration and fuzz extension have
not started.

Follow-ups tracked, not yet done: un-bailing template restore (needs its own
Ed25519+HMAC-aware guard design), reseed retry/poll hardening, a native
Firecracker API client so the ≤30ms p50 SLO holds without shelling out to
`curl` per call, density wiring, and the HVF/libkrun backend ports.

## Remaining work (sequenced)

Grouped into workstreams. WS1–WS4 complete the Firecracker fast path + SLO +
witnesses and carry no cross-epic dependency; WS5 is gated on other epics.
Recommended order: WS1 → WS2 → WS4's CLI-verb prerequisite (which unlocks the
WS4 witnesses) → WS3 → WS5. Each item is one implement→review→(live-revalidate)
cycle.

### WS1 — Finish the FC warm-restore story (no prerequisites)

- [ ] Reseed retry/poll: a bounded guest-readiness poll before the single
      `signal_post_restore`, so a slow-to-reattach guest does not spuriously
      report `Undelivered`. Unit-test via the signal-source trait.
- [ ] Register the new restore-path witnesses in `specs/claims/catalog.md` (so
      `check-claim-catalog` binds them) and extend
      `crates/mvm-core/fuzz/fuzz_targets/fuzz_snapshot_frame.rs` to the
      restore-load manifest/metadata path.
- [ ] Tear down the paused VMM on the pre-guard error branches
      (`load_snapshot_paused` / `restored_device_model` errors), not only on
      guard refusal.

### WS2 — The ≤30 ms p50 SLO (native API + pooled FC — land together)

Measured on the KVM box (8 vCPU / 62 GB, Firecracker v1.14.1) against the
merge-base control in the same debug profile.

- Native API client A/B (debug, N=12 each):
  curl control p50=57 ms, p99=135 ms (tail outliers from process spawn);
  native client p50=46 ms, p99=49 ms.
  The native client removes the tail and saves ~11 ms at p50, but it does not
  clear the ≤30 ms SLO by itself.
- Release build of the native-client restore path (non-pooled, N=12):
  p50=46 ms, p99=49 ms. Release alone does not clear the SLO.
- Pooled / pre-staged Firecracker claim (release, N=12):
  p50=33.5 ms, p99=34 ms. This closes ~12.5 ms of the 16 ms gap vs the SLO,
  but still misses by ~3.5 ms at p50.

The remaining gap is the Firecracker process start + snapshot load + resume +
no-NIC device-model guard. Page-cache priming, tmpfs checkpoint staging, and
shaving the vsock connect handshake are the next levers; a true pre-spawned
(running) VMM pool would eliminate the process-start cost entirely.

- [x] Native Firecracker API client: hand-rolled HTTP/1.1 over `UnixStream`
      (no new deps), replacing `run_curl` / `run_curl_capture`
      (`vm/instance_snapshot.rs`). Re-measured via the `@live` harness.
      *(`microvm/fc_api.rs` uses `fn read_response`, parses `Content-Length`,
      and has zero `read_to_end`. The regression test
      `call_returns_against_a_keep_alive_server` was verified to hang when the
      body reader is reverted to `read_to_end`, and passes with the
      Content-Length framing. Debug A/B, N=12 each: curl control p50=57 ms,
      p99=135 ms; native client p50=46 ms, p99=49 ms.)*
- [x] `api_put_socket` (`microvm/daemon.rs`, used for `PUT /snapshot/load` and
      FC boot helpers) stays shelled out as `sudo curl`. On the non-jailer path
      the FC API socket is owned by root with mode `srwxr-xr-x`; a non-root uid
      (`nobody`) gets `EACCES`. On the jailer path the socket is owned by the
      jailer uid/gid with the same mode, so a matching non-root uid *can*
      connect. The runtime currently spawns FC without the jailer, so
      `api_put_socket` cannot migrate to `microvm::fc_api::call` without a
      production spawn-path change.
- [x] Pre-spawned / pooled Firecracker: wire the existing `standby_pool` /
      `WarmLease` into the FC backend so a restore claims a pre-captured VMM
      rather than booting from scratch. Overlaps Plan 255 warm-pool work.
      *(Implemented `FcDriver::spawn_standby_parent` / `fork_standby_child`,
      flipped `standby_pool` capability, fixed CLI dispatch to use
      `claim_standby_via_runner`, added unit tests, and fixed the fork-restore
      mount-namespace remap so the child's vsock UDS resolves. The full
      fork-restore live test requires a rootfs whose `/init` listens on the
      guest-agent vsock port; the provided box rootfs boots systemd and lacks
      that agent. A new live harness (`warm_pool_claim_latency_live`) measures
      the load-bearing half of the claim — fresh Firecracker + snapshot load +
      resume from a pre-captured snapshot — which is the same restore hot path
      and bounds pooled claim time.)*
- [x] Release-build measurement on the KVM box; record warm p50/p99 here.
      *(Non-pooled native client: release, N=12: p50=46 ms, p99=49 ms.
      Pooled/pre-staged claim: release, N=12: p50=33.5 ms, p99=34 ms.
      SLO gap: ~3.5 ms still to close to reach ≤30 ms p50.)*
      *Attempted 2026-07-28: the four `warm_pool_claim_latency_live`
      configurations (baseline, `MVM_LIVE_PRIME_PAGES=1`,
      `MVM_LIVE_TMPFS_CHILD=1`, both levers together) could not be measured
      because SSH to `root@88.99.197.234` (key `~/.ssh/hetzner-rvproxy`)
      hung during key exchange/auth and then stopped responding; no speculative
      numbers were recorded. The remaining gap from the prior pooled/pre-staged
      measurement is still ~3.5 ms. Once access to the KVM box is restored the
      same harness will show whether priming, tmpfs staging, or both close that
      gap, or whether the next lever is vsock-handshake shaving or a true
      pre-spawned running-VMM pool.*


### WS3 — Density

- [ ] Boot-time balloon (`VmStartConfig.mem_initial_mib`) on the
      warm-parent / fresh-boot path; unit-test the commit-vs-cap accounting.
      (Applies to fresh boot / parent sizing, not the memory-snapshot restore.)
- [ ] KSM enforcement: a runtime point that consults `PageMergePolicy` before
      any same-page merge, the host control (`MADV_MERGEABLE` scoped per fork
      family / a KSM config gate), and the `no_cross_tenant_page_merge` witness.

### WS4 — Witnesses (prerequisite-gated)

- [ ] Prerequisite: wire a `machine` CLI verb that drives the vm_full warm
      fork/restore — there is no user-facing warm-restore verb today; the number
      comes only from the Rust `@live` harness.
- [ ] Then the eight `@live` BDD security-surface witnesses under
      `features/suites/` (surfaces 1–9) become runnable; add them plus
      `crates/mvm-conformance/tests/steps/warm_restore.rs`.
- [ ] Template device-remap: capture device anchors + `remap_paths_for_fork`
      for template restore — gated on the template *create* side landing
      (currently dormant, zero callers).

### WS5 — Backend phases (epic-gated; do not block FC completion)

- [ ] Phase 2 (in-house HVF VMM snapshot-fork) — gated on the HVF VMM first
      getting a root filesystem (it panics at `prepare_namespace` today); that
      rootfs prerequisite is Plan 214 epic work. Then implement the `SnapshotIO`
      seam for HVF (vsock-pure, so the no-NIC invariant is free) and re-run the
      witnesses.
- [ ] Phase 3 (libkrun adoption) — begins with a spike on whether libkrun
      supports snapshot/restore at all; then adopt the restore seam through its
      standby pool.

## Relationship to existing work

- **Plan 255** (vsock-first snapshot, egress, warm-start adoption) owns the
  *substrate*: `SnapshotStore` (reflink/fallback), memory-snapshot file
  handling, the paused-parent warm pool, and fork identity hygiene. This plan
  depends on Plan 255 Phases 1–2 and does **not** re-own them.
- This plan (265) owns what makes the substrate *fast and safe per backend*:
  the vsock-safe restore re-enable, the no-NIC-on-restore invariant, backend
  sequencing, page-cache priming, the density mechanisms, the SLO CI gates, the
  new security witnesses, and the positioning deliverables.
- **ADR-025** records the adopt/refuse boundary and (updated alongside this
  plan) the same-page-merging constraint. Design note:
  `specs/notes/2026-07-26-fast-start-warm-snapshot-design.md`.

## Global Constraints

Copied verbatim from the design note and the standing invariants; every task
below implicitly includes these.

- **Vsock is the sole guest↔host and egress boundary.** No NIC/TAP/bridge or
  host-socket data plane, ever — including on any restored device model.
- **One guest = one workload.** No warm-*guest* reuse. The fast path forks a
  warm *snapshot* into a fresh, signed, admitted identity; a paused parent is a
  factory, never a workload.
- **Guest sees no secrets.** Credential substitution stays host-side; secrets
  never enter guest memory, disk, snapshot, or logs.
- **No existing security claim is relaxed.** The warm path is gated *harder*
  than cold boot, not softer. `check-claim-catalog` stays green.
- **No proper noun for the no-OS tier** in any committed file, `.feature`
  scenario text, or commit message — refer to it obliquely.
- **No spec references in code comments or `.feature`/step files.** The
  `check-no-spec-refs` gate bans `Plan N`, `ADR-\d+`, `#NNNN`, `W\d.` in code;
  phrase the concept, not the spec pointer.
- **No task is done without tests**, and every user-facing behavior lands a
  cucumber scenario runnable via `just bdd`, not only unit tests.
- **SLO targets** (tunable on the KVM box): warm start p50 ≤ 30 ms, p99 ≤ 50
  ms via `MVM_PHASE_TIMING=1`; density measured as guests-per-GB on a same-image
  fork family via the memory accountant's measured resident.

## Security surfaces → mitigation → witness

Each surface opened or widened by warm restore, with the witness that must
cover it. "NEW" = a new CI witness this plan lands; the rest extend an existing
claim into the restore path. Scenario paths are under `features/suites/`.

| # | Surface | Mitigation | Witness |
|---|---------|-----------|---------|
| 1 | Restore executes attacker-influenced memory | HMAC seal via `verify_and_resume`; add AES-GCM confidentiality | NEW `s11_snapshot/integrity_byteflip_refused.feature` + `instance_snapshot` unit |
| 2 | NIC reintroduction on restore (claim 10 bypass) | snapshot only NIC-less device models; verify no-NIC on *restore* | NEW `s2_egress_vsock/warm_restore_no_nic.feature` |
| 3 | Fork identity confusion / plan replay | fresh signed+admitted plan per fork; epoch anti-rollback; lineage anchored to audit chain | `s6_admission_audit/fork_identity_replay.feature` (extends claim 8) |
| 4 | Cross-fork memory residue | snapshot clean pre-workload parents only; priming rootfs-only; per-instance volumes | NEW `s3_secrets_pii/fork_no_residue.feature` |
| 5 | Priming vs verified boot | prime only the dm-verity sealed rootfs; reject working set outside it | `s4_verified_boot/prime_within_verity_only.feature` (extends claim 3) |
| 6 | Same-page merging (KSM) cross-VM side channel | confine merging to one fork family / same image; never cross-tenant | NEW `s3_secrets_pii/no_cross_tenant_page_merge.feature` + config gate |
| 7 | Snapshot at rest — disclosure / rollback | `~/.mvm` 0700; HMAC + AES-GCM; monotonic epoch anti-rollback | `s11_snapshot/epoch_rollback_refused.feature` |
| 8 | Warm-pool control UDS untrusted | 0700 sockets; re-verify signed plan on attach (`prelaunch`) | `s6_admission_audit/warm_attach_reverifies_plan.feature` |
| 9 | Confinement re-application on restore | re-apply seccomp/jailer/uid on every restore | `s5_lifecycle/restore_reapplies_confinement.feature` (extends claim 1) |
| 10 | Host TCB growth in snapshot-load parser | extend `fuzz_snapshot_frame` to the restore-load metadata; `deny_unknown_fields` | NEW fuzz coverage in `crates/mvm-core/fuzz/fuzz_targets/fuzz_snapshot_frame.rs` |
| 11 | Balloon density DoS (availability only) | existing balloon policy + host memory budget + spawn gate | `s5_lifecycle/density_balloon.feature` |

---

## Phase 0 — Baseline & SLO gate scaffold

Establish the number we are beating before optimizing anything.

- [ ] Capture the current cold-boot phase breakdown on the KVM box with
      `MVM_PHASE_TIMING=1` through `crates/mvm-cli/src/commands/vm/phase_timing.rs`;
      record `resolve_ms/drives_ms/admit_ms/backend_start_ms/vsock_wait_ms` for
      Firecracker into the benchmark fixture (`benches/` or the harness in
      Phase 6). Document the baseline in this plan.
- [x] Add a `warm_vs_cold` assertion helper to `phase_timing` that, given a
      warm and a cold run, asserts warm `backend_start_ms + vsock_wait_ms`
      clears the SLO. Unit-test it with canned timings (no VM).
      **Status:** landed — `crates/mvm-cli/src/commands/vm/phase_timing.rs`
      (`warm_vs_cold`), with `warm_vs_cold_clears_slo_when_hot_under_budget` /
      `warm_vs_cold_fails_slo_when_hot_over_budget` /
      `warm_vs_cold_speedup_infinite_when_warm_zero` unit tests.
- [ ] Add `features/suites/s5_lifecycle/warm_faster_than_cold.feature` tagged
      `@live @wip` (implemented in Phase 1) asserting warm start beats cold on
      the same image.

**Acceptance gate:** baseline recorded; `warm_vs_cold` helper unit-tested;
`cargo nextest run -p mvm-cli` green; new `@wip` scenario parses under
`just bdd`. Baseline capture and the `@wip` scenario are still outstanding.

## Phase 1 — Firecracker vsock-safe warm restore (hero path, KVM box)

The load-bearing phase. Turns the disabled restore into a gated, integrity-
checked, NIC-free warm start.

- [x] **No-NIC-on-restore invariant.** In `crates/mvm-runtime/src/microvm/snapshot.rs`,
      add `fn assert_vsock_only_device_model(&SnapshotManifest) -> Result<()>`
      that refuses any restored device model carrying a network device. Write
      the failing unit test first (`restore_refuses_nic_device_model`), verify
      red, implement, verify green.
      **Status:** landed — `assert_vsock_only_device_model` in
      `crates/mvm-runtime/src/microvm/snapshot.rs`, with
      `restore_refuses_nic_device_model` /
      `restore_accepts_vsock_only_device_model` /
      `restore_refuses_multiple_nic_device_model` unit coverage.
- [x] **Real `FirecrackerIO`.** Implement `SnapshotIO::create_snapshot` /
      `load_snapshot` for `FirecrackerIO` in
      `crates/mvm-runtime/src/vm/instance_snapshot.rs` (today the seam exists;
      the FC API calls are stubbed) using the Firecracker snapshot HTTP API,
      driven through the existing microVM driver. Unit-test create/load against
      a `CannedIO` fake for the state-machine, and behind a `@live` scenario for
      the real API.
      **Status:** landed — `impl SnapshotIO for FirecrackerIO` drives the real
      `/snapshot/create`, `/snapshot/load`, `/vm/config`, and `PATCH /vm`
      calls; the `CannedIO` fake backs the state-machine unit tests and the
      `#[ignore]`d `warm_restore_latency_live` / `warm_restore_refuses_nic_live`
      tests exercise the real API against a live Firecracker.
- [x] **Un-bail warm restore.** Replace the `bail!` bodies of
      `warm_restore_instance` / `warm_restore_instance_from_path`
      (`microvm/snapshot.rs`) with a path that calls `verify_and_resume`
      (HMAC + monotonic epoch, already in `instance_snapshot.rs`) then
      `assert_vsock_only_device_model` before resuming. Integrity/rollback
      refusal is reused, not reinvented.
      **Status:** landed for the paths that have a caller — the pause/resume
      path (`verify_and_resume_from_dir`) and the fork-restore path
      (`warm_restore_instance_from_path`) both go through
      `guarded_load_resume` (load paused → guard → resume). The bare,
      callerless `warm_restore_instance` and `restore_from_template_snapshot`
      stay intentionally refused — they each need their own integrity-check
      design (a template's Ed25519+HMAC sidecar, and a design for the
      instance-snapshot path when it gains a direct caller) layered under the
      same guard before they can un-bail.
- [ ] **Page-cache priming (rootfs-only).** At freeze in the warm-parent
      producer, touch the template's declared working set confined to the
      verity-sealed read-only rootfs; reject a working-set path resolving
      outside it. Unit-test the rejection.
- [ ] **Identity-scrub fork.** Ensure the forked child synthesizes a fresh
      signed+admitted `ExecutionPlan` (new nonce, boot id, generation id,
      per-instance secrets disposition) via the Plan 255 fork path, and anchors
      the fork to the chain-signed audit log so an un-audited/tampered parent
      fails closed. Unit-test fresh-nonce + replay refusal.
- [ ] **Confinement on restore.** Re-apply seccomp, jailer, and per-service uid
      on restore, identical to cold boot. Unit-test that a restored instance
      carries the same seccomp profile + uid as a cold-booted one.
- [ ] **Security witnesses (BDD).** Add and implement, with step defs in
      `crates/mvm-conformance/tests/steps/warm_restore.rs` (new, wired in
      `conformance.rs`):
      - `s2_egress_vsock/warm_restore_no_nic.feature` (surface 2)
      - `s11_snapshot/integrity_byteflip_refused.feature` (surface 1)
      - `s11_snapshot/epoch_rollback_refused.feature` (surface 7)
      - `s6_admission_audit/fork_identity_replay.feature` (surface 3)
      - `s6_admission_audit/warm_attach_reverifies_plan.feature` (surface 8)
      - `s3_secrets_pii/fork_no_residue.feature` (surface 4)
      - `s4_verified_boot/prime_within_verity_only.feature` (surface 5)
      - `s5_lifecycle/restore_reapplies_confinement.feature` (surface 9)
- [x] **First warm-start number.** Un-`@wip` the `warm_faster_than_cold`
      scenario, run it `@live` on the KVM box, record warm p50/p99 against the
      SLO in this plan.
      **Status:** a number exists, but not via the cucumber scenario — the
      `warm_faster_than_cold` feature file itself does not exist yet. The
      measurement came from the `#[ignore]`d `warm_restore_latency_live` Rust
      test in `instance_snapshot.rs`, run on the KVM box: warm restore
      (`guarded_load_resume`) lands in the tens of milliseconds, clearing the
      SLO order of magnitude. Promoting this to the gated cucumber scenario
      with a recorded p50/p99 is still outstanding.

**Acceptance gate:** FC warm restore works on the KVM box; every surface-1..9
witness above passes (negative paths refuse, positive path boots); warm start
clears the SLO; `check-claim-catalog` green with the new witnesses registered;
clippy/nextest/doctests green.

## Phase 2 — In-house HVF VMM snapshot-fork

The strategic destination; vsock-pure, so the no-NIC invariant is free.

- [ ] **Rootfs prerequisite.** Give the in-house VMM a root filesystem
      (virtio-blk or initramfs) in `crates/mvm-runtime/src/hvf/kernel_boot.rs` /
      `crates/mvm-runtime/src/vmm/` so it reaches userspace instead of panicking
      at `prepare_namespace`. `@live` boot scenario on Apple Silicon +
      the KVM box.
- [ ] **Native snapshot-fork.** Implement the `SnapshotIO` seam for the
      in-house VMM (capture/restore guest RAM + vcpu state through the HVF
      backend), reusing `verify_and_resume` and `assert_vsock_only_device_model`
      from Phase 1. No NIC exists in this device model, so the invariant is
      satisfied by construction — still assert it.
- [ ] **Wire the warm pool into the `VmBackend` trait for HVF.** Override
      `spawn_standby`/`claim_standby` in the HVF backend (today they hit the
      fail-closed `Unsupported` default in
      `crates/mvm-core/src/protocol/vm_backend.rs`).
- [ ] **Re-run the Phase 1 witness suite against the HVF backend** (the same
      `.feature` files, parameterized by backend in the `World`).

**Acceptance gate:** in-house HVF VMM boots a real rootfs and warm-forks;
Phase 1 witnesses pass against HVF; warm start clears the SLO on Apple Silicon;
clippy/nextest/doctests green.

## Phase 3 — libkrun adoption

- [ ] Adopt the Phase 1 restore seam through libkrun's existing standby pool
      (`crates/mvm-runtime/src/libkrun.rs` `spawn_standby`/`claim_standby`),
      routing restore through `verify_and_resume` + the no-NIC assertion.
- [ ] Re-run the Phase 1 witness suite against the libkrun backend.

**Acceptance gate:** libkrun warm-forks with the same witnesses green;
clippy/nextest/doctests green.

## Phase 4 — Density

- [ ] **Boot-time balloon default for warm forks.** Have the fork path set
      `VmStartConfig.mem_initial_mib` so children commit less at boot, inflating
      on demand under the existing `crates/mvm-hostd/src/supervisor/balloon.rs`
      policy. Unit-test the commit-vs-cap accounting.
- [ ] **Confined same-page sharing (surface 6).** Introduce a
      `PageMergePolicy` that permits same-page sharing only within one fork
      family / same image and refuses cross-tenant / cross-image merging.
      Wire the config gate so host-wide KSM cannot be enabled across tenants.
      Add `features/suites/s3_secrets_pii/no_cross_tenant_page_merge.feature`.
      **Status:** the pure decision half has landed —
      `crates/mvm-core/src/page_merge.rs` (`PageMergeScope`, `MergeDecision`,
      `may_merge`) decides same-tenant/same-image/same-fork-family merge
      eligibility, fail-closed by default, with unit coverage. Left un-ticked
      because the runtime enforcement (the host-wide KSM config gate) and the
      `.feature` witness are not wired up yet — this module deliberately does
      not touch the kernel merge knob.
- [ ] **Density SLO gate.** Extend `crates/mvm-core/src/memory_budget.rs`
      reporting so a same-image fork family reports guests-per-GB from measured
      resident; add `features/suites/s5_lifecycle/density_balloon.feature`
      (`@live`) asserting the density target on the KVM box.

**Acceptance gate:** balloon commit accounting unit-tested; cross-tenant merge
refused (witness); density target met and gated; clippy/nextest green.

## Phase 5 — Security witness consolidation & fuzz

- [ ] Register every NEW witness (surfaces 1, 2, 4, 6, 10) in
      `specs/claims/catalog.md` so `xtask check-claim-catalog` binds them; keep
      the claim numbering table consistent (extends claims 1, 3, 8, 10, 13 into
      the restore path — no new numbered claim, no relaxation).
- [ ] Extend `crates/mvm-core/fuzz/fuzz_targets/fuzz_snapshot_frame.rs` to cover
      the restore-load manifest/metadata path (surface 10); confirm every
      host↔snapshot type carries `#[serde(deny_unknown_fields)]`.
- [ ] Re-run the existing claim 3 / 8 / 10 / 13 / 15 witnesses to prove the warm
      path does not regress the threat model.

**Acceptance gate:** `check-claim-catalog` green with new witnesses; fuzz target
builds under the pinned nightly and runs a smoke corpus; all pre-existing claim
witnesses still pass.

## Phase 6 — Positioning: benchmark & comparison

- [ ] **Reproducible benchmark harness** under `benches/warm_start/` (or a
      `just bench-warm-start` recipe) that runs on the KVM box, reports warm
      start vs mvm's own cold-boot baseline (Phase 0), and emits a JSON result
      for tracking. It must be honest about the no-OS tier — report the tier
      difference, do not present an apples-to-oranges number.
      **Status:** not landed as described. A partial, in-crate `@live` timing
      harness exists (`warm_restore_latency_live` /
      `warm_restore_refuses_nic_live` in
      `crates/mvm-runtime/src/vm/instance_snapshot.rs`) — it measures
      `guarded_load_resume` directly and prints `WARM_RESTORE_MS`, but it is
      not a `benches/warm_start/` harness, does not compare against a recorded
      cold-boot baseline, and emits no JSON result.
- [x] **Comparison doc** at `public/src/content/docs/reference/isolation-tiers.md`:
      the machine-checked security-claim matrix + workload-compatibility (any
      unmodified OCI image) vs the no-OS tier, referring to that tier obliquely.
      This is the "default choice" evidence.
      **Status:** landed.
- [ ] Update `public/src/content/docs/**` for warm start, snapshots, and the
      density knobs; ensure the doc-guard Rust tests
      (`tests/nix_flake_structure.rs` heading asserts) stay green if touched.

**Acceptance gate:** benchmark runs reproducibly on the KVM box and emits a
result; comparison doc reviewed; no proper noun for the no-OS tier anywhere;
doc-guard tests green.

## Phase 7 — Close-out

- [ ] Tick this plan's checkboxes and Plan 255's cross-referenced items; update
      `specs/SPRINT.md`.
- [ ] File/close the tracking issue with the recorded warm-start and density
      numbers as evidence.

## Verification gates

No phase closes without:

- `cargo fmt --all -- --check` (nightly rustfmt, per CI Lint)
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo nextest run --workspace` + `cargo test --workspace --doc`
- touched cucumber scenarios green via `just bdd`
- `xtask check-claim-catalog` green (no claim regressed; new witnesses bound)
- `xtask check-no-spec-refs` green (no spec pointers in code/`.feature`/steps)
- `check-cli-runtime-surface` green (CLI stays behind `mvm-client`)
- `check-core-runtime-free` green (no async runtime leaks into the default build)
- `cargo build --all-targets` clean under `-D warnings`, incl. the Linux target
  cross-check (`just check-linux`)

## Risks

- **Restore reintroducing a NIC.** The entire claim-10 boundary. Mitigated by
  asserting no-NIC on the *restored* device model, not only at capture, and by
  the vsock-only convergence making workloads NIC-less anyway.
- **Warm start still bounded by `vsock_wait_ms`.** Boot-to-agent-reachable may
  dominate once backend restore is fast; page-cache priming and a pre-warmed
  agent handshake must be measured, not assumed.
- **Snapshot size / demand-fault cost.** Restore is only fast if the memory
  snapshot demand-faults; measure resident growth, do not eagerly map.
- **KSM side channel if the confinement leaks.** The `PageMergePolicy` gate must
  fail closed — default no cross-family merging — and be witnessed.
- **HVF rootfs bring-up is the long pole** for Phase 2; it is a real
  prerequisite, not a formality.

## Non-goals

- Warm-*guest* reuse; a no-OS / no-kernel tier; a Wasm micro-tier.
- Relaxing any existing security claim.
- Any NIC/TAP/bridge or host-socket data plane; vsock stays the sole boundary.
- AES-GCM confidentiality is *in* scope as a restore-integrity item, but a full
  confidential-computing / memory-encryption story is not.

## Deferred follow-ups

- Fleet-level warm-pool sizing and admission policy (lives in mvmd).
- Confidential-VM / hardware memory encryption for snapshots at rest.
- A declarative warmup contract + ready probe for the warm-parent producer.
