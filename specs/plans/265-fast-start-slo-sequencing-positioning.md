# Plan 265 — Fast-start SLO, backend sequencing & competitive positioning

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status:** Draft.

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
| 10 | Host TCB growth in snapshot-load parser | fuzz the restore-load device-model parser (`RestoredDeviceModel`, which lives in mvm-runtime — a Firecracker `GET /vm/config` JSON view, not an extension of mvm-core's snapshot-frame format); non-`deny_unknown_fields` by design since it only reads one field of Firecracker's own schema | NEW fuzz coverage in `crates/mvm-runtime/fuzz-backend/fuzz_targets/restored_device_model.rs` (mvm-core's `fuzz_snapshot_frame` is a separate, unrelated type and stays untouched) |
| 11 | Balloon density DoS (availability only) | existing balloon policy + host memory budget + spawn gate | `s5_lifecycle/density_balloon.feature` |

---

## Phase 0 — Baseline & SLO gate scaffold

Establish the number we are beating before optimizing anything.

- [ ] Capture the current cold-boot phase breakdown on the KVM box with
      `MVM_PHASE_TIMING=1` through `crates/mvm-cli/src/commands/vm/phase_timing.rs`;
      record `resolve_ms/drives_ms/admit_ms/backend_start_ms/vsock_wait_ms` for
      Firecracker into the benchmark fixture (`benches/` or the harness in
      Phase 6). Document the baseline in this plan.
- [ ] Add a `warm_vs_cold` assertion helper to `phase_timing` that, given a
      warm and a cold run, asserts warm `backend_start_ms + vsock_wait_ms`
      clears the SLO. Unit-test it with canned timings (no VM).
- [ ] Add `features/suites/s5_lifecycle/warm_faster_than_cold.feature` tagged
      `@live @wip` (implemented in Phase 1) asserting warm start beats cold on
      the same image.

**Acceptance gate:** baseline recorded; `warm_vs_cold` helper unit-tested;
`cargo nextest run -p mvm-cli` green; new `@wip` scenario parses under
`just bdd`.

## Phase 1 — Firecracker vsock-safe warm restore (hero path, KVM box)

The load-bearing phase. Turns the disabled restore into a gated, integrity-
checked, NIC-free warm start.

- [ ] **No-NIC-on-restore invariant.** In `crates/mvm-runtime/src/microvm/snapshot.rs`,
      add `fn assert_vsock_only_device_model(&SnapshotManifest) -> Result<()>`
      that refuses any restored device model carrying a network device. Write
      the failing unit test first (`restore_refuses_nic_device_model`), verify
      red, implement, verify green.
- [ ] **Real `FirecrackerIO`.** Implement `SnapshotIO::create_snapshot` /
      `load_snapshot` for `FirecrackerIO` in
      `crates/mvm-runtime/src/vm/instance_snapshot.rs` (today the seam exists;
      the FC API calls are stubbed) using the Firecracker snapshot HTTP API,
      driven through the existing microVM driver. Unit-test create/load against
      a `CannedIO` fake for the state-machine, and behind a `@live` scenario for
      the real API.
- [ ] **Un-bail warm restore.** Replace the `bail!` bodies of
      `warm_restore_instance` / `warm_restore_instance_from_path`
      (`microvm/snapshot.rs`) with a path that calls `verify_and_resume`
      (HMAC + monotonic epoch, already in `instance_snapshot.rs`) then
      `assert_vsock_only_device_model` before resuming. Integrity/rollback
      refusal is reused, not reinvented.
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
- [ ] **First warm-start number.** Un-`@wip` the `warm_faster_than_cold`
      scenario, run it `@live` on the KVM box, record warm p50/p99 against the
      SLO in this plan.

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
- [ ] **Density SLO gate.** Extend `crates/mvm-core/src/memory_budget.rs`
      reporting so a same-image fork family reports guests-per-GB from measured
      resident; add `features/suites/s5_lifecycle/density_balloon.feature`
      (`@live`) asserting the density target on the KVM box.

**Acceptance gate:** balloon commit accounting unit-tested; cross-tenant merge
refused (witness); density target met and gated; clippy/nextest green.

## Phase 5 — Security witness consolidation & fuzz

- [ ] Register every NEW witness (surfaces 1, 2, 4, 6, 10) in the
      machine-checked ledger embedded in `specs/adrs/001-microvm-security-posture.md`
      (between the `claims-catalog` markers — there is no longer a standalone
      `specs/claims/catalog.md`; that content was folded into this ADR) so
      `xtask check-claim-catalog` binds them; keep the claim numbering table
      consistent (extends claims 1, 3, 8, 10, 13 into the restore path — no new
      numbered claim, no relaxation). Surface 2's guard
      (`fn:assert_vsock_only_device_model`) is registered against claim 10;
      surfaces 1, 4, 6 remain unregistered.
- [x] Add fuzz coverage for the restore-load device-model parser (surface 10):
      `crates/mvm-runtime/fuzz-backend/fuzz_targets/restored_device_model.rs`
      feeds `RestoredDeviceModel`'s parser arbitrary bytes. This parser turned
      out to live in mvm-runtime (a Firecracker `GET /vm/config` JSON view),
      not as an extension of mvm-core's `fuzz_snapshot_frame` (a different
      type, the sealed vmstate/mem envelope format) — mvm-core's target is
      untouched.
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
- [ ] **Comparison doc** at `public/src/content/docs/reference/isolation-tiers.md`:
      the machine-checked security-claim matrix + workload-compatibility (any
      unmodified OCI image) vs the no-OS tier, referring to that tier obliquely.
      This is the "default choice" evidence.
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
