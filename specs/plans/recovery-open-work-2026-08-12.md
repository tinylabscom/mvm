# Recovery plan: open workstreams, issues, and production readiness

**Date:** 2026-08-12
**Main checkout:** `c1e06dea8` on `main`
**Open PRs:** 14
**Open issues:** 44
**BDD status:** 54 features, 175 scenarios, 723 steps — all passed (macOS host, hermetic)
**Clippy:** clean (`cargo clippy --workspace --all-targets -- -D warnings`)
**Workspace tests:** one reproducible flake in `mvm-backends` parallel run (see Blockers §1)

This plan recovers the open Claude sessions shown in the screenshot, maps each to the
repo's actual state, and lays out a dependency-ordered path to a production-ready `mvm`
with complete BDD coverage of every README example and every open issue closed.

---

## 1. Screenshot sessions → recovered workstreams

| Screenshot label                        | Actual artifact                                | Status            | What remains                                                                                                          |
| --------------------------------------- | ---------------------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------- |
| `builder vm`                            | PR #2421 `feat/323-phase3-adopt-on-contention` | Open, BLOCKED     | Land Phase 3 so concurrent builds share one persistent builder VM instead of queueing.                                |
| `2416 - max-connections - flake build`  | PR #2416 `feat/324-store-lock-ownership`       | Open, BLOCKED     | Give the store image lock to the supervisor whose lifetime matches the VM; unblocks #2421 and removes a flake source. |
| `#2403 & #2399`                         | #2399 merged; #2403 closed unmerged            | Done / obsolete   | #2399 (eBPF lane gates) merged. #2403 (bpf-linker pin) was closed; replaced by issue #2413.                           |
| `#2414 -- unknown argv flag`            | PR #2414 `fix/machine-run-unknown-flag-argv`   | Open, BLOCKED     | Make `machine run` name an unknown flag instead of passing it to guest argv.                                          |
| `Build Plan 327 Phase 1 — the HVF vCPU` | PR #2422 `plan/327-hvf-vcpu-quota`             | Open, BLOCKED     | Implement a CPU quota for the HVF tier; Phase 0 spike measured, Phase 1 implementation needed.                        |
| `Implement RFC 6962 consistency proof`  | Issue #2423                                    | Open              | Add RFC-6962 Merkle consistency proofs to `mvm-contract::merkle` (piece A of A/B/C).                                  |
| `wasm-demo`                             | Plan 320 website wasm demo                     | Partial           | E1/E2.1/E3.1 landed; E2 substitution core, E3 audit writer, and `/demo` UI not started.                               |
| `test - python`                         | PR #2424 `fix/hvf-machine-run-agent`           | Open, BLOCKED     | Fix SDK sidecar host-service startup; Python host-time round trip is the live witness.                                |
| `#2408`                                 | PR #2408 `feat/316-phase1b-network-limits`     | Open, BLOCKED     | Add signed transport-neutral network limits (Plan 316 Phase 1b).                                                      |
| `#1411`                                 | PR #1411                                       | Merged 2026-07-03 | Historical; `admit_and_start` shared entrypoint. No action.                                                           |
| `website - live`                        | PR #2359                                       | Merged 2026-08-12 | Website redesign merged; any remaining polish is post-merge cleanup.                                                  |
| `Open PRs` (general)                    | 14 open PRs total                              | See §3            | Review queue, land ready ones, rebase blocked ones.                                                                   |

### Registered worktrees with uncommitted work

All worktrees live in `/Users/auser/work/tinylabs/mvmco/.worktrees/` as required.
Only these have dirty state:

| Worktree                     | Branch                                | Dirty files                                                                                                                                                        | Interpretation                                                                             |
| ---------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| `mvm-312-boundaries`         | `feat/312-boundary-contracts`         | Many (`mvm-conformance`, `mvm-core`, `mvm-hostd`, `mvm-runtime`, feature files, `specs/REFACTOR-STATUS.md`, `specs/SPRINT.md`, new `examples/pid1_reaping/`)       | Active boundary-contracts work; appears to be the carry branch for several closeout items. |
| `mvm-320-e23b`               | `feat/320-e2-3-substitution-registry` | `crates/mvm-contract/src/substitution.rs`, `crates/mvm-hostd/src/keyholder/substitution.rs`                                                                        | wasm-demo substitution-registry work in progress.                                          |
| `mvm-328-consistency`        | `feat/328-merkle-consistency-proofs`  | `crates/mvm-contract/src/merkle.rs`                                                                                                                                | RFC-6962 consistency proof implementation in progress.                                     |
| `mvm-argv-unknown-flag`      | `fix/machine-run-unknown-flag-argv`   | `crates/mvm-cli/src/commands/mod.rs`, `crates/mvm-cli/src/commands/tests.rs`, `features/suites/s0_cli/machine_run_contract.feature`                                | #2414 implementation nearly done.                                                          |
| `mvm-egress-ac`              | `fix/uniform-egress-apple-container`  | `specs/REFACTOR-STATUS.md`, `specs/plans/308-workload-grants-implementation.md`, `specs/plans/320-wasm-browser-demo.md`, `xtask/src/check_uniform_vsock_egress.rs` | Cross-plan bookkeeping for egress uniformity.                                              |
| `mvm-fast-build`             | `feat/fast-mvmctl-build`              | `Justfile`, `README.md`, build scripts, `specs/SPRINT.md`, new `scripts/check-mvmctl-build-time.sh`                                                                | Build-time optimization work.                                                              |
| `mvm-stage0-store-integrity` | `fix/stage0-store-integrity`          | Stage 0 init, libkrun builder, ext4 mkfs, plan docs                                                                                                                | Stage 0 store integrity fix in progress.                                                   |

The main checkout has one dirty file: `public/src/components/landing/HeroStackDiagram.tsx`
(from the now-merged website redesign PR #2359). It should be stashed or discarded after
confirming it is not needed.

---

## 2. Production-readiness health check

### Green

- `cargo clippy --workspace --all-targets -- -D warnings` — clean.
- `just bdd` (hermetic macOS) — 54 features, 175 scenarios, 723 steps passed.
- Most unit/integration test suites pass individually.

### Red / flaky

1. **`mvm-backends` parallel test flake.** `legacy::hvf::tests::terminate_pid_reaps_child_without_grace_timeout`
   and `terminate_pid_escalates_when_sigterm_is_ignored` fail when the whole workspace
   runs in parallel with `No such file or directory` for `sleep`/`sh`. They pass in
   isolation. Root cause: the tests do not preserve `PATH` under parallel `TestEnv`
   mutation by other tests. **Fix required before calling tests complete.**
2. **Linux-only gates not verified here.** Per `AGENTS.md`, Linux all-target clippy,
   Firecracker/KVM tests, Nix evals, and builder-VM operations must run inside the
   project builder VM. These are gating several open PRs.

### README example coverage gaps

The BDD manifest at `features/suites/s8_readme_contract/readme_coverage.toml` covers all
26 fenced blocks at the token/help level, but functional live coverage is missing for:

- `--mount` host-directory transient shares.
- Persistent `machine start`, `exec`, `logs`, `reconfigure`, `inspect` beyond help existence.
- Full dev-loop: `deps install`, `deps capture-live HASH`, `deps inspect`.
- `machine build --flake ./out` and `machine run --entrypoint` end-to-end.
- Nix `mkGuest` flake build.
- Rust embedding snippets (only token-checked, never compiled in BDD).

The placeholder `HASH` in `deps capture-live HASH` would fail if run literally; either
the example must be made runnable or the BDD witness must prove the placeholder is
replaced before execution.

---

## 3. Open PR triage: what each needs

| PR    | Branch                                | State   | Next step                                                                                 |
| ----- | ------------------------------------- | ------- | ----------------------------------------------------------------------------------------- |
| #2412 | `feat/2390-accountable-prune`         | CLEAN   | Ready to merge after final review; closes accountable-prune path for audit rotation.      |
| #2424 | `fix/hvf-machine-run-agent`           | BLOCKED | Needs CI `Test` job to finish; SDK sidecar host-time Python witness.                      |
| #2422 | `plan/327-hvf-vcpu-quota`             | BLOCKED | Needs review; Phase 1 implementation after measured Phase 0 spike.                        |
| #2421 | `feat/323-phase3-adopt-on-contention` | BLOCKED | Depends on #2416 (store-lock ownership); also needs `Test workspace` failure triage.      |
| #2420 | `feat/308-pool-grant-ceiling`         | DIRTY   | Needs rebase (merge conflicts); bounds warm-claimed children by host grant ceiling.       |
| #2419 | `fix/326-builder-store-durability`    | BLOCKED | Needs review; builder-store FLUSH + `T_FLUSH` + corruption fast-fail.                     |
| #2417 | `fix/egress-proxy-end-attribution`    | BLOCKED | Needs review/recheck; egress splice error attribution.                                    |
| #2416 | `feat/324-store-lock-ownership`       | BLOCKED | Implementation done; blocked on CI/review, gates #2421.                                   |
| #2415 | `docs/2398-security-claims-coverage`  | UNKNOWN | Docs-only; verify CI status and merge.                                                    |
| #2414 | `fix/machine-run-unknown-flag-argv`   | BLOCKED | Implementation mostly done in worktree `mvm-argv-unknown-flag`; needs final review/merge. |
| #2411 | `fix/lowercase-image-ref`             | BLOCKED | OCI repo capitalization normalization; needs review.                                      |
| #2410 | `feat/316-phase1a-network-flow`       | BLOCKED | Plan 316 Phase 1 — FlowMux wire contract; large design review.                            |
| #2408 | `feat/316-phase1b-network-limits`     | BLOCKED | Signed network limits; depends on #2410 framing.                                          |
| #2406 | `fix/vsock-egress-gate-paths`         | BLOCKED | Repoint vsock-only-egress gate at real workload paths; closes #2400.                      |

---

## 4. Open issue closeout strategy

### Immediate safety/correctness batch (land first)

These are concrete bugs or have open PRs and should close soon:

- **#2165** — Block-root bootargs contract. PR #2330 merged; needs live HVF + Firecracker witnesses and issue closeout.
- **#2321** — Cap substitution forward responses. PR #2330 merged the bounded forward leg; verify and close.
- **#2323** — Firecracker teardown polling quantization. PR #2330 merged shared backoff; verify and close.
- **#2401** — Unknown flag swallowed into guest argv. PR #2414 open.
- **#2400** — `check-vsock-only-egress` scanned zero files. PR #2406 open.
- **#2413** — Move eBPF telemetry lane to `bpf-linker` 0.11.0. Small toolchain bump.
- **#2423** — RFC-6962 consistency proofs (piece A). Worktree `mvm-328-consistency` has started.

### Reliability / performance batch

- **#2135** — Security lane is red. Needs a clean exact Linux Security workflow run, then merge, then a clean scheduled/release run.
- **#2289** — Kernel 6.12.103 rollout. Build release artifacts, run verified-boot/reproducibility witnesses, `mvmctl vm rekernel` rollout.
- **#2292** — Firecracker `driver_boot` 630 ms shell/curl overhead. Remove/justify privileged ops, publish `ColdLaunchBench` 20-sample report.
- **#2299** — Comparable guest-boot measurements. Define backend-neutral interval, instrument both backends.
- **#2318** — Receipt store two `sync_all` calls per append. Decide control vs record, rebuild missing head, re-measure.
- **#2307** — Gate nextest override filters. Add `xtask check-nextest-groups` and CI gate.

### Networking rewrite (Plan 316)

All phases depend strictly on the previous phase. Only #2370 is actionable after #2369
(which is complete). The open PRs #2410 and #2408 cover Phase 1/1b.

Order: #2370 → #2371 → #2372 → #2373 → #2374 → #2375 → #2376 → #2377.

### Warm-launch pool (Plan 299 / issues #2193–#2199, #2333, #2336)

This is the longest dependency chain:

```text
#2333 bootless launch preparation
    → #2193 verified artifact prewarm
        → #2194 HVF parent / #2196 Firecracker parent
            → #2195 fixed read-only shares
                → #2197 resident-process hardening
                    → #2198 CLI timing/refusal contract
                        → #2199 1,000-claim release matrix
```

- **#2336** warm-claim handshake failure is a single point of failure blocking the whole
  chain and should be diagnosed first.

### Agent / Studio surface

```text
#2169 bounded inspector → #2083 versioned launcher → #2166 epic closeout
```

### Governance / deferred

- **#2256** Plan 306 declared-backing/tier honesty. Not started; depends on Plan 316 and backend capability matrix.
- **#2211** eBPF egress telemetry. Spike complete; decide whether to narrow issue or complete byte/latency attribution.

---

## 5. Completion plan

### Phase 0 — Stabilize the trunk (1–2 days)

1. Discard or commit the stale `public/src/components/landing/HeroStackDiagram.tsx`
   change in the main checkout.
2. Fix the `mvm-backends` parallel test flake (`terminate_pid_*` tests) by preserving
   a known-good `PATH` or using absolute paths for `sleep`/`sh`.
3. Run `cargo test --workspace` serially and confirm zero failures on macOS.
4. Run Linux all-target clippy/tests inside the builder VM for the current `main`.
5. Rebase the DIRTY PR #2420 (`feat/308-pool-grant-ceiling`) onto current `main`.

### Phase 1 — Land the ready open PRs (2–3 days)

In merge order:

1. **#2412** `feat/2390-accountable-prune` (state CLEAN).
2. **#2414** `fix/machine-run-unknown-flag-argv` — finish from worktree `mvm-argv-unknown-flag`.
3. **#2411** `fix/lowercase-image-ref`.
4. **#2415** `docs/2398-security-claims-coverage` if CI is green.
5. **#2417** `fix/egress-proxy-end-attribution`.
6. **#2419** `fix/326-builder-store-durability`.
7. **#2416** `feat/324-store-lock-ownership`.
8. **#2421** `feat/323-phase3-adopt-on-contention` (after #2416).
9. **#2424** `fix/hvf-machine-run-agent`.
10. **#2420** `feat/308-pool-grant-ceiling` (after rebase).
11. **#2422** `plan/327-hvf-vcpu-quota`.

After each merge: update `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`, and close the
linked issue(s).

### Phase 2 — Close the immediate issue batch (3–5 days)

- Close #2165, #2321, #2323 with PR #2330 evidence.
- Close #2400 with PR #2406 evidence.
- Close #2401 with PR #2414 evidence.
- Land #2413 (bpf-linker bump).
- Land #2423 (RFC-6962 consistency proofs) from worktree `mvm-328-consistency`.
- Restore #2135 Security lane green, then close.
- Close #2289 after release-artifact rollout.
- Implement #2307 `xtask check-nextest-groups`.

### Phase 3 — README example completeness (3–5 days)

Add functional BDD coverage for every README example that is not already exercised:

1. `--mount` transient host-directory shares (`machine run --mount "$PWD:/work:ro"`).
2. Persistent machine lifecycle: `start`, `exec`, `logs`, `reconfigure`, `inspect`
   against a real (or fixture-backed) persistent machine.
3. Dev-loop: `build compile`, `machine build --flake ./out`, `deps install`,
   `deps capture-live` with a real hash, `deps inspect`.
4. Nix `mkGuest` flake build from a fixture.
5. Rust embedding snippets: compile them as part of BDD or a dedicated `rust-compile`
   CI job.
6. Fix or replace the `HASH` placeholder in `deps capture-live HASH` so the example
   is literally runnable.
7. Run every example manually and fix any bug found.

Update `readme_coverage.toml` so every example maps to a scenario that actually
executes it, not just a help witness.

### Phase 4 — Backend shim removal: make `VmmDriver` the sole backend owner (Plan 269) (2–3 weeks)

The `mvm-backends/src/legacy/` directory contains old `VmBackend` trait shells
(`HvfBackend`, `LibkrunBackend`, `QemuBackend`) that the new `VmmDriver`
implementations still wrap. This is unfinished extraction debt from Plan 298 and
is the source of the confusing `legacy/` naming and the parallel test flake in
`legacy/hvf.rs`.

Goal: absorb the old shells into the drivers, implement the missing blanket
`impl VmBackend for WorkloadRunner<D: VmmDriver, ...>`, migrate remaining callers
(codesign, builder VM, QEMU bridge, tests, examples), decide `WasmBackend` and
QEMU disposition, and delete `mvm-backends/src/legacy/`.

Acceptance gate from Plan 269:

- `cargo nextest run --workspace` green.
- `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo xtask check-claim-catalog` green.
- No production code references `FirecrackerBackend`, `HvfBackend`,
  `LibkrunBackend`, or `QemuBackend` as raw `VmBackend` impls.
- Every selectable workload backend is a `WorkloadRunner<D: VmmDriver, ...>`
  (with any `WasmBackend` exception documented).

### Phase 5 — Performance and reliability (2–4 weeks)

- #2292 Firecracker boot overhead.
- #2299 comparable guest-boot metrics.
- #2318 receipt-store durability.
- #2280 kernel/boot-substrate matrix.
- #2281 filesystem adopt/decline decision.

### Phase 6 — Warm-launch pool (4–6 weeks)

Diagnose and fix #2336 first. Then execute the dependency chain #2333 → #2193 →
#2194/#2196 → #2195 → #2197 → #2198 → #2199.

### Phase 7 — Networking rewrite (Plan 316) (6–8 weeks)

Execute phases 1–8 in order. This is the largest structural change and should not be
interleaved with unrelated large refactors.

### Phase 8 — Agent / Studio surface (3–4 weeks)

#2169 → #2083 → #2166.

### Phase 9 — Final reconciliation

- Fresh GitHub query returns zero stale open issues.
- Every README example has a passing BDD scenario.
- Host + Linux all-target clippy, workspace tests, BDD, Nix flake check, Security,
  and live backend witnesses are green.
- `specs/SPRINT.md`, `specs/REFACTOR-STATUS.md`, and this plan agree.

---

## 6. Immediate next actions (proposed)

1. **Stabilize tests:** Fix the `mvm-backends` parallel PATH flake and confirm
   `cargo test --workspace` is green on macOS.
2. **Land ready PRs:** Start with #2412, #2414, #2411, #2415.
3. **Close screenshot-related issues:** Drive #2400, #2401, #2423 to closure.
4. **Begin README BDD gaps:** Pick the `--mount` example first (small, high user value).

Each action should be done in a fresh worktree under `.worktrees/`, with git operations
performed from the main checkout per `AGENTS.md`.
