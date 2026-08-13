# Plan 329 — Run-first CLI ergonomics and upstream-sandbox adoption

**Status:** Active — ratified. `mvmctl run` and `mvmctl machine run` are both
first-class commands sharing one consolidated implementation.

**Bound by:** [ADR-027](../adrs/027-cli-surface-consolidation.md) (to be amended),
[ADR-023](../adrs/023-secrets-subsystem-egress-substitution.md),
[ADR-025](../adrs/025-warm-snapshot-prior-art-adoption-boundary.md),
[Plan 255](255-vsock-first-snapshot-egress-adoption.md),
[Plan 298](298-warm-claim-service-and-hvf-pool.md).

**Adds no new numbered security claim.** It changes CLI presentation and adds
convenience surfaces; every workload still admits through a signed
`ExecutionPlan`, crosses the vsock seam, and emits chain-signed audit entries.

## Context

The upstream sandbox runtime surveyed in ADR-025 and Plan 255 has converged on
the same microVM thesis as mvm, but it ships a more polished day-to-day UX:
a single `run <command>` flagship, auto-detected language runtimes, simple
security presets, first-class templates, and agent-facing snapshot/fork
primitives. That project is useful inspiration for mvm's ergonomics, not its
assurance model.

Inside mvm, the CLI is in the middle of consolidation and simplification:

- `mvmctl machine` is the user-facing workload noun per ADR-027.
- `mvmctl run` exists but is **hidden** and retained only as an SDK transport.
- There are multiple, partially overlapping `run` argument structs in the tree
  (`vm::exec::Args`, `vm::exec::RunArgs`, `machine::MachineRunArgs`).
- The `mvm-client` facade migration (refactor/13-mvm-client-facade.md) is
  restructuring how lifecycle verbs reach the runtime.

This plan decides what to adopt from the upstream UX, what to refuse, and how
to resolve the `run` / `machine run` duplication without weakening mvm's
security posture.

## Decision record: the CLI shape

### Option A — Flatten everything to top-level verbs (remove `machine`)

`mvmctl run`, `mvmctl ls`, `mvmctl stop`, `mvmctl exec`, etc.

**Rejected.** mvm's surface is broader than "run a sandbox": `build`,
`deploy`, `kernel`, `template`, `trust`, `bundle`, and others already occupy
top-level verbs. A flat namespace would make `ls`, `stop`, `create`, and `exec`
ambiguous (stop a VM? a build? a pool?), and it would recreate the "wall of
verbs" problem ADR-027 was written to fix.

### Option B — Keep `machine` and add `run` as a hidden alias

`mvmctl run` dispatches to `mvmctl machine run`.

**Rejected as a hidden alias.** ADR-027's central invariant is "one object, one
noun; no second name for the same running VM." A hidden alias preserves the
duplication the consolidation exists to remove.

### Option C — `run` is a visible top-level command; `machine run` stays (selected)

- `mvmctl run python3 script.py` is the **flagship one-shot** command for users
  who want the lowest-friction path.
- `mvmctl machine run python3 script.py` remains the **noun-grouped** equivalent
  for users who prefer the `machine` lifecycle namespace.
- Both commands share **one consolidated argument struct and implementation**;
  they are not maintained as separate code paths.
- `mvmctl machine create/start/stop/exec/rm/ls/inspect/...` remain the
  management surface for persistent and advanced lifecycle operations.
- The internal SDK transport migrates from the hidden `run` to the visible
  `run`, or to `machine exec` for already-running machines.
- ADR-027 is amended to record that `run` is a first-class transient verb and
  `machine run` is its noun-grouped sibling.

**Rationale:** this gives users the low-friction `run <command>` pattern that
upstream sandboxes and tools like `docker run` have established, while keeping
the organized `machine` namespace and avoiding duplicate implementations.

## Objective

Deliver a `run`-first CLI that matches the upstream sandbox's ergonomic
flagship while keeping mvm's stronger assurance posture intact:

1. Consolidate the duplicate `run` surfaces under one canonical `mvmctl run`.
2. Add runtime auto-detection so `mvmctl run npm test` works without a manifest.
3. Add simple security-profile presets (`--profile`).
4. Make templates and OCI-image bases first-class.
5. Expose snapshot/fork as an agent-facing primitive, admission-safe.
6. Revive a scoped MCP / agent-plugin surface for dev-only use.
7. Add built-in benchmarking and publish warm-start/density SLOs.

## Invariants (non-negotiable)

1. **Vsock remains the sole guest↔host and egress boundary.** No guest-NIC
   default, no transparent TLS MITM inside the guest.
2. **One guest = one workload.** Warm parents are factories, not reused
   workloads.
3. **Guest sees no secrets.** Credential substitution stays host-side and
   destination-bound.
4. **Every run admits through a signed `ExecutionPlan`.** Convenience does not
   bypass admission or the chain-signed audit log.
5. **No interactive access to production microVMs.** SSH, console, and shell
   remain dev-only or absent in production.
6. **Container and wasm tiers stay opt-in and prod-refused.** No silent
   degradation to a weaker backend.

## Phases

### Phase 0 — Ratify the CLI decision

- [ ] Draft an amendment to ADR-027 recording Option C.
- [ ] Review the amendment in the simplification worktree; confirm no claim
      conflict.
- [x] Audit every in-repo reference to `mvmctl machine run` (tests, docs,
      SDKs, examples, BDD fixtures, scripts).
- [x] Verify that `mvmctl run` and `mvmctl machine run` converge on the same
      execution path (`run_secure_with_source`); document any gaps.
- [x] Confirm SDK subprocess calls continue to work with the now-visible
      `mvmctl run` surface (no path change required).

**Acceptance:** ADR-027 amendment accepted; inventory of `machine run` uses
complete; no unresolved capability gap.

### Phase 1 — Consolidate the `run` argument surface

- [x] Remove the legacy `vm::exec::Args` struct and fold its consumers onto
      `vm::exec::RunArgs`.
- [x] Promote `Commands::Run` from `hide = true` to a documented, ordered
      top-level subcommand while keeping `machine run` visible.
- [ ] Ensure `MachineAction::Run` and the top-level `Commands::Run` both consume
      the same consolidated `RunArgs` struct (currently `MachineRunArgs` converts
      into `RunArgs`; consider flattening the wrapper in a follow-up slice).
- [ ] Ensure the consolidated args can drive both the direct execution path
      and the `mvm-client::MvmClient::run_machine` facade method.
- [ ] Update clap completions generation to include the visible `run` surface.
- [x] Adjust tests that assumed `run` was hidden.

**Acceptance:** `cargo test -p mvm-cli --lib` and `cargo clippy -p mvm-cli
--all-targets -- -D warnings` green; `mvmctl run --help` and
`mvmctl machine run --help` both resolve and document the same execution path.

### Phase 2 — Runtime auto-detection

- [ ] Define a small, auditable runtime catalog mapping command names and
      project files to OCI image refs (e.g. `python3` / `requirements.txt` →
      `python:3.12-alpine`, `cargo` / `Cargo.toml` → `rust:1.85-alpine`).
- [ ] Implement detection order: explicit `--image`, then argv[0], then
      project files in the working directory, then the bundled default image.
- [ ] Add `--no-detect` to force the default image, and `--image` to override.
- [ ] Add `--template` to pick a built-in template by name.
- [ ] Ensure auto-detected runs still produce a signed `ExecutionPlan` with
      default-deny egress.
- [ ] Add unit tests for each detection rule and BDD scenarios for at least
      Python, Node, Rust, and Go.

**Acceptance:** `mvmctl run python3 -c "print('ok')"` boots the right image
without a manifest; detection is deterministic and tested.

### Phase 3 — Security profile presets

- [ ] Add `--profile {restrictive,standard,dev,permissive}` to `mvmctl run`.
- [ ] Map each preset unambiguously to existing policy flags (env passthrough,
      host mounts, network allowlist, seccomp posture).
- [ ] Surface the effective profile in execution receipts and `mvmctl doctor`.
- [ ] Reject `--profile permissive` unless `MVM_ACK_PERMISSIVE_RUN=1` is set,
      matching the current escape-hatch behavior.
- [ ] Add tests for preset-to-policy mapping and receipt contents.

**Acceptance:** Presets work, are documented, and do not create new privileged
paths beyond the existing policy vocabulary.

### Phase 4 — Templates and OCI-image bases

- [ ] Implement `mvmctl template build --image <ref>` as a first-class path,
      alongside the existing Nix-flake path.
- [ ] Add built-in language templates (python, node, rust, go, ruby, java,
      shell, data-science, web-dev) backed by pinned OCI refs.
- [ ] Allow saving a running dev-tier sandbox as a custom template.
- [ ] Integrate templates with the snapshot-first storage from Plan 255.
- [ ] Add BDD scenarios for template build, save, and reuse.

**Acceptance:** A user can `mvmctl template build --image python:3.12-alpine`
and then `mvmctl run --template python <script>`.

### Phase 5 — Snapshot/fork DX

- [ ] Expose `mvmctl machine fork <parent> --as <child>` over the consolidated
      `VmBackend` seam.
- [ ] Expose `mvmctl machine restore <checkpoint> --as <child>` with the
      admission-safe semantics from Plan 255.
- [ ] Add `--branch` auto-naming for dev sandboxes.
- [ ] Ensure every forked/restored child gets fresh identity, authority, and
      per-instance secrets; warm parents carry no workload authority.
- [ ] Add positive and negative tests: fork succeeds, unauthorized parent reuse
      fails closed.

**Acceptance:** Fork and restore are agent-usable primitives that do not bypass
admission.

### Phase 6 — Agent integration (MCP / plugins)

- [ ] Revive a thin MCP server surface, scoped to **dev-only** sandbox
      execution (production workloads remain admission-only and non-interactive).
- [ ] Add `mvmctl plugin install {claude,codex,gemini,opencode,mcp}` that emits
      the minimal config/skill files each agent needs.
- [ ] Expose a small tool set: `run_command`, `create_sandbox`, `exec_in_sandbox`,
      `list_sandboxes`, `stop_sandbox`.
- [ ] Add BDD scenarios for agent tool use and receipt verification.

**Acceptance:** Claude Code can `/sandbox python3 script.py` and the call is
audited like any other run.

### Phase 7 — Observability and performance

- [ ] Add `mvmctl doctor --benchmark` (or a new `mvmctl benchmark` verb) that
      measures cold start, warm claim, and density on the current host.
- [ ] Emit structured JSON output for CI and regression tracking.
- [ ] Define warm-start and density SLOs once Plan 298/Plan 255 measurements
      are stable.
- [ ] Publish the SLOs in the docs and add a CI gate that fails on regression.

**Acceptance:** `mvmctl doctor --benchmark --json` produces reproducible numbers;
SLOs are documented.

### Phase 8 — Distribution polish

- [ ] Generate shell completions (`mvmctl completions bash/zsh/fish`).
- [ ] Improve `install.sh` to bootstrap a non-Nix host enough to run the
      dev-tier Docker backend and the `run` command.
- [ ] Evaluate a Homebrew tap for macOS users who do not use Nix.

**Acceptance:** Completions generate without errors; install script improvements
are tested on a clean macOS and Linux CI runner.

## What this plan refuses

These upstream ideas are explicitly out of scope because they conflict with mvm
invariants:

- **Guest NIC + eBPF/L7 MITM proxy** — moves enforcement off the vsock seam.
- **Transparent TLS MITM inside the guest** — changes the guest trust model.
- **Reusing dirty guests across workloads** — violates one-guest-one-workload.
- **Mutable shared store as control-plane authority** — undermines signed-plan
  admission.
- **SSH into production microVMs** — conflicts with the no-interactive-prod
  posture.
- **Container runtime / `containerd` shim on the runtime path** — mvm consumes
  OCI images, not OCI runtimes.
- **Wasm backend as a production isolation tier** — remains claim-free and
  opt-in per ADR-024.

## Dependencies and ordering

```text
Phase 0 (ADR amendment)
    │
    ▼
Phase 1 (consolidate run args)
    │
    ├──► Phase 2 (auto-detection)
    │
    ├──► Phase 3 (profile presets)
    │
    ├──► Phase 4 (templates / OCI)
    │
    ├──► Phase 5 (snapshot/fork DX)
    │
    ├──► Phase 6 (agent integration)
    │
    ├──► Phase 7 (benchmark / SLOs)
    │
    └──► Phase 8 (distribution polish)
```

Phases 2–8 are independent after Phase 1 lands. They may be parallelized across
worktrees once the canonical `run` surface is stable.

## Definition of done

- `mvmctl run <command>` is the documented flagship for one-shot execution.
- `mvmctl run` is visible and documented; `mvmctl machine run` remains visible.
- Every auto-detected or templated run still produces a signed `ExecutionPlan`
  and chain-signed audit entries.
- `cargo nextest run --workspace`, `cargo clippy --workspace --all-targets --
  -D warnings`, and `cargo fmt --all --check` are green.
- All new surfaces have unit or BDD tests covering happy path, error path, and
  at least one negative security path.
- SLOs are published and benchmarked.
- ADR-027 is amended and the plan's checkboxes are up to date.
