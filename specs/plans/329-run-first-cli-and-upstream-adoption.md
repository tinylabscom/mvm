# Plan 329 — Run-first CLI ergonomics and upstream-sandbox adoption

**Status:** Active. Phase A landed the ADR-027 amendment, the verb visibility
triage, and `xtask check-cli-help-matches-docs`. Phase 1 landed the shared
argument core: `RunArgs` is declared once and flattened into both verbs.

**Bound by:** [ADR-027](../adrs/027-cli-surface-consolidation.md) (amended
2026-08-17),
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

## Corrections to this plan (2026-08-17)

Grounding the plan against the tree found four places where it was scoped
against something other than what is there.

1. **Phase 3 was largely already shipped when this plan was written.**
   `RunProfile` already carries all four presets — `restrictive` / `standard` /
   `dev` / `permissive` — at `crates/mvm-cli/src/commands/vm/exec.rs`, and
   `permissive` already gates on `MVM_ACK_PERMISSIVE_RUN=1`. What is actually
   missing is narrower: the two entry points disagree on the default
   (`machine run` defaults to `dev`, `run` to `standard`), and the effective
   profile is not surfaced in `mvmctl doctor`. Phase 3 is re-scoped to those.

2. **The two run surfaces diverged in both directions**, so Phase 1 is a merge,
   not a rename. `machine run` alone has `--net`, `--allow-host`,
   `--healthcheck` and its four companions, `--ttl`, `--stdin`, `--attach`,
   `--fresh`, `--reset`, `--from-workload-ir`, `--cpu-limit`, `--grants-file`.
   The formerly-hidden `run` alone has `--mode live|plan|record`, `--dev`,
   `--prod`, `--launch-plan`, `--ack-divergence`. This is the Phase 0
   capability-gap audit, and it is now done.

3. **Phase 2 must not invent a project config file.** One exists:
   `mvm.toml` / `Mvmfile.toml`, with a Cargo-style walk-up from the working
   directory that stops at a `.git` boundary
   (`mvm_core::domain::manifest::discover_manifest_from_dir`), and a
   `ManifestMachineWorkflow` table already carrying image, net, allow_hosts,
   cpus, and mem. It is simply not consulted by `machine run`, which errors
   when given no source flag. Wire the existing discovery in rather than
   adding a second config idiom.

4. **Phase 6 is blocked by a standing decision this plan did not acknowledge.**
   [ADR-002](../adrs/002-local-mcp-server.md) is **Withdrawn** — the server,
   its `mcp` Cargo feature, the `mvmctl ops mcp stdio` verb and the CI lane
   were deleted — and `xtask check-workflow-paths` enforces
   `removed_mcp_server_stays_out_of_ci`. Reviving MCP means superseding an ADR
   and deciding that gate's fate before any code is written.

## Phase A — CLI truth: ADR amendment, verb visibility, docs gate

Added 2026-08-17. Not in the original phase list, and a precondition for all of
it: the published CLI reference and `mvmctl --help` described different
products. The reference documented `mvmctl run` as the one-shot flagship and
`mvmctl secret` / `mvmctl trust` as the entry points to the substitution and
receipt subsystems; all three were `hide = true`. Eleven documented verbs were
invisible, and seven visible verbs had no reference row.

- [x] Amend ADR-027: `run` is a first-class transient verb; restate the
      hidden/visible split as three buckets (visible / dev tooling / internal
      `__` transports) with the cost of hiding made explicit.
- [x] Promote the user-facing verb groups out of `hide = true` — `run`, `env`,
      `manifest`, `image`, `catalog`, `cache`, `network`, `pool`, `secret`,
      `trust`, `bundle`, `artifact`, `deps`, `ops`, `shell-init` — grouped by
      `display_order`.
- [x] Keep `seccomp-audit`, `storage`, `reconcile`, `dashboard`,
      `persistent-builder` hidden as dev tooling, and the `__`-prefixed
      subprocess transports hidden as internal.
- [x] Add reference rows for the visible verbs that had none: `kernel`,
      `deploy`, `generate`, `template`, `prepare`, `explain`, `watch`, `pack`,
      `pool`, `bundle`, `artifact`, `deps`.
- [x] Add `xtask check-cli-help-matches-docs` — every documented verb is
      visible, every visible verb is documented — and register it in the Lint
      job. Mutation-checked red in both directions before being believed.
- [x] Fix the stale `--network-preset` references on live paths; the flag does
      not exist. The `mvmctl doctor` claim-10 failure string named it, and
      also cited ADR-002 for a claim that lives in ADR-001.

**Acceptance:** `mvmctl --help` and `cli-commands.md` agree, and a gate keeps
them agreeing.

### Phase 0 — Ratify the CLI decision

- [x] Draft an amendment to ADR-027 recording Option C. *(Phase A)*
- [ ] Review the amendment in the simplification worktree; confirm no claim
      conflict.
- [ ] Audit every in-repo reference to `mvmctl machine run` (tests, docs,
      SDKs, examples, BDD fixtures, scripts).
- [x] Verify that the hidden `mvmctl run` and `mvmctl machine run` were not
      diverging in capability; document any gaps that must close before
      removal. *(They had diverged in both directions — see Corrections 2.)*
- [ ] Update SDK subprocess calls to use the new canonical `mvmctl run` path.

**Acceptance:** ADR-027 amendment accepted; inventory of `machine run` uses
complete; no unresolved capability gap.

### Phase 1 — Consolidate the `run` argument surface

- [x] Merge the shared surface into a single `RunArgs` source of truth in
      `mvm-cli`, flattened into both verbs. **Deviation from the wording
      above, deliberate:** a literal single struct would give `mvmctl run`
      `--name`/`-d`/`--port`/`--ttl`/`--entrypoint` and make it a complete
      synonym for `machine run`, contradicting "flagship one-shot" in the
      decision record above and re-creating the second-name-for-one-operation
      that ADR-027 forbids. The 26 shared execution flags are declared once in
      `RunArgs`; `run` adds `SdkTransportArgs`, `machine run` adds the
      lifecycle flags.
- [ ] Ensure the consolidated args can drive both the direct execution path
      and the `mvm-client::MvmClient::run_machine` facade method.
- [x] Ensure `MachineAction::Run` and the top-level `Commands::Run` both consume
      the same consolidated `RunArgs` struct (flattened into each).
- [x] Promote `Commands::Run` from `hide = true` to a documented, ordered
      top-level subcommand while keeping `machine run` visible. *(Phase A)*
- [ ] Update clap completions generation to include the visible `run` surface.
- [x] Adjust tests and BDD fixtures that assumed `run` was hidden or that
      `machine run` had a divergent argument surface.

**Acceptance:** `cargo nextest run --workspace` and `cargo clippy --workspace
--all-targets -- -D warnings` green; `mvmctl run --help` and
`mvmctl machine run --help` both resolve and document the same consolidated
argument surface.

### Phase 2 — Runtime auto-detection

- [x] Define a small, auditable runtime catalog mapping command names and
      project files to OCI image refs. `mvm_core::runtime_catalog`, modelled on
      the existing `Catalog`/`CatalogEntry` — same `search`/`find` shape, same
      `schema_version`. In-tree, never fetched at runtime.
- [x] Implement detection order: explicit source, `--runtime`, `--no-detect`,
      `mvm.toml` walk-up, argv[0], project files, bundled default. **Reuses
      `mvm_core::domain::manifest::discover_manifest_from_dir`** rather than
      adding a second project-config idiom (Corrections 3).
- [x] Add `--no-detect` to force the default image; `--image` already overrode.
      Also `--runtime <name>` as the explicit selector.
- [ ] Add `--template` to pick a built-in template by name. *(Deferred to
      Phase 4, which is where templates are built.)*
- [x] Ensure auto-detected runs still produce a signed `ExecutionPlan` with
      default-deny egress. Detection settles a *source* and touches no policy
      field; witnessed by `a_detected_run_is_still_deny_all_and_standard_profile`
      and a BDD scenario asserting `profile: standard` / `network: deny-all`.
- [x] Add unit tests for each detection rule (12 in `mvm-core`, 12 in the CLI
      resolver) and BDD scenarios. Ordering and refusal rules mutation-checked
      red before being believed.

**Acceptance:** `mvmctl run python3 -c "print('ok')"` boots the right image
without a manifest; detection is deterministic and tested.

**Scope correction made while building it:** inference is `mvmctl run` only.
`machine run` creates a named, possibly persistent machine, and picking its base
image from the working directory is a footgun there — before the split,
`machine run` inside any Rust checkout silently chose `rust:1-alpine`. It keeps
its error naming every way to supply a source. `--runtime` works on both, since
that is the user naming one. The seam is one `Inference` enum passed to one
resolver, so the two verbs cannot drift apart on anything else.

### Phase 3 — Security profile presets

- [ ] Add `--profile {restrictive,standard,dev,permissive}` to `mvmctl run`.
- [x] Reconcile the default: both verbs now default to `standard`. `machine
      run` defaulted to `dev`, which on the persistent machine-spec path
      admitted a writable (`:rw`) host share without the user asking. It now
      refuses at spec time naming `--profile dev`, so the share fails closed
      and loudly rather than being silently downgraded to read-only.
- [ ] Surface the effective profile in execution receipts and `mvmctl doctor`.
- [x] Reject `--profile permissive` unless `MVM_ACK_PERMISSIVE_RUN=1` is set
      (already shipped before this plan — see Corrections 1).
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

- [x] Expose `mvmctl machine fork <parent> --as <child>` over the consolidated
      `VmBackend` seam.
- [x] Expose `mvmctl machine restore <checkpoint> --as <child>` with the
      admission-safe semantics from Plan 255.
- [x] Add `--branch` auto-naming for dev sandboxes.
- [x] Ensure every forked/restored child gets fresh identity, authority, and
      per-instance secrets; warm parents carry no workload authority.
- [x] Add positive and negative tests: fork succeeds, unauthorized parent reuse
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

- [x] Add a benchmark verb: `mvmctl bench`, a separate verb rather than a
      `doctor` flag — doctor reports posture without side effects, and this
      boots VMs. Cold start and warm claim are selectable lanes
      (`--lane prepared-cold|warm-claim|…`). **Density is not covered**; it is
      Plan 265 WS3 and needs a different harness.
- [x] Emit structured JSON output for CI and regression tracking — `--json`
      prints, and every run writes, the same versioned report the CI gate
      produces, so a user's report and a CI report are comparable artifacts.
- [x] Warm-start budgets were already defined and published (200/250/300 ms
      prepared-cold p50/p95/p99; 30/50 ms warm-claim p50/p99). `bench` now
      prints each measured percentile beside the budget judging it. Density
      SLOs remain undefined — Plan 265 WS3.
- [x] Published and gated already (the launch-budget page and the
      boot-latency lane). This adds the user-facing way to check a host
      against them.

**Acceptance:** `mvmctl bench --json` produces a versioned report against
documented budgets. Two deliberate refusals keep the numbers meaningful: a
debug build refuses to measure (its percentiles are the build profile's, not
the host's), and a run below 20 samples is labelled indicative rather than
publication-grade.

**Not done:** density. `mvmctl bench` measures latency only; Plan 265 WS3 and
Phase 4 own density and remain open.

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
