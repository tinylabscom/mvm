# Content-Addressed Asset Identity

Backing: shipped-source
Validation: check-sprint-append

**Date:** 2026-09-02
**Status:** In progress
**Branch:** `feat/asset-identity`
**Worktree:** `.worktrees/mvm-asset-identity`

## Pitch

Every asset bound to a run — dataset, model, prompt, agent, policy, and the
compute environment itself — gets a content-derived address that follows it.
The address is recorded in the signed `ExecutionPlan` and the chain-signed
audit log. Comparing addresses verifies identity; no database, no
investigation, no trust in mvm's local state.

## What already exists (no new work)

| Asset class | Existing identity |
|---|---|
| Compute environment | `SignedImageRef.sha256` + `environment` kernel pin + verity roothash |
| Agent (workload code) | `PlanArtifact.bundle_sha256` (content-addressed bundle) |
| App dependencies | `DepsVolumeBinding.volume_hash` + `manifest_sha256` (hash-locked, claim 11) |

## Gaps this plan closes

1. **Mounted assets (dataset/model)** — `HostShareGrant` records paths only;
   no content digest. No TOCTOU defense between admission and mount
   materialization either.
2. **Unmounted file assets (prompt, model weights served from host)** — no
   representation at all.
3. **Policy identity** — `network_policy` / `egress_policy` / `tool_policy` /
   `fs_policy` enter the plan as bare `PolicyRef` name strings; the resolved
   policy bytes are never hashed.
4. **No offline compare tool** — an external verifier cannot recompute the
   digest of an asset and compare it against what was admitted.

## Design constraints

- `ExecutionPlan` gains one new optional field `asset_identities`, serde
  default + skip-when-empty, so existing plans serialize byte-identically and
  the frozen `plan_id` replay vectors in `content_id.rs` stay valid
  (`xtask check-content-address-determinism` keeps passing).
- No new trust roots: identities ride the existing plan signature and the
  existing chain-signed audit log.
- Directory hashing reuses the same walk the materializer uses, so the
  recorded identity is exactly what the guest sees.

## Tasks

- [x] 1. Digest primitives: canonical tree hash (`compute_tree_digest`) in
  `mvm-build` next to the materialization walk; unit tests (empty dir, nested
  tree, symlink, streaming large file, determinism across runs).
- [x] 2. Contract types: `AssetKind` (Dataset | Model | Prompt | Agent |
  Policy | ComputeEnvironment | Other), `AssetIdentity { kind, name, digest }`,
  `asset_identities: Vec<AssetIdentity>` on `ExecutionPlan`; serde roundtrip +
  default-value tests. `HostShareGrant.content_sha256: Option<ContentDigest>`
  (skip-when-none).
- [x] 3. Admission: compute share digests at admission (`admit_plan_for_boot`
  params), re-verify at materialization (`mounts.rs`) — refuse on drift.
  Compute resolved `NetworkPolicy` + `EgressPolicy` digests. Populate
  `plan.asset_identities` (shares + `--asset` bindings + image + bundle +
  policies).
- [x] 4. Audit: emit `plan.asset_identities` chain-signed entry at admission
  with per-asset kind/name/digest labels; extend `trust audit verify` tests.
- [x] 5. CLI: `--asset <KIND>:<HOST_PATH>` on `machine run` (repeatable);
  `mvmctl trust asset id <path>` prints the canonical digest for offline
  comparison. CLI arg-parsing integration tests.
- [x] 6. Claim 19 in ADR-001 narrative + machine-checked ledger
  (`fn:` witnesses), claim doc under `specs/claims/`, BDD suite
  `features/suites/sNN_asset_identity/`.
- [x] 7. Gates: `cargo check --workspace`, `cargo test --workspace` (host),
  `just check-gated`, clippy workspace (builder VM) green.
- [x] 8. Sync `specs/SPRINT.md`; tick this plan's boxes as tasks land.

## As-built notes (2026-09-02)

Deltas from the task list above, recorded so the plan stays honest about
what shipped:

- The digest primitive is the pre-existing `mvm_fs::hash::hash_source`,
  not a new `compute_tree_digest` in `mvm-build` — reuse-first won; the
  tree walk, its symlink handling, and its unit vectors already existed.
- The contract field is `AssetIdentity { kind, locator, content_sha256 }`
  (not `name`/`digest`); `AssetKind` has the six classes without an
  `Other` variant — an exhaustive-match test forces a deliberate revisit
  if a seventh class is ever added. Digests are bare 64-hex, matching
  `hash_source` output and the deps-volume convention.
- Network/egress policy digests (task 3) were cut: the resolved policy is
  already inside the signed plan, so hashing it added a second encoding
  of the same bytes.
- Share digests and asset digests canonicalize the path before hashing so
  a symlink alias (macOS `/tmp`) yields the same identity; `hash_source`
  refuses a symlink root.
- No `specs/claims/` doc file: claims 16/17 reference docs that also do
  not exist in-tree, so claim 19 follows the same ledger-only pattern.
- The BDD suite is `s33_content_addressed_assets` (the next free number).

## Out of scope (stated, not implied)

- Prompts as runtime payloads over the input channel (preview claim 17) — not
  content-addressed here; a declared `--asset prompt:FILE` is the supported
  route for prompt identity.
- Model/dataset lineage *across runs* (which checkpoint became which
  deployment) — identity per run, not lifecycle lineage.
- Registering assets that live outside the run (external registries) — the
  address is computed from what was bound, nothing else.
