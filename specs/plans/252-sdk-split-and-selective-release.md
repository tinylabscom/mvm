# Plan 252 — SDK crate split and selective SDK release

**Status:** Complete (2026-07-13; single-CLI SDK split and release lane landed)

## Goal

Stop routine `mvmctl` and workspace builds from compiling the heavy SDK
authoring stack, while preserving a production-quality SDK release path for
external users. The end state is:

- runtime/build crates depend only on small shared crates, not on `mvm-sdk`;
- the Python SDK (`mvm`), TypeScript SDK (`@runmvm/mvm`), and the ordinary
  `mvmctl` release are published on an explicit SDK release cadence;
- SDK publication is explicit and decoupled from ordinary runtime releases.

## Why this plan exists

The repo already avoids building every workspace member by default, but the
default `mvmctl` build still pulls `crates/mvm-sdk` transitively. Today that
happens because `mvm-sdk` mixes three different responsibilities in one crate:

1. canonical workload IR types used by runtime/build crates;
2. sealed-volume audit helpers used by `mvm-build`, `mvm-hostd`, and CLI deps
   verbs;
3. heavy authoring machinery: tree-sitter decorator parsing, compile
   orchestration, runtime-record lowering, schema emitters, and Rust SDK
   builders.

That shape means a normal `cargo build` of `mvmctl` drags in the same
authoring-only dependencies that the publishable SDK uses. It also leaves the
release automation in an inconsistent state: the workspace/toolchain is `0.18.0`
while both external SDK packages are currently `0.15.1`, so the existing
release-triggered publish workflows cannot be the production release contract.

## Product decisions

These decisions are part of the plan, not follow-up bikeshedding:

1. **Split by responsibility, not by language.**
   The external Python and TypeScript SDKs stay where they are. The Rust-side
   work is to restore small shared crates for runtime/build consumers and keep
   `mvm-sdk` as the authoring crate.

2. **Keep one CLI for now.**
   The shared Rust crates should be separated by responsibility, but the
   user-facing CLI stays `mvmctl`. We are not taking on a second artifact,
   feature-gated command surface, or separate support matrix unless the
   remaining build graph becomes a real operational problem.

3. **Decouple SDK release cadence from ordinary toolchain releases.**
   Runtime releases continue to use the existing `vX.Y.Z` cadence. SDK releases
   use a dedicated `sdk-vX.Y.Z` release/tag and publish only when that release
   is cut.

4. **Keep one version across the SDK release set.**
   For a given SDK release, the Python package and the TypeScript package carry
   the same version and are released together, with `mvmctl` remaining the host
   CLI they shell to.

5. **Do not publish from implicit repo state.**
   The SDK release workflows must read a checked-in release manifest, perform
   dry-run packaging, and refuse partial or mismatched publishes before touching
   PyPI, npm, or GitHub release assets.

## Architecture

### A. New crate boundaries

- `crates/mvm-ir`
  - owns canonical workload IR types, validation, canonicalization, hashing,
    version helpers, and helpers such as `host_matches`;
  - is the only IR dependency for runtime/build crates.

- `crates/mvm-deps-audit`
  - owns sealed-volume primitives now living in
    `mvm_sdk::compile::deps_audit`;
  - is the shared dependency for `mvm-build`, `mvm-hostd`, and CLI deps verbs.

- `crates/mvm-sdk`
  - remains the Rust authoring SDK;
  - depends on `mvm-ir` and `mvm-deps-audit`;
  - keeps builders, compile orchestration, decorator parsing,
    runtime-record lowering, machine wrappers, and schema emitters.

### B. CLI stance

- `mvmctl` remains the single CLI surface for both runtime/operator and SDK
  authoring flows.
- We may still rewire obvious IR-only call sites from `mvm_sdk::ir` to
  `mvm-ir`, but we are not introducing `sdk-tools`, `mvm-sdkctl`, or
  feature-gated command disappearance in this plan.

### C. Release model

- Add `sdks/release.toml` as the single checked-in source of truth for:
  - SDK release version;
  - Python package path/name;
  - TypeScript package path/name;
  - supported CLI binary name resolution order.
- Runtime releases (`vX.Y.Z`) keep using `.github/workflows/release.yml`.
- SDK releases (`sdk-vX.Y.Z`) use a dedicated workflow that:
  - validates `sdks/release.toml`;
  - publishes the Python and npm packages;
  - verifies the published artifacts.

## Phases

### Phase 0 — Lock the SDK release contract

- [x] Add `sdks/release.toml` and move the current package-version checks to
      that manifest.
- [x] Specify the SDK binary resolution contract in the Python and TypeScript
      SDKs: `MVM_CLI_BIN` override first, then `mvmctl`, with an actionable
      missing-CLI error.
- [x] Add a checked-in compatibility note explaining that published SDK
      packages shell to `mvmctl`, while source-checkout users can still point
      `MVM_CLI_BIN` at a locally built binary.
- [x] Add a regression gate proving the current mismatch is intentional until
      this plan lands: runtime release workflows must not try to publish SDKs
      from the `0.18.x` toolchain release stream.

**Acceptance gate:** no runtime release job attempts PyPI/npm publication, and
an SDK dry-run can validate package versions without reading `Cargo.toml`.

### Phase 1 — Extract `mvm-ir`

- [x] Create `crates/mvm-ir` and move the canonical IR modules out of
      `crates/mvm-sdk/src/ir/`.
- [x] Finish migrating the remaining obvious IR-only consumers to `mvm-ir`:
  - [x] `mvm-network`
  - [x] `mvm-storage`
  - [x] `mvm`
  - [x] `mvm-hostd`
  - [x] `mvm-cli` IR-only call sites
- [x] Keep `mvm-sdk` re-exporting the IR so the Rust SDK public surface does
      not break.
- [x] Add a dependency guard test proving `mvm-network`, `mvm-storage`,
      `mvm-hostd`, and `mvm` no longer depend on `mvm-sdk`.

**Acceptance gate:** IR-only runtime/build crates no longer reach `mvm-sdk`.

### Phase 2 — Extract `mvm-deps-audit`

- [x] Create `crates/mvm-deps-audit` and move the sealed-volume primitives out
      of `mvm_sdk::compile::deps_audit`.
- [x] Repoint `mvm-build`, `mvm-hostd`, and the CLI deps verbs to
      `mvm-deps-audit`.
- [x] Leave `mvm-sdk` re-exporting these APIs for source compatibility where
      appropriate.
- [x] Add tamper-detection and round-trip tests at the new crate boundary so
      the move is not a pure file shuffle.

**Acceptance gate:** `mvm-build` and `mvm-hostd` no longer depend on
`mvm-sdk` only to verify or seal dependency volumes.

### Phase 3 — Single-CLI cleanup

- [x] Finish re-pointing obvious IR-only `mvm-cli` call sites to `mvm-ir`.
- [x] Keep `build compile`, runtime-record helpers, and `run --mode plan`
      on the existing `mvmctl` surface.
- [x] Add dependency-guard checks for the crates that should stay off
      `mvm-sdk` even though `mvm-cli` still uses it.

**Acceptance gate:** the one-CLI product surface stays intact while the
shared runtime/build crates remain decoupled from `mvm-sdk`.

### Phase 4 — Production SDK release automation

- [x] Replace the current release-coupled SDK publish path with a dedicated
      `.github/workflows/publish-sdk.yml`.
- [x] Retain `publish-pypi.yml` and `publish-npm.yml` only as reusable
      `workflow_call` jobs or fold them into the new orchestrator.
- [x] Trigger SDK publication from:
  - `release: published` for `sdk-vX.Y.Z`;
  - `workflow_dispatch` dry-run for rehearsals.
- [x] Add preflight registry checks:
  - refuse if the version already exists on PyPI or npm;
  - refuse if `sdks/release.toml` disagrees with package metadata;
- [x] Add post-publish smoke checks:
  - install the built Python artifact in a clean env and import it;
  - `npm pack` and smoke the built TypeScript package.

**Acceptance gate:** SDK publication is explicit, dry-runnable, provenance-aware,
and can succeed or fail independently of the ordinary runtime release flow.

### Phase 5 — CI, docs, and operational closeout

- [x] Add CI lanes for:
  - shared runtime/build crate graph checks without `mvm-sdk`;
  - SDK release dry-run workflow.
- [x] Update `specs/runbooks/publish-sdks.md` for the new `sdk-vX.Y.Z` release
      flow, manifest, rehearsals, and rollback expectations.
- [x] Update contributor docs to explain the single-CLI contract for published
      SDKs and source-checkout development against local binaries.
- [x] Update any stale workflow comments and release notes that still claim the
      SDK must ship on every toolchain release.

**Acceptance gate:** the repo documents one supported way to ship SDKs, and CI
protects both the lean runtime build and the explicit SDK release lane.

## Verification gates

No phase closes without these being green for the touched surface:

- `cargo fmt --all -- --check`
- `cargo check --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- dry-run SDK publication via the dedicated workflow

Additional mandatory graph checks:

- `cargo tree -p mvm-network -e normal` and `cargo tree -p mvm-hostd -e normal`
  must not include `mvm-sdk` after Phases 1 and 2.

## Risks

- The shared crate splits reduce unnecessary transitive coupling, but `mvm-cli`
  still depends on `mvm-sdk`, so the main binary does not yet get the full
  build-closure win.
- The Python and TypeScript SDKs shell to the ordinary `mvmctl`, so release and
  docs drift around that single-CLI contract must stay tightly tested.
- PyPI is immutable per version. The new workflow must do all version and
  packaging checks before the publish step.
- Re-exporting `mvm-ir` and `mvm-deps-audit` from `mvm-sdk` reduces churn, but
  it also creates a temporary dual-path API surface that must be documented and
  eventually simplified.

## Non-goals

- Rewriting the external Python or TypeScript SDKs into a different packaging
  model.
- Reworking the machine facade, runtime transport, or SDK language surface
  beyond what is needed to keep published packages aligned with `mvmctl`.
- Changing the public package names on PyPI or npm.
