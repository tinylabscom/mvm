# Plan 182 — Trait hygiene and backend catalog consolidation (Implementation Plan)

> **Numbering:** 182 is the next free plan number in this checkout
> (`specs/plans/` currently runs through 181). `check-spec-numbers`
> rejects duplicates — confirm still-free at merge time.

> **For agentic workers:** use `superpowers:subagent-driven-development`
> or `superpowers:executing-plans` for implementation. Steps use checkbox
> syntax (`- [ ]`) and must stay honest: do not tick a box until the code,
> tests, clippy, and docs for that step are green.

**Goal:** tighten the project's trait seams where duplication has already
appeared, and reduce backend-dispatch duplication without destabilizing the
runtime surface. Concretely, this plan lands:

1. one shared wall-clock trait instead of three local `Clock` copies,
2. one canonical `KeyProvider` trait instead of the current duplicate core/runtime
   definitions,
3. one source of truth for backend metadata consumed by `AnyBackend` and
   `mvmctl doctor`,
4. one targeted macro family (`backend_catalog!`) that removes repetitive
   backend selector boilerplate without hiding backend behavior behind heavy
   macro indirection.

**Why now:** the codebase already uses traits heavily at the real seams
(`VmBackend`, `BuilderVm`, `NetworkProvider`, `VolumeBackend`,
`BackendLauncher`, `ServiceHandler`), but there are still a few places where
the abstraction story is drifting:

- three copy-pasted `Clock` traits with identical `now()` contracts,
- two `KeyProvider` traits with the same method and overlapping impl intent,
- hand-maintained backend-name arrays in `mvm-cli doctor`,
- a hand-maintained `AnyBackend` switchboard that duplicates backend names,
  aliases, marker files, tiers, and test vectors in one file.

This is small enough to fix now and large enough that leaving it alone will
keep generating drift.

**Non-goals:**

- Do **not** replace `AnyBackend` with a fully dynamic plugin registry in this
  plan. Keep the public enum and the current backend-selection behavior.
- Do **not** add broad macros for "all trait impls". Only macroize the backend
  metadata table, where the duplication is structural and stable.
- Do **not** change backend priority, security-tier classification, marker-file
  names, or warm-start semantics as part of cleanup. Those are behavior changes
  and require their own plan.

---

## Guardrails (every task)

- Preserve the existing `VmBackend` trait contract in
  `crates/mvm-core/src/protocol/vm_backend.rs`. Backends stay trait impls; this
  plan is about metadata drift and duplicate micro-traits, not removing the
  backend seam.
- Shared traits that belong in `mvm-core` must remain runtime-light. Do not
  introduce `tokio`, `async-trait`, or backend/runtime deps into `mvm-core` to
  support these cleanups.
- Macro use must stay narrow and transparent. A reader opening the generated
  code should still be able to explain backend behavior from one file without
  spelunking through layered macro DSLs.
- `mvmctl doctor` and `AnyBackend` must read backend names from the same source
  after this plan. No second hand-maintained list survives.
- If a compatibility shim is temporarily needed (for example a re-export while
  callers migrate), it must be zero-behavior: no second implementation, no
  duplicated tests, no diverging default-provider logic.
- Per task: `cargo clippy -p <crate> --all-targets -- -D warnings` clean.
- Before closing the plan: `cargo test --workspace`, `cargo check --workspace`,
  and docs updates must be green/current per the repo Definition of Done.

---

## File Structure

New:

- `crates/mvm-backend/src/catalog.rs`

Primary edits:

- `crates/mvm-core/src/util/time.rs`
- `crates/mvm-hostd/src/supervisor/aggregate.rs`
- `crates/mvm-hostd/src/supervisor/circuit_breaker.rs`
- `crates/mvm-cli/src/commands/vm/plan_admission.rs`
- `crates/mvm-core/src/crypto/keystore.rs`
- `crates/mvm/src/security/keystore.rs`
- `crates/mvm/src/vm/instance/lifecycle.rs`
- `crates/mvm/src/vm/instance_snapshot.rs`
- `crates/mvm-backend/src/backend.rs`
- `crates/mvm-backend/src/lib.rs`
- `crates/mvm-cli/src/doctor.rs`
- `public/src/content/docs/reference/architecture.md`

---

## Phase 1 — Shared micro-traits (start here)

### Task 1 — Introduce a single shared wall-clock trait in `mvm-core`

**Files:** `crates/mvm-core/src/util/time.rs`;
edit `crates/mvm-core/src/lib.rs`,
`crates/mvm-hostd/src/supervisor/aggregate.rs`,
`crates/mvm-hostd/src/supervisor/circuit_breaker.rs`,
`crates/mvm-cli/src/commands/vm/plan_admission.rs`.

- [x] **Step 1 — add the canonical trait.** Create `mvm_core::time::{Clock, SystemClock}`
      with the current shared contract: `fn now(&self) -> chrono::DateTime<Utc>`.
      Keep it sync, object-safe, and dependency-light.
- [x] **Step 2 — migrate the three local copies.** Delete the local `Clock`/`SystemClock`
      definitions in `aggregate.rs`, `circuit_breaker.rs`, and `plan_admission.rs`,
      replacing them with imports from `mvm_core::time`.
- [x] **Step 3 — preserve determinism tests.** Keep every existing fixed-clock test
      pattern intact by swapping only the trait path, not the injected fake-clock
      shape.
- [x] **Step 4 — green.** Run targeted verification:
      `cargo test -p mvm-hostd circuit_breaker`,
      `cargo test -p mvm-hostd aggregate`,
      `cargo test -p mvm-cli plan_admission`,
      then `cargo clippy -p mvm-core -p mvm-hostd -p mvm-cli --all-targets -- -D warnings`.
- [ ] **Step 5 — commit.** `git commit -m "refactor(core): share Clock trait via mvm_core::time"`

### Task 2 — Unify `KeyProvider` on the core definition

**Files:** `crates/mvm-core/src/crypto/keystore.rs`,
`crates/mvm/src/security/keystore.rs`,
`crates/mvm/src/vm/instance/lifecycle.rs`,
`crates/mvm/src/vm/instance_snapshot.rs`,
any remaining callers from `rg -n 'security::keystore|default_provider\\('`.

- [x] **Step 1 — choose the canonical owner.** Keep
      `mvm_core::crypto::keystore::KeyProvider` as the single real trait and the
      single real set of provider implementations. It already has stricter input
      validation and richer backend selection logic than the duplicate runtime copy.
- [x] **Step 2 — migrate runtime callers.** Update `mvm` call sites to import/use
      `mvm_core::crypto::keystore::{KeyProvider, default_provider, ...}` directly.
- [x] **Step 3 — retire the duplicate implementation.** Replace
      `crates/mvm/src/security/keystore.rs` with either:
      1. a pure re-export shim if the path is still externally consumed in-tree, or
      2. delete the module entirely if no callers remain.
      The end state must have one implementation, not two copies that happen to match.
- [x] **Step 4 — green.** Run the keystore-focused tests in the owning crate
      (`cargo test -p mvm-core keystore`) plus any runtime tests that still
      exercise snapshot/lifecycle key loading, then
      `cargo clippy -p mvm-core -p mvm --all-targets -- -D warnings`.
- [ ] **Step 5 — commit.** `git commit -m "refactor(crypto): unify KeyProvider on mvm_core"`

### Task 3 — Document the trait ownership rules

**Files:** `public/src/content/docs/reference/architecture.md`

- [x] **Step 1 — update the “Key Abstractions” section.** Add the actual trait
      seams now in use: `VmBackend`, `BuilderVm`, `VmBackendForBuilder`,
      `BackendLauncher`, `NetworkProvider`, `VolumeBackend`, `ServiceHandler`,
      `SecretStore`, `KeyProvider`.
- [x] **Step 2 — state the ownership rule plainly.** Document that reusable,
      runtime-light seams live in `mvm-core`; backend/runtime-specific seam
      traits stay in the owning crate (`mvm-backend`, `mvm-build`, `mvm-hostd`,
      `mvm-storage`, `mvm-network`).
- [x] **Step 3 — correct drift.** Remove or rewrite any Lima-era wording that
      conflicts with the current builder-VM requirement while touching the
      trait-abstraction section.
- [ ] **Step 4 — commit.** `git commit -m "docs(architecture): document canonical trait seams"`

---

## Phase 2 — Backend metadata single source of truth

### Task 4 — Freeze current backend behavior with selector tests

**Files:** `crates/mvm-backend/src/backend.rs`, `crates/mvm-cli/src/doctor.rs`

- [x] **Step 1 — encode the current matrix.** Add/expand tests that assert the
      existing canonical names, aliases, tiers, and marker-file ownership for:
      firecracker, apple-container, libkrun, vz, qemu, mock.
- [x] **Step 2 — encode doctor parity.** Add a test that the backend names shown
      by `doctor`’s balloon and warm-start support collectors are sourced from the
      same backend set and stay in stable order.
- [ ] **Step 3 — run red first.** Make the tests fail against any stale
      hand-maintained list before introducing the catalog abstraction.
- [x] **Step 4 — green baseline.** `cargo test -p mvm-backend backend`,
      `cargo test -p mvm-cli doctor`,
      `cargo clippy -p mvm-backend -p mvm-cli --all-targets -- -D warnings`.

### Task 5 — Add a catalog macro for backend metadata

**Files:** new `crates/mvm-backend/src/catalog.rs`;
edit `crates/mvm-backend/src/lib.rs` and `crates/mvm-backend/src/backend.rs`.

- [x] **Step 1 — introduce one macro family only.** Add `macro_rules! backend_catalog`
      that declares each backend exactly once with:
      enum variant, constructor, canonical name, accepted aliases, security tier,
      marker filename, and whether the backend participates in `list_all`.
- [x] **Step 2 — generate the repetitive selectors.** Use the catalog macro to
      generate:
      `AnyBackend::from_hypervisor`,
      `AnyBackend::for_started_vm`,
      `AnyBackend::tier`,
      `AnyBackend::inner`,
      and the exported catalog iteration helper used by the CLI.
- [x] **Step 3 — keep `auto_select` handwritten.** Platform-priority logic stays
      explicit in `auto_select()` because it is behavioral policy, not mere metadata.
- [x] **Step 4 — no behavior drift.** The public `AnyBackend` enum remains intact,
      constructors keep returning the same concrete backends, and marker-file names
      do not change.
- [x] **Step 5 — green.** `cargo test -p mvm-backend`,
      `cargo clippy -p mvm-backend --all-targets -- -D warnings`.
- [ ] **Step 6 — commit.** `git commit -m "refactor(backend): centralize backend metadata catalog"`

### Task 6 — Make `mvmctl doctor` consume the backend catalog

**Files:** `crates/mvm-cli/src/doctor.rs`; any needed export in `crates/mvm-backend/src/lib.rs`

- [x] **Step 1 — remove hand-maintained name arrays.** Replace the local
      `["firecracker", "apple-container", "libkrun", "qemu"]` /
      `["firecracker", "apple-container", "libkrun", "qemu", "vz"]` arrays with an
      iterator or slice exported from `mvm-backend`.
- [x] **Step 2 — keep intentional filtering explicit.** If doctor should show a
      subset for a given section, make that filtering a field in the catalog or a
      named helper, not another ad hoc string list in the CLI.
- [x] **Step 3 — verify exact output.** Update the relevant doctor tests so the
      visible backend ordering and names stay stable after the refactor.
- [x] **Step 4 — green.** `cargo test -p mvm-cli doctor`,
      `cargo clippy -p mvm-cli -p mvm-backend --all-targets -- -D warnings`.
- [ ] **Step 5 — commit.** `git commit -m "refactor(doctor): source backend support maps from backend catalog"`

---

## Phase 3 — Closeout and macro boundary

### Task 7 — Explicitly reject the wrong macros

**Files:** `specs/plans/182-trait-hygiene-and-backend-catalog.md` (closeout notes)

- [x] **Step 1 — record the decision.** In the closeout commit, note that this plan
      intentionally does **not** add a generic trait-impl macro for the hostd
      `Noop*` types or a blanket forwarding macro for every `AnyBackend` method.
- [x] **Step 2 — justify it concretely.** The reason must be explicit:
      those families vary in method signatures and policy enough that a macro would
      compress syntax while obscuring behavior; the backend catalog is the one place
      where the duplication is truly declarative.
- [x] **Step 3 — keep the catalog macro narrow.** Confirm only one new macro family
      landed as part of this plan.

**Closeout note:** this plan intentionally stops at `backend_catalog!`. It does
not introduce a generic hostd `Noop*` trait-impl macro or a blanket forwarding
macro for every `AnyBackend` method. Those families differ enough in method
signatures, ownership, and policy that a macro would save a little syntax while
making the behavior harder to audit. The backend catalog is the one place where
the duplication is truly declarative, so it is the one place macro generation
improves the design instead of obscuring it.

### Task 8 — Final verification and index updates

- [ ] `cargo test --workspace` green.
- [x] `cargo check --workspace` green.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` green in the required environment(s).
- [x] `public/src/content/docs/reference/architecture.md` matches the code.
- [x] `specs/SPRINT.md` notes the plan addition and, when implementation begins,
      reflects its current state accurately.
- [x] `specs/REFACTOR-STATUS.md` is updated in the same change when the plan moves
      from not-started to active and again when it lands.

**Verification note:** on this host, the literal aggregate `cargo test --workspace`
reaches `mvm-backend` and then the `mvm_backend` unit-test binary is terminated by
`SIGKILL` even with `-- --test-threads=1`. The same package passes under
`cargo test -p mvm-backend`, and `cargo test -p mvm`, `cargo test -p mvm-cli doctor`,
and `cargo test -p mvm-backend backend` are green. Treat the remaining unchecked
workspace-test box as an execution-environment/resource issue, not a known assertion
failure in Plan 182's code.

---

## Success criteria

- [x] There is exactly one shared `Clock` trait in the workspace.
- [x] There is exactly one real `KeyProvider` trait implementation surface.
- [x] `AnyBackend` backend names, aliases, tiers, and marker files are declared in
      one place.
- [x] `mvmctl doctor` does not carry its own backend-name lists.
- [x] Only one new macro family lands, and it is the backend catalog generator.
- [x] No runtime/backend behavior changes were introduced under the guise of cleanup.

## Deferred follow-ups

- [ ] A future plan may replace `AnyBackend`’s remaining explicit `auto_select`
      policy with a richer registry object if the project ever needs dynamically
      installed backends. That is intentionally out of scope here.
- [ ] If more duplicate micro-traits appear after this cleanup, audit them against
      the Phase 1 ownership rule before introducing any new shared abstractions.
