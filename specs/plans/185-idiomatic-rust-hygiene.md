# Plan 185 - Idiomatic Rust hygiene audit (Implementation Plan)

> **Numbering:** 185 is the next free plan number in this checkout after
> Plan 184 (`backend-descriptor-registry`).
> `check-spec-numbers` rejects duplicates - confirm still-free at merge time.

> **For agentic workers:** use `superpowers:subagent-driven-development`
> or `superpowers:executing-plans` for implementation. Steps use checkbox
> syntax (`- [ ]`) and must stay honest: do not tick a box until the code,
> tests, clippy, and docs for that step are green.

**Goal:** make the Rust codebase cleaner and more idiomatic by removing
recurring sharp edges that showed up during the trait/backend audit: ad hoc
process-global test environment mutation, inconsistent poisoned-lock behavior,
overly generic trait/type names, stringly typed backend/provider selectors, and
large functions that are hard to test directly.

This plan is deliberately incremental. It does not attempt a broad rewrite. Each
task must leave the workspace compiling, preserve behavior, and reduce one
specific class of friction.

**Non-goals:**

- Do **not** rewrite stable subsystem APIs only for style.
- Do **not** add abstraction without a second concrete use or an existing local
  pattern to follow.
- Do **not** replace capability data with traits. `VmCapabilities`,
  `SnapshotCapability`, and related security-profile data remain factual values
  returned by the backend behavior trait.
- Do **not** rename public CLI terms or manifest fields as part of Rust-internal
  cleanup.

---

## Guardrails (every task)

- Prefer small helper APIs over repeated local patterns.
- Prefer typed structs/enums/newtypes at module boundaries; keep raw strings at
  CLI/config parsing edges.
- Keep error handling explicit. Runtime code should return typed errors or
  contextual `anyhow` errors; tests may panic, but helper APIs should still make
  failures readable.
- Test support must not bloat production builds. Shared test helpers live behind
  `cfg(test)` and/or `mvm-core/test-support`.
- Per task: run the narrow tests for touched code and
  `cargo clippy -p <crate> --all-targets -- -D warnings`.
- Before closing the plan: `cargo test --workspace`, `cargo check --workspace`,
  and `cargo clippy --workspace --all-targets -- -D warnings` must be green in
  the required environment(s), or any host-specific blocker must be documented in
  this plan and the rollup.

---

## Phase 1 - Test environment hygiene

### Task 1 - Add one shared RAII env-var guard

**Files:** `crates/mvm-core/src/util/test_env.rs`,
`crates/mvm-core/src/util/mod.rs`,
`crates/mvm-core/src/crypto/keystore.rs`.

- [x] **Step 1 - add `TestEnv`.** Add `mvm_core::util::test_env::TestEnv`
      behind `cfg(any(test, feature = "test-support"))`. It serializes
      process-wide env mutation behind a mutex, saves the original value once,
      and restores all touched variables on drop.
- [x] **Step 2 - test the helper.** Cover restore-after-set,
      restore-after-remove, and repeated writes to the same variable.
- [x] **Step 3 - migrate a security-adjacent first consumer.** Replace direct
      `std::env::{set_var,remove_var}` calls in the `mvm-core` keystore tests
      with `TestEnv`.
- [x] **Step 4 - green.** Verified with:
      `cargo test -p mvm-core test_env`,
      `cargo test -p mvm-core keystore`,
      `cargo clippy -p mvm-core --all-targets -- -D warnings`.
- [ ] **Step 5 - commit.** `git commit -m "test(core): add shared env guard"`

### Task 2 - Roll `TestEnv` through high-risk env-mutating tests

**Files:** start from
`rg -n 'std::env::set_var|std::env::remove_var|env::set_var|env::remove_var' crates tests`.

Priority order:

1. tests that mutate `MVM_DATA_DIR`, `HOME`, `PATH`, or `XDG_*`,
2. tests in crates that already share a test binary with many modules
   (`mvm-cli`, `mvm-backend`, `mvm-build`),
3. lower-risk single-var parser tests.

- [ ] **Step 1 - enable `mvm-core/test-support` where needed.** Add the feature
      only to dev/test dependency surfaces that use `TestEnv`.
- [x] **Step 2 - migrate `mvm-backend::backend` env tests.** Replace manual
      `HOME`/`MVM_DATA_DIR` save-restore blocks in backend selector/marker tests
      with `TestEnv` and `tempfile::TempDir`, while temporarily retaining the
      legacy crate-local env lock so they still serialize with unmigrated tests.
      Verified with `cargo test -p mvm-backend backend` and
      `cargo clippy -p mvm-core -p mvm-backend --all-targets -- -D warnings`.
- [ ] **Step 3 - finish remaining `mvm-backend` env tests.** Migrate
      `apple_container`, `libkrun`, `base::runtime_meta`, and provider tests;
      then remove the legacy crate-local env lock if no callers remain.
- [ ] **Step 4 - migrate `mvm-cli` env tests.** Prioritize `doctor`,
      `bench_probe`, `audit_posture`, `volume`, and session tests.
- [ ] **Step 5 - migrate `mvm-build` env tests.** Prioritize builder selection,
      networking preference, cache path, and timeout/env parser tests.
- [ ] **Step 6 - leave justified exceptions explicit.** Runtime binaries that set
      env for child-process setup may keep direct env mutation, but tests should
      not.
- [ ] **Step 7 - green.** Run targeted crate tests after each batch and clippy for
      each touched crate.

---

## Phase 2 - Lock-poison and shared-state policy

### Task 3 - Standardize poisoned-lock handling

**Files:** start from
`rg -n 'expect\\(\".*poison|mutex poisoned|lock poisoned|unwrap_or_else\\(.*into_inner' crates tests`.

- [ ] **Step 1 - write the policy into this plan.** Runtime state locks return an
      error or fail closed when poisoning means state may be corrupt. Test/global
      serialization locks recover with `into_inner()` so one failed test does not
      poison the rest of the test binary.
- [ ] **Step 2 - add a tiny helper if it pays for itself.** If repeated recovery
      code remains noisy, add a focused helper for test locks rather than a broad
      mutex wrapper.
- [ ] **Step 3 - migrate known test/global locks.** Start with the env/test locks
      and helper-style mutexes discovered during Plan 182 and this plan.
- [ ] **Step 4 - keep runtime fail-closed paths explicit.** Do not blanket-recover
      locks that protect real runtime state such as worker pools, backend launch
      maps, or audit cursors unless the local invariant proves recovery is safe.
- [ ] **Step 5 - green.** Run targeted tests and clippy for each touched crate.

---

## Phase 3 - Naming and API clarity

### Task 4 - Rename overly generic internal traits/types where the blast radius is small

**Files:** initial candidates:
`crates/mvm/src/storage/backend.rs`,
`crates/mvm/src/vm/egress_proxy.rs`,
`crates/mvm-hostd/src/supervisor/egress.rs`.

- [ ] **Step 1 - classify names before editing.** Separate public/user-facing
      names from internal Rust names. Only internal names are candidates here.
- [ ] **Step 2 - rename `storage::Backend` if call sites stay manageable.**
      Candidate: `DeviceMapperBackend` or `ThinDeviceBackend`, depending on what
      the surrounding module actually models.
- [ ] **Step 3 - clarify the two `EgressProxy` traits without unifying them.**
      Candidate names should reflect layer ownership, for example runtime VM
      egress vs supervisor policy egress.
- [ ] **Step 4 - update docs/comments only where they reference Rust type names.**
      Do not churn user docs for internal-only renames.
- [ ] **Step 5 - green.** Run targeted tests and clippy for each touched crate.

### Task 5 - Push stringly selectors toward typed values at module boundaries

**Files:** start with backend/provider selector paths:
`crates/mvm-backend/src/catalog.rs`,
`crates/mvm-backend/src/backend.rs`,
`crates/mvm-network/src/registry.rs`,
`crates/mvm-storage/src/mount_provider.rs`.

- [ ] **Step 1 - keep strings at CLI/config edges.** Parsing raw user input stays
      close to Clap/config decoding.
- [ ] **Step 2 - use typed selectors internally.** Prefer `BackendKind` and
      descriptor APIs inside backend code; prefer provider-specific enums where
      network/storage mode is already structured.
- [ ] **Step 3 - avoid duplicate registries.** If a descriptor/registry already
      owns a selector table, reuse it instead of creating another string list.
- [ ] **Step 4 - green.** Run targeted tests and clippy for touched crates.

---

## Phase 4 - Function shape and construction patterns

### Task 6 - Audit long constructors and parameter lists

**Files:** start from clippy pressure and manual inspection of functions that
thread many related values through runtime/build/CLI layers.

- [ ] **Step 1 - prefer params structs over long argument lists.** Add a named
      struct when multiple call sites pass the same conceptual bundle.
- [ ] **Step 2 - prefer builders for multi-field optional construction.** Use a
      builder when construction mixes required and optional fields or when tests
      repeatedly create the same large fixture.
- [ ] **Step 3 - keep builders local.** Do not introduce a generic builder
      framework; use plain structs/impls matching local style.
- [ ] **Step 4 - green.** Add or update tests for any extracted construction
      logic and run clippy for touched crates.

### Task 7 - Split large functions only when the split buys tests or clarity

- [ ] **Step 1 - identify functions with mixed parsing, validation, side effects,
      and rendering.** CLI and build modules are the likely first pass.
- [ ] **Step 2 - extract pure validation/translation helpers first.** These get
      unit tests and reduce the need for broad integration-only coverage.
- [ ] **Step 3 - avoid churn-only splits.** Do not break a function apart if the
      resulting helpers are just reordered lines without clearer names or tests.
- [ ] **Step 4 - green.** Run targeted tests and clippy for touched crates.

---

## Phase 5 - Unsafe, platform, and feature boundaries

### Task 8 - Audit unsafe boundaries and platform-specific code

**Files:** start from
`rg -n 'unsafe \\{|unsafe fn|SAFETY:|cfg\\(|target_os|target_arch' crates`.

- [ ] **Step 1 - require local `SAFETY:` invariants.** Every `unsafe` block that
      remains must explain the concrete invariant that makes it sound. Generic
      comments such as "required by Rust 2024" are not enough unless they also
      state the synchronization or ownership guarantee.
- [ ] **Step 2 - isolate platform/FFI unsafe behind small safe wrappers.** VZ,
      libkrun, libc/syscall, and env-mutation code should expose narrow safe
      functions to the rest of the crate wherever practical.
- [ ] **Step 3 - keep platform cfgs narrow.** Linux/macOS-only behavior should be
      gated at the smallest useful module/function boundary, while host-side
      cargo builds continue to compile on non-target platforms.
- [ ] **Step 4 - green.** Run targeted tests for touched code and clippy for each
      touched crate.

### Task 9 - Audit feature and dependency boundaries

**Files:** crate `Cargo.toml` files plus feature-gated modules.

- [ ] **Step 1 - keep test helpers out of production builds.** Confirm
      `mvm-core/test-support` and any future test-support features are only used
      from tests/dev surfaces.
- [ ] **Step 2 - check optional heavy deps.** Ensure optional stacks such as
      schema generation, manifest verification, egress CA, platform bindings,
      and live-test helpers stay feature-gated or target-gated as intended.
- [ ] **Step 3 - avoid accidental workspace feature widening.** When a crate adds
      a workspace dependency, document why any extra features are needed and run
      a targeted `cargo tree -p <crate> -e features` check if the feature set is
      nontrivial.
- [ ] **Step 4 - green.** Run `cargo check -p <crate>` and clippy for touched
      crates; defer broad dependency-count work to Plan 126.

---

## Phase 6 - Error shapes, fixtures, and docs hygiene

### Task 10 - Standardize error shapes and error tests

**Files:** start from library modules that expose public errors and CLI/binary
edges that currently wrap them.

- [ ] **Step 1 - clarify `thiserror` vs `anyhow`.** Library/domain crates expose
      typed errors when callers can react programmatically; CLI and binary edges
      add `anyhow::Context` for operator-facing messages.
- [ ] **Step 2 - stop matching error strings in tests where typed errors exist.**
      Prefer enum variants, error kinds, or structured fields. Keep substring
      assertions only for final user-facing CLI text.
- [ ] **Step 3 - add context at process and filesystem boundaries.** File, socket,
      command, and config errors should include the path/operation without
      leaking secrets.
- [ ] **Step 4 - green.** Run targeted tests and clippy for touched crates.

### Task 11 - Consolidate repeated fixtures and builders

**Files:** initial candidates include tests constructing `ExecutionPlan`,
`FlakeRunConfig`, backend configs, admission inputs, and large CLI fixtures.

- [ ] **Step 1 - identify repeated fixture constructors.** Start with structs
      copied across three or more tests or crates.
- [ ] **Step 2 - move shared fixtures to the owning crate's test-support module.**
      Keep fixtures close to the type owner; expose cross-crate fixtures through
      explicit test-support features only when needed.
- [ ] **Step 3 - prefer fixture builders over partially valid literals.** Builders
      should produce valid defaults and make invalid-test mutations explicit.
- [ ] **Step 4 - green.** Add tests for fixture helpers if they carry logic, then
      run targeted tests and clippy.

### Task 12 - Audit secret/debug exposure

**Files:** start from
`rg -n 'derive\\(.*Debug|println!|eprintln!|tracing::|log::|format!' crates`
plus secret-bearing modules.

- [ ] **Step 1 - identify secret-bearing types.** Keys, tokens, signed secrets,
      tenant data, placeholder values, credential names, and redaction payloads
      must not expose raw values through `Debug`, `Display`, logs, or panic text.
- [ ] **Step 2 - use secrecy/zeroize wrappers consistently.** Prefer existing
      `secrecy` and `zeroize` patterns over local redaction wrappers unless the
      local type needs a domain-specific display.
- [ ] **Step 3 - add negative tests for secret formatting where practical.** Tests
      should prove debug/log-facing output redacts or omits raw secret material.
- [ ] **Step 4 - green.** Run targeted security/crypto/policy tests and clippy
      for touched crates.

### Task 13 - Add documentation verification to closeout

- [ ] **Step 1 - run doc generation after type renames.** Use
      `cargo doc --workspace --no-deps` or a narrower crate set if workspace docs
      hit a host/platform blocker.
- [ ] **Step 2 - fix broken intra-doc links introduced by renames.** Prefer real
      Rustdoc links for type names that are part of the public crate API.
- [ ] **Step 3 - document any doc-generation blocker.** If workspace docs cannot
      run on the host, record the exact crate and error in this plan and the
      rollup before closeout.

---

## Phase 7 - Closeout

### Task 14 - Final verification and index updates

- [ ] `cargo test --workspace` green.
- [ ] `cargo check --workspace` green.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` green in the
      required environment(s).
- [ ] `cargo doc --workspace --no-deps` green, or a documented host/platform
      blocker explains why a narrower doc command was used.
- [ ] `specs/SPRINT.md` reflects the plan and its real state.
- [ ] `specs/REFACTOR-STATUS.md` reflects the plan and its real state.
- [ ] Closeout note lists any intentionally deferred style debts with concrete
      reasons.
