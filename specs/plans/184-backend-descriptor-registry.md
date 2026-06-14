# Plan 184 — Backend descriptor registry (Implementation Plan)

> **Numbering:** 184 is the next free plan number in this checkout after
> syncing `origin/main`, where 183 is already used by
> `183-builder-vm-egress-posture-and-dns.md`.
> `check-spec-numbers` rejects duplicates — confirm still-free at merge time.

> **For agentic workers:** use `superpowers:subagent-driven-development`
> or `superpowers:executing-plans` for implementation. Steps use checkbox
> syntax (`- [x]`) and must stay honest: do not tick a box until the code,
> tests, clippy, and docs for that step are green.

**Goal:** promote the existing backend catalog into a real descriptor/registry
surface without replacing the existing `VmBackend` behavior seam or forcing an
all-at-once rewrite of `AnyBackend`.

Concretely, this plan lands:

1. a first-class `BackendDescriptor` type and registry API in `mvm-backend`,
2. one shared source for backend discovery, listing, doctor output, and
   admission/backend selection help,
3. one descriptor-driven instantiation path for both `AnyBackend` and
   trait-object consumers,
4. a smaller, more explicit `AnyBackend` that remains only where enum-specific
   behavior is still genuinely required.

**Why now:** Plan 182 fixed the worst duplication by centralizing backend names,
tiers, marker files, and support flags behind `backend_catalog!`. That leaves
the codebase in a better state, but it still has two architectural facts worth
cleaning up:

- the catalog is still mostly “metadata behind helper fns”, not a first-class
  descriptor/registry API,
- many read-only or generic consumers still conceptually ask for “a backend” by
  going through `AnyBackend`, even when they only need discovery metadata or
  `VmBackend` behavior.

This plan addresses that gap without destabilizing backend-specific call paths.

**Non-goals:**

- Do **not** replace the `VmBackend` trait. It remains the one runtime behavior
  contract.
- Do **not** add runtime-loaded plugins, dylib discovery, or user-installable
  backends in this plan.
- Do **not** remove `AnyBackend` outright. Keep it until the remaining
  backend-specific operations are demonstrably narrow and intentional.
- Do **not** rewrite backend auto-selection policy into data. The priority ladder
  in `AnyBackend::auto_select()` remains handwritten policy.
- Do **not** unify unrelated layer-local traits just because they share a name
  (for example the runtime vs supervisor `EgressProxy` seams).

---

## Guardrails (every task)

- Preserve `mvm_core::vm_backend::VmBackend` in
  `crates/mvm-core/src/protocol/vm_backend.rs` as the sole backend behavior
  trait. Registry work is additive around it.
- Keep the registry compile-time and static. No `libloading`, no dynamic
  registration hooks, no process-global mutation during normal startup.
- Descriptor data must stay declarative: selector, aliases, tier, marker-file
  ownership, support flags, display metadata, and constructor wiring belong in
  the descriptor; behavioral policy does not.
- `AnyBackend`, `mvmctl doctor`, and any future backend help/listing surfaces
  must read selectors/aliases/tier/support flags from the same descriptor
  source.
- If a consumer only needs backend metadata or a `VmBackend` trait object, do
  not route it through an enum match just for convenience.
- Any new trait-object constructor must stay explicit about ownership:
  `Arc<dyn VmBackend>` for shared generic consumers, `AnyBackend` where
  backend-specific branching still exists.
- Per task: `cargo clippy -p <crate> --all-targets -- -D warnings` clean.
- Before closing the plan: `cargo test --workspace`, `cargo check --workspace`,
  and docs updates must be green/current per the repo Definition of Done.

---

## File Structure

Primary edits:

- `crates/mvm-backend/src/catalog.rs`
- `crates/mvm-backend/src/backend.rs`
- `crates/mvm-backend/src/lib.rs`
- `crates/mvm-cli/src/doctor.rs`
- `crates/mvm-cli/src/commands/build/build.rs`
- `crates/mvm-cli/src/exec.rs`
- `crates/mvm-hostd/src/supervisor/backend.rs`
- `public/src/content/docs/reference/architecture.md`

Possible follow-on touchpoints if generic callers are migrated in this plan:

- `crates/mvm-cli/src/commands/vm/up.rs`
- `crates/mvm-cli/src/commands/vm/down.rs`
- `crates/mvm-cli/src/commands/vm/status.rs`
- `crates/mvm-cli/src/commands/vm/logs.rs`

---

## Phase 1 — Promote the catalog into a real registry

### Task 1 — Introduce `BackendDescriptor` and registry APIs

**Files:** `crates/mvm-backend/src/catalog.rs`; edit `crates/mvm-backend/src/lib.rs`.

- [x] **Step 1 — rename the concept, not the behavior.** Replace or wrap
      `BackendCatalogEntry` with a first-class `BackendDescriptor` type whose
      fields remain the current factual metadata:
      `kind`, `selector`, `aliases`, `tier`, `marker_file`,
      `started_vm_probe_order`, `include_in_list_all`,
      `include_in_balloon_support`, `include_in_warm_start_support`.
- [x] **Step 2 — add descriptor-facing helpers.** Export a small registry API:
      `descriptors()`, `descriptor(kind)`, `descriptor_for_selector(...)`,
      `descriptor_for_marker_file(...)`, `started_vm_probe_descriptors()`,
      and the existing support/listing iterators renamed around descriptors.
- [x] **Step 3 — add human-facing metadata while staying factual.** Add a stable
      display label field only if it is immediately consumed by doctor/docs/help.
      Do not add narrative prose or policy knobs to the descriptor just because
      they might be useful later.
- [x] **Step 4 — keep the macro narrow.** `backend_catalog!` may expand to build
      the descriptor table and related wiring, but it must remain one flat
      declarative table, not a layered DSL.
- [x] **Step 5 — green.** `cargo test -p mvm-backend catalog`,
      `cargo test -p mvm-backend backend`,
      `cargo clippy -p mvm-backend --all-targets -- -D warnings`.
- [x] **Step 6 — commit.** `git commit -m "refactor(backend): promote catalog into descriptor registry"`

### Task 2 — Add descriptor-driven constructors for both enum and trait-object consumers

**Files:** `crates/mvm-backend/src/catalog.rs`, `crates/mvm-backend/src/backend.rs`.

- [x] **Step 1 — preserve the enum constructor path.** Keep the existing
      descriptor-to-`AnyBackend` instantiation path so current enum-based callers
      remain stable.
- [x] **Step 2 — add the generic constructor path.** Add a descriptor-driven
      `Arc<dyn VmBackend>` constructor for consumers that only need the trait
      surface and do not care about enum-specific methods.
- [x] **Step 3 — prove trait-object parity.** Add tests that descriptor-based
      trait-object construction returns backends with the same `name()`,
      `capabilities()`, and `security_profile().tier` as the enum path for every
      registered backend where construction is side-effect free.
- [x] **Step 4 — green.** `cargo test -p mvm-backend backend`,
      `cargo clippy -p mvm-backend --all-targets -- -D warnings`.
- [x] **Step 5 — commit.** `git commit -m "refactor(backend): add descriptor-driven backend constructors"`

---

## Phase 2 — Migrate read-only and generic consumers first

### Task 3 — Move discovery/listing consumers onto descriptors

**Files:** `crates/mvm-cli/src/doctor.rs`; any needed exports in `crates/mvm-backend/src/lib.rs`.

- [x] **Step 1 — keep doctor descriptor-only.** Ensure doctor reads backend
      names, tiers, and support participation from descriptors rather than from
      `AnyBackend` helper methods or local strings.
- [x] **Step 2 — freeze visible ordering.** Preserve the current stable ordering
      in doctor and backend-list surfaces with tests that assert descriptor order
      explicitly.
- [x] **Step 3 — make listing helpers descriptor-named.** If helper names still
      speak in terms of “catalog entries”, rename them to “descriptors” so the
      public shape matches the architecture.
- [x] **Step 4 — green.** `cargo test -p mvm-cli doctor`,
      `cargo clippy -p mvm-cli -p mvm-backend --all-targets -- -D warnings`.
- [x] **Step 5 — commit.** `git commit -m "refactor(doctor): consume backend descriptors directly"`

### Task 4 — Move clearly generic callers off the enum where possible

**Files:** `crates/mvm-cli/src/commands/build/build.rs`,
`crates/mvm-cli/src/exec.rs`,
plus any additional call sites found by `rg -n 'AnyBackend::auto_select|AnyBackend::from_hypervisor' crates/mvm-cli crates/mvm`.

- [x] **Step 1 — classify call sites honestly.** Split callers into:
      1. descriptor-only,
      2. `VmBackend`-only,
      3. genuinely enum-specific.
      Record the remaining enum-specific sites in a short closeout note.
- [x] **Step 2 — migrate the easy generic sites.** Where a caller only invokes
      shared `VmBackend` methods (`name`, `capabilities`, `start`, `stop`,
      `status`, `logs`, `list`, `install`, `is_available`), switch it to the
      descriptor/trait-object path.
- [x] **Step 3 — keep backend-specific code explicit.** Leave call sites that
      still need `start_firecracker`, variant pattern matches, or other
      enum-specific behavior on `AnyBackend`; do not hide them behind downcasts
      or a second trait.
- [x] **Step 4 — green.** Run the targeted CLI/runtime tests touched by the
      migration, then `cargo clippy -p mvm-cli -p mvm-backend --all-targets -- -D warnings`.
- [x] **Step 5 — commit.** `git commit -m "refactor(cli): migrate generic backend callers onto descriptor registry"`

---

## Phase 3 — Tighten the remaining enum boundary

### Task 5 — Shrink `AnyBackend` to the intentionally enum-specific surface

**Files:** `crates/mvm-backend/src/backend.rs`

- [x] **Step 1 — keep policy methods explicit.** `auto_select()`,
      `from_build_output()`, and any backend-specific helpers like
      `start_firecracker()` remain handwritten and visible in `backend.rs`.
- [x] **Step 2 — remove descriptor-shaped duplication.** If any remaining
      `AnyBackend` method is just a second copy of selector/alias/tier/marker/
      support-flag metadata, move it behind the descriptor registry or delete it.
- [x] **Step 3 — keep one obvious escape hatch.** Retain `as_vm_backend()` for
      callers that already have an enum and only need the shared trait methods.
- [x] **Step 4 — add a boundary test.** Add or update a test that asserts the
      enum still exists for backend-specific flows while descriptor-only
      consumers no longer need to instantiate it.
- [x] **Step 5 — green.** `cargo test -p mvm-backend`,
      `cargo clippy -p mvm-backend --all-targets -- -D warnings`.
- [x] **Step 6 — commit.** `git commit -m "refactor(backend): narrow AnyBackend to enum-specific behavior"`

### Task 6 — Update supervisor/docs language to match the new design

**Files:** `crates/mvm-hostd/src/supervisor/backend.rs`,
`public/src/content/docs/reference/architecture.md`

- [x] **Step 1 — remove stale “future registry” wording.** Update the supervisor
      module comment so it describes the actual shipped relationship between
      `BackendLauncher`, `VmBackend`, `AnyBackend`, and the backend descriptor
      registry.
- [x] **Step 2 — document the ownership split plainly.** In the architecture
      reference, state that:
      `VmBackend` owns runtime behavior,
      the backend descriptor registry owns backend discovery metadata and
      constructor wiring,
      `AnyBackend` remains the closed enum for intentionally backend-specific
      operations.
- [x] **Step 3 — note the non-goal explicitly.** Document that the registry is
      compile-time/static today and is not a runtime plugin system.
- [x] **Step 4 — commit.** `git commit -m "docs(architecture): describe backend descriptor registry"`

---

## Phase 4 — Closeout

### Task 7 — Final verification and index updates

- [x] `cargo test --workspace` green.
- [x] `cargo check --workspace` green.
- [x] `cargo clippy --workspace --all-targets -- -D warnings` green in the required environment(s).
- [x] `public/src/content/docs/reference/architecture.md` matches the code.
- [x] `specs/SPRINT.md` reflects the plan and its real state.
- [x] `specs/REFACTOR-STATUS.md` reflects the plan and its real state.

### Task 8 — Closeout note: what intentionally did not change

- [x] Record, in the closing update to this file, that the shipped end state is:
      one `VmBackend` behavior trait,
      one compile-time descriptor registry,
      one remaining `AnyBackend` enum for backend-specific operations,
      and no runtime plugin loading.

---

## Closeout (2026-06-14) — STATUS: COMPLETE

Shipped end state:

- **One behavior trait:** `mvm_core::vm_backend::VmBackend`, untouched.
- **One compile-time descriptor registry:** `mvm_backend::catalog` — `backend_catalog!`
  expands one flat table of `BackendDescriptor`s; helpers are descriptor-named
  (`descriptors`, `descriptor`, `descriptor_for_selector`, `descriptor_for_marker_file`,
  `started_vm_probe_descriptors`, `list_all_descriptors`, `balloon_support_descriptors`,
  `warm_start_support_descriptors`). `descriptor_for_*` return the descriptor, not a bare kind.
- **Dual construction from the same descriptors:** `instantiate` → `AnyBackend`;
  `into_dyn` / `instantiate_dyn` → `Arc<dyn VmBackend>`. A parity test asserts the two paths
  agree on name/capabilities/tier for every backend; an ordering-freeze test pins the
  doctor/ls/probe surfaces.
- **One remaining enum:** `AnyBackend`, narrowed to genuinely backend-specific operations
  (`auto_select` policy, `from_build_output`, `start_firecracker`, the `pause.rs` Vz-variant
  check, the libkrun-only standby-pool methods) plus the `as_vm_backend` bridge. No
  descriptor-shaped duplication remained to remove — Plan 182 and Task 1 had already routed
  `tier`/`from_hypervisor`/`for_started_vm`/`list_all` through the registry.
- **No runtime plugin loading:** the registry is static; no `libloading`, no dynamic
  registration.

What intentionally did **not** change:

- `AnyBackend::auto_select()` stays handwritten platform policy (a non-goal to data-ify it).
- The `build.rs`/`exec.rs` `auto_select()` call sites stay on the enum: they extract `.name()`
  or call `.stop()`/`.start_with_mode()` on the policy-selected backend, where the enum's
  inherent trait delegation is the right tool and `into_dyn` would only add an `Arc` allocation.
  The only clean generic migration was doctor's descriptor-iterating collectors (done).
- Unrelated same-named traits (runtime vs supervisor `EgressProxy`) were left alone.
