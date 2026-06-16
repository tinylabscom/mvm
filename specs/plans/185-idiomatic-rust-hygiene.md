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

- [x] **Step 1 - write the policy into this plan.** Runtime state locks return an
      error or fail closed when poisoning means state may be corrupt. Test/global
      serialization locks recover with `into_inner()` so one failed test does not
      poison the rest of the test binary.

      **POLICY (decided):**
      - **Test/global serialization locks** (locks whose only job is to serialize
        env/cwd/fixture mutation across the test binary's threads — they guard *no*
        real state, just ordering) **recover from poison via `into_inner()`**: a
        panic in one test must not cascade-poison the lock and fail every sibling
        test. The shared `mvm_core::util::test_env::TestEnv` guard already encodes
        this (`ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner())`), so the
        preferred form is to *fold env-serialization locks into `TestEnv`* and let
        non-env serializers (cwd, signal) use the same `unwrap_or_else(into_inner)`.
      - **Runtime state locks** (worker/standby pools, backend launch/handle maps,
        audit cursors, the broker registry, anything guarding data a later reader
        trusts) **fail closed**: poison means a writer panicked mid-mutation and the
        guarded state may be torn, so propagate the error / bail rather than hand a
        caller a half-written value. Do **not** blanket-`into_inner()` these.
- [x] **Step 2 - add a tiny helper if it pays for itself.** N/A — `TestEnv` *is*
      the focused test-lock helper (it owns the recovery + restore). Non-env test
      serializers use the one-line `unwrap_or_else(|p| p.into_inner())` directly;
      a second wrapper would not pay for itself.
- [~] **Step 3 - migrate known test/global locks.** Done for the env serializers:
      every env-mutating test lock is folded into `TestEnv` (mvm-core/mvm-hostd/
      mvm-build incl. `builder_backend_select` + `vz_builder`/libkrun-sys/mvm-cli).
      Non-env test serializers already recover (`ts_runner::CWD_LOCK`,
      `runtime_meta::HOME_TEST_LOCK`). Remaining: `mvm-cli::dev_vz` env lock (hot
      file — other sessions) + the `mvm-backend` test env locks (host-gated build),
      to land where CI/Linux runs them.
- [x] **Step 4 - keep runtime fail-closed paths explicit.** Audited the
      `.lock().unwrap()` sites: the runtime ones (e.g. the guest-agent
      `RUN_ENTRYPOINT_LOCK`, supervisor pool/registry mutexes) are intentionally
      left fail-closed (a panic-poisoned runtime lock means torn state). Only
      serialization-only test locks were touched.
- [x] **Step 5 - green.** `cargo nextest run -p mvm-build [--features builder-vm]`
      + `cargo clippy -p mvm-build --features builder-vm --all-targets -- -D warnings`
      green for the folded locks.

---

## Phase 3 - Naming and API clarity

### Task 4 - Rename overly generic internal traits/types where the blast radius is small

**Files:** initial candidates:
`crates/mvm/src/storage/backend.rs`,
`crates/mvm/src/vm/egress_proxy.rs`,
`crates/mvm-hostd/src/supervisor/egress.rs`.

- [x] **Step 1 - classify names before editing.** Separate public/user-facing
      names from internal Rust names. Only internal names are candidates here.
      `storage::Backend` is internal-only (re-exported within the `storage`
      module; CLI consumes `ThinPool`/`ThinPoolImpl`, never the trait).
- [x] **Step 2 - rename `storage::Backend` if call sites stay manageable.**
      Renamed to `DeviceMapperBackend` (the module models dmsetup/device-mapper
      thin-pool ops; impls are `DmsetupBackend` + `MockBackend`). Blast radius
      was three files: `storage/backend.rs`, `storage/mod.rs`, `storage/pool.rs`.
- [x] **Step 3 - clarify the two `EgressProxy` traits without unifying them.**
      Renamed by layer ownership: the runtime per-VM lifecycle stub in
      `mvm/src/vm/egress_proxy.rs` → `VmEgressProxy` (zero external callers), and
      the supervisor's L7 payload-inspecting decision trait in
      `mvm-hostd/src/supervisor/egress.rs` → `SupervisorEgressProxy` (~25 refs
      across mvm-hostd/mvm-cli/mvm-core). Concrete impls `StubEgressProxy`,
      `NoopEgressProxy`, `L7EgressProxy` keep their names.
- [x] **Step 4 - update docs/comments only where they reference Rust type names.**
      Done for both the `storage::Backend` and `EgressProxy` renames; no user-doc
      churn (internal-only names).
- [x] **Step 5 - green.** storage: `mvm` lib+tests clippy clean + 14 storage tests;
      egress: `mvm-core`/`mvm`/`mvm-hostd`/`mvm-cli` clippy clean + 773 supervisor
      tests pass.

### Task 5 - Push stringly selectors toward typed values at module boundaries

**Files:** start with backend/provider selector paths:
`crates/mvm-backend/src/catalog.rs`,
`crates/mvm-backend/src/backend.rs`,
`crates/mvm-network/src/registry.rs`,
`crates/mvm-storage/src/mount_provider.rs`.

- [x] **Step 1 - keep strings at CLI/config edges.** Confirmed: backend selection
      already funnels raw `--hypervisor`/config strings through the single edge
      parser `AnyBackend::from_hypervisor(&str)` → `catalog::descriptor_for_selector`.
      Network/storage providers register by a `kind()` string *on purpose* — it's
      the documented open-registry extension point (external S3/NFS/custom providers
      join without a core-enum edit), so those strings are left as-is.
- [~] **Step 2 - use typed selectors internally.** The typed foundation already
      exists from the backend descriptor registry: `BackendKind` enum +
      `AnyBackend::kind()`. Exposed `kind()` as `pub` (was needlessly `pub(crate)`
      while `BackendKind` was already `pub`) and migrated the `&AnyBackend`-in-hand
      call sites in `mvm-cli/pool.rs` from `name() == "vz"` to
      `kind() == BackendKind::Vz`. Deferred: the `kernel_identity`/`image_identity`/
      `compat_for_launch` sites still take `&dyn VmBackend` (the mvm-core trait,
      which cannot expose `BackendKind` without a layer inversion) — typing those
      needs a `&dyn VmBackend → &AnyBackend` signature ripple through pool.rs,
      scoped as a follow-up to avoid churning that hot file here.
- [x] **Step 3 - avoid duplicate registries.** Removed the duplicated alias literal
      `backend_name == "vz" || backend_name == "virtualization"` in pool.rs in favor
      of `backend.kind() == BackendKind::Vz` — the descriptor registry already owns
      the vz alias table, so the call site no longer re-lists it.
- [x] **Step 4 - green.** `mvm-backend`/`mvm-cli` clippy clean; 14 pool tests pass.

#### Task 5 deferred follow-ups

- [ ] Convert `kernel_identity`/`image_identity`/`compat_for_launch` (and the
      `StandbyCompatParams.backend` field at the call-chain root) from
      `&dyn VmBackend` to `&AnyBackend`, then replace their `name() == "..."`
      comparisons with `kind()` checks. Held back from the Task 5 slice because
      pool.rs is a hot file (warm-pool work) and the signature ripple is best
      landed when that area is quiet.

---

## Phase 4 - Function shape and construction patterns

### Task 6 - Audit long constructors and parameter lists

**Files:** start from clippy pressure and manual inspection of functions that
thread many related values through runtime/build/CLI layers.

- [x] **Step 1 - prefer params structs over long argument lists.** Add a named
      struct when multiple call sites pass the same conceptual bundle.

      Audit anchored on the `#[allow(clippy::too_many_arguments)]` suppressions
      (AGENTS.md §"Clippy" bans that attribute outright — builder-struct is the
      fix; only bindgen FFI like `libkrun-sys/src/sys.rs` is exempt). Findings,
      all now resolved:
      - **`mvm-build::firecracker::boot_builder_vsock`** (9 args) — grouped the
        eight non-env args into a `BuilderVsockBoot` params struct, body
        byte-identical; `#[allow]` removed. **Done.**
      - **`mvm::vm::instance::fc_config::generate` + `mvm::security::jailer::
        launch_jailed`** — the `mvm` Firecracker instance/pool/tenant lifecycle
        subtree was **dead code** (unwired from `vm/mod.rs`, `compile_error!`-
        confirmed). Deleted the whole orphaned cluster (`vm/instance/`,
        `vm/pool/`, `vm/tenant/`, `bridge.rs`, `disk_manager.rs`) and trimmed
        `security/jailer.rs` to its one live `jailer_available()` probe, which
        also removed `launch_jailed`'s suppression by deletion (#931). The last
        hand-written `too_many_arguments` allow in the tree is gone.
      - **The two claim-12 security paths** — `substitution_proxy::
        sign_into_headers` (#926, `SignRequest` builder) and `terminator::tls::
        terminate_and_substitute` (#927, `TlsTermination` builder). Each
        destructures the built value at its top so the signing / TLS-terminate
        bodies are byte-for-byte unchanged.
      With those three PRs there are **zero** hand-written
      `#[allow(clippy::too_many_arguments)]` left in the workspace.
- [x] **Step 2 - prefer builders for multi-field optional construction.** The two
      claim-12 refactors use the `::builder()` + `with_*()` + `build()` shape
      (the AGENTS.md standing preference over a plain params struct, #923).
- [x] **Step 3 - keep builders local.** Plain local structs + `with_*`/`build()`
      impls matching the existing `RequestCtx`/`InspectorReporter` style; no
      generic builder framework.
- [x] **Step 4 - green.** Per-PR: `cargo clippy -p mvm-hostd`/`-p mvm`/`-p mvm-cli`
      `--all-targets -- -D warnings`, the touched sign/terminator/substitution
      lib tests (85 + 66) and `mvm` lib tests (203), nightly `fmt --all --check`,
      and the `check-no-spec-refs-in-comments` + `check-spec-numbers` gates.

  **Deferred (optional polish, not a lint violation):** the functions that
  already carry a params struct via a `too_many_arguments`-explaining comment
  (`gateway_bridge`, `checkpoint`, `up`, `plan_builder`, `firecracker`,
  `install`) are lint-clean today; upgrading them from plain params structs to
  full `::builder()` shapes is style polish, tracked but not required.

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

- [~] **Step 1 - require local `SAFETY:` invariants.** Every `unsafe` block that
      remains must explain the concrete invariant that makes it sound. Generic
      comments such as "required by Rust 2024" are not enough unless they also
      state the synchronization or ownership guarantee.

      First pass: the simple-syscall `mvm-guest` files — `entrypoint.rs` (fcntl,
      setrlimit, kill-pgroup), `volume.rs` (mount/umount2 with owned CStrings),
      `exec_stream.rs` (kill-pgroup, kill-sig-0 probe), `process_rpc.rs` (pre_exec
      async-signal-safe closure, kill-pgroup), `netinit.rs` (zeroed POD
      `sockaddr_nl`), `worker_pool.rs` (sysconf) — now carry a per-block `SAFETY:`
      naming the ownership/async-signal-safety/POD invariant. Verified host clippy
      **and** `--target aarch64-unknown-linux-musl` clippy (the mount/netlink/
      setrlimit blocks are Linux-gated). Audit baseline at the time: ~454 `unsafe`
      sites vs ~261 `SAFETY:` comments workspace-wide.

      Second pass: the `mvm-verity-init` bin (13 blocks — dm-verity ioctls, the
      `copy_nonoverlapping` payload assembly, and the mount/chdir/chroot/execv
      syscalls). Each block now names its concrete invariant; `do_ioctl` gained a
      `# Safety` doc spelling out the fd/`data_size` contract its callers uphold.

      Console pass: `mvm-guest/console.rs` — every `unsafe` block
      (openpty/fork/dup2/close/ioctl/socket/bind/listen/accept/shutdown/kill/
      waitpid/from_raw_fd) now states its concrete fd-ownership /
      pointer-validity / async-signal-safety invariant, replacing the prior
      generic one-liners.

      Agent pass: the `mvm-guest-agent` bin — the four `unsafe` blocks that
      still lacked an invariant (two post-bind `close(fd)` cleanups + two test
      bodies calling the async-signal-safe signal handlers directly) now carry
      one; the `install_signal_handlers` block already had a solid note.
- [~] **Step 2 - isolate platform/FFI unsafe behind small safe wrappers.** VZ,
      libkrun, libc/syscall, and env-mutation code should expose narrow safe
      functions to the rest of the crate wherever practical.

      `mvm-verity-init`: the three fixed-payload dm ioctls (VERSION/DEV_CREATE/
      DEV_SUSPEND) now route through a safe `dm_ioctl_fixed(fd, cmd, &mut DmIoctl)`
      wrapper — a `const _` assertion pins `DM_IOCTL_STRUCT_SIZE ==
      size_of::<DmIoctl>()` so the "a `&mut DmIoctl` fully backs the kernel access"
      argument can't silently rot. The redundant typed deref that re-set
      `DM_READONLY_FLAG` on the (only u8-aligned) `Vec` pointer was dropped — the
      flag is already set in the payload bytes — leaving one documented raw-pointer
      ioctl for the variable-length TABLE_LOAD path.

      `console.rs`: the post-fork child was calling `putenv` (which can
      `malloc` and mutates the global `environ`) and `execvp` between `fork()`
      and exec — but the guest agent is multithreaded by the time it serves a
      ConsoleOpen request, so the child may call only async-signal-safe
      functions or risk an allocator-lock deadlock. Fixed by assembling the
      child's environment in the parent before the fork and `execve`-ing a
      fixed array (the shell path is absolute, so no PATH search). The pure
      core, `build_shell_env_from`, is unit-tested without touching
      process-global state.
- [ ] **Step 3 - keep platform cfgs narrow.** Linux/macOS-only behavior should be
      gated at the smallest useful module/function boundary, while host-side
      cargo builds continue to compile on non-target platforms.
- [ ] **Step 4 - green.** Run targeted tests for touched code and clippy for each
      touched crate.

#### Task 8 deferred follow-ups

- [x] `mvm-verity-init` bin (dm-verity ioctls) — done in the Step 1 second pass
      above; fixed-payload ioctls isolated behind `dm_ioctl_fixed`.
- [x] `mvm-guest/console.rs` (PTY/termios) — done in the Step 1 console pass
      above; also dropped the post-fork malloc path (Step 2).
- [x] `mvm-guest-agent` bin — done in the Step 1 agent pass above (the four
      remaining `close(fd)` / signal-handler-test blocks).
- [ ] Annotate the remaining deeper `unsafe` cluster with `SAFETY:`
      invariants, one reviewed file at a time (it needs genuine soundness
      reasoning, not a formula): the `mvm-vm-host/vz_objc.rs` objc2 FFI (~100)
      — best done while the Plan-152 vz work is quiet.

### Task 9 - Audit feature and dependency boundaries

**Files:** crate `Cargo.toml` files plus feature-gated modules.

- [x] **Step 1 - keep test helpers out of production builds.** Verified clean: all
      six `test-support` consumers (mvm-backend, mvm-hostd, mvm-build, mvm-cli,
      mvm-vm-host, libkrun-sys) request `mvm-core = { features = ["test-support"] }`
      only under `[dev-dependencies]`, and mvm-core defines `test-support = []` (an
      empty feature — no transitive activation) with an inline comment documenting
      its dev/test-only intent. A production (non-dev) build of any crate never
      enables it, and `TestEnv` is gated `cfg(any(test, feature = "test-support"))`.
- [x] **Step 2 - check optional heavy deps.** Verified clean: mvm-core's optional
      stacks are each `dep:`-gated behind a feature *and* documented inline —
      `egress-ca`→`rcgen` (sync, no tokio), `hostd-transport`/`manifest-verify`→
      `tokio` (the only async surfaces), `schemars` JsonSchema derive (off by
      default, build-time codegen only), and the `attestation-*` provider stubs.
      The `check-core-runtime-free` xtask gate (a Lint job) already enforces that
      the default closure carries no tokio, so a regression fails CI.
- [x] **Step 3 - avoid accidental workspace feature widening.** Verified clean: the
      Phase-1 dev-deps added `features = ["test-support"]` and nothing else; no crate
      pulls an mvm-core feature it doesn't use. `cargo tree -p mvm-core -e features`
      shows the runtime-free default; the heavy features only appear when explicitly
      requested by the hostd-transport / manifest-verify / egress-ca consumers.
- [x] **Step 4 - green.** Audit-only — no code change needed (the boundaries already
      hold). Manifest audit + `cargo tree -e features` confirm the gating; broad
      dependency-count work stays deferred to Plan 126.

---

## Phase 6 - Error shapes, fixtures, and docs hygiene

### Task 10 - Standardize error shapes and error tests

**Files:** start from library modules that expose public errors and CLI/binary
edges that currently wrap them.

- [x] **Step 1 - clarify `thiserror` vs `anyhow`.** Audit confirms the boundary
      is already the intended one: domain/library surfaces that callers react to
      programmatically expose typed `thiserror` enums (the hostd keyholder
      `ProxyError`/`TerminatorError`/`SignDispatchError`, `RotationError`,
      `OciUnpackError`, plan/bundle errors), while the bulk of fallible
      operations use `anyhow` with `.context()`/`bail!` for operator-facing
      messages. No reshaping needed.
- [x] **Step 2 - stop matching error strings in tests where typed errors exist.**
      Finding: the actionable surface is **tiny**. Where a typed enum exists and
      callers react, the tests already use `matches!` (the hostd security paths).
      Almost every `unwrap_err().to_string().contains(...)` in the tree is on an
      `anyhow` error (e.g. `mock::start`, `capture_fs_quick`, `AddDir::parse`,
      `migrate_wrapped_keys`' version `bail!`s) or a `serde_json` parse error —
      where the rendered string is the only handle and is the correct thing to
      assert. The one genuine candidate was `load_master_key`, which surfaces an
      anyhow-wrapped `RotationError::KeyFilePerms { mode }`; its test now
      `downcast_ref::<RotationError>()`s and matches the structured `mode` field
      instead of substring-matching `"0644"` (robust to message rewording).
- [x] **Step 3 - add context at process and filesystem boundaries.** Spot-check
      confirms FS/command/config errors already carry the path/operation via
      `.with_context(|| format!("…{}", path.display()))` (e.g. the host-signer
      keypair, key-rotation, secret-store paths) without leaking secret values.
- [x] **Step 4 - green.** `cargo test -p mvm-core load_master_key` +
      `cargo clippy -p mvm-core --all-targets -- -D warnings`.

### Task 11 - Consolidate repeated fixtures and builders

**Files:** initial candidates include tests constructing `ExecutionPlan`,
`FlakeRunConfig`, backend configs, admission inputs, and large CLI fixtures.

- [x] **Step 1 - identify repeated fixture constructors.** The clearest
      duplication: **six** near-identical ~40-line minimal `ExecutionPlan`
      fixtures across the mvm-hostd audit/admission cluster
      (`audit/{emitter,bind,host_keypair,plan_persist}`,
      `supervisor/{lifecycle_hooks,audit_recorder}`). The realistic-shape
      fixtures (`signing::sample_plan`, supervisor `aggregate`/`audit`, mvm-cli
      `policy_resolver`) are a *materially different* plan and were left alone.
- [x] **Step 2 - move shared fixtures to the owning crate's test-support module.**
      Added `mvm_core::plan::test_support::PlanFixture`, gated
      `cfg(any(test, feature = "test-support"))` so it never reaches production;
      both mvm-hostd and mvm-cli already enable `mvm-core/test-support` in
      dev-deps. Adds no deps — `check-core-runtime-free` stays green (#953).
- [x] **Step 3 - prefer fixture builders over partially valid literals.**
      `PlanFixture` produces a valid minimal local plan by default and exposes
      `with`-style overrides (`tenant`/`plan_id`/`workload`/`runtime_profile`/
      `nonce`/`secrets`/`validity`) so each migrated site states only what it
      pins; the six `fixture_plan` fns are now thin wrappers (call sites
      unchanged). Net −156 lines.
- [x] **Step 4 - green.** 2 new `PlanFixture` unit tests + 83 migrated
      mvm-hostd audit/supervisor tests pass; `cargo clippy -p mvm-core
      --features test-support -p mvm-hostd --all-targets -- -D warnings`.

### Task 12 - Audit secret/debug exposure

**Files:** start from
`rg -n 'derive\\(.*Debug|println!|eprintln!|tracing::|log::|format!' crates`
plus secret-bearing modules.

- [x] **Step 1 - identify secret-bearing types.** Audit conclusion: the
      codebase already enforces this well. The name-based
      `check-no-display-on-secret-types` gate is clean; a field-name sweep for
      raw secret fields (`secret`/`password`/`api_key`/`private_key`/`token` of
      `String`/`Vec<u8>`) on non-`SecretBox` types surfaced **no unprotected
      types** — the only hits are an opaque `pid_token` CLI arg and the
      already-hand-redacted `vmgenid::GenerationToken`.
- [x] **Step 2 - use secrecy/zeroize wrappers consistently.** Already the
      pattern: raw credential values live in zeroizing `secrecy::SecretBox`
      (e.g. the keyholder resolver returns `SecretBox<Vec<u8>>`), and
      secret-bearing structs carry hand-written redacting `Debug` impls with
      `// allow(secret-debug)` notes. No new wrappers needed.
- [x] **Step 3 - add negative tests for secret formatting where practical.**
      Added the missing ones — types that had a redacting `Debug` but no test
      pinning it, so a future edit dropping the impl can't silently start
      leaking (the name-gate only checks an impl *exists*, not that it
      *redacts*): `HostSigner` (mvm-hostd), `ResolvedBinding`/`ResolvedSecrets`
      and `EgressCa` (mvm-core). `identity::SecretBytes`, the TLS intermediate,
      and the web-search provider already had equivalent tests.
- [x] **Step 4 - green.** The 3 new tests + existing redaction tests pass;
      `cargo clippy -p mvm-core --features egress-ca -p mvm-hostd --all-targets
      -- -D warnings`, nightly fmt, and the `check-no-display-on-secret-types` /
      spec gates clean. (PR for the tests is tracked in SPRINT.)

### Task 13 - Add documentation verification to closeout

- [x] **Step 1 - run doc generation after type renames.** Ran
      `RUSTDOCFLAGS="-W rustdoc::broken_intra_doc_links" cargo doc --workspace
      --no-deps`. Finding: **the Phase 3 renames introduced zero broken links** —
      grepping the unresolved-link set for `Backend`/`EgressProxy`/
      `DeviceMapperBackend`/`BackendKind` returns nothing, so #892/#894/#895
      updated their own doc links cleanly.
- [~] **Step 2 - fix broken intra-doc links.** The doc run surfaced ~115
      *pre-existing* broken intra-doc links (not introduced by this plan),
      spread across every crate (mvm-hostd 26, mvm-build 26, mvm-backend 16,
      mvm-core 15, mvm-guest 13, libkrun-sys 8, others ≤4). These are general
      doc-hygiene debt — private-item links, std-trait links written bare
      (`[`FromStr`]`), test-fn links, prose that should be backticked, and a few
      module-doc `//!` links that don't resolve even fully-qualified.
      **`mvm-core` cleared** (16 sites): public API got real qualified links
      (`[`SecretStore::list`]`, `[`crate::crypto::snapshot_hmac`]`,
      `[`std::str::FromStr`]`, the `SIG_ALG_*` consts), private/test/prose items
      were backticked, and `cargo doc -p mvm-core --no-deps` is now clean under
      `-D rustdoc::broken_intra_doc_links`.
      **`mvm-build` partially cleared** (45 → 32 under `--all-features`): fixed
      the *unconditional* path bugs — `vz_builder.rs` dropped the `crate::`
      prefix on 10 `libkrun_builder::…` links the code itself qualifies;
      `vz.rs` `Boot`/`Restore` → `StartupMode::{Boot,Restore}`; `builder_vm.rs`
      `LibkrunBuilderVm` → `crate::libkrun_builder::LibkrunBuilderVm`; private
      consts + external objc2 types backticked. This pass also **refined the
      finding** (see Step 3): the count is feature- and platform-sensitive.
- [~] **Step 3 - document the doc-generation conditions.** Not a host/platform
      *blocker* (`cargo doc` runs here), but the workspace doc build is
      **feature- and platform-conditional**, which the initial `~115` count hid:
      (a) many links target `#[cfg(feature = …)]` modules (e.g.
      `crate::libkrun_builder::*`) that are absent unless docs run with
      `--all-features`; (b) a cluster targets `#[cfg(target_os = "linux")]`
      builder-VM bins (`mvm-host-vm-init`, egress-proxy internals) that simply
      aren't in the doc graph on a **macOS** host — they resolve on a **Linux**
      doc build, and backticking them to satisfy macOS would *degrade* the
      valid Linux docs. So the Phase 7 doc gate must run **on Linux with
      `--all-features`, per-crate**; only links that are broken *there* are real
      bugs. mvm-core + the unconditional mvm-build bugs are fixed; the rest is
      tracked below.

  **Deferred (tracked) — clear the remaining broken intra-doc links before
  Phase 7 (counts are the macOS-host default-feature run; re-measure on Linux
  with `--all-features`, which is the real gate — many are feature/platform
  artifacts, not bugs):**
  - [ ] mvm-hostd (26)
  - [~] mvm-build (32 left under `--all-features`; unconditional path bugs fixed —
        remainder is module-doc `//!` qualification + `cfg(linux)` builder-VM bins
        that resolve only on a Linux doc build)
  - [ ] mvm-backend (16)
  - [ ] mvm-guest (13)
  - [ ] libkrun-sys / deps (8)
  - [ ] mvm-cli (4), mvm-vm-host (3), mvm (2), mvm-sdk (1), mvm-oci (1)

---

## Phase 7 - Closeout

### Task 14 - Final verification and index updates

- [x] `cargo test --workspace` green **on Linux** (the required env — `mvm-backend`
      tests SIGKILL under macOS amfid, so they can only be validated on Linux).
      Verified on the x86_64 Linux box: 3720+ tests pass across the heavy crates
      alone (mvm-core 1244, mvm-hostd 962, mvm-backend 914, …) plus the rest of
      the suite, **zero genuine failures**. Two non-genuine results, both
      understood: (1) the run first surfaced 15 failures in the `cfg(linux)`
      `mvm-host-vm-init` bin — a real test-isolation bug (unguarded
      `set_var("TMPDIR", …)` leaking a non-existent path to parallel tests),
      invisible on macOS where the bin is `cfg`-excluded; **fixed** with `TestEnv`
      + a valid sentinel (PR #960, now 151/151). (2) `each_embedded_binary_starts_
      with_elf_magic` fails only under `MVM_SKIP_EMBED_BINARIES=1` (it asserts
      real ELF payloads; the flag embeds zero-byte stubs) — a documented env
      artifact, green in a real-embed CI build.
- [x] `cargo check --workspace` green (the test build above compiled the whole
      workspace + all test targets on Linux).
- [~] `cargo clippy --workspace --all-targets -- -D warnings` green in the
      **required env (macOS CI)** — verified for all Plan 185 changes. A Linux
      clippy run additionally surfaced **pre-existing** lints in the `cfg(linux)`
      `mvm-build` bin `mvm-host-vm-init` (same clippy 0.1.96 both hosts; macOS
      never lints that bin because it's `cfg`-excluded): 9 `doc list item without
      indentation`, 1 `empty line after doc comment`, 1 `collapsible if`. These
      are unrelated to Plan 185 and predate it; tracked as a separate Linux-clippy
      follow-up (chasing "Linux clippy green" risks a cascade through dependent
      crates — out of this plan's scope).
- [~] `cargo doc --workspace --no-deps` — **documented blocker, not a Plan 185
      regression.** Task 13 proved the renames introduced zero broken links;
      separately, `cargo doc --workspace --all-features` on Linux inventories
      **~122 pre-existing broken intra-doc links** scattered ~1-per-file across
      ~60 files (feature/platform-gated artifacts mixed with genuine bare-path
      bugs). mvm-core + mvm-build's unconditional bugs are fixed (#939/#941); the
      remaining crates are a tracked doc-hygiene follow-up that must be measured
      and fixed **on Linux with `--all-features`** (only links broken there are
      real). This is the "narrower doc command / documented reason" Task 14 allows.
- [x] `specs/SPRINT.md` reflects the plan and its real state.
- [x] `specs/REFACTOR-STATUS.md` reflects the plan and its real state.
- [x] **Closeout note — intentionally deferred debts, with reasons:**
      1. **Task 8 — `mvm-vm-host/vz_objc.rs` objc2 SAFETY audit.** Held while the
         Plan-152 vz work is active (concurrent vz worktrees/PRs); touching ~120
         `msg_send` blocks now would collide. Resume when vz is quiet.
      2. **Task 13 — remaining-crate broken intra-doc links (~122 under Linux
         `--all-features`).** Pre-existing doc-hygiene debt, not introduced by this
         plan (renames were clean). Must be re-measured + fixed on Linux +
         `--all-features` per-crate, because macOS tooling can't separate real
         bugs from `cfg(feature)`/`cfg(target_os="linux")` artifacts.
      3. **Pre-existing Linux-only clippy lints in `mvm-host-vm-init`** (11, doc
         formatting + collapsible-if). Surfaced by the Phase 7 Linux clippy run;
         orthogonal to Plan 185; deferred to avoid a cross-crate Linux-clippy
         cascade inside this closeout.
