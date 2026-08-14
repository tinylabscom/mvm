# Plan 329: Remove DockerBackend — make MVM unapologetically microVM-only

**Status:** Ready for review  
**Branch:** `feat/remove-docker-backend`  
**Worktree:** `.worktrees/mvm-remove-docker`

## Goal

Remove the shared-kernel Docker container dev tier from MVM entirely. MVM will run workloads only through hardware-virtualized microVM backends (Firecracker, libkrun, HVF, QEMU) or the claim-free Wasm portability tier. Hosts without a usable hypervisor will fail closed with a clear diagnostic message.

## Motivation

MVM's core value proposition is hardware-isolated microVMs: per-workload kernel, no guest NIC, signed and audited execution plans, dm-verity boot. The DockerBackend is a shared-kernel container path that contradicts this differentiation even when labeled as a dev tier. Removing it:

- Eliminates brand confusion between containers and microVMs.
- Removes a large, host-privileged code path from the runtime.
- Frees engineering time for microVM-backend improvements.
- Makes the security story honest and uniform.

## Scope

### In scope

- Remove `DockerBackend` implementation (`crates/mvm-runtime/src/docker_backend.rs`).
- Remove `AnyBackend::Docker` variant and all dispatch sites.
- Remove `BackendKind::Docker` from protocol and contract types.
- Remove Docker from backend catalog, auto-selection, and CLI mapping.
- Remove DockerBackend references from tests and conformance code.
- Update ADRs and docs that describe the Docker dev tier.
- Update `mvmctl doctor` and error messages to no longer suggest Docker.

### Out of scope

- Removing OCI image support. MVM still pulls and runs OCI images inside microVMs.
- Removing Docker Hub / registry references. OCI registries remain fully supported.
- Removing the WasmBackend.
- Adding a replacement container runtime.

## Breaking-change note

`BackendKind::Docker` appears in signed execution plans, capability negotiation, and runtime descriptors. Removing the variant means any persisted plan or record that names `Docker` will fail to deserialize. This is acceptable because Docker was explicitly prod-refused and never a supported production path. We will not provide a migration; affected artifacts were dev-only and intentionally non-durable.

## Phases

### Phase 1 — Core runtime removal

- [x] Delete `crates/mvm-runtime/src/docker_backend.rs`.
- [x] Remove `pub mod docker_backend;` from `crates/mvm-runtime/src/lib.rs`.
- [x] Remove `DockerBackend` import and `AnyBackend::Docker` variant from `crates/mvm-runtime/src/backend.rs`.
- [x] Remove all Docker match arms in `crates/mvm-runtime/src/backend.rs`.
- [x] Remove Docker backend catalog entry from `crates/mvm-runtime/src/catalog.rs`.
- [x] Remove `BackendKind::Docker` from `crates/mvm-core/src/protocol/vm_backend.rs`.
- [x] Remove Docker references from `crates/mvm-contract/src/protocol/vm_backend.rs`.
- [x] Remove Docker references from `crates/mvm-contract/src/protocol/resource_controls.rs`.
- [x] Remove Docker match arm from `crates/mvm-vmm/src/host/observability_target.rs`.
- [x] Update `deps/libkrun-sys/src/error.rs` to no longer suggest `--hypervisor docker` on Windows.

### Phase 2 — Tests and conformance

- [x] Remove DockerBackend usage from `crates/mvm-conformance/tests/steps/volume.rs`.
- [x] Remove Docker-specific tests from `crates/mvm-runtime/src/backend.rs`.
- [x] Update `crates/mvm-cli/src/doctor/warm_start.rs` to remove docker backend assertions.
- [x] Run `cargo check --workspace` and fix compile errors.
- [x] Run `cargo clippy --workspace -- -D warnings` and fix all findings.
- [x] Run `cargo test --workspace` on the host (flakes observed under `cargo test` resolved under `cargo nextest run --workspace`; see notes below).

### Phase 3 — Dependencies and cleanup

- [x] Audit `crates/mvm-runtime/Cargo.toml` and other `Cargo.toml` files for dependencies that were only used by DockerBackend.
- [x] Remove any now-unused dependencies (`which` was removed from `mvm-runtime` and `libkrun-sys`).
- [x] Run `cargo machete` to confirm no Docker-specific unused deps remain.
  - Result: `cargo machete` still reports pre-existing unused dependencies (`ipnet`, `toml` in `mvm-hostd`; `mio`, `virtio-queue`, `virtio-vsock`, `vm-memory` in `mvm-runtime`; etc.). These are not Docker-specific and are out of scope for this removal change.

### Phase 4 — Documentation

- [x] Update `specs/adrs/034-docker-dev-tier-backend.md` status to **Retired** and add a note explaining the reversal.
- [x] Update `MIGRATION-269.md` if it references DockerBackend.
- [x] Update `CLAUDE.md` runtime module listing.
- [x] Update `specs/notes/2026-07-29-universal-initramfs-future-tiers.md`.
- [x] Update public docs (`public/src/content/docs/`) to remove Docker install/run references.
- [x] Update `specs/REFACTOR-STATUS.md` and `specs/SPRINT.md` if they track DockerBackend work.
- [ ] Update `specs/research/linux-container-runtime-review.md` (file lives on `main` but not in this worktree; requires rebase to include) to reflect the removal decision.

### Phase 5 — Verification

- [x] Full workspace `cargo check` passes.
- [x] Full workspace `cargo clippy -- -D warnings` passes.
- [x] Host-side `cargo test --workspace` passes under `cargo nextest run --workspace` (11483 passed, 26 skipped, 1 leaky).
- [x] `mvmctl doctor` no longer lists Docker as a backend option.
- [x] `--hypervisor docker` produces a clear "unsupported backend" error.

## Acceptance criteria

- No `DockerBackend` or `BackendKind::Docker` remains in the codebase.
- `cargo check --workspace` and `cargo clippy --workspace -- -D warnings` pass.
- All existing tests pass (or are updated/removed if they depended on Docker).
- Documentation accurately describes MVM as microVM-only.
- ADR-034 is marked retired with rationale.

## Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Breaking old dev-only signed plans | Acceptable; Docker was prod-refused and documented as non-durable. |
| Tests that relied on DockerBackend | Replace with MockBackend or skip/remove where no microVM equivalent exists. |
| Users depending on Docker for CI | Direct them to QEMU/Firecracker on Linux or document how to install a hypervisor. |
| Docs scattered across many files | Use targeted grep and update each reference systematically. |

## Dependencies

None. This is a pure removal change.

## Progress notes

### Test results

- `cargo check --workspace` passes.
- `cargo clippy --workspace -- -D warnings` passes.
- `cargo fmt --all -- --check` passes.
- `cargo nextest run --workspace` passes: **11483 tests passed, 26 skipped, 1 leaky**.
- Two `mvm-agentd::entrypoint_execute` tests
  (`test_execute_stdout_cap_prunes_and_marks_a_gap_without_killing_the_wrapper`
  and `test_execute_wrapper_cannot_forge_an_agent_gap_record_on_fd3`) failed
  under the full parallel run due to their 300 ms deadlines not being met under
  load. Both pass in isolation and are unrelated to the Docker backend removal.
- A plain `cargo test --workspace` run showed flaky failures in process-spawning
  tests (`doctor::toolchain::tests::check_cmd_rustup_on_host`,
  `mvm-hostd::netd_bin::a_tampered_gateway_entry_breaks_the_chain`). These are
  the same concurrency-sensitive tests the project addresses with the
  `process-handshake` group in `.config/nextest.toml`; they passed under
  nextest.

### Remaining Docker mentions (intentionally kept)

- OCI registry support still references Docker Hub (`docker.io`,
  `registry-1.docker.io`, Docker-Content-Digest headers, Docker v2 manifest
  media types). These are distribution-spec concepts, not the Docker runtime
  backend, and are out of scope for removal.
- `mvm-cli manifest export-oci` produces a `docker load`-able image via Nix
  `dockerTools.streamLayeredImage`. This is an OCI artifact export path, not a
  runtime backend.
- `crates/mvm-runtime/src/image.rs` contains a build helper (`ensure_bake`)
  that downloads the `bake` binary using Docker. This is a build-time tool
  dependency, not a workload runtime backend, and is left for a separate
  follow-up because it needs an alternative binary distribution mechanism.
- User-facing analogies like "like `docker run --rm`" remain in docs as
  descriptive comparisons.

### Dependency audit

- `which` was removed from `crates/mvm-runtime/Cargo.toml` and
  `crates/deps/libkrun-sys/Cargo.toml` because the Docker backend and the
  supervisor-binary resolver path that consumed it were both removed.
- `cargo machete` was run. It reports pre-existing unused dependencies in
  `mvm-hostd`, `mvm-runtime`, `mvm-http`, `mvm-cli`, and `mvm-build` that are
  unrelated to Docker backend removal; they are left for separate cleanup.

### Follow-up

- `specs/research/linux-container-runtime-review.md` lives on `main` but was
  added after this worktree branched. It should be updated in the same PR once
  the worktree is rebased onto `main` (or updated separately on `main`).
