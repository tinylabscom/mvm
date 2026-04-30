# mvm Sprint 7: Role-Based NixOS Profiles & Reconcile Ordering

Previous sprints:
- [SPRINT-1-foundation.md](sprints/SPRINT-1-foundation.md) (complete)
- [SPRINT-2-production-readiness.md](sprints/SPRINT-2-production-readiness.md) (complete)
- [SPRINT-3-real-world-validation.md](sprints/SPRINT-3-real-world-validation.md) (complete)
- Sprint 4: Security Baseline 90% (complete)
- Sprint 5: Final Security Hardening (complete)
- [SPRINT-6-minimum-runtime.md](sprints/SPRINT-6-minimum-runtime.md) (complete)

Sprint 7 implements role-based NixOS microVM profiles and reconcile ordering. Based on [specs/plans/8-configuration-and-isolation.md](plans/8-configuration-and-isolation.md).

The Role enum, RuntimePolicy, instance timestamps, config drive, vsock, and sleep eligibility were implemented in Sprint 6. This sprint adds the NixOS module system, build integration, CLI support, and reconcile ordering.

---

## Phase 1: pool_create with Role Parameter
**Status: COMPLETE**

Pass the role through from CLI and reconcile into pool_create().

- [x] `src/vm/pool/lifecycle.rs` — add `role: Role` parameter to `pool_create()`
- [x] `src/agent.rs` — pass `dp.role.clone()` to `pool_create()` in reconcile
- [x] Tests: pool_create with explicit role (Gateway), verify persisted in pool.json

## Phase 2: CLI --role Argument
**Status: COMPLETE**

Add `--role` to `mvm pool create`.

- [x] `src/main.rs` — add `--role` arg to `PoolCmd::Create` (default: "worker")
- [x] `src/main.rs` — `parse_role()` helper converts string to `Role` enum
- [x] `src/infra/display.rs` — add `role` to PoolRow and PoolInfo display structs

## Phase 3: Reconcile Ordering (Gateway Before Worker)
**Status: COMPLETE**

Ensure gateway pools are reconciled before worker pools within each tenant.

- [x] `src/agent.rs` — `role_priority()` function: Gateway=0, Builder=1, Worker=2, CapabilityImessage=3
- [x] `src/agent.rs` — Phase 2-3: sort `dt.pools` by role_priority before iteration
- [x] `src/agent.rs` — Phase 6: reverse sort for sleep (workers sleep before gateways)
- [x] Tests: `test_role_priority_ordering`, `test_reconcile_sorts_pools_by_role`

## Phase 4: NixOS Manifest Parser (mvm-profiles.toml)
**Status: COMPLETE**

Config-file-driven Nix build: manifest maps (role, profile) → .nix module paths.

- [x] `src/vm/pool/nix_manifest.rs` — NixManifest, ProfileEntry, RoleEntry structs
- [x] `src/vm/pool/nix_manifest.rs` — from_toml(), resolve(), role_requirements()
- [x] `src/vm/pool/mod.rs` — add `pub mod nix_manifest;`
- [x] Tests: TOML parse roundtrip, resolve valid/invalid, role_requirements, minimal manifest

## Phase 5: Build Integration
**Status: COMPLETE**

Update nix build to use manifest-driven role+profile attribute resolution.

- [x] `src/vm/pool/build.rs` — `resolve_build_attribute()` tries loading mvm-profiles.toml from builder VM
- [x] `src/vm/pool/build.rs` — if found: `tenant-<role>-<profile>`, else fallback to `tenant-<profile>`
- [x] `src/vm/pool/build.rs` — `run_nix_build()` gains `role` parameter

## Phase 6: Nix Role Modules
**Status: COMPLETE**

Create NixOS role modules and update flake for role+profile combinations.

- [x] `nix/roles/gateway.nix` — gateway service, hostname, config drive mount, IP forwarding
- [x] `nix/roles/worker.nix` — worker agent service, vsock sleep-prep listener
- [x] `nix/roles/builder.nix` — Nix daemon, flakes enabled
- [x] `nix/roles/capability-imessage.nix` — placeholder
- [x] `nix/mvm-profiles.toml` — reference manifest mapping roles+profiles to modules
- [x] `nix/flake.nix` — mkGuest with roleModules, combined tenant-role-profile outputs
- [x] Backward compat: legacy `tenant-minimal`, `tenant-python` outputs preserved

## Phase 7: Documentation
**Status: COMPLETE**

- [x] `docs/roles.md` — role semantics, drive model, reconcile ordering, NixOS modules
- [x] `specs/SPRINT.md` — update with final metrics

---

## Summary

| Metric | Value |
|--------|-------|
| Lib tests | 276 |
| Integration tests | 10 |
| Total tests | 286 |
| Clippy warnings | 0 |
| New files | `src/vm/pool/nix_manifest.rs`, `nix/roles/*.nix`, `nix/mvm-profiles.toml` |

## Files Created/Modified

| File | Changes |
|------|---------|
| `src/vm/pool/nix_manifest.rs` | **NEW** — TOML manifest parser (8 tests) |
| `src/vm/pool/mod.rs` | Add `pub mod nix_manifest` |
| `src/vm/pool/lifecycle.rs` | `pool_create()` gains `role: Role` param (1 new test) |
| `src/vm/pool/build.rs` | `resolve_build_attribute()`, `run_nix_build()` gains role |
| `src/agent.rs` | `role_priority()`, sort pools in reconcile phases 2-3 and 6 (3 new tests) |
| `src/main.rs` | `--role` CLI arg, `parse_role()` helper |
| `src/infra/display.rs` | `role` field in PoolRow and PoolInfo |
| `nix/roles/gateway.nix` | **NEW** — gateway role module |
| `nix/roles/worker.nix` | **NEW** — worker role module |
| `nix/roles/builder.nix` | **NEW** — builder role module |
| `nix/roles/capability-imessage.nix` | **NEW** — placeholder |
| `nix/mvm-profiles.toml` | **NEW** — reference manifest |
| `nix/flake.nix` | `roleModules` param, 6 combined outputs, legacy compat |
| `docs/roles.md` | **NEW** — role semantics, drive model, reconcile ordering, NixOS modules |
