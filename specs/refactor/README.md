# mvm v1 Clean Restructure — Plan of Record

Index and status dashboard for the disposable-v1 restructure of `mvm`.

## What this is

The current tree is treated as a disposable v1. This effort restructures it completely — no legacy paths, no compatibility shims, no aliases, hard renames only. The bar is a codebase an expert human can read and navigate end to end: fully tested, following established Rust best practice, radically smaller than what AI-driven development left behind. Security, auditability, attestation-via-nix, and data governance are non-negotiable — they are preserved or strengthened at every step, never traded away for simplicity.

Two capabilities are **core goals** in their own right, not by-products of simplification: one auditable host egress seam for every backend, and **producing wasm containers** — a `WasmBackend` running workloads as WASI wasm modules, enabled by a `no_std` core that compiles to `wasm32`/the browser (more backends from one model). See [01-goals.md](01-goals.md) and [02-architecture.md](02-architecture.md) §Wasm-container backend & `no_std` core.

## Status

**Phase 0 — COMPLETE.** Spec sweep, ADR consolidation (92 → 30, contiguous, absolute decision form), dead-dep drop, BDD harness scaffolding, worktree sweep, SDK relocation, `bin/dev` → `scripts/dev`, and the `${NAME}` secrets decision are all landed. Detail: [07-progress-and-decisions.md](07-progress-and-decisions.md).

**Phase 1a — crate consolidations (7/7) + the `mvm-contract` extraction COMPLETE.** Crate count 20 → 14; the long pole — pulling all `plan/`+`policy/`+`protocol/` wire/policy DTOs (through the signed `ExecutionPlan` itself) down into the `#![no_std]` `mvm-contract`, which compiles on `wasm32` — landed in 13 subagent-driven batches (design of record: [10-increment3-protocol-core-split.md](10-increment3-protocol-core-split.md)). The full `nextest --workspace` behavioral gate is met (green after every move). Remaining Phase-1 absorptions: `mvm-fs` (1c) + `mvm-net` (1d) fold-ins, `mvm-build` slim (1f), `mvm-sdk` `PackageType` (1g), and the `mvm-client` facade + CLI routing (1h/1i). Detail: [07-progress-and-decisions.md](07-progress-and-decisions.md).

**Phases 1b–4 — not started** (1b `mvm-core`-on-`mvm-contract` is largely subsumed by the completed extraction; the `WasmBackend` seam WS11 is now unblocked).

This status line is the single source of truth for "where are we" — if any other doc in this set implies a later stage is further along, this line wins.

## Relationship to `specs/SPRINT.md`

`specs/SPRINT.md` is the live working ledger — checkboxes get ticked there as work lands, day to day. **This directory (`specs/refactor/`) is the full, organized plan of record**: SPRINT.md reorganized, expanded, and cross-referenced for long-term navigation, with the execution-progress facts (commit shas, deviations, decisions) folded in that don't fit a rolling checklist doc. When the two disagree on a target-state design decision, SPRINT.md is more current by definition (it's live); when they disagree on execution progress, this directory's [07-progress-and-decisions.md](07-progress-and-decisions.md) is the fuller account.

## Contents

| Doc | Covers |
|---|---|
| [01-goals.md](01-goals.md) | Why this restructure exists, the measured-symptoms-to-target table, reference models studied, definition of done |
| [02-architecture.md](02-architecture.md) | Target crate map, dependency direction, binary model, feature model, directory model, backend/egress model, top-level repo layout |
| [03-networking.md](03-networking.md) | The consolidated vsock networking design — single seam, standardized protocol, generic tunnel + typed connectors |
| [04-security.md](04-security.md) | Security and data-governance model: secrets substitution, PII redaction, verified boot, signed plans, audit chain |
| [05-sdk-and-testing.md](05-sdk-and-testing.md) | SDK pipeline (tree-sitter → IR → nix template), `PackageType` trait, BDD-first testing model |
| [06-execution-plan.md](06-execution-plan.md) | The full workstream list (Phase 0 → Phase 4) with acceptance gates, and the phase sequencing |
| [07-progress-and-decisions.md](07-progress-and-decisions.md) | Execution reality: what's done, what's deviated from plan and why, what's left |
| [08-adr-consolidation.md](08-adr-consolidation.md) | The ADR consolidation: 92 legacy ADRs → 30 contiguous, and the cluster mapping |
| [09-closeout.md](09-closeout.md) | Issue/PR disposition table and the biggest confirmed code removals |
| [10-increment3-protocol-core-split.md](10-increment3-protocol-core-split.md) | The `mvm-core` → `mvm-contract` wire/policy DTO split — per-module cut, extraction order, byte-identity invariant (design of record for the Phase 1a long pole) |
| [11-wasm-backend.md](11-wasm-backend.md) | The `WasmBackend` seam (WS11 core goal) — scoped as the claim-free portability tier, the three resolved open questions, the seam + WASI egress transport, the POC gate, and the P1–P4 plan |
| [12-workload-address-pilot.md](12-workload-address-pilot.md) | Decision-ready pilot: a UOR-ADDR-compatible `WorkloadAddress` (JCS+SHA-256) for the Workload IR — additive host-side, zero new deps, the security boundary it must not cross, and the deferred `uor-addr`-crate/browser (WS11 P4) decision |

Read order for a newcomer: this README, then [01-goals.md](01-goals.md), then [02-architecture.md](02-architecture.md), then whichever of 03–09 matches what you're touching.
