# mvm v1 Clean Restructure — Historical Design Set

This directory is a frozen historical design set, not a plan or status
dashboard. GitHub issues own current scope and progress. Do not execute its
checklists or infer current architecture from its status statements; consult a
current issue and the ADRs/contracts it links.

## What this is

The current tree is treated as a disposable v1. This effort restructures it completely — no legacy paths, no compatibility shims, no aliases, hard renames only. The bar is a codebase an expert human can read and navigate end to end: fully tested, following established Rust best practice, radically smaller than what AI-driven development left behind. Security, auditability, attestation-via-nix, and data governance are non-negotiable — they are preserved or strengthened at every step, never traded away for simplicity.

Two capabilities are **core goals** in their own right, not by-products of simplification: one auditable host egress seam for every backend, and **producing wasm containers** — a `WasmBackend` running workloads as WASI wasm modules, enabled by a `no_std` core that compiles to `wasm32`/the browser (more backends from one model). See [01-goals.md](01-goals.md) and [02-architecture.md](02-architecture.md) §Wasm-container backend & `no_std` core.

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

These documents are retained only while their durable decisions are extracted
or rejected. They are not the newcomer read order. Start from the current
GitHub issue as described in [`specs/README.md`](../README.md).
