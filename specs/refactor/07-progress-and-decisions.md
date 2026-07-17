# Progress & Decisions

The execution reality: what's landed, what's been deliberately deviated from plan and why, and what's genuinely still open. This is the doc to read when you need to know "is X actually true today" rather than "is X the target."

## Phase 0 — COMPLETE

- **specs/ sweep** (`72a4214a7`).
- **Claims/compliance/threat-models consolidated into their topic ADRs** (`985225f4e`) — `check-claim-catalog` verifies 16 claims / 38 witnesses from ADR-002 (at the time of that commit; the ADR set has since been renumbered — see [08-adr-consolidation.md](08-adr-consolidation.md)).
- **92 → 30 ADRs, renumbered contiguous 001–030**, rewritten to absolute decision form (17,973 → 3,912 lines). All machine-checked gates green on the resulting set: claim-catalog (16 claims / 38 witnesses), trust-gradient, adr-coverage. Detail: [08-adr-consolidation.md](08-adr-consolidation.md).
- **Dead workspace deps dropped** (`dfc70f6a7`).
- **BDD cucumber harness** scaffolded.
- **Worktrees swept** to the 2-tree working set.
- **SDK python/typescript moved** to `crates/mvm-sdk/sdks/`.
- **`bin/dev` → `scripts/dev`.**
- **Secrets decision made and committed:** the `${NAME}` named-placeholder design (ADR-023 + WS-NET) — see [04-security.md](04-security.md) for the design and [03-networking.md](03-networking.md) for where it rides the wire.

## Phase 1a — 7 of 7 crate consolidations done (crate count 20 → 14)

Method: structure-first / easy-first, on a single long-lived green branch. Each move landed as its own commit, validated by `cargo check --workspace --all-targets` green immediately after. The whole set was then validated together by a full `cargo clippy --workspace --all-targets` (0 errors / 0 warnings), the xtask gates, and nightly `cargo fmt --all` clean.

| Move | Commit |
|---|---|
| `mvm-network` → `mvm-net` (crate rename) | `6ae57b438` |
| `mvm-ext4` + `mvm-oci` → `mvm-fs` (submodules `ext4`/`oci`) | `10977e915` |
| `mvm-vm-host` → `mvm-hostd` (flat; 3 supervisor bins) | `3fc1dae6d` |
| `mvm-mcp` → `mvm-cli` (`crate::mcp`, behind `mcp` feature) | `42b432b89` |
| `mvm` + `mvm-backend` → `mvm-runtime` (flat; ~96 files rewired) | `764b7d897` |
| `mvm-guest` + `mvm-guest-helpers` → `mvm-agentd` (~214 files) | `19f1830ba` |
| `mvm-storage` → `mvm-runtime` `crate::storage::volume` (nested to dodge a `backend.rs`/`mod.rs` collision with the pre-existing dm-thin `crate::storage`; `s3` feature renamed `storage-s3`) | — |

Current crate set (14): `mvm-agentd, mvm-build, mvm-cli, mvm-client, mvm-conformance, mvm-core, mvm-fs, mvm-host-services-ffi, mvm-hostd, mvm-net, mvm-runtime, mvm-sdk, mvm-verify` + `crates/deps/libkrun-sys`.

## Key decisions & deviations

Each of these is a deliberate call made during execution, diverging from the literal crate map in [02-architecture.md](02-architecture.md) §Crate map. None is drift — each has a stated rationale, and each should be revisited explicitly (not silently overridden) if circumstances change.

- **`mvm-host-services-ffi` kept separate**, not folded into `mvm-agentd` as the crate map says. It's a `cdylib` (lib name `mvm_host_services`) that the SDK Python/TypeScript runtimes `dlopen` and that nix bakes into the runtime-overlay. Folding it in would change the artifact name and break both the FFI contract and the nix packaging contract. It stays a standalone crate; its dependency on the renamed guest crate was updated to point at `mvm-agentd`.
- **`qemu.rs` kept** in `mvm-runtime`. SPRINT WS1e literally says "delete qemu.rs" and the backend/egress model in [02-architecture.md](02-architecture.md) lists QEMU as dropped, but the standing direction from outside this sprint is to keep QEMU as an opt-in Linux dev substrate. The drop is deferred/contested — flagged here for an explicit decision, not silently kept or silently dropped.
- **`egress_server.rs` parked/dead** — it moved into `mvm-hostd` during the `mvm-vm-host` → `mvm-hostd` consolidation, but it's unwired: it references a removed `EgressGate::admitted_addrs` API from an earlier API refactor. It needs to either be revived during the WS-NET networking consolidation (see [03-networking.md](03-networking.md) / [06-execution-plan.md](06-execution-plan.md) WS-NET) or deleted outright. Leaving it as dead code past WS-NET would violate the WS8 "0 dead modules" gate.
- **`mvm-storage` landed at `crate::storage::volume`, not bare `crate::storage`.** `mvm-runtime` already had an unrelated `crate::storage` module (the dm-thin CoW pool for instance rootfs/snapshots — `ThinPool`/`DmsetupBackend`/its own `StorageError`), imported verbatim from the pre-consolidation `mvm` crate. A flat merge would have collided on `backend.rs`/`mod.rs` filenames and on two distinct `StorageError` types with the same name. `volume` nests the former `mvm-storage` crate (the `VolumeBackend`/`StorageProvider` data-plane traits) as a sibling of `pool`/`thin`/`backend` under the existing `storage` module — same host-storage-substrate grouping, no symbol or file clash.
- **`architecture.yml`'s category-10 "substrate server" invariant is CI-only** — there's no local xtask mirror of it. The absorbed `substrate_server_category` metadata was merged into `mvm-hostd` along with the rest of `mvm-vm-host`. If that CI gate flags the single-host-binary consolidation (i.e. it was written assuming multiple substrate-server binaries and now sees one), the gate needs to be reconciled to match — the consolidation into one host binary is what the plan intends, so the gate is what should move, not the crate structure.

## Phase 1a long pole — `mvm-protocol` extraction (COMPLETE)

- **`mvm-protocol` extraction** — a **design effort**, not a mechanical merge, and it *was* the long pole of Phase 1a (now done — see "All three increments have landed" below). `mvm-core`'s `plan/` + `policy/` + `protocol/` modules carried roughly 126 `crate::` references into `config`/`crypto`/`security`/`instance`/`tenant`. Pulling "wire + policy" out from below `mvm-core` (per the target dependency direction in [02-architecture.md](02-architecture.md), `mvm-protocol` sits *under* `mvm-core`) meant inverting a meaningful fraction of the foundation, not just moving files. Even `mvm-sdk::ir` — which became part of `mvm-protocol` — reached into `mvm-core` via `ir/validate.rs` → `mvm_core::entrypoint_policy`, so the IR extraction and the protocol extraction were entangled with each other as well as with `mvm-core`.

  The resolution: Phase 1b's `no_std` constraint on `mvm-core` (rebuilding it on top of `mvm-protocol`) is exactly what forces the clean pure-DTO boundary to be drawn — a `no_std` crate can't casually depend on the `std`-only parts of what's currently `mvm-core`. So 1a-protocol and 1b are being treated as one designed pass rather than two sequential mechanical steps: you can't design the cut cleanly without simultaneously deciding what `mvm-core` looks like on the other side of it.

  **All three increments have landed.** Increments 1–2: `mvm-verify` → `mvm_protocol::verify`; Workload IR + entrypoint → `mvm_protocol::{ir,entrypoint}`, wasm-clean. **Increment 3 — the wire/policy DTO split — is COMPLETE** (13 subagent-driven batches, Tier 0 `6577d06ba` → final `51471dd7`), per the design of record [10-increment3-protocol-core-split.md](10-increment3-protocol-core-split.md). Every `plan/`+`policy/`+`protocol/` wire/policy DTO — leaves, the two biggest single-file splits (`bundle.rs` 2360, `vm_backend.rs` 2693), and the claim-8 signed `ExecutionPlan` itself (46/46 fields byte-identical) — now lives in `#![no_std]+alloc` `mvm-protocol`; all signing/verify/synthesis/resolution/fs/net/tar logic stays in `mvm-core` on top. The four mechanics held as designed (kept `DateTime<Utc>` via scoped no_std chrono; `std::net`→`core::net`; scoped `thiserror`; orphan-rule free-fn rewrites), the mvm↔mvmd signed contract stayed byte-identical (pinned JCS fixture for `ControlRequest`; verbatim `ExecutionPlan`), and the whole signed plan now compiles on `wasm32` — the `no_std` foundation the wasm-container core goal (WS11) needs. Two candidates the design flagged "deferred" resolved to permanent `mvm-core` residents (`security_profile`, the mvmd↔hostd `HostdRequest` IPC) — see the design doc's "Intentionally stays in mvm-core" section.

- **The full `nextest --workspace` behavioral gate — now satisfied.** Every one of the 13 `mvm-protocol` extraction batches (and the `mvm-storage` fold) was validated by a full `cargo nextest run --workspace` (excluding `mvm-runtime` for macOS codesign-SIGKILL and `mvm-conformance` for its cucumber harness — both run on Linux CI) plus `clippy --workspace --all-targets -D warnings`, the `wasm32` build, the xtask gates, and nightly `fmt --all`. Suite held at ~6567–6597 passing / 0 failed across the whole sequence. The behavioral gate for WS1a-mechanical is met.

## Not started

Phases 1b through 4 have not started. One line each:

- **1b** `mvm-core` rebuild on `mvm-protocol` (entangled with the `mvm-protocol` extraction above).
- **1c** `mvm-fs`: fold in build's rootfs/overlay/unpack (the `mvm-ext4`+`mvm-oci` merge already landed; this is the remaining absorption).
- **1d** `mvm-net`: fold in host tunnel/gateway/dns + guest net/tun/netinit (the crate rename already landed; this is the remaining absorption).
- **1f** `mvm-build`: slim the builder pipeline.
- **1g** `mvm-sdk`: `PackageType` trait, language-surface relocation under `crates/mvm-sdk/languages/`, runtime SDK/decorator first-class enablement.
- **1h/1i** `mvm-client` facade completion + `mvm-cli` routed entirely through it.
- **WS4** single `~/.mvm` directory.
- **WS5** two-feature collapse.
- **WS6** trait dispatch + zero hardcoding.
- **WS2** single host + single guest binary, no forks.
- **WS-NET** consolidated vsock networking + standardized protocol.
- **WS9** lifecycle correctness (vsock-sourced exit codes, healthcheck reaper).
- **WS8** file/function size + dead-code removal.
- **WS7** simple CLI (`Command` trait dispatch, verb redesign).
- **WS10** tiny kernel + low memory + density.
- **WS-DX** developer experience & performance (sub-second launch, warm start, snapshot/fork).
- **WS12** ADRs-alive + website docs.
- **WS13** issue/PR close-out.
- **WS11** wasm-container backend + `no_std` core (**core goal** — its `no_std` core lands with `mvm-protocol` in 1a/1b and is CI-gated from then; the `WasmBackend` seam follows once the protocol crate is wasm-clean).
- **WS14** mvmd contract freeze.

Full descriptions and acceptance gates for every item above: [06-execution-plan.md](06-execution-plan.md).
