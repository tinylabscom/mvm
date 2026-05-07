---
title: "ADR-010: Per-language function-service factories live in mvm.lib"
status: Proposed
date: 2026-05-06
supersedes: none
related: ADR-007 (function-call entrypoints); plan 48-function-service-factories; mvmforge ADR-0010 §3 (cross-repo counterpart); mvmforge ADR-0009 (function-call entrypoints)
---

## Status

Proposed. Counterpart to mvmforge ADR-0010 §3 (amended 2026-05-06,
Option A), which states the factories live in mvm. This ADR records
the substrate-side commitment.

## Context

Per ADR-007, function-call entrypoints are a first-class workload
shape in mvm. mvmforge generates the artifacts (`flake.nix`,
`launch.json`, source bundle) that `mvmctl up` consumes for these
workloads. Today mvmforge also ships the Nix factories that bake
per-language wrappers into the rootfs
(`mkPythonFunctionService.nix`, `mkNodeFunctionService.nix`,
`mkWasmFunctionService.nix` at `mvmforge/nix/factories/`). The
wrappers implement a wire contract (single-shot respawn, structured
error envelope, decoder hardening, payload caps) that lives next to
`mvmctl invoke`'s side of the same protocol.

The factories belong with the substrate, not with the SDK. The wrapper
contract is the substrate's contract. Putting the factories on the
mvm side gives:

- **User-visible artifacts contain zero internal-toolchain files.**
  Today's generated `flake.nix` imports `./nix/factories/...`; under
  this ADR it references `mvm.lib.<system>.mk<Lang>FunctionService`.
- **Single source of truth for wire contract.** Wrapper invariants
  (single-shot respawn, envelope marker, decoder hardening, payload
  caps) live next to `mvmctl invoke` in mvm.
- **mvm version pin = wrapper version pin.** Upgrading mvm upgrades
  wrappers atomically.

## Decision

Expose three new attributes on `mvm.lib.<system>` for each supported
arch (`x86_64-linux`, `aarch64-linux`):

- `mkPythonFunctionService`
- `mkNodeFunctionService`
- `mkWasmFunctionService`

Each accepts the args specified in
`mvmforge/specs/contracts/mvm-mkfunctionservice.md` and returns the
record `{ extraFiles, servicePackages, service }`. The contract is
the binding interface; mvm guarantees backward compatibility under
the schema-version rules in ADR-007.

The factories live at `mvm/nix/lib/factories/` (mirroring the
existing `mvm/nix/lib/minimal-init/` precedent). They are exposed
from `outputs.lib.<system>` in `nix/flake.nix`.

The wrapper templates that the factories reference live at
`mvm/nix/wrappers/` (per Plan 49 — wrapper relocation).

## Invariants

- The `{ extraFiles, servicePackages, service }` return shape is
  versioned by the contract document
  (`mvmforge/specs/contracts/mvm-mkfunctionservice.md`), not by
  independent ADR. Breaking changes require a contract revision
  (mvmforge cross-repo coordination).
- The factory's `service` attribute composes into `mkGuest`'s
  `services` attrset using the existing merge semantics (caller-wins
  per-service).
- Per-call hygiene (fresh subprocess per call, env baseline, FD
  reset, per-call TMPDIR, cleanup) is the substrate's responsibility,
  encoded in the factory output and enforced by the `mkGuest`-emitted
  init.
- Function-service factories return a **different** shape from
  existing service factories (`mkPythonService`, `mkNodeService`,
  `mkStaticSite`) which return `{ package, service, healthCheck }`.
  The two surfaces remain side by side; no migration of the existing
  factories.
- `mvmctl doctor` grows a check that asserts the factory symbols are
  exposed — protects against accidental removal during refactors.

## Consequences

- mvmforge's bundled factory copies (`nix/factories/`) become dead
  code once `flake.lock` here bumps. mvmforge's cleanup PR (cross-
  repo plan §F) deletes them.
- New surface area on `mvm.lib`: any future per-language factory
  (e.g. `mkRustFunctionService` if function-entrypoint Rust support
  lands per mvmforge ADR-0015's deferred work) lives here too.
- Contract drift risk: the binding contract is on mvmforge's side
  (`mvm-mkfunctionservice.md`). When that contract is revised,
  mvm's factories must update in lock-step. CI lanes on both sides
  should fail-closed on divergence — proposed: a CI job that
  fetches the contract file and asserts the mvm factories' arg
  shape matches.
- **Out of scope:** Rust function-service support (deferred);
  migration of existing service factories (no migration — the two
  surfaces coexist).
