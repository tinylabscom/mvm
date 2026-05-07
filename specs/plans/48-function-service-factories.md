# Plan 48 — Per-language function-service factories live in `mvm.lib`

Status: **Proposed.** Implements ADR-010. Counterpart to mvmforge
ADR-0010 §3.

## Background

mvmforge today ships per-language Nix factories at
`mvmforge/nix/factories/mk{Python,Node,Wasm}FunctionService.nix`.
These factories bake per-call wrappers + service definitions into a
`mkGuest`-compatible shape. They encode how `mvmctl invoke` dispatches
a function call into a VM — wire contract, single-shot respawn, payload
caps, decoder hardening — which is substrate concern, not SDK concern.

Per mvmforge ADR-0010 §3 (amended 2026-05-06, Option A), the factories
move to mvm. mvmforge has feature-detect + fallback in
`mvmforge/crates/mvmforge/src/flake.rs:68-82` so it picks up the
upstream symbols on the next `flake.lock` bump.

## Goal

Expose three new factory attributes on `mvm.lib.<system>`:

- `mkPythonFunctionService`
- `mkNodeFunctionService`
- `mkWasmFunctionService`

Each accepts the args specified in
`mvmforge/specs/contracts/mvm-mkfunctionservice.md` (the binding
contract, 339 lines) and returns the record
`{ extraFiles, servicePackages, service }`.

## Implementation

### Step 1: Lift the factories

Copy the three factory files from `mvmforge/nix/factories/` into
`mvm/nix/lib/factories/` (preserving the precedent set by
`mvm/nix/lib/minimal-init/`):

- `mvm/nix/lib/factories/mkPythonFunctionService.nix`
- `mvm/nix/lib/factories/mkNodeFunctionService.nix`
- `mvm/nix/lib/factories/mkWasmFunctionService.nix`

Path updates inside each factory: the factories reference wrapper
files at `nix/wrappers/*`. Coordinate with Plan 49 (wrappers
relocation) — both PRs land together to avoid two breaking changes.

### Step 2: Wire into `mvm.lib`

Modify `mvm/nix/flake.nix` around line 793 (the
`lib.mkGuest = mkGuestFn;` block). Existing precedents at lines
508–759 (`mkNodeService`, `mkPythonService`, `mkStaticSite`) show the
shape — add three more attributes per `<system>`:

```nix
lib = forAllSystems (system: {
  # ... existing entries ...
  mkPythonFunctionService = import ./lib/factories/mkPythonFunctionService.nix;
  mkNodeFunctionService   = import ./lib/factories/mkNodeFunctionService.nix;
  mkWasmFunctionService   = import ./lib/factories/mkWasmFunctionService.nix;
});
```

### Step 3: Smoke test

New file `mvm/tests/factory_shape.nix` (or a Rust integration test
that shells `nix eval`):

- Invoke each factory with a trivial `appPkg` derivation.
- Assert the return is a record with keys `extraFiles`,
  `servicePackages`, and `service`.
- Assert `extraFiles` is an attrset, `servicePackages` is a list, and
  `service` has `command`, `env`, etc. (at least the keys mkGuest
  consumes).

The 8-case contract test surface from
`mvmforge/specs/contracts/mvm-mkfunctionservice.md` is the deeper
acceptance gate; port the test cases or coordinate with mvmforge to
keep their wrapper-test suite (`mvmforge/tests/wrappers/`) running
against the relocated copies.

## Critical files

- New: `mvm/nix/lib/factories/mkPythonFunctionService.nix` (copied)
- New: `mvm/nix/lib/factories/mkNodeFunctionService.nix` (copied)
- New: `mvm/nix/lib/factories/mkWasmFunctionService.nix` (copied)
- Modified: `mvm/nix/flake.nix` — extend the `lib` attrset.
- New: `mvm/tests/factory_shape.nix` — smoke test.
- Reference contract: `mvmforge/specs/contracts/mvm-mkfunctionservice.md`.

## Acceptance per contract

- `nix flake show` on an mvm checkout exposes
  `lib.x86_64-linux.mkPythonFunctionService` (and aarch64-linux,
  plus Node and Wasm).
- The 8 contract test cases pass against an mvm-side test invocation:
  rootfs invariant, stdin/stdout round-trip, per-call respawn
  isolation, stderr logging, envelope preservation, host-mode
  rejection (`network.mode == "host"`), wall-clock cap, stdout cap.

## Verification

- `nix flake show` smoke.
- Factory shape test (above).
- mvmforge bumps `flake.lock` to point at the mvm branch; runs
  `just real-mvm-check` and `just real-mvm-up` against
  `examples/python/hello-func/`. Boots end-to-end means the lift
  succeeded.

## Out of scope

- Function-entrypoint Rust language support. Deferred per mvmforge
  ADR-0015 — would add `mkRustFunctionService` here in a future plan
  alongside a hardened Rust wrapper template.
- Migration / removal of existing service factories
  (`mkPythonService`, `mkNodeService`, `mkStaticSite`). They remain
  side-by-side; no migration required.

## Effort

~2 days (lift, wire, test).

## Coordination

Pairs with Plan 49 (wrappers move). Land together. After both merge
to mvm `main` and mvmforge bumps `flake.lock`, mvmforge ships its
cleanup PRs (delete bundled factories + wrappers, drop fallback
branch).
