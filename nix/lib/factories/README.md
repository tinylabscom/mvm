# mvm Nix factories — function-service builders

These factories live in `nix/lib/factories/` and are exposed via
`mvm.lib.<system>.mk{Python,Node,Wasm}FunctionService`. They emit
the wrapper + entrypoint files that mvm's `RunEntrypoint` verb
consumes (mvm ADR-007).

Relocated from `mvmforge/nix/factories/` under mvm plan 48
(function-service-factories). The corresponding mvm ADR is
`specs/adrs/010-function-service-factories.md`; the binding contract
is `mvmforge/specs/contracts/mvm-mkfunctionservice.md`. mvmforge's
generated flake.nix dispatches to these factories when a workload
declares `entrypoint.kind = "function"` (mvmforge plan 0003 /
ADR-0009).

## Files

- `mkPythonFunctionService.nix` — Python (CPython 3.x) factory. v1
  emits a single self-contained Python wrapper that does both
  hardening and dispatch.
- `mkNodeFunctionService.nix` — Node.js (≥ 22) mirror.
- `mkWasmFunctionService.nix` — WASI Preview 1 modules hosted by
  `wasmtime`. Generic across any compile-to-WASM toolchain (Rust,
  Go, Zig, AssemblyScript, .NET NativeAOT-LLVM, Kotlin/Wasm, …) per
  ADR-0010 §4. The user-provided `.wasm` IS the wrapper — it
  satisfies the wire contract via WASI host functions; mvmforge bakes
  wasmtime around it. `module` is interpreted as the relative path of
  the `.wasm` file inside the bundled source tree.

## Contract

Each factory takes:

```nix
{
  pkgs,           # nixpkgs.legacyPackages.<system>
  workloadId,    # workload id from the IR
  module,        # IR entrypoint.module
  function,      # IR entrypoint.function
  format,        # IR entrypoint.format ("json" | "msgpack")
  appPkg,        # the user-source derivation (per ADR-0008)
}
```

and returns:

```nix
{
  extraFiles,    # passed straight to mvm's mkGuest extraFiles
  servicePackages, # extra packages mkGuest needs in the rootfs (e.g. python3)
  service,       # services.<workloadId> entry for mkGuest
}
```

## Hardening

The wrapper scripts mirror the hardening invariants `mvmforge-runtime`
implements in audited Rust (ADR-0009 §"Wrapper template"):

- `prctl(PR_SET_DUMPABLE, 0)` on Linux before reading stdin.
- 1 MiB v1 stdin cap; reject larger payloads with a sanitized
  envelope.
- Top-level catch + sanitized envelope on stderr (`{kind, error_id,
  message}`). Never log payload content.

The cross-language hardening parity is a v1 trade-off: a follow-up PR
swaps these wrappers for the compiled `mvmforge-runtime` binary once
the Nix-side build story (rustPlatform + workspace lockfile vendoring)
is plumbed. Until then, **changes to the runtime crate's hardening
semantics must be mirrored here.**
