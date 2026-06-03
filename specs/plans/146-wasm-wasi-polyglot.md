# Plan 146 — WASI-polyglot workload language (deferred)

> **Status: DEFERRED — revisit during/after the rearchitecture refactor.**
> Not urgent, no demonstrated blocker. Captured now so the idea (and the map)
> isn't lost. Distinct from Plan 144 (`wasm-sandbox` *backend*, framing A — a
> non-production browser/demo sandbox). This is framing **B**: wasm as a
> workload *language* running inside a real, hardened microVM.

## Goal (the why)

**DX / breadth.** Let someone write a workload in *any* language that compiles
to WASI and have it execute on the microVM — without mvm paying the full
per-language cost (wrapper + nix runtime + registry row) it paid for Python and
TypeScript. One wasm runner = an on-ramp for a whole ecosystem. The microVM
remains the isolation boundary (ADR-002 unchanged); wasm here is a *packaging /
language-on-ramp* mechanism, not a second sandbox.

## Honest scope (set expectations precisely)

- The artifact must be a **WASI command** targeting `wasm32-wasip1` (a `_start`
  that reads stdin / writes stdout). Browser wasm (`wasm32-unknown-unknown`)
  can't do I/O and is out of scope.
- Practically this is **self-contained compute functions**, not arbitrary
  programs: threads, real sockets, native deps, and dynamic linking are beyond
  WASI Preview 1's surface.
- Languages it unlocks today — first-class: **Rust, C/C++ (wasi-sdk), Zig,
  Swift, AssemblyScript, TinyGo**; workable but heavier: **Go (`GOOS=wasip1`),
  C#/.NET, Kotlin/Wasm**. Still a real DX win.

## Approach

- **Phase 1 — raw-WASI contract (broad, low per-language cost).** Define and
  document the wire contract: the `.wasm` reads `[args, kwargs]` (json|msgpack)
  on stdin and writes the encoded result to stdout — the same protocol the
  py/node wrappers implement. Users write a small WASI `main` themselves. This
  instantly accepts the whole `wasm32-wasi` ecosystem.
- **Phase 2 — per-language SDK shims (DX, incremental).** Add thin shims (Rust
  first) that do the stdin/stdout glue so users write only their function —
  decorator-grade DX, added per language as demand shows. "Support any wasm
  language" (phase 1) and "great DX in language X" (phase 2) are different-sized
  commitments; ship phase 1 first.

## Seams (from `specs/notes/wasm-support-exploration.md`)

- [ ] **Declaration path (the design crux).** A `.wasm` has no decorator AST.
  Pick a manifest (`mvm.toml`: `module="app.wasm"`, `function="<export>"`,
  resources, env) and/or a CLI flag (`mvmctl compile foo.wasm --function
  <export>`); hand-authored IR-JSON (`--from-ir`) already works as a stopgap.
- [ ] **Nix bake.** A `wasm` case in `nix/lib/factories/mkFunctionService.nix` +
  the data-driven registry (`nix/lib/factories/languages/registry.nix` — the
  comment already pre-describes the row: `interpreter = null` + a wrapper-kind
  branch): `servicePackages = [ pkgs.wasmtime ]`, bake the user's module at the
  working dir (`/app/dispatch.wasm`), write `runtime.json` `language=wasm`.
  **No wrapper script** — the `.wasm` IS the entrypoint.
- [ ] **Runner — already coded.** `crates/mvm-runner/src/{config,main}.rs`
  `Language::Wasm` → `wasmtime run dispatch.wasm`. Confirm it still holds after
  the refactor; no new work expected here.
- [ ] **Compile.** Add a `language=="wasm"` branch in
  `crates/mvm-sdk/src/compile/orchestrator.rs` that bypasses reachability +
  `strip_framework` (opaque binary; copy the `.wasm` + data files as-is).
- [ ] **IR — already open.** `Entrypoint::Function.language` is a free string;
  `wasm` is in `crates/mvm-ir/data/supported_languages.txt`.
- [ ] **Security note.** The microVM is still the boundary (ADR-002 holds), but
  mvm bakes/owns the py/node wrappers and cannot audit an arbitrary user `.wasm`
  the same way — record this in the posture, don't overclaim.
- [ ] **Example + tests.** `examples/wasm/hello/` (a tiny WASI command),
  compile lane (mirror `compile_hello_app_ts`), E2E boot+invoke on libkrun.

## References
- `specs/notes/wasm-support-exploration.md` — the full exploration (two framings, status).
- `specs/plans/144-wasm-sandbox-backend.md` + `specs/adrs/069-wasm-sandbox-backend.md` — framing A (distinct: the non-prod browser/demo *backend*).
- `specs/adrs/010-function-service-factories.md` §4 — the `mkWasmFunctionService` design note.
