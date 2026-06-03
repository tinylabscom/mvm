# WebAssembly support — exploration findings (2026-06-03)

Exploration only (no code). Captures where wasm stands after Python + TypeScript
function workloads shipped (`v0.15.2`), so a follow-up session can start from the
map rather than re-deriving it.

## Bottom line

We do **not** support wasm yet, in either of the two senses it's been framed:

| # | Framing | What it is | Status |
|---|---------|-----------|--------|
| **A** | `wasm-sandbox` **backend** (Plan 144, ADR-069) | Portable, **non-production** sandbox — `--hypervisor wasm-sandbox` (alias `browser`). `kvm=false, vsock=false, virtio=false`; in-memory virtual FS; logical snapshots. **Not** microVM isolation. | **Unstarted** — Plan 144 = 0/46 tasks; ADR-069 "Proposed"; gated on Plans 120/121/134. Slice 1 even mocks the runner — real `wasmtime`/WASI is a *deferred follow-up*. |
| **B** | wasm as a workload **language** | A `.wasm` function run **inside a real hardened microVM** via `wasmtime run` — same compile→build→boot→invoke spine as Python/TS, full ADR-002 isolation. | **~30% scaffolded** — guest runner + IR accept it; nix bake + declaration path missing. |

## Recommendation: pursue B (wasm-as-language), defer A

B is the natural sibling to the Python/TS work, gives **real isolation** (A
explicitly doesn't), fits the data-driven language registry, and its hardest
half (guest-side dispatch) is **already coded**. A is a separate product
(browser/demo sandbox), explicitly non-prod, a bigger lift (new `VmBackend` +
capabilities matrix + control-plane shim), and gated on other plans. The rest of
this note is about B.

## B — what already exists

- **Guest runner dispatch:** `crates/mvm-runner/src/config.rs:23-58` — `Language::Wasm`,
  program `wasmtime`, default module `dispatch.wasm`; `crates/mvm-runner/src/main.rs:154`
  does `wasmtime run <module>`. Doc comment: the `.wasm` itself satisfies the
  stdin→fn→stdout wire contract via WASI; "generic across any compile-to-WASM
  (Rust/Go/Kotlin/Wasm…) per ADR-0010 §4".
- **IR:** `Entrypoint::Function.language` is an open string; `language="wasm"` is
  in `crates/mvm-ir/data/supported_languages.txt` (validator accepts it).
- **Registry intent:** `nix/lib/factories/languages/default.nix` comment —
  "wasm … becomes a row with `interpreter = null` + a wrapper-kind discriminator".
- **Design note:** `specs/adrs/010-function-service-factories.md` (`mkWasmFunctionService`),
  `specs/plans/15-wasm-container-support.md` (older).

## B — what's missing (the seams a build would touch)

1. **Nix bake** — a `wasm` case in `nix/lib/factories/mkFunctionService.nix` (+ the
   registry): `servicePackages = [ pkgs.wasmtime ]`, bake the user's module at the
   working dir (`/app/dispatch.wasm`), write `/etc/mvm/runtime.json` with
   `language=wasm`. **No wrapper script** — unlike py/node, the `.wasm` *is* the
   entrypoint; the runner already runs `wasmtime run`. Needs the registry's
   `interpreter=null` + wrapper-kind branch the comment describes.
2. **Declaration path (the crux — real design work).** A `.wasm` is an opaque
   binary: no `@mvm.app`/`mvm.app({...})(fn)` AST to parse. Options to decide:
   a manifest (`mvm.toml`), CLI flags (`mvmctl compile foo.wasm --function <export>`),
   or hand-authored IR-JSON (`--from-ir`, already supported). This is the main new
   decision and the right thing to brainstorm first.
3. **Contract.** A WASI command module (target `wasm32-wasi`) that reads stdin
   `[args, kwargs]` and writes the encoded result to stdout — same protocol as the
   py/node wrappers. An SDK shim would provide the dance so user code stays plain.
   **Security caveat:** mvm bakes + owns the py/node wrappers; it cannot audit an
   arbitrary user `.wasm` the same way. The isolation boundary is still the microVM
   (ADR-002 holds), but the in-guest dispatch code is the user's — note this in the
   posture.
4. **Compile.** Skip reachability + framework-strip for wasm (opaque binary; copy
   the `.wasm` + any data files as-is). `crates/mvm-sdk/src/compile/orchestrator.rs`
   would gain a `language=="wasm"` branch that bypasses the tree-sitter walk.

## References
- `specs/plans/144-wasm-sandbox-backend.md` + `specs/adrs/069-wasm-sandbox-backend.md` — framing A.
- `specs/adrs/010-function-service-factories.md` §4 — framing B design note (`mkWasmFunctionService`).
- `crates/mvm-runner/src/{config,main}.rs` — the coded `Language::Wasm` dispatch.
- `nix/lib/factories/languages/{registry,default}.nix` — the data-driven registry the wasm row plugs into.
