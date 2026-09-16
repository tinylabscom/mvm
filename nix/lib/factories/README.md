# mvm Nix function-service factory

`mkFunctionService` bakes the wrapper + entrypoint files that mvm's
`RunEntrypoint` verb consumes (mvm ADR-005). Bundled into every
mvm-emitted artifact when the workload declares
`entrypoint.kind = "function"` (plan 0003 / ADR-0009).

For the common single-app, single-function case, prefer the
**`mkFunctionWorkload`** one-call helper at `nix/lib/mkFunctionWorkload.nix`
(plan 71). It reads the workload IR JSON, composes this factory
with `mkGuest`, and returns the rootfs derivation directly:

```nix
packages.${system}.default = mvm.lib.${system}.mkFunctionWorkload {
  irFile = ./workload-ir.json;
  appPkg = ./src;
};
```

This factory remains the recommended entry point when you need
custom `mkGuest` composition (multi-app workloads, hand-rolled
network policy, mounts, addons, …). The helper rejects those
shapes with an explicit pointer to this composition path.

## Files

- `mkFunctionService.nix` — single generic factory. Dispatches on the
  `language` input to the registry under `languages/`.
- `languages/registry.nix` — the language registry, data only. One row per
  language: the interpreter package (`python3`, `nodejs_22`), the wrapper
  directory under `nix/wrappers/`, the wrapper extension, and an optional
  shebang stamp.
- `languages/default.nix` — the generic builder that turns each registry row
  into `{ language, runnerScript, servicePackages }`.

WASM is not yet in the registry — the user's `.wasm` IS the wrapper
(no interpreter package, different input semantics), so it will land
either as a registry entry with a tagged `wrapperKind` field or as a
sibling `mkWasmFunctionService` factory. Decision pending.

## Adding a language

One data row, no new `.nix` file, no dispatcher edit, no caller-side switch:

1. Add a row to `languages/registry.nix`, and the wrapper scripts
   (`oneshot.<ext>`, `longrunning.<ext>`) under `nix/wrappers/<dir>/`.
2. Append the bare name to
   `crates/mvm-contract/data/supported_languages.txt` so the IR validator
   accepts it as an `Entrypoint::Function.language` value.
3. Append the name to the `languageResults = map testLanguage [ ... ]` list
   in the repository-root `tests/factory_shape.nix`.

## Contract

```nix
mkFunctionService {
  pkgs,         # nixpkgs.legacyPackages.<system>
  language,     # "python" | "node" — registry key
  workloadId,   # workload id from the IR
  module,       # IR entrypoint.module
  function,     # IR entrypoint.function
  format,       # IR entrypoint.format ("json" | "msgpack")
  appPkg,       # the user-source derivation (per ADR-0008)
  sourcePath ? "/app",
  concurrency ? null,   # ADR-0011 — opts into warm-process tier
}
```

Returns the `{ extraFiles, servicePackages, service }` triple a
downstream `mkGuest` composition layer consumes.

`extraFiles` always contains:
- `/etc/mvm/entrypoint` → `/usr/lib/mvm/wrappers/runner`
- `/usr/lib/mvm/wrappers/runner` → the language's wrapper script
  (cold-tier `oneshot.*` or warm-tier `longrunning.*` depending on
  `concurrency`).
- `/etc/mvm/wrapper.json` → wrapper config (module, function, format,
  working_dir, mode).
- `/etc/mvm/runtime.json` → agent config (language, module, function,
  format, source_path, optional concurrency).

## Hardening invariant

v1 wrapper hardening lives inside the per-language wrapper sources
(`nix/wrappers/<lang>/{oneshot,longrunning}.{py,mjs}`), which mirror
the audited Rust `mvm-runner` crate's semantics. A follow-up PR
replaces the inlined script with the compiled `mvm-runner` binary
baked at `/usr/lib/mvm/wrappers/runner`. Until then, **changes to
mvm-runner's hardening must be mirrored into the wrappers** (and
vice versa).

## Nix checks and the Rust harness

A property of a guest can be asserted from a Nix check or from a Rust test.
Decide which one owns it before writing either:

- **A Nix check provides the package and the session environment.** It builds
  the derivation and fails only on what a realized derivation alone can show: a
  store path entering a closure, a closure over its budget, an output that does
  not build. `guest-rootfs-no-glibc` and `guest-rootfs-package-budget` in
  `nix/flake.nix` are the shape.
- **The Rust harness owns behavioral assertions.** What the wrapper, the
  entrypoint or the agent does once it runs — exit status, output, the audit
  entry, the refusal — is asserted in a `cargo nextest` test, not in a
  `runCommand` script.
- **Never catalog one assertion in both.** Two copies drift, and the drift stays
  invisible until one of them is wrong. When a Nix build needs a behavior to
  hold, it runs the Rust tests that assert it: `nix/packages/mvmctl.nix` sets
  `doCheck` so its check phase runs the crates' own suites rather than restating
  them in shell.
