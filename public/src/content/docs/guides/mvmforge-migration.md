---
title: Migrating from mvmforge
description: mvmforge has been merged into mvm. Workloads previously authored against ../mvmforge import from `mvm` instead; the surface is otherwise unchanged.
---

mvmforge — the sibling repo that previously held the workload SDKs —
has been merged into this repo and deprecated. Every author-side
capability now lives under `crates/mvm-sdk/`, `crates/mvm-sdk/sdks/python/mvm/`, and
`crates/mvm-sdk/sdks/typescript/`. There is no longer a cross-repo boundary; one
mvm release ships the substrate and the SDK in lockstep.

## What moved

| mvmforge surface                   | mvm equivalent                                              |
| ---------------------------------- | ----------------------------------------------------------- |
| `mvmforge-ir` crate                | `crates/mvm-ir`                                             |
| `mvmforge-sdk` crate (Rust builder)| `crates/mvm-sdk` (`builder` module)                         |
| `mvmforge-addon` crate             | `crates/mvm-sdk/src/addon/`                                 |
| `mvmforge` host CLI compile path   | `crates/mvm-sdk/src/compile/` + `mvmctl build compile`            |
| `mvmforge-runtime` (in-guest)      | `crates/mvm-runner` + `nix/lib/factories/mkFunctionService` |
| Python SDK (`@mv.func`)            | `crates/mvm-sdk/sdks/python/mvm/` (`@mvm.app`)                             |
| TypeScript SDK                     | `crates/mvm-sdk/sdks/typescript/`                                          |

## Author-side renames

- `@mv.func(...)` → `@mvm.app(...)`
- Package import `mvmforge` → `mvm`
- Env var `MVMFORGE_*` → `MVM_*` (e.g. `MVMFORGE_IR_OUT` → `MVM_IR_OUT`,
  `MVMFORGE_MVM_FLAKE_URL` → `MVM_FLAKE_URL`).
- Generated flake attribute `mvmforge.workload` → `mvm.workload`.
- Lockfile filename `mvmforge.lock` → `mvm.lock`.

There is no compatibility shim. Hard rename per the no-back-compat
decision recorded in the SDK port plan — this is v1 of the merged
surface.

## What's new

- `mvm.python_image({...})` / `mvm.node_image({...})` helpers that
  collapse the most common `image=` decoration into a single call.
- Lifecycle hook kwargs on `@mvm.app(...)`: `before_build`,
  `before_start`, `after_start`, `before_stop`.
- Packaging moved behind control-plane flows. `mvmctl` keeps the local
  compile/build/run surface.
- The Rust-side compile pipeline is now a library (`mvm-sdk::compile`),
  so automation can call into the same rendering primitives without going
  through `mvmctl`.

## Migration steps

1. **Update imports.** Search-and-replace `from mvmforge` →
   `from mvm` (Python) or `from "mvmforge-sdk"` → `from "@runmvm/mvm"`
   (TypeScript).
2. **Rename the decorator.** `@mv.func(...)` → `@mvm.app(...)`. The
   kwargs are unchanged.
3. **Rename env vars.** Any CI script that exports `MVMFORGE_*`
   variables — rename to `MVM_*`.
4. **Update lockfile references.** If your tooling reads
   `mvmforge.lock`, point it at `mvm.lock` (or regenerate via
   `mvmctl addon lock` once the addon CLI lands).
5. **Drop the mvmforge cargo dep.** If you had `mvmforge-ir`,
   `mvmforge-sdk`, or `mvmforge-addon` in your `Cargo.toml`, replace
   with the single `mvm-sdk` workspace dep.

For the full v1 SDK surface see [the SDK
guide](/guides/sdk/).

## What if you're hitting issues

The hard rename is deliberate, so the most common failure mode is a
caller that still references the old name — usually `mvmforge` in an
`import`, `MVMFORGE_*` in CI env, or `mv.func` in a decorator.
Search-and-replace per the table above resolves most of it.

If you hit something the table above doesn't cover — a missing
helper, a behavioural difference at runtime, a CI script that fails
in a way the rename doesn't explain — please open an issue at
[github.com/tinylabscom/mvm/issues](https://github.com/tinylabscom/mvm/issues)
with:

- the mvmforge call site you're porting (the file + the line),
- the equivalent you tried in `mvm`,
- the error you saw (full stderr + exit code).

The maintainer team treats mvmforge → mvm migration friction as a
documentation defect: if you got stuck, this guide is missing a row.
