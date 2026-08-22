---
title: SDK reference
description: Current and planned language SDK surfaces for mvm.
---

The SDKs share one runtime model:

- `mvm` executes sandboxes and enforces local runtime policy.
- Workload IR is the shared build/deploy contract.
- Runtime recordings and static decorators both lower into the same build path.

## Language status

| Language | Current status | Use today |
| --- | --- | --- |
| Python | Partial runtime SDK plus declarative workload SDK. | Local runtime scripts and static declarations. |
| TypeScript/Node.js | Partial runtime SDK plus declarative workload SDK. | Local runtime scripts and static declarations. |
| Rust | Build-time SDK and lower-level IR contract. | Tooling, generators, and typed declarations. |

## Runtime parity target

The language SDKs should converge on:

- `Sandbox.create(...)`
- `sandbox.commands.run(...)`
- `sandbox.files.read/write/list/remove(...)`
- `sandbox.logs(...)`
- declarative `network.ports` on `Sandbox.create(...)`
- `sandbox.snapshot(...)`
- `sandbox.cold()` / `sandbox.resume()`
- `sandbox.stop()` / `sandbox.destroy()`
- explicit audit/run identifiers in returned results

Methods not implemented in a language SDK should stay documented as planned, not implied by examples.

## Machine wrappers

Python, TypeScript, and Rust also expose thin host-side wrappers for the
beginner `mvmctl machine ...` surface. These wrappers shell through the CLI so
OCI pull, admission, artifact verification, receipts, audit, networking, and
persistent machine state stay owned by `mvmctl`; use `Machine.check_artifact`,
`Machine.checkArtifact`, or Rust `MachineCheckArtifact` for the read-only
`machine check-artifact` preview.

## Related references

- [Sandbox types](/sdk/sandbox-types/)
- [Runtime modes](/sdk/runtime-modes/)
- [Operations cookbook](/sdk/operations-cookbook/)
- [Declaration workflow](/sdk/declaration-workflow/)
- [Declaration cookbook](/sdk/declaration-cookbook/)
- [Lifecycle matrix](/sdk/lifecycle-matrix/)
- [Errors & metrics](/sdk/errors-metrics/)
