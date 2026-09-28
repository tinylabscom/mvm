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
| Rust | Build-time SDK and lower-level IR contract, plus the `MvmClient` runtime client in `mvm-client`. | Tooling, generators, typed declarations, and host-side machine lifecycle. |

## Runtime parity target

The language SDKs should converge on:

- `Sandbox.create(...)`
- a one-shot with a captured result — shipped as `sandbox.exec(...)` in Python and TypeScript
- `sandbox.files.read/write/list/remove(...)` — shipped in Python and TypeScript
- `sandbox.logs(...)`
- declarative `network.ports` on `Sandbox.create(...)`
- `sandbox.snapshot(...)`
- `sandbox.cold()` / `sandbox.resume()`
- `sandbox.stop()` / `sandbox.destroy()`
- explicit audit/run identifiers in returned results

Methods not implemented in a language SDK should stay documented as planned, not implied by examples.

## Machine wrappers

Python and TypeScript also expose `Machine`, a host-side handle for
machine lifecycle: `run` (boot a transient machine), `create` (persist a
named definition), `start`, `stop`, `rm`, `inspect`, `logs`, `ls` (the host
inventory, with each machine's dev/prod posture), and `exec` on a dev
machine. Like `Sandbox`, each call goes to `libmvm_hostlib` in-process —
OCI resolution, admission under a signed plan, audit, and persistent machine
state stay owned by `mvm-client`, and the SDK never runs `mvmctl`. Rust
programs use `mvm-client` directly; see the
[Rust quickstart](/getting-started/rust-quickstart/).

Artifact preview (`mvmctl machine check-artifact`) and interactive shells are
CLI-only.

## Related references

- [Sandbox types](/sdk/sandbox-types/)
- [Runtime modes](/sdk/runtime-modes/)
- [Operations cookbook](/sdk/operations-cookbook/)
- [Declaration workflow](/sdk/declaration-workflow/)
- [Declaration cookbook](/sdk/declaration-cookbook/)
- [Lifecycle matrix](/sdk/lifecycle-matrix/)
- [Errors & metrics](/sdk/errors-metrics/)
