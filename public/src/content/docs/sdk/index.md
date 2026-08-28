---
title: SDK overview
description: "The two SDK surfaces mvm exposes: runtime lifecycle APIs and decorator-style workload declarations."
---

`mvm` has two SDK surfaces because sandbox users have two different jobs.

| Surface | Best for | Current status |
| --- | --- | --- |
| Runtime SDK | Create a sandbox from application code, run commands, move files, snapshot, and stop it. | Partial in Python and TypeScript; Rust ships the `MvmClient` lifecycle client in `mvm-client`. |
| Decorator SDK | Declare a reproducible workload in source code and compile it into `mvm` Workload IR. | Available for build-time declarations. |

The runtime SDK is the imperative surface: your app owns a sandbox lifecycle. The decorator SDK is the declarative surface: your source file declares what should be built and executed.

The parity target is product behavior, not a copy of another site: application developers should get simple lifecycle ergonomics, while platform developers get decorators that compile into secure `mvm` Workload IR.

Both surfaces target the same runtime model:

- `mvm` owns local microVM lifecycle, image materialization, guest communication, signed plans, and host-side enforcement.
- Nix-built microVM artifacts are the preferred path for reproducibility and auditability.
- OCI images are compatibility inputs and must pass through verification, cache scoping, and launch policy before execution.

## What runs where

| Code | Runs on | Notes |
| --- | --- | --- |
| Your SDK client | Host process | Owns lifecycle and receives errors/logs. |
| Static decorator compiler | Host, without importing user code | Reads declarations and emits Workload IR. |
| Workload entrypoint | Guest microVM | Runs behind guest/host policy boundaries. |
| Runtime admission | `mvm` | Verifies local plans and launches the microVM backend. |

## Security defaults

The SDK docs use conservative language until implementation and tests prove stronger behavior:

- Secret examples use references, not plaintext values.
- Mutable OCI tags are local development examples only.
- Network access is deny-by-default unless a page says otherwise.
- Planned APIs are labeled Planned and should not be copied as shipped code.
- Strong product claims link back to [the security claim ledger](/security/claim-ledger/).

## Next

- [Runtime SDK](/sdk/runtime/) for lifecycle-oriented APIs.
- [SDK security model](/sdk/security-model/) for host execution, guest execution, secrets, network, audit, and state-retention rules.
- [Operations cookbook](/sdk/operations-cookbook/) for current SDK calls, target helpers, and CLI fallbacks.
- [Decorator SDK](/sdk/decorator/) for workload declarations and static compile.
- [Declaration cookbook](/sdk/declaration-cookbook/) for concrete decorator-style Python and TypeScript declarations.
- [Sandbox types](/sdk/sandbox-types/) for product-level helper patterns.
- [Lifecycle matrix](/sdk/lifecycle-matrix/) for current CLI support, current SDK support, and SDK parity targets.
- [Errors & metrics](/sdk/errors-metrics/) for the error/result shape target.
