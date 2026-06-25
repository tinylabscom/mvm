---
title: Rust SDK
description: Rust build-time SDK and Workload IR contract.
---

The Rust SDK is the typed authoring and lowering surface for `mvm`.

Current:

- Workload and app builders;
- image, source, resources, network, entrypoint helpers;
- Workload IR emission;
- static decorator parsing support in `mvm-sdk`;
- runtime recording types and lowering.

Planned:

- high-level local runtime lifecycle client;
- shared fixture parity with Python and TypeScript runtime clients.

## Example

```rust
use mvm_sdk::*;

let workload = workload("worker")
    .app(
        app("worker")
            .source(local_path("."))
            .image(nix_packages(["python312"]))
            .entrypoint(entrypoint_command(["python", "-m", "worker"]))
            .resources(resources(1, 256, 512))
            .build()?,
    )
    .build()?;
emit(&workload)?;
```

Rust is the right layer for tools that generate or validate Workload IR directly.
