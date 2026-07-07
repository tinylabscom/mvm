---
title: Rust SDK
description: Rust build-time SDK and Workload IR contract.
---

Rust has two SDK surfaces:

- **Authoring** — `mvm-sdk`: build Workload IR (the same IR the Python/TypeScript
  decorators emit).
- **Runtime** — `mvm-client`: the `MvmClient` facade for driving machines
  (create/run/exec/stop/reconfigure), shared with the CLI, the GUI, and the
  fleet orchestrator.

## Authoring — build Workload IR (`mvm-sdk`)

Current:

- Workload and app builders;
- image, source, resources, network, entrypoint helpers;
- Workload IR emission;
- static decorator parsing support in `mvm-sdk`;
- runtime recording types and lowering.

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

## Runtime — drive machines (`mvm-client`)

The `MvmClient` trait is the runtime SDK: a `LocalBackend` drives the host
in-process, and a `GatewayBackend` (feature `remote`) drives a remote fleet over
REST. Both speak the same `MachineSpec` intent type.

Build a `MachineSpec` fluently with `MachineSpec::builder(name, image)` — the two
required fields are supplied up front, so `build()` is infallible; `cpus`
(default 1), `memory_mib` (default 512), and `env` (accumulates) are optional:

```rust
use mvm_client::{MvmClient, MachineSpec};
use mvm_client_local::LocalBackend;

// inside an async context:
let client = LocalBackend::new();

let spec = MachineSpec::builder("web", "nginx")
    .cpus(2)
    .memory_mib(512)
    .env("PORT", "8080")
    .build();

let machine = client.run_machine(spec).await?;
let out = client
    .exec_machine(&machine.id, vec!["nginx".into(), "-v".into()])
    .await?;
println!("{}", String::from_utf8_lossy(&out.stderr));
client.stop_machine(&machine.id).await?;
```

The builder is equivalent to a struct literal — every field stays public — but
reads far better at call sites and lets new optional fields land without churning
existing callers.
