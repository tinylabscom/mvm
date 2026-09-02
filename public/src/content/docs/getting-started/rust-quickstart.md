---
title: Rust quickstart
description: Declare mvm workloads from Rust and emit Workload IR.
---

Rust has both an authoring surface (`mvm-sdk`, the ground-truth type model for
Workload IR) and a runtime surface (`mvm-client`, the `MvmClient` lifecycle
facade shared with the CLI and the fleet orchestrator).

> **Status:** `crates/mvm-sdk` ships build-time workload builders and the runtime recording/lowering contract; `crates/mvm-client` ships the `MvmClient` runtime facade (`LocalBackend` in-process, `GatewayBackend` over REST).

## Build-time declaration

```rust
use mvm_sdk::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workload = workload("hello-rust")
        .app(
            app("hello")
                .source(local_path("."))
                .image(nix_packages(["bash", "coreutils"]))
                .entrypoint(entrypoint_command(["bash", "-lc", "echo hello from mvm"]))
                .resources(resources(1, 256, 512))
                .build()?,
        )
        .build()?;

    emit(&workload)?;
    Ok(())
}
```

Pipe the generated IR into the normal compile/build path used by the CLI.

## Runtime lifecycle

Drive machines from Rust with the `MvmClient` facade. `MachineSpec::builder`
gives a fluent, forward-compatible way to describe what to run:

```rust
use mvm_client::{LocalBackend, MachineSpec, MvmClient};

// inside an async context:
let client = LocalBackend::new();

let spec = MachineSpec::builder("web", "nginx")?
    .cpus(2)
    .memory_mib(512)
    .env("PORT", "8080")
    .build();

let machine = client.run_machine(spec).await?;
println!("started {}", machine.name);
client.stop_machine(&machine.id).await?;
```

See the [Rust SDK reference](/sdk/rust/) for the authoring and runtime surfaces
side by side.

## When to use Rust

- You need typed Workload IR construction.
- You are writing mvm-adjacent tooling.
- You need to validate generated plans before exposing them through a higher-level SDK.

Use Python or TypeScript when your application needs an ergonomic sandbox lifecycle today.
