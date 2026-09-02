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
(default 1), `memory_mib` (default 512), and `env` (accumulates) are optional.

`builder` itself returns a `Result`: `image` is parsed into a `RootfsSource` (an
absolute / `./` / `~/` path or `path:<p>` is a local rootfs, `flake:<ref>#<attr>`
is a flake output, anything else or `oci:<ref>` is a registry reference), so a
declaration that names nothing is refused here rather than at boot. The spec
carries the parsed value and serializes it back as that same string.

```rust
use mvm_client::{LocalBackend, MachineSpec, MvmClient};

// inside an async context:
let client = LocalBackend::new();

let spec = MachineSpec::builder("web", "nginx")?
    .cpus(2)
    .memory_mib(512)
    .build();

let machine = client.run_machine(spec).await?;
let logs = client.machine_logs(&machine.id, Default::default()).await?;
println!("{}", String::from_utf8_lossy(&logs));
client.stop_machine(&machine.id).await?;
```

The builder is equivalent to a struct literal — every field stays public — but
reads far better at call sites and lets new optional fields land without churning
existing callers.

Two `LocalBackend` limits are worth knowing before you build against it:

- `run_machine` and `create_machine` **refuse** a spec with a non-empty `env`.
  The in-process boot path has no delivery seam for guest environment
  variables, and dropping them silently would be worse than failing; use the
  CLI run path when a workload needs env.
- `exec_machine` always returns an error — in-guest exec goes through the
  guest-agent RPC path, which this backend does not wire. `GatewayBackend`
  is unaffected.

### Embedding it — studio, mvmd, and custom frontends

`connect(Target)` returns a `Box<dyn MvmClient>` and hides the transport, so one
piece of UI/service code drives either this host or a remote fleet:

```rust
use mvm_client::{connect, MvmClient, Target};

// In-process — this host's microVMs (auto-selected VMM). No daemon required.
let local = connect(Target::Local)?;          // == mvm_client::LocalBackend::new()

// Remote — a hosted fleet or a local sidecar over REST (feature `remote`).
let remote = connect(Target::Gateway {
    base_url: "https://fleet.example.com".into(),
    token: std::env::var("MVM_TOKEN")?,
})?;

for m in remote.list_machines(Default::default()).await? {
    println!("{}", m.id.0);
}
```

The **studio** desktop app is this pattern: a `GatewayBackend` by default, or the
in-process `LocalBackend` when built `--features local` with
`MVM_STUDIO_BACKEND=local` — one `dyn MvmClient` behind its Tauri commands.

```toml
# a frontend that drives machines. `LocalBackend` is unconditional; the
# `remote` feature adds the REST `GatewayBackend`.
mvm-client = { path = "../mvm/crates/mvm-client", features = ["remote"] }
```

A **host-side daemon that manages instances directly** — the **mvmd** fleet
orchestrator, or your own controller — instead links the `mvmctl` library facade
for the runtime types, host shell seam, and the gated host↔guest IPC transport.
`default-features = false` keeps it lean (no async runtime unless you opt into the
transport):

```toml
# a daemon that runs the host that hosts sandboxes
mvmctl = { path = "../mvm", default-features = false, features = ["hostd-transport"] }
```

```rust
use mvmctl::core::{instance::InstanceStatus, pool::Role, protocol};
use mvmctl::runtime::shell;   // host command-execution seam
```

Rule of thumb: **drive sandboxes → the `MvmClient` facade; run the host that hosts
them → the `mvmctl` facade.**
