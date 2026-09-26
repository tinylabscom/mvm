---
title: Rust quickstart
description: Declare, launch and drive mvm workloads from Rust with one dependency, mvm-client.
---

A Rust program depends on one crate, `mvm-client`. It carries the runtime
surface (the `MvmClient` lifecycle facade shared with the CLI and the fleet
orchestrator, and `LocalBackend`, which admits and boots on this host) and
re-exports the authoring surface as `mvm_client::authoring`, so the same
dependency declares a workload, launches it, and drives its guest.

```toml
[dependencies]
mvm-client = { git = "https://github.com/tinylabscom/mvm" }
```

> **Status:** `mvm-client` ships `LocalBackend` (in-process) and, behind the
> `remote` feature, `GatewayBackend` over REST. The Python and TypeScript SDKs
> reach the same surface in-process through `libmvm_hostlib`, a C ABI over this
> crate; none of them runs `mvmctl`.

## Build-time declaration

```rust
use mvm_client::authoring::*;

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

`LaunchRequest` describes what to boot. Every field is validated when the
request is built, and a field the in-process launcher cannot honour yet (a
command override, guest environment variables) is refused there rather than
dropped. Egress is a grant: it is signed into the plan the machine is admitted
under, and the host egress gate reads it from there.

```rust
use mvm_client::{LaunchRequest, LifecycleMode, LocalBackend, MvmClient, RootfsSource};

// inside an async context:
let client = LocalBackend::new();

let image: RootfsSource = "docker.io/library/nginx:1.27".parse()?;
let request = LaunchRequest::builder(LifecycleMode::Transient, image)
    .name("web")
    .cpus(2)
    .memory_mib(512)
    .port("8080:80")
    .allow_egress("api.example.com", 443)
    .ttl_seconds(1800)
    .build()?;

let launched = client.launch(request).await?;
println!("started {} under plan {}", launched.machine.name, launched.plan_id);

client.stop_machine(&launched.machine.id).await?;
```

`client.create_machine(...)` and `client.start_machine(...)` persist a named
definition and boot it later; `mvm_client::inventory::list_local_inventory`
lists every machine on the host with its dev/prod posture.

### Driving a dev machine's guest

On a machine whose posture is `dev`, `mvm_client::guest` runs processes and
touches files through the guest agent, with the same audit entries as
`mvmctl machine proc` and `fs`. A sealed production machine refuses these.

```rust
use mvm_client::guest::{self, ProcStart, ProcWaitEvent};

fn run_in_guest(machine: &str) -> Result<(), Box<dyn std::error::Error>> {
    let token = guest::start_process(
        machine,
        ProcStart {
            argv: vec!["uname".into(), "-a".into()],
            ..ProcStart::default()
        },
    )?;
    let ended = guest::wait_process(machine, &token, Some(30), |event| {
        if let ProcWaitEvent::Stdout { chunk } = event {
            print!("{}", String::from_utf8_lossy(chunk));
        }
    })?;
    println!("{ended:?}");
    Ok(())
}
```

See the [Rust SDK reference](/sdk/rust/) for the authoring and runtime surfaces
side by side.

## When to use Rust

- You need typed Workload IR construction.
- You are writing mvm-adjacent tooling.
- You need to validate generated plans before exposing them through a higher-level SDK.

Use Python or TypeScript when your application needs an ergonomic sandbox lifecycle today.
