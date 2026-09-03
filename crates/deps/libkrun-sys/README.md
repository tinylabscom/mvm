# libkrun-sys

`libkrun-sys` is mvm's narrow Rust binding and safe lifecycle wrapper for Red
Hat libkrun. libkrun is linked into a supervisor process and runs guests with
KVM on Linux or Hypervisor.framework on Apple Silicon macOS.

## Who uses it

`mvm-backends` implements the libkrun VMM driver with this crate. `mvm-build`
uses it for the optional libkrun builder path, `mvm-hostd` runs the dedicated
libkrun supervisor, and `mvm-cli` exposes feature-gated live support.
`mvm-runtime` uses it in tests and integration wiring.

## Build modes

| Feature | Behavior |
|---|---|
| default | Builds without libkrun or FFI; live entry points report unavailable |
| `libkrun-sys` | Compiles checked-in bindings and links against `libkrun` |

The stubbed default keeps workspace builds portable on machines where libkrun
is not installed. The live feature must only be enabled where the matching
native library and platform hypervisor are available.

## How it works

1. Availability helpers locate an installation and provide actionable errors.
2. `KrunContext` configures memory, CPUs, kernel/rootfs, environment, devices,
   and inherited file descriptors through a safe Rust API.
3. `start` validates the configuration and transfers it to the FFI context.
4. `supervisor` holds the long-running process boundary and exchanges bounded
   framed control messages with its parent.
5. `stop` and the supervisor protocol coordinate lifecycle completion.

Unsafe code is confined to the checked-in bindings and their small wrapper
boundary. Backend selection, workload admission, network policy, and general
runtime orchestration live in higher-level crates.

## Main modules

| Module | Responsibility |
|---|---|
| `context` | Safe configuration types and `KrunContext` |
| `start` | Guest entry and boot calls |
| `supervisor` | Long-lived supervisor configuration and loop |
| `framing` | Bounded parent/supervisor messages |
| `error` | Availability probing and typed failures |
| `sys` | Generated/raw FFI plus bundled-kernel helpers |

## Developing

Run `cargo test -p libkrun-sys` for the portable path. Live tests require the
repository's explicitly selected libkrun environment. Any FFI change needs
layout/ABI checks, error-path coverage, and a review of ownership across every
C pointer and callback.
