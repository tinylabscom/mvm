# mvm-backends

`mvm-backends` implements the concrete VMM drivers used by mvm. It translates
the portable `mvm-vmm` driver contract into Firecracker, Hypervisor.framework,
libkrun, and QEMU mechanics while leaving workload orchestration to
`mvm-runtime`.

## Who uses it

`mvm-runtime` selects these drivers and wraps them in machine lifecycle logic.
`mvm-cli` enables the backend features requested by the product surface. The
crate is not intended as a user-facing API.

## How it works

Each driver consumes a validated `VmmSpec`, creates platform resources, starts
or attaches to its VMM, exposes a lifecycle handle, and implements stop,
observation, checkpoint, and restore capabilities supported by that backend.
Process-based backends use dedicated process modules; the in-house HVF path
implements the low-level hypervisor traits and reuses the shared device model.

Firecracker support is split further because it owns a daemon API socket,
namespace setup, control requests, snapshots, host resources, and event-driven
process observation. Guards use RAII so partial launch failures tear down only
resources created by that attempt.

## Main modules

| Module | Responsibility |
|---|---|
| `driver::fc` | Firecracker `VmmDriver` implementation |
| `driver::hvf` | In-house macOS Hypervisor.framework driver |
| `driver::libkrun` | libkrun supervisor-backed driver |
| `driver::qemu` | Development/test QEMU driver |
| `fc` | Firecracker API, lifecycle, snapshot, namespace, and I/O helpers |
| `mock` | Deterministic driver used by higher-level tests |

## Features and platforms

The default feature set is empty. `test-support` exposes fixtures and controls
needed by downstream tests. Firecracker and Linux-specific behavior is gated
by target OS; HVF is macOS-only. Unsupported platforms compile the portable
surfaces but cannot start the corresponding backend.

## Developing

Run `cargo test -p mvm-backends` on the host for portable tests. Linux/KVM and
Firecracker tests run only in the approved builder/test environment, while
explicit HVF live tests run on macOS. Always compile Linux-gated targets after
changing a shared driver type.
