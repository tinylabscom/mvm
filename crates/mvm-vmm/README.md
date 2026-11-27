# mvm-vmm

`mvm-vmm` contains the backend-agnostic virtual-machine monitor model. It
defines the hypervisor and driver traits, shared virtio devices, guest-memory
access, host-process helpers, checkpoint formats, and vsock transport, and it
holds the concrete Firecracker, HVF, libkrun and QEMU drivers behind the `fc`,
`hvf`, `libkrun` and `qemu` features. The default build has none of them.

## Who uses it

`mvm-runtime`, `mvm-client` and `mvm-cli` enable all four driver features;
`mvm-runtime` assembles those drivers into workload lifecycles. `mvm-build`, `mvm-hostd`, and
`mvm-cli` use its boot, supervisor, checkpoint, and host-resource types.

## How it works

There are two related abstraction levels:

1. `hv::HypervisorVm` and `HypervisorVcpu` abstract low-level memory mappings,
   vCPU exits, interrupts, and device notification.
2. `driver::VmmDriver` abstracts a complete backend process from the runtime,
   using `VmmSpec` and lifecycle/checkpoint operations.

The shared `vmm` engine loads a kernel into guest memory, constructs the FDT,
registers virtio-mmio devices, runs vCPUs, and dispatches exits to those
devices. The driver layer lets Firecracker, HVF, libkrun, and QEMU participate
in the same higher-level lifecycle even when they do not all use the in-process
device engine.

Host support modules prepare inherited descriptors, command lines, runtime
metadata, brokers, consoles, audit endpoints, and workload exit observation.
Vsock modules provide the common guest transport and the egress bridge.

## Main modules

| Module | Responsibility |
|---|---|
| `driver` | Portable full-backend trait and launch specification |
| `vmm` | Guest memory, kernel loading, vCPU loop, and virtio devices |
| `host` | Host-side launch resources and process helpers |
| `checkpoint` / `snapshot` | Portable lifecycle state and integrity metadata |
| `quota` | Runtime resource quota policy and control |
| `vsock_transport` | Backend-neutral guest communication |
| `vsock_egress_bridge` | Guest traffic mediation over vsock |
| `post_restore` | State repair and validation after restore |
| `driver::{fc, hvf, libkrun, qemu}`, `fc` | Concrete drivers and Firecracker host mechanics, one feature each |
| `mock` | Hypervisor-free `VmmDriver` test double |
| `run_sidecars` | Clearing a run's leftover sidecars before the next boot |

## Design boundaries

This crate does not select a backend, perform workload admission, or own CLI
state. Concrete platform calls belong in the feature-gated driver modules;
orchestration and persistence belong in `mvm-runtime`.

## Developing

Run `cargo test -p mvm-vmm`. Device and wire changes require round-trip,
malformed-input, and bounds tests. Shared trait changes must also pass the
gated-target check so Linux-only implementations are compiled.
