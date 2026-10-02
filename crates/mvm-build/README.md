# mvm-build

`mvm-build` turns workload declarations and external artifacts into verified,
bootable mvm artifact sets. It owns the Nix/builder pipeline, acquisition and
cache logic, guest image assembly, provenance, and the protocols used to drive
isolated builder VMs.

## Who uses it

`mvm-cli` exposes build and bootstrap commands, `mvm-runtime` consumes built
artifacts for launch, `mvm-client` uses build results in the local facade, and
`mvm-hostd` uses build identities during admission and execution. The root
`mvmctl` crate re-exports it. `mvm-conformance` exercises it in development.

## How it works

A build begins with a canonical workload or Nix manifest. The pipeline resolves
the required kernel, rootfs, initramfs, runtime overlay, SDK sidecar, and guest
agent. Content can be acquired from signed releases, OCI registries, local Nix
outputs, or an isolated persistent/ephemeral builder.

Builder VM images are treated as published artifacts by default: `mvmctl` will
fetch and verify the pinned builder image from the signed image set. Building
the builder VM from a local `mvm-images` checkout is supported for contributors
but is opt-in only — set `MVM_IMAGES_DIR` and `MVM_ALLOW_LOCAL_BUILDER_BUILD=1`
to enable a local build. This keeps ordinary developer and CI invocations fast
and deterministic while preserving the contributor workflow for image work.

Builder commands cross a versioned protocol rather than sharing arbitrary host
shell state. Inputs and outputs are staged explicitly, egress readiness is
checked before dependency installation, and artifacts are verified before
entering the cache. The final packed artifact records runtime identity and
provenance so admission can bind the files that are later booted.

## Main areas

| Area | Representative modules |
|---|---|
| Pipeline | `pipeline`, `artifacts`, `run_image`, `packed_artifact` |
| Acquisition | `artifact_acquisition`, `kernel_fetch`, `release_signature` |
| Builder VM | `builder_vm`, `persistent_builder`, `builderd`, `builder_protocol` |
| Guest images | `rootfs`, `initramfs`, `rootfs_inject`, `oci_runtime_inject` |
| Toolchain | `nix`, `app_deps`, `embed_toolchain`, `guest_agent_build` |
| Networking | `builder_route`, `egress_proxy`, `egress_readiness` |
| Integrity | `provenance`, `runtime_identity`, `cache`, `cache_install` |

## Features

Builder orchestration and pure ext4 materialization are unconditional library
capabilities. The remaining opt-ins are `manifest-verify`,
`contributor-bootstrap`, and `release-channel`; native libkrun linkage remains
behind the `libkrun-sys` crate's own feature. Platform-specific operations still
run only on supported hosts.

## Developing

Run `cargo test -p mvm-build`. Nix evaluation, builder-VM operations, and
Linux-specific checks must run in the project builder VM. Artifact changes need
cache-hit/miss, digest mismatch, partial-transfer, and provenance tests.
