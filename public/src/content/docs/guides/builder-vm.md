---
title: "Builder VM"
description: How mvm builds Linux microVM images from the host without requiring you to enter a dev shell or install host-side Nix.
---

The short version: **you run `mvmctl build` from the host, and mvm runs Nix inside the builder VM.** You do not need to enter an interactive dev shell to build a template or runtime image.

The host process is the control plane. The builder VM is the Linux execution boundary for Nix evaluation, Nix builds, and image assembly. The runtime backend is separate: after the image is built, mvm boots the prebuilt kernel and rootfs with the selected microVM backend, such as Firecracker on Linux or Apple Virtualization on macOS.

```text
macOS or Linux host
  |
  | mvmctl build --flake .
  v
host-side mvmctl process
  |
  | stages flake, job metadata, and artifact directory
  v
builder VM
  |
  | runs nix eval / nix build on Linux
  v
host artifact cache
  |
  | mvmctl up --hypervisor apple-container
  v
runtime microVM
```

## What Runs Where

| Work | Runs on | Why |
|---|---|---|
| CLI parsing, config loading, cache lookup | Host | Fast local control-plane work. |
| Nix flake evaluation | Builder VM | The target is a Linux image, and the build environment must be Linux. |
| `nix build` | Builder VM | Keeps host Nix optional and avoids macOS/Linux platform mismatch. |
| Rootfs and kernel artifact extraction | Builder VM, then host cache | The builder produces artifacts; the host stores and reuses them. |
| Runtime boot | Runtime backend | Uses an already-built image. This is Firecracker, Apple Virtualization, libkrun, or another backend. |
| Runtime guest agent traffic | Runtime microVM | Uses the runtime VM's guest communication path, normally vsock where supported. |

This separation is deliberate. A build can take seconds or minutes because it may fetch and compile Nix closures. A runtime boot benchmark should normally measure only the already-built image booting, not the build phase.

## You Do Not Need a Dev Shell to Build

The normal build command is:

```bash
mvmctl build --flake .
```

That command should be run from your project directory on the host. `mvmctl` takes care of starting or reaching the builder VM, staging the flake, running the build, and copying the result back.

Use an interactive shell only when you want to debug the builder environment:

```bash
mvmctl dev shell
```

Examples of things a dev shell is useful for:

- inspecting the Linux build environment;
- manually running `nix build` to debug a flake error;
- checking disk usage in the builder VM's Nix store;
- reproducing an issue that only appears inside the Linux build boundary.

Examples of things that should not require a dev shell:

- `mvmctl build --flake .`;
- `mvmctl run`;
- `mvmctl up --flake .`;
- building a registered template;
- booting a prebuilt runtime image.

## Build Then Boot

For an explicit two-step flow:

```bash
# 1. Build the runtime image.
mvmctl build --flake .

# 2. Boot the already-built image.
mvmctl up --flake . --hypervisor apple-container
```

On macOS, `--hypervisor apple-container` selects the Apple Virtualization runtime backend when available. The builder VM remains a build-time implementation detail. It is not the same VM as your workload VM.

For development convenience, `mvmctl run` combines the two phases:

```bash
mvmctl run
```

That is equivalent to "build if needed, then boot." It is convenient for daily use, but it is not the right measurement point if you are trying to isolate runtime boot latency.

## Builder VM vs Runtime MicroVM

The builder VM and runtime microVM have different jobs:

| VM | Purpose | Lifetime | State |
|---|---|---|---|
| Builder VM | Runs Linux Nix builds and image assembly. | Reused or launched as needed by the build pipeline. | Has a warm Nix store/cache. |
| Runtime microVM | Runs your workload from a finished image. | Created by `mvmctl up`, `run`, `exec`, or tests. | Uses the built rootfs/kernel artifacts. |

Do not benchmark the builder VM when you want runtime boot time. The builder VM exists so that the host can ask for Linux builds without becoming a Linux build machine itself.

## Persistent builder personas

There are two builder personas in the developer experience:

| Persona | Command shape | Interaction model | Purpose |
|---|---|---|---|
| Developer builder VM | `cargo run -- dev up` / `mvmctl dev up` | Persistent and debuggable; may open an interactive shell with `--shell`. | Keep the Linux development/build boundary warm while a developer iterates. |
| Build worker VM | `cargo run -- build` / `mvmctl build` | Persistent but non-interactive. | Run normal Nix/image build jobs without making the user manage the VM. |

The low-level persistent-builder controls already exist:

```bash
mvmctl persistent-builder start --workspace .
mvmctl persistent-builder status
mvmctl persistent-builder submit --flake path:/work --attr packages.aarch64-linux.default
mvmctl persistent-builder stop
```

`mvmctl build` also has an explicit escape hatch:

```bash
mvmctl build --no-persistent-builder
```

The intended top-level DX is that developers do not need to invoke the low-level controls for normal use. `dev up` should ensure the interactive/developer builder is present, and `build` should use a persistent non-interactive builder by default when the platform supports it. If the persistent path is unavailable, the command should say why it fell back rather than silently changing the trust and performance model.

## Communication Model

From the user's perspective, the interface is the host command:

```bash
mvmctl build --flake .
```

Internally, mvm stages the build request into the builder boundary: source path, selected profile, target system, output directory, and job metadata. The builder runs the Linux-side build and returns structured artifact metadata to the host.

The exact transport is backend-specific. Implementations may use mounted job directories, virtio-fs, a control socket, vsock, or a small supervisor process. That detail should not leak into the user workflow. The contract is:

1. the host starts the request;
2. the builder VM performs Linux-only work;
3. the host receives a kernel/rootfs artifact set;
4. runtime commands boot those artifacts.

## Resident builder control plane

The builder VM does not expose a shell or a free-form command channel. Build
work is driven by a small resident service, `mvm-builderd`, baked into the
builder rootfs at `/sbin/mvm-builderd` and started at boot. The host `mvmctl`
connects to it over vsock and sends **typed, allowlisted requests** — there is
no "run this command in the builder" primitive.

The request set is fixed and enumerated: a version handshake, a capability
probe, a flake check, a guest-image build, a host-tool build, a source
prefetch, a store-path query, and a job cancel. Each one streams structured
progress and log chunks back and ends in a typed terminal result — an artifact
or store path, a completion, or a categorized failure — never an interactive
session. Unknown request fields are rejected, and any operation the daemon does
not implement fails closed rather than falling back to a shell.

This keeps the boundary clean in both directions:

- **One host surface.** Users only ever run `mvmctl`. The daemon is internal;
  its transport, port, and socket paths are implementation detail.
- **Guest images stay tool-free.** The host/builder toolchain (`mvmctl`,
  `mvm-builderd`, Nix) is never baked into a runtime guest image — only the
  builder rootfs carries `mvm-builderd`, and a build-time check enforces it.
- **Host Nix stays optional.** Nix evaluation and builds happen inside the
  builder VM behind these requests, regardless of whether the host has Nix.

`mvmctl doctor` reports a "builder daemon" line: it scans the builder-VM state
directories and probes each daemon's control socket, so readiness (or its
absence) is observable without starting a build.

## Nix on the Host

Host-side Nix is not required for normal mvm use.

On macOS, host Nix also does not remove the need for a Linux build boundary: the guest image is a Linux artifact. A macOS `nix` install can be useful for editor tooling, formatting, or unrelated projects, but `mvmctl build` should treat the builder VM as the authoritative place where Nix evaluation and builds happen.

On Linux, the host may already be capable of Linux Nix builds, but mvm still keeps the same conceptual boundary: `mvmctl build` is the user-facing command, and the builder path owns image construction and cache policy. This keeps the CLI behavior consistent across platforms.

## Caching

The builder VM keeps build state warm so repeated builds avoid re-fetching the world:

- Nix store paths are cached inside the builder environment.
- Built runtime artifacts are cached on the host.
- Unchanged flakes and lock files should reuse previous work.

The first build is allowed to be slower because it may bootstrap the builder image and populate the Nix store. Later builds should be dominated by changed inputs.

When `mvmctl` is running from this source checkout, the builder image is local-build only. A populated `~/.cache/mvm/builder-vm/<arch>/` cache can be reused only when its source fingerprint matches the current `nix/images/builder-vm/{flake.nix,flake.lock}` inputs, its recorded artifact digests still match the cached `vmlinux`, `rootfs.ext4`, and optional `cmdline.txt`, and its provenance summary matches the same source fingerprint and artifact filename set. On cache miss, fingerprint drift, artifact drift, or provenance drift, mvm uses a dev image that contains `/sbin/mvm-host-vm-init` as a Stage 0 bootstrap image to build `nix/images/builder-vm/` into a hidden staging directory, validates the kernel and rootfs, records the source fingerprint, artifact digests, and non-sensitive provenance summary, then promotes the staged output into the live cache. It prefers a local Stage 0 seed from `~/.mvm/dev/current/`, `~/.mvm/dev/prebuilt/v*/`, or `~/.mvm/dev/builds/*/`; if none of those images satisfies the Stage 0 contract, it may download the normal published dev image through the signed/hash-verified dev-image path and use it as the bootstrap seed only. It still refuses to download a published builder-VM image in a source checkout, so edits under `nix/images/builder-vm/` are built locally and are not masked by release artifacts. With `--verbose`, source-checkout cache decisions include a safe reason code such as `hit`, `missing_artifact`, `invalid_stage0_artifacts`, `missing_fingerprint`, `fingerprint_mismatch`, `missing_artifact_digest_manifest`, `artifact_digest_mismatch`, `missing_provenance`, or `provenance_mismatch`; these diagnostics do not print artifact contents, local paths, or raw digest metadata. `mvmctl dev status` also reports the builder-cache kind, readiness, and the same safe reason code without attempting a rebuild. `mvmctl dev cache inspect` exposes the same safe builder-cache summary plus dev-image presence, and `--json` emits only sanitized labels for automation.

## Benchmarking Runtime Boot

When measuring whether a prebuilt runtime image boots under a budget such as 200 ms, separate the phases:

```text
Build benchmark:
  host mvmctl build -> builder VM -> artifacts

Runtime boot benchmark:
  existing artifacts -> runtime backend -> guest ready signal
```

The runtime boot benchmark should start after the kernel and rootfs already exist. It should not include:

- builder VM startup;
- Nix evaluation;
- dependency download;
- rootfs assembly;
- artifact copy from the builder.

For Apple Virtualization runtime tests, point the benchmark config at the built kernel and rootfs and use the Apple backend. The builder VM is only involved if the benchmark setup step chooses to rebuild the image first.

## Failure Modes

If `mvmctl build` fails, check the phase named in the error:

| Symptom | Likely phase | What to inspect |
|---|---|---|
| Builder image missing or invalid | Builder bootstrap | `mvmctl doctor`, cache directory, builder image manifest. |
| Flake attribute not found | Nix evaluation | `flake.nix`, selected `--profile`, `packages.<system>.<profile>`. |
| Package fetch or hash mismatch | Nix build | The failing derivation output and fixed-output hash. |
| Artifact metadata missing | Artifact extraction | Builder result JSON, kernel/rootfs output paths. |
| Runtime boot timeout | Runtime backend | Backend logs, kernel command line, guest init, guest agent readiness. |

The important debugging rule is to keep build failures and boot failures separate. A Nix failure is not a runtime boot regression, and a runtime timeout is not usually a builder VM problem if the image already exists.

See also: [Custom microVM kernels](/guides/kernels/) for `mvmctl kernel build`.
