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
  | mvmctl machine run --hypervisor hvf
  v
runtime microVM
```

## What Runs Where

| Work                                      | Runs on                     | Why                                                                                                  |
| ----------------------------------------- | --------------------------- | ---------------------------------------------------------------------------------------------------- |
| CLI parsing, config loading, cache lookup | Host                        | Fast local control-plane work.                                                                       |
| Nix flake evaluation                      | Builder VM                  | The target is a Linux image, and the build environment must be Linux.                                |
| `nix build`                               | Builder VM                  | Keeps host Nix optional and avoids macOS/Linux platform mismatch.                                    |
| Rootfs and kernel artifact extraction     | Builder VM, then host cache | The builder produces artifacts; the host stores and reuses them.                                     |
| Runtime boot                              | Runtime backend             | Uses an already-built image. This is Firecracker, Apple Virtualization, libkrun, or another backend. |
| Runtime guest agent traffic               | Runtime microVM             | Uses the runtime VM's guest communication path, normally vsock where supported.                      |

This separation is deliberate. A build can take seconds or minutes because it may fetch and compile Nix closures. A runtime boot benchmark should normally measure only the already-built image booting, not the build phase.

## There Is No Shell Into The Builder VM

The normal build command is:

```bash
mvmctl build --flake .
```

That command should be run from your project directory on the host. `mvmctl` takes care of starting or reaching the builder VM, staging the flake, running the build, and copying the result back.

The builder VM is headless by design — there is no interactive shell into it, not even for debugging. You never "enter" it to inspect the Linux build environment, manually run `nix build`, or check Nix store disk usage; you debug through its logs and structured output instead:

- `mvmctl build --flake .` prints the build's own progress and errors.
- `mvmctl doctor` reports the resolved builder backend and its readiness.
- A failing `nix build` inside the builder VM surfaces its error back to the host command that triggered it — there's no separate shell session to reproduce it in.

None of the following ever require or offer a shell into the builder VM:

- `mvmctl build --flake .`;
- `mvmctl run`;
- `mvmctl machine run --flake .`;
- building a registered template;
- booting a prebuilt runtime image.

## Build Then Boot

For an explicit two-step flow:

```bash
# 1. Build the runtime image.
mvmctl build --flake .

# 2. Boot the already-built image.
mvmctl machine run --flake . --hypervisor hvf
```

On macOS 26+ the default runtime backend is HVF (Hypervisor.framework, vsock-only). The builder VM remains a build-time implementation detail. It is not the same VM as your workload VM.

That distinction matters for networking. A macOS HVF workload VM is already
vsock-only, with no guest NIC in the runtime path. The builder VM is different:
the workload path does not imply anything about builder bootstrap. On current
macOS HVF hosts, a source-checkout builder-image rebuild now stays on the
trusted HVF builder transport once a cached or verified base builder image
exists, rather than silently falling back to the older libkrun gateway path.
If the base image is missing, the builder path may still need a verified
bootstrap artifact for fetch-capable rebuilds. So seeing a `network-backend` or
gateway check in `mvmctl doctor` does not mean workload traffic is going
through a legacy guest-NIC helper.

For development convenience, `mvmctl run` combines the two phases:

```bash
mvmctl run
```

That is equivalent to "build if needed, then boot." It is convenient for daily use, but it is not the right measurement point if you are trying to isolate runtime boot latency.

## Builder VM vs Runtime MicroVM

The builder VM and runtime microVM have different jobs:

| VM              | Purpose                                   | Lifetime                                                  | State                                   |
| --------------- | ----------------------------------------- | --------------------------------------------------------- | --------------------------------------- |
| Builder VM      | Runs Linux Nix builds and image assembly. | Reused or launched as needed by the build pipeline.       | Has a warm Nix store/cache.             |
| Runtime microVM | Runs your workload from a finished image. | Created by `mvmctl machine run`, `run`, `exec`, or tests. | Uses the built rootfs/kernel artifacts. |

Do not benchmark the builder VM when you want runtime boot time. The builder VM exists so that the host can ask for Linux builds without becoming a Linux build machine itself.

## Persistent builder VM

There is exactly one builder persona: a persistent, non-interactive build
worker VM. It stays warm across builds (`cargo run -- build` / `mvmctl
build`) so a developer iterating on a flake doesn't pay a builder-VM boot
on every invocation. There is no separate "developer" persona with a
shell — the builder VM is headless in every mode.

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

The intended top-level DX is that developers do not need to invoke the low-level controls for normal use: `mvmctl bootstrap` pre-fetches the builder VM image, and `build` uses a persistent non-interactive builder by default when the platform supports it. If the persistent path is unavailable, the command should say why it fell back rather than silently changing the trust and performance model.

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

When `mvmctl` is running from this source checkout, the builder image is local-build only. A populated `~/.mvm/cache/builder-vm/<arch>/` cache can be reused only when its source fingerprint matches the current `nix/images/builder-vm/{flake.nix,flake.lock}` inputs, its recorded artifact digests still match the cached `vmlinux`, `rootfs.ext4`, and optional `cmdline.txt`, and its provenance summary matches the same source fingerprint and artifact filename set. On cache miss, fingerprint drift, artifact drift, or provenance drift, mvm uses a dev image that contains `/sbin/mvm-host-vm-init` as a Stage 0 bootstrap image to build `nix/images/builder-vm/` into a hidden staging directory, validates the kernel and rootfs, records the source fingerprint, artifact digests, and non-sensitive provenance summary, then promotes the staged output into the live cache. It prefers a local Stage 0 seed from `~/.mvm/dev/current/`, `~/.mvm/dev/prebuilt/v*/`, or `~/.mvm/dev/builds/*/`; if none of those images satisfies the Stage 0 contract, it may download the normal published dev image through the signed/hash-verified dev-image path and use it as the bootstrap seed only. It still refuses to download a published builder-VM image in a source checkout, so edits under `nix/images/builder-vm/` are built locally and are not masked by release artifacts. With `--verbose`, source-checkout cache decisions include a safe reason code such as `hit`, `missing_artifact`, `invalid_stage0_artifacts`, `missing_fingerprint`, `fingerprint_mismatch`, `missing_artifact_digest_manifest`, `artifact_digest_mismatch`, `missing_provenance`, or `provenance_mismatch`; these diagnostics do not print artifact contents, local paths, or raw digest metadata. `mvmctl doctor` reports the builder-cache readiness and the resolved builder backend without attempting a rebuild, and its `--json` output emits only sanitized labels for automation.

Editing `nix/images/builder-vm/` or files under `nix/lib/` changes the builder-VM
source fingerprint, so the next run from a source checkout invalidates the cached
image and rebuilds it locally. That Stage 0 rebuild needs a host `mkfs.ext4`
(`e2fsprogs` on Debian/Ubuntu, `brew install e2fsprogs` on macOS). If the rebuild
fails with a missing `mkfs.ext4` error, install `e2fsprogs` and rerun; the cached
Nix store and built artifacts remain warm.

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

| Symptom                          | Likely phase        | What to inspect                                                       |
| -------------------------------- | ------------------- | --------------------------------------------------------------------- |
| Builder image missing or invalid | Builder bootstrap   | `mvmctl doctor`, cache directory, builder image manifest.             |
| Flake attribute not found        | Nix evaluation      | `flake.nix`, selected `--profile`, `packages.<system>.<profile>`.     |
| Package fetch or hash mismatch   | Nix build           | The failing derivation output and fixed-output hash.                  |
| Artifact metadata missing        | Artifact extraction | Builder result JSON, kernel/rootfs output paths.                      |
| Runtime boot timeout             | Runtime backend     | Backend logs, kernel command line, guest init, guest agent readiness. |

The important debugging rule is to keep build failures and boot failures separate. A Nix failure is not a runtime boot regression, and a runtime timeout is not usually a builder VM problem if the image already exists.

See also: [Custom microVM kernels](/guides/kernels/) for `mvmctl kernel build`.
