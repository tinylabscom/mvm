---
title: "Custom microVM kernels"
description: "Build or download the slim builder/workload kernels mvm boots, with mvmctl build kernel build."
---

mvm boots slim, custom-configured Linux kernels for the builder VM and for
workload microVMs. The kernel definitions live in
[mvm-images](https://github.com/tinylabscom/mvm-images), which builds and
publishes them as members of the signed image set `mvmctl` pins. Installed
binaries use that published, verified workload kernel on a cold cache. A source
checkout with an mvm-images checkout selected (`MVM_IMAGES_DIR`, or a sibling
`../mvm-images`) compiles the kernel from it on the first image-backed run
through Stage 0, then reuses it.
`mvmctl build kernel build` or `just kernel-workload` remains available when you
want to prewarm the cache explicitly.

## Build a kernel

```bash
# Compile the builder kernel for this host (slow on first run, then cached)
mvmctl build kernel build --which builder --source compile

# Download the kernel from the image set this mvmctl pins
mvmctl build kernel build --which workload --source download

# Download if a prebuilt exists for this release, else compile locally
mvmctl build kernel build --all --source auto
```

Flags:

- `--which {builder,workload}` — which kernel (default `builder`).
- `--all` — build both variants.
- `--source {compile,download,auto}` — where the kernel comes from (default
  `compile`, unless `--kernel-source` or `MVM_KERNEL_SOURCE` is set).
- `--arch {aarch64,x86_64}` — target arch (default: host arch).
- `--boot-check` — after building the default workload kernel, boot a throwaway
  VM on it and confirm the in-guest agent answers over vsock.

Workload kernels ship with `CONFIG_CC_OPTIMIZE_FOR_SIZE=y`. There is no
`workload-sizeopt` selector on `--which` — the only two values are `builder`
and `workload`.

The compiled or downloaded kernel is cached at
`~/.mvm/cache/kernels/<arch>/<variant>/vmlinux` and reused by every
later run that needs it. (A kernel left at the older
`~/.mvm/cache/builder-vm/<arch>/kernels/<variant>/` path is moved to the
current one the next time it is read, so an existing cache is not rebuilt.) (There is no `mvmctl dev` command — it was removed.)

When the kernel was compiled locally, the cache directory also carries a
resolved `config` sidecar and `kernel-metrics-<arch>.json`, so you can inspect
the exact `olddefconfig` result without a CI round-trip.

### Troubleshooting a first-run kernel failure

The first image-backed run may build the workload kernel through Stage 0. If
the output says `builder egress endpoint ... exited with status signal: 15
(SIGTERM)`, that is normally the host-side egress endpoint being stopped as
Stage 0 cleans up. It is not, by itself, a workload boot failure.

Treat a following error such as `resolved workload kernel ... carries no
device-mapper/dm-verity support` as the real failure. Workloads boot from a
verity-sealed root and require the workload kernel's device-mapper and
dm-verity support; a builder kernel cannot be used for this purpose. Rebuild
the workload variant with `--which workload`, or download the matching
published kernel.

## Inspect resolved configs and metrics

The kernel flake — the shared base config, the per-variant deltas, the
resolved-config and metrics outputs, and the built-in symbol budget — is
mvm-images'. Edit and inspect it there; a compile from that checkout leaves the
resolved `config` sidecar and `kernel-metrics-<arch>.json` next to the cached
kernel, as described above.

## compile vs download

- **compile** builds locally through the Stage 0 bootstrap. It can only build
  the **host** architecture — Stage 0 boots a host-arch VM, so it cannot
  cross-compile. The first build can take several minutes depending on the
  host; later runs reuse the persistent Nix store. The compile path prints an
  elapsed-time heartbeat, and `--verbose`
  streams the live `nix build` console output.
- **download** fetches the kernel from the image set this mvmctl's
  `images.lock` pins. A given mvmctl only ever fetches that pinned kernel —
  never a substitute for a kernel-config edit in your mvm-images checkout. Use
  `--source compile` when you need to exercise local kernel changes. This is
  the only way to obtain the **other** architecture's kernel.

The global kernel policy also applies when acquiring a kernel directly. This
also applies to `machine run --image`:

```bash
# Prefer the pinned, verified image-set kernel, even from a source checkout.
MVM_KERNEL_SOURCE=download just kernel-workload

# The same policy applies to the first image-backed run.
MVM_KERNEL_SOURCE=download mvmctl machine run --image python:3.12 -- python -V
```

`MVM_KERNEL_SOURCE=auto` downloads when the pinned image set carries the kernel
and otherwise falls back to the local compile path. Unset defaults to local
compile from a source checkout with an mvm-images checkout selected, and
download otherwise. An explicit
`--source` always wins over the environment policy.

## Integrity

Downloaded kernels are members of the signed image set: `mvmctl` checks the
set's root manifest against the digest `images.lock` pins, its signature
against the pinned mvm-images release identity, and the kernel's size and
SHA-256 against the root before admitting it to the cache; a mismatch deletes
the download and aborts. See [Releases & downloads](/reference/releases/) for
how image sets are published.
