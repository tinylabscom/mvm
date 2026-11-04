---
title: "Custom microVM kernels"
description: "Build or download the slim builder/workload kernels mvm boots, with mvmctl dev kernel build."
---

mvm boots slim, custom-configured Linux kernels for the builder VM and for
workload microVMs. Because the config is custom, the public Nix cache has no
substitute for them. Installed binaries use the published, hash-verified
workload kernel on a cold cache. A source checkout builds the dedicated kernel
automatically on the first image-backed run through Stage 0, then reuses it.
`mvmctl dev kernel build` or `just kernel::workload` remains available when you
want to prewarm the cache explicitly.

## Build a kernel

```bash
# Compile the builder kernel for this host (slow on first run, then cached)
mvmctl dev kernel build --which builder --source compile

# Download the prebuilt, hash-verified kernel that shipped with this mvmctl
mvmctl dev kernel build --which workload --source download

# Download if a prebuilt exists for this release, else compile locally
mvmctl dev kernel build --all --source auto
```

Flags:

- `--which {builder,workload,workload-k8s,rootless}` — which kernel (default
  `builder`). `workload-k8s` is never compiled; only a cached one is selectable.
- `--all` — build both variants.
- `--source {compile,download,auto}` — where the kernel comes from (default
  `compile`, unless `--kernel-source` or `MVM_KERNEL_SOURCE` is set).
- `--arch {aarch64,x86_64}` — target arch (default: host arch).
- `--boot-check` — after building the default workload kernel, boot a throwaway
  VM on it and confirm the in-guest agent answers over vsock.

Workload kernels ship with `CONFIG_CC_OPTIMIZE_FOR_SIZE=y`. There is no
`workload-sizeopt` selector on `--which`.

The compiled or downloaded kernel is cached at
`~/.mvm/cache/kernels/<arch>/<variant>/vmlinux` and reused by every
later run that needs it. (A kernel left at the older
`~/.mvm/cache/builder-vm/<arch>/kernels/<variant>/` path is moved to the
current one the next time it is read, so an existing cache is not rebuilt.)

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

A locally compiled kernel leaves its resolved `config` and
`kernel-metrics-<arch>.json` beside it in the cache (see above). The kernel
flake and its config outputs live in the `mvm-images` repository, so inspect or
diff configs from a checkout of it.

## compile vs download

- **compile** builds locally through the Stage 0 bootstrap. It can only build
  the **host** architecture — Stage 0 boots a host-arch VM, so it cannot
  cross-compile. The first build can take several minutes depending on the
  host; later runs reuse the persistent Nix store. The compile path prints an
  elapsed-time heartbeat, and `--verbose`
  streams the live `nix build` console output.
- **download** fetches a prebuilt `vmlinux-<arch>-<variant>` from the GitHub
  release whose tag matches **this mvmctl's own version**. A given mvmctl can
  only ever fetch the kernel that shipped with it — never a substitute for an
  in-tree kernel-config edit. Use `--source compile` when you need to exercise
  local kernel changes. This is the only way to obtain the **other**
  architecture's kernel.

The global kernel policy also applies when acquiring a kernel directly. This
also applies to `machine run --image`:

```bash
# Prefer the matching hash-verified release kernel, even from a source checkout.
MVM_KERNEL_SOURCE=download just kernel::workload

# The same policy applies to the first image-backed run.
MVM_KERNEL_SOURCE=download mvmctl machine run --image python:3.12 -- python -V
```

`MVM_KERNEL_SOURCE=auto` downloads when the matching release asset exists and
otherwise falls back to the local compile path. Unset defaults to local compile
from a source checkout and download for an installed binary. An explicit
`--source` always wins over the environment policy.

## Integrity

Downloaded kernels are SHA-256-verified against the release's
`kernel-<arch>-checksums-sha256.txt` before being admitted to the cache; a
mismatch deletes the download and aborts. `MVM_SKIP_HASH_VERIFY=1` is the
documented emergency escape — never use it in CI.

The kernels themselves are published by the `kernel-build` GitHub Actions
workflow on every `v*` release tag. See [Releases & downloads](/reference/releases/)
for the full pipeline.
