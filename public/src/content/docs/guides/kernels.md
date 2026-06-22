---
title: "Custom microVM kernels"
description: "Build or download the slim builder/workload kernels mvm boots, with mvmctl build kernel build."
---

mvm boots slim, custom-configured Linux kernels for the builder VM and for
workload microVMs. Because the config is custom, the public Nix cache has no
substitute for them — a fresh machine compiles from source, which is the slow,
memory-heavy step a first `mvmctl dev up` otherwise hits implicitly.
`mvmctl build kernel build` makes that step explicit and one-time.

## Build a kernel

```bash
# Compile the builder kernel for this host (slow on first run, then cached)
mvmctl build kernel build --which builder --source compile

# Download the prebuilt, hash-verified kernel that shipped with this mvmctl
mvmctl build kernel build --which workload --source download

# Download if a prebuilt exists for this release, else compile locally
mvmctl build kernel build --all --source auto
```

Flags:

- `--which {builder,workload}` — which kernel (default `builder`).
- `--all` — build both variants.
- `--source {compile,download,auto}` — where the kernel comes from (default `compile`).
- `--arch {aarch64,x86_64}` — target arch (default: host arch).

The compiled or downloaded kernel is cached at
`~/.cache/mvm/builder-vm/<arch>/kernels/<variant>/vmlinux` and reused by every
later `dev up`.

## compile vs download

- **compile** builds locally through the Stage 0 bootstrap. It can only build
  the **host** architecture — Stage 0 boots a host-arch VM, so it cannot
  cross-compile. First compile is 3–10 min; later runs hit the persistent Nix
  store. The compile path prints an elapsed-time heartbeat, and `--verbose`
  streams the live `nix build` console output.
- **download** fetches a prebuilt `vmlinux-<arch>-<variant>` from the GitHub
  release whose tag matches **this mvmctl's own version**. A given mvmctl can
  only ever fetch the kernel that shipped with it — never a substitute for an
  in-tree kernel-config edit (a source checkout compiles instead). This is the
  only way to obtain the **other** architecture's kernel.

## Integrity

Downloaded kernels are SHA-256-verified against the release's
`kernel-<arch>-checksums-sha256.txt` before being admitted to the cache; a
mismatch deletes the download and aborts. `MVM_SKIP_HASH_VERIFY=1` is the
documented emergency escape — never use it in CI.

The kernels themselves are published by the `kernel-build` GitHub Actions
workflow on every `v*` release tag. See [Releases & downloads](/reference/releases/)
for the full pipeline.
