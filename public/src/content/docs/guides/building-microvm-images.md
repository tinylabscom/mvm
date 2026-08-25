---
title: "Building MicroVM Images"
description: How to build mvm microVM images from your own project — the mvm repository is a library, not a place to put your code.
---

mvm is a **library**, not a project to fork. You keep your code, your `flake.nix`, and your `mvm.toml` in your own repository, and `mvmctl` builds your microVM image by running `nix build` against your flake. **You should never need to edit anything inside the mvm repository.**

Under the hood, mvm wraps [microvm.nix](https://github.com/microvm-nix/microvm.nix) (MIT) — that's the NixOS module that abstracts Firecracker, Cloud Hypervisor, QEMU, crosvm, kvmtool, and stratovirt. The choice is recorded in [ADR-030](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/030-libkrun-pivot.md).

## The two files in your project

Every mvm project has a `mvm.toml` and a `flake.nix`:

```toml
# my-app/mvm.toml
flake     = "."
profile   = "default"
vcpus     = 1
memory_mib = 256
```

```nix
# my-app/flake.nix
{
  description = "my microVM app";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    mvm.url     = "github:tinylabscom/mvm";
  };

  outputs = { self, nixpkgs, mvm, ... }: {
    packages.x86_64-linux.default = mvm.lib.x86_64-linux.mkGuest {
      name = "my-app";
      services.web = {
        command = [ "/usr/local/bin/web" ];
      };
    };
  };
}
```

That's the whole user-side surface. `mvmctl machine build` reads `mvm.toml`, follows `flake = "."` to your flake, and runs `nix build` against it.

## Building

From your project directory:

```sh
mvmctl machine build              # reads mvm.toml; builds the named flake target
mvmctl run                # builds (if needed) + boots
```

`mvmctl machine build` is a host command. You run it from macOS or Linux, and mvm sends the Linux-only Nix work into the builder VM. The builder VM is headless — there is no shell into it, not even for debugging; you never need one before or during a normal build.

`mvmctl` selects the runtime backend automatically when you boot the finished image. Use `--hypervisor` on runtime commands when you want to force a specific runtime backend:

```sh
mvmctl machine run --flake . --hypervisor hvf
mvmctl machine run --flake . --hypervisor firecracker
```

If you want to drive `nix build` directly without `mvmctl` in the loop:

```sh
nix build .#default
```

That direct Nix command is only for users who intentionally manage their own Nix environment. It bypasses mvm's builder VM orchestration and is not required for the normal workflow. See [Builder VM](/guides/builder-vm/) for the detailed build boundary.

## What `mkGuest` accepts

`mvm.lib.<system>.mkGuest { … }` takes a single attribute set:

| Field | Type | Purpose |
|---|---|---|
| `name` | `string` | Human-readable identifier; baked into the rootfs at `/etc/mvm/name`. |
| `entrypoint` | `attrs` | The boot-time workload. Exactly one of three forms (see below). |
| `services` | `attrs` (optional) | Auxiliary supervised services. Same shape as `entrypoint.services`. |
| `packages` | `[pkg]` (optional) | Extra Nix packages added to the rootfs closure. |
| `hypervisor` | `string` (optional) | Override the default (`firecracker`). |
| `vcpus`, `memory_mib` | `int` (optional) | Resource defaults; `mvm.toml` overrides at run time. |
| `dev` | `bool` (optional) | Explicit accessible-vs-sealed image default. Inferred from entrypoint by default; the launch profile and run shape still decide agent-verb grants. |
| `uids` | `attrs` (optional) | `{ agent = 990; entrypoint = 0|1000; }` — privilege model override. See [Rootless workloads](#rootless-workloads) below. |
| `extraFiles` | `attrs` (optional) | `{ "/abs/path" = { content; mode?; }; }` baked into the rootfs at build time. |

SSH is not a template capability. `mkGuest` fails Nix evaluation if `packages`
or `extraFiles` try to add SSH clients, SSH servers, SSH config, host keys,
`authorized_keys`, `known_hosts`, or private-key material, and the rootfs build
also rejects SSH-related Nix store paths pulled in transitively. Guest control
is vsock-only; do not build images that rely on SSH.

## Entrypoint forms

`entrypoint` declares **exactly one** of:

```nix
# Form 1 — interactive PTY shell (accessible image, dev-friendly)
entrypoint.shell = "/bin/bash";

# Form 2 — single sealed program (production default)
entrypoint.command = [ "/usr/local/bin/serve" "--port" "8080" ];

# Form 3 — supervised multi-service
entrypoint.services = {
  web    = { command = [ "/bin/web" ]; };
  worker = { command = [ "/bin/worker" ]; restart = "always"; };
};
```

## Attached vs detached — lifecycle of the running VM

Independent of the sealed/accessible distinction, mvm exposes two **runtime lifecycle modes** modeled after libkrun's `SpawnMode`:

| Mode | What it means | When to use |
|---|---|---|
| `attached` | VM lifecycle bound to the calling process — Ctrl-C / process exit sends SIGTERM to the VM. | `mvmctl run` interactive, `mvmctl machine run -it` shell sessions, test harnesses that want deterministic teardown. |
| `detached` | VM survives caller exit — only `mvmctl machine stop` (or `VmBackend::stop`) terminates it. | `mvmctl machine run` (background), production agents, CI fixtures that boot once and run multiple phases. |

The default is `attached`. Pass `-d` to detach:

```sh
mvmctl machine run --flake .      # attached (default); Ctrl-C stops the VM
mvmctl machine run --flake . -d   # detached; the VM outlives this command
mvmctl machine wait my-app        # block until the VM exits (attached only)
mvmctl machine stop my-app        # terminate a detached VM
```

There is no command that converts a running VM between the two modes: the
mode is fixed at launch.

The lifecycle mode is **orthogonal** to the sealed/accessible distinction:

| Combination | Use case |
|---|---|
| accessible + attached | Dev-mode debug session: `entrypoint.shell`, Ctrl-C ends the session. |
| accessible + detached | Long-running dev container: shell available, survives reconnect. |
| sealed + attached | Test harness running an entrypoint to completion, exit captured. |
| sealed + detached | Production: `entrypoint.command`, runs forever until `mvmctl machine stop`. |

The trait surface lives at `mvm_core::vm_backend::{StartMode, VmBackend::start_with_mode, VmBackend::wait, VmBackend::detach}`. The libkrun backend records `StartMode` intent at `~/.mvm/vms/<name>/mode.json`; `mvmctl machine inspect` surfaces it.

## Sealed vs accessible — the same flake works for both

The mvm builder transparently determines whether the resulting image is **sealed** (production — no console attach) or **accessible** (dev — `mvmctl machine console <vm>` opens an interactive PTY over vsock). The decision is encoded in `passthru.mvm.{accessible, sealed, entrypointKind}` on the resulting derivation, and `mvmctl` reads that metadata to gate the `console` subcommand.

The default inference:

| Entrypoint form | Default mode |
|---|---|
| `entrypoint.shell = …` | **accessible** (`dev = true`) |
| `entrypoint.command = …` | **sealed** (`dev = false`) |
| `entrypoint.services = …` | **sealed** (`dev = false`) |

Override either way with the explicit `dev` field:

```nix
# A shell entrypoint that's still sealed (no console attach allowed)
mkGuest { entrypoint.shell = "/bin/bash"; dev = false; ... }

# A command entrypoint that's accessible for debugging
mkGuest { entrypoint.command = [ "..." ]; dev = true; ... }
```

The same flake source is consumed in **both** dev and production builds —
there's no separate "dev flake" the user has to maintain. The image metadata
continues to describe the guest profile and the host-side console gate, but it
is not the sole input to agent-verb authority. At launch, a baked-entrypoint
run on a non-dev profile receives the restricted ProdSafe grant; PTY and
ad-hoc argv runs require DevOnly verbs. This keeps an OCI image's artifact
metadata separate from the shape of the run that consumes it.

The `mkGuest` library produces a **busybox-as-PID-1** rootfs (no NixOS, no systemd) and emits an ext4 image directly. The boot path is: kernel → `/init` script → mounts `/proc` `/sys` `/dev` → execs your entrypoint. No service manager between the kernel and your code. mvm's security overlay (per-service uids, seccomp tier, dm-verity, read-only `/etc`) layers on top in Phase 6 without changing this base.

## Boot-time targets

**Hard floor: every prepared-cold boot must complete in strictly under 200 ms
on every supported backend.** This is a per-boot maximum, not a percentile that
can hide a slow launch. A backend that cannot meet it is not release-ready.

| Backend | Cold p50 | Snapshot-cloned p50 | Notes |
|---|---|---|---|
| Firecracker (Linux/KVM) | < 200 ms | ≤ 30 ms | Hard prepared-cold requirement; every measured dispatch must pass. |
| Cloud Hypervisor (Linux/KVM) | < 200 ms | ≤ 50 ms | Tier-1 peer of FC. Adds VFIO/GPU, virtio-gpu, virtio-fs, larger guests. Opt-in via `--hypervisor cloud-hypervisor`. |
| libkrun / libkrun (Linux/KVM) | < 200 ms | ≤ 30 ms | Cross-platform default; libkrun-backed. |
| libkrun / libkrun (macOS HVF) | < 200 ms | ≤ 60 ms | Cross-platform default; libkrun-backed. |
| Apple Virtualization framework | < 200 ms | ≤ 200 ms | Legacy ladder; superseded by libkrun per ADR-013. |

The artifact expectation is surfaced on every `mkGuest` derivation as
`passthru.mvm.expectedBootMs`, while `mvmctl bench prepared-cold` enforces the
runtime maximum from raw samples. See [ADR-013 §"Boot-time budget"](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/013-libkrun-libkrun-microvm-nix-pivot.md)
for the original backend rationale.

The floor is achievable because the rootfs uses **busybox-as-PID-1** with a custom `/init` (no NixOS, no systemd, no OpenRC). See [ADR-030](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/030-libkrun-pivot.md) for why this matters and the implementation breadcrumb.

## What's inside the mvm repository (and why you don't touch it)

The repository's `nix/` directory contains:

- `nix/flake.nix` — exposes `lib.<system>.mkGuest` for your flake to consume.
- `nix/profiles/minimal.nix` — an **internal** test fixture used by mvm's own smoke tests (`tests/smoke_libkrun.rs`, `tests/nix_flake_structure.rs`). Not a starter template.

The internal fixture lives under the `internal-` namespace in flake outputs (`nixosConfigurations.internal-minimal-…`, `packages.<system>.internal-minimal-runner`) so the boundary is mechanical: anything `internal-*` is for mvm developers, not for users.

## Validating a change to your flake

```sh
cd my-app
nix flake check --no-build
```

`mvmctl build validate` does the same with extra `mvm.toml` checks layered on.

## Cross-platform notes

mvm runs Nix builds inside the project builder VM and copies the finished kernel/rootfs artifacts back to the host cache. You don't need host-side Nix, and you don't need to enter a dev shell before building.

- **Linux**: the builder VM provides the Linux build boundary and cache policy. Firecracker is the default runtime backend when `/dev/kvm` is available.
- **macOS**: the host `mvmctl machine build` command orchestrates a Linux builder VM. The resulting runtime image boots on the HVF backend by default on macOS 26+ (Hypervisor.framework, vsock-only), or libkrun on macOS 13–25.
- **Windows**: Tauri-only (the `mvm-studio` desktop app packages a WSL2-backed builder + runtime). See [ADR-009](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/009-cross-platform-strategy.md).

## Rootless workloads

PID 1 must be uid 0 (kernel mandate). Everything else can — and by default in production *does* — run non-root. mkGuest's `uids` knob controls the privilege drop:

| Process | Default uid | Role |
|---|---|---|
| `/init` (PID 1) | 0 | Mounts pseudofs, forks the agent in the background, drops privs, exec's the entrypoint |
| `mvm-guest-agent` | 990 | Vsock RPC handler (never needs root); supervised by `/init` |
| Entrypoint (workload) | **0 in dev**, **1000 in prod** | Your service or shell |

> **Agent binary status:** as of Phase 1 W6.1.1 the agent at `/usr/local/bin/mvm-guest-agent` is a **stub** — a sh script that logs startup and sleeps. The supervision pattern is real (init forks it under uid 990 before setpriv-exec'ing the entrypoint); the vsock RPC surface lands when W6.1.2 swaps in the cross-compiled Rust binary. Every derivation surfaces `passthru.mvm.agentBinary = "stub" | "real"` so production deployments can refuse to boot a stub image.

The dev/prod default split is intentional:

- **Dev** keeps entrypoint as root because debug shells expect root: `apt install`, `mount`, `tcpdump`. Forcing rootless dev would break those flows on first try.
- **Prod** drops to uid 1000 by default per ADR-001 W2.1 — "no guest binary can elevate to uid 0." A workload that *isn't* root can't be re-elevated.

`/init` uses `setpriv --reuid=N --regid=N --clear-groups --no-new-privs --` to drop. `--no-new-privs` blocks `setuid` re-elevation, so even if the workload finds a SUID binary, it can't reach uid 0.

### Override

```nix
# Rootless dev shell — forces non-root even in dev mode.
mkGuest {
  entrypoint.shell = "/bin/bash";
  uids = { entrypoint = 1000; };
}

# Rootful prod workload — explicit override, rarely the right call.
mkGuest {
  entrypoint.command = [ "/usr/local/bin/serve" ];
  uids = { entrypoint = 0; };
}

# Non-default agent uid (e.g. to avoid collisions with host-side ranges).
mkGuest {
  entrypoint.command = [ "/bin/x" ];
  uids = { agent = 5000; };
}
```

The resolved values surface as `passthru.mvm.uids = { agent; entrypoint; }` and `passthru.mvm.rootlessEntrypoint :: bool` so `mvmctl machine inspect` can cross-check against `/proc/<pid>/status` at runtime.

## Why no OCI

mvm is microVMs, not containers. Even though the underlying libkrun library exposes OCI image pulls (`RootfsSource::Oci`), mvm uses **only** the host-local disk-image path. The bridge between your Nix-built `.ext4` rootfs and the runtime is a sibling `.raw` hard-link with `fstype("ext4")` — no registry, no auth, no pull cache, fully offline-by-default once your rootfs is built. ADR-013 §"Non-goal: OCI / container images" carries the full rationale.
