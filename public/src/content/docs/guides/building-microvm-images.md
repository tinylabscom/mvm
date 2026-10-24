---
title: "Building MicroVM Images"
description: How to build mvm microVM images from your own project — the mvm repository is a library, not a place to put your code.
---

mvm is a **library**, not a project to fork. You keep your code, your `flake.nix`, and your `mvm.toml` in your own repository, and `mvmctl` builds your microVM image by running `nix build` against your flake. **You should never need to edit anything inside the mvm repository.**

(The exception is when you are developing mvm's *own* system images — the
builder VM, the default workload image, the kernel, the runtime overlay.
That workflow uses a sibling [`mvm-images`](https://github.com/tinylabscom/mvm-images)
checkout and is documented in [Developing Images with a Sibling Checkout](/guides/image-sibling-checkout/).)

Under the hood, mvm wraps [microvm.nix](https://github.com/microvm-nix/microvm.nix) (MIT) — that's the NixOS module that abstracts Firecracker, Cloud Hypervisor, QEMU, crosvm, kvmtool, and stratovirt. The choice is recorded in [ADR-030](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/030-libkrun-pivot.md).

## The two files in your project

Every mvm project has a `mvm.toml` and a `flake.nix`:

```toml
# my-app/mvm.toml
flake     = "."
profile   = "default"
cpus      = 1          # `vcpus` is an accepted alias
mem       = "256M"
```

`mvm.toml` uses `deny_unknown_fields`, so a key it does not define is a parse
error. Memory is `mem` (a size string); `memory_mib` is a `mkGuest` argument,
not a manifest key.

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
      # `entrypoint` is required — mkGuest throws without exactly one of
      # `shell` / `command` / `services`.
      entrypoint.command = [ "/usr/local/bin/web" ];
    };
  };
}
```

That's the whole user-side surface. `mvmctl machine build` reads `mvm.toml`, follows `flake = "."` to your flake, and runs `nix build` against it.

## Building

From your project directory:

```sh
mvmctl machine build                      # reads mvm.toml; builds the named flake target
mvmctl machine run --manifest . -- <cmd>  # boots the built image and runs <cmd>
```

A bare `mvmctl run` refuses with "needs a command" — it takes a trailing argv
(or `--launch-plan`), and it never inspects `flake.nix` to decide what to
build.

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
| `entrypoint` | `attrs` | The host-dispatched workload. Exactly one of three forms (see below). |
| `services` | `attrs` (optional) | Declared and recorded, but **not enforced** — the multi-service supervisor is not wired. |
| `packages` | `[pkg]` (optional) | Extra Nix packages added to the rootfs closure. |
| `hypervisor` | `string` (optional) | Override the default (`firecracker`). |
| `vcpus`, `memory_mib` | `int` (optional) | Resource defaults; `mvm.toml` overrides at run time. |
| `dev` | `bool` (optional) | Explicit accessible-vs-sealed image default. Inferred from entrypoint by default; the launch profile and run shape still decide agent-verb grants. |
| `uids` | `attrs` (optional) | Account and direct-script drop declarations (default: both 901); not an override of the universal runtime identity. See [Rootless workloads](#rootless-workloads). |
| `extraFiles` | `attrs` (optional) | `{ "/abs/path" = { content; mode?; }; }` writes text, `{ source; mode?; }` copies a file, and `{ link; }` makes a symlink to a Nix store path. All are baked into the rootfs at build time. |

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

# Form 3 — supervised multi-service (NOT WIRED: the boot falls through
# to a recovery shell; the multi-service supervisor is not built yet)
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
mvmctl machine wait my-app        # block until the guest reports ready (hidden verb)
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

The `mkGuest` library composes a workload ext4 rootfs with static busybox
utilities, packages and workload metadata, but **no mvm-authored shell `/init`**
or `/sbin/init`. Both dev and sealed boots run the universal initramfs agent
as PID 1. It activates over vsock, mounts the read-only root and runtime,
then dispatches the entrypoint on the host's `RunEntrypoint` request. The
entrypoint is not autostarted as PID 1; its exit does not kill PID 1.

Every composition carries integer `passthru.mvm.baseImageContract = 1` and
`/etc/mvm/base-image-contract` containing exactly `1\n`.
Keep the declared entrypoint argv aligned with any wrapper supplied through
`extraFiles`; the host uses `passthru.mvm.entrypointArgv` for admission.
`bootCommand` and `/etc/mvm/boot` are no longer part of the interface.
Workload composition here is separate from the canonical Linux bases,
kernels and builder image owned by `mvm-images`.

## Boot-time targets

**Hard floor: every prepared-cold boot must complete in strictly under 200 ms
on every supported backend.** This is a per-boot maximum, not a percentile that
can hide a slow launch. A backend that cannot meet it is not release-ready.

| Backend | Cold p50 | Snapshot-cloned p50 | Notes |
|---|---|---|---|
| Firecracker (Linux/KVM) | < 200 ms | ≤ 30 ms | Hard prepared-cold requirement; every measured dispatch must pass. |
| HVF (macOS 26+, Apple Silicon) | < 200 ms | ≤ 60 ms | In-house Hypervisor.framework VMM; macOS default. |
| libkrun (explicit macOS 13–25 preview) | < 200 ms | ≤ 30 ms | Bundled in the signed Apple Silicon release; the real packaged guest-launch witness is still required. |
| QEMU (Linux dev/test) | — | — | Opt-in dev/test substrate; no snapshot support. |

The artifact expectation is surfaced on every `mkGuest` derivation as
`passthru.mvm.expectedBootMs`, while `mvmctl bench --lane prepared-cold` enforces the
runtime maximum from raw samples. See the
[cold-launch performance plan](https://github.com/tinylabscom/mvm/blob/main/specs/plans/299-cold-launch-performance.md)
for the measured budgets and backend rationale.

The boot path uses the static Rust initramfs agent rather than NixOS,
systemd or OpenRC. Boot-time metadata is not a substitute for measurements
on the selected backend.

## What's inside the mvm repository (and why you don't touch it)

The repository's `nix/` directory contains:

- `nix/flake.nix` — exposes `lib.<system>.mkGuest` for your flake to consume.
- `nix/profiles/minimal.nix` — an **internal** test fixture pinned by mvm's own `tests/nix_flake_structure.rs`. Not a starter template.

The internal fixture lives under the `internal-` namespace in flake outputs (`nixosConfigurations.internal-minimal-…`, `packages.<system>.internal-minimal-runner`) so the boundary is mechanical: anything `internal-*` is for mvm developers, not for users.

## Validating a change to your flake

```sh
cd my-app
nix flake check --no-build
```

`mvmctl dev validate` does the same with extra `mvm.toml` checks layered on.

## Cross-platform notes

mvm runs Nix builds inside the project builder VM and copies the finished kernel/rootfs artifacts back to the host cache. You don't need host-side Nix, and you don't need to enter a dev shell before building.

- **Linux**: the builder VM provides the Linux build boundary and cache policy. Firecracker is the default runtime backend when `/dev/kvm` is available.
- **macOS**: the host `mvmctl machine build` command orchestrates a Linux builder VM. On supported Apple Silicon hosts running macOS 26+, both the builder and resulting runtime use native HVF (Hypervisor.framework, vsock-only) without libkrun. macOS 13–25 has a bundled libkrun preview selected explicitly with `--builder libkrun` and `--hypervisor libkrun`.
- **Windows**: Tauri-only (the `mvm-studio` desktop app packages a WSL2-backed builder + runtime). See [ADR-009](https://github.com/tinylabscom/mvm/blob/main/specs/adrs/009-cross-platform-strategy.md).

## Rootless workloads

The universal initramfs agent performs privileged activation as PID 1 and then
drops to the fixed workload identity. It dispatches both dev and sealed
workloads as uid 901; an accessible image is not a grant of root privilege.

| Process | Default uid | Role |
|---|---|---|
| Initramfs agent (PID 1) | 0 → 901 | Activates and mounts the root, starts runtime services, then serves vsock RPC |
| Entrypoint (workload) | 901 | Your service or shell |
| Addon DNS / CRNG reseed / egress | 987 / 988 / 989 | Dedicated runtime services |

> **Agent binary status:** the agent is the cross-compiled Rust binary; `mkGuest` emits `passthru.mvm.agentBinary = "real"` unconditionally. The `"stub"` value is retained only as something a consumer may refuse — nothing produces it any more.

The immutable root names `root` (0), `mvm-worker` (901), `mvm-dns` (987),
`mvm-crng` (988) and `mvm-egress` (989). Optional `builderUid = 902` adds
`mvm-builder`. No guest NIC is present; egress uses authenticated FlowMux
over vsock and local adapters on loopback.

### Override

```nix
# Declare the workload account and direct-script privilege drop.
mkGuest {
  entrypoint.shell = "/bin/bash";
  uids = { entrypoint = 901; };
}

# Add an account row outside the fixed set.
mkGuest {
  entrypoint.command = [ "/bin/x" ];
  uids = { agent = 5000; };
}
```

These declarations surface as `passthru.mvm.declaredUids`.
`passthru.mvm.uids` reports the actual runtime's agent/workload uid 901 and
`passthru.mvm.rootlessEntrypoint` is true. Overrides do not reconfigure the universal
agent's uid or elevate an already-unprivileged workload. When a generated
entrypoint script is invoked directly as root it uses `mvm-setpriv` for its
declared drop; normal agent dispatch skips that second drop.
The runtime provides `/mvm/runtime/setpriv`, and `withSetpriv` controls the
additional baked helper.

Function-workload compositions preserve their source symlink,
`/etc/mvm/entrypoint`, wrapper/runtime JSON and lifecycle hook files.
`before_start.sh` was previously called only by the shell boot script and is
not dispatched on the universal path; it remains baked for lifecycle support,
not a promise that startup hooks run today.

## Why no OCI

mvm is microVMs, not containers. Even though the underlying libkrun library exposes OCI image pulls (`RootfsSource::Oci`), mvm uses **only** the host-local disk-image path. The bridge between your Nix-built `.ext4` rootfs and the runtime is a sibling `.raw` hard-link with `fstype("ext4")` — no registry, no auth, no pull cache, fully offline-by-default once your rootfs is built. ADR-013 §"Non-goal: OCI / container images" carries the full rationale.
